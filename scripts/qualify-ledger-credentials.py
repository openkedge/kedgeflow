#!/usr/bin/env python3
"""Destructive credential-publisher qualification on an empty disposable systemd host.

Uses isolated real TLS/authenticated etcd and three temporary host accounts.
Generated PKI and root fixture administration do not qualify production PKI/storage.
"""

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import pwd
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
ACCOUNTS = ("kf-control", "kf-credentials", "kf-credential-agent")
UNITS = ("kedgeflow-ledger-issue.service", "kedgeflow-ledger-publish.service")


def require(condition, message="credential qualification failed"):
    if not condition:
        raise RuntimeError(message)


def run(argv, check=True):
    result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=100)
    require(not check or result.returncode == 0, f"fixture command failed: {argv[0]}")
    return result


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def write(path, raw, uid=0, gid=0, mode=0o400):
    path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
    os.chown(path, uid, gid)
    path.chmod(mode)


def pki(directory):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable credential CA")])

    def builder(subject, key):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
        )

    ca = builder(ca_name, ca_key).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
    ca = ca.add_extension(
        x509.KeyUsage(True, False, False, False, False, True, True, False, False), True
    )
    ca = ca.sign(ca_key, hashes.SHA256())
    write(directory / "ca.pem", ca.public_bytes(serialization.Encoding.PEM), mode=0o444)
    for name in ("server", "client"):
        key = ec.generate_private_key(ec.SECP256R1())
        # Empty CN: etcd's authenticated JSON gateway refuses client CN authentication.
        leaf = builder(x509.Name([]), key).add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            True,
        )
        leaf = leaf.add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        leaf = leaf.sign(ca_key, hashes.SHA256())
        write(directory / f"{name}.pem", leaf.public_bytes(serialization.Encoding.PEM), mode=0o444)
        write(
            directory / f"{name}.key",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )


def qualify(binary, etcd_binary):
    require(platform.system() == "Linux" and os.geteuid() == 0 and __debug__)
    require(Path("/proc/1/comm").read_text().strip() == "systemd")
    for name in ACCOUNTS:
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError("refusing existing project account")
        require(
            run(["getent", "group", name], check=False).returncode != 0,
            "refusing existing project group",
        )
    unit_root = Path("/etc/systemd/system")
    for unit in UNITS:
        require(not (unit_root / unit).exists() and not (unit_root / unit).is_symlink())
        require(
            run(["systemctl", "show", unit, "-p", "LoadState", "--value"], False).stdout.strip()
            == b"not-found",
            "refusing existing project unit",
        )
    base = Path(tempfile.mkdtemp(prefix="kf-ledger-", dir="/run"))
    marker = base.name
    owned, units, child = [], [], None
    observations = []
    report = {
        "status": "failed",
        "scope": "protected ledger token issuer and local sink",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "etcd_sha256": hashlib.sha256(etcd_binary.read_bytes()).hexdigest(),
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [Path(__file__), *sorted((ROOT / "deploy/linux/credentials").iterdir())]
            if p.is_file()
        },
    }
    try:
        base.chmod(0o755)
        for name in ACCOUNTS:
            run(
                [
                    "useradd",
                    "--system",
                    "--no-create-home",
                    "--user-group",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    name,
                ]
            )
            owned.append(name)
        users = {name: pwd.getpwnam(name) for name in ACCOUNTS}
        publisher, service, agent = (
            users[name] for name in ("kf-credentials", "kf-control", "kf-credential-agent")
        )
        require(len({p.pw_uid for p in users.values()}) == 3)
        inputs = base / "inputs"
        inputs.mkdir(mode=0o750)
        os.chown(inputs, 0, publisher.pw_gid)
        stage = base / "stage"
        stage.mkdir(mode=0o750)
        os.chown(stage, publisher.pw_uid, publisher.pw_gid)
        output = base / "services"
        output.mkdir(mode=0o755)
        role = output / "control"
        role.mkdir(mode=0o750)
        os.chown(role, 0, service.pw_gid)
        destination = role / "credentials"
        destination.mkdir(mode=0o750)
        os.chown(destination, 0, service.pw_gid)
        tools = base / "tools"
        tools.mkdir(mode=0o755)
        shutil.copyfile(binary, tools / "kf-ledger-credentials")
        (tools / "kf-ledger-credentials").chmod(0o755)
        shutil.copyfile(ROOT / "deploy/linux/credentials/publish.py", tools / "publish.py")
        (tools / "publish.py").chmod(0o755)
        pki(inputs)
        signing_key = ec.generate_private_key(ec.SECP256R1())
        write(
            inputs / "jwt.key",
            signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ),
        )
        write(
            inputs / "jwt.pub",
            signing_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )
        password = secrets.token_urlsafe(48)
        admin_password = secrets.token_urlsafe(48)
        for filename in ("client.key",):
            os.chown(inputs / filename, publisher.pw_uid, publisher.pw_gid)
        write(inputs / "ordinary.password", password, publisher.pw_uid, publisher.pw_gid)
        client_port, peer_port = port(), port()
        endpoint = f"https://127.0.0.1:{client_port}"
        peer = f"http://127.0.0.1:{peer_port}"
        child = subprocess.Popen(
            [
                str(etcd_binary),
                "--name=credential-fixture",
                "--log-level=error",
                f"--data-dir={base}/data",
                f"--listen-client-urls={endpoint}",
                f"--advertise-client-urls={endpoint}",
                f"--listen-peer-urls={peer}",
                f"--initial-advertise-peer-urls={peer}",
                f"--initial-cluster=credential-fixture={peer}",
                "--client-cert-auth",
                f"--auth-token=jwt,sign-method=ES256,priv-key={inputs}/jwt.key,"
                f"pub-key={inputs}/jwt.pub,ttl=3s",
                f"--trusted-ca-file={inputs}/ca.pem",
                f"--cert-file={inputs}/server.pem",
                f"--key-file={inputs}/server.key",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        context = ssl.create_default_context(cafile=inputs / "ca.pem")
        context.load_cert_chain(inputs / "client.pem", inputs / "client.key")

        def api(route, body, token=None):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", client_port, context=context, timeout=5
            )
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = token
            try:
                connection.request("POST", "/v3/" + route, json.dumps(body), headers)
                response = connection.getresponse()
                status = response.status
                return status, json.loads(response.read(128 << 10))
            finally:
                connection.close()

        for attempt in range(100):
            require(child.poll() is None, "fixture etcd exited")
            try:
                if api("kv/range", {"key": "eA=="})[0] == 200:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("fixture etcd unavailable")
        for name in ("root", "ordinary", "reader"):
            user_password = admin_password if name == "root" else password
            require(api("auth/user/add", {"name": name, "password": user_password})[0] == 200)
            require(api("auth/role/add", {"name": name})[0] == 200)
            require(api("auth/user/grant", {"user": name, "role": name})[0] == 200)

        def encode(value):
            return base64.b64encode(value.encode()).decode()

        permissions = [
            {"permission": "READWRITE", "key": "/authority/", "range_end": "/authority0"}
        ]
        require(
            api(
                "auth/role/grant",
                {
                    "name": "ordinary",
                    "perm": {
                        "permType": "READWRITE",
                        "key": encode("/authority/"),
                        "range_end": encode("/authority0"),
                    },
                },
            )[0]
            == 200
        )
        require(
            api(
                "auth/role/grant",
                {
                    "name": "reader",
                    "perm": {
                        "permType": "READ",
                        "key": encode("/authority/"),
                        "range_end": encode("/authority0"),
                    },
                },
            )[0]
            == 200
        )
        require(api("auth/enable", {})[0] == 200)
        require(api("auth/authenticate", {"name": "root", "password": password})[0] != 200)
        issuer = {
            "profile": "KF-LEDGER-CREDENTIALS-0.1",
            "staging_root": str(stage),
            "issuers": [
                {
                    "name": "control-primary",
                    "endpoint": endpoint,
                    "ca": str(inputs / "ca.pem"),
                    "certificate": str(inputs / "client.pem"),
                    "private_key": str(inputs / "client.key"),
                    "username": "ordinary",
                    "password_file": str(inputs / "ordinary.password"),
                    "scope_prefix": "/authority",
                    "permissions": permissions,
                }
            ],
        }
        mapping = {
            "profile": issuer["profile"],
            "publisher": "kf-credentials",
            "staging_root": str(stage),
            "credential_root": str(output),
            "destinations": [
                {
                    "name": "control-primary",
                    "username": "ordinary",
                    "scope_prefix": "/authority",
                    "permissions": permissions,
                    "role": "control",
                    "filename": "primary.token",
                }
            ],
        }
        read_permissions = [dict(permissions[0], permission="READ")]
        issuer["issuers"].append(
            dict(
                issuer["issuers"][0],
                name="control-readonly",
                username="reader",
                permissions=read_permissions,
            )
        )
        mapping["destinations"].append(
            dict(
                mapping["destinations"][0],
                name="control-readonly",
                username="reader",
                permissions=read_permissions,
                filename="readonly.token",
            )
        )
        write(inputs / "issuer.json", json.dumps(issuer), 0, publisher.pw_gid, 0o440)
        write(inputs / "mapping.json", json.dumps(mapping))
        probe = tools / "probe.py"
        write(
            probe,
            """import json,os,socket,sys
status=dict(line.split(":",1) for line in open("/proc/self/status") if ":" in line)
assert os.geteuid()==int(sys.argv[2])
assert int(status["CapEff"].strip(),16)==int(sys.argv[3])
assert status["NoNewPrivs"].strip()=="1" and status["Seccomp"].strip()=="2"
network=True
try: socket.socket(socket.AF_INET).close()
except OSError: network=False
assert network==(int(sys.argv[3])==0)
open(sys.argv[1],"w").write(json.dumps({"uid":os.geteuid(),"caps":status["CapEff"].strip(),"seccomp":2,"no_new_privs":1,"inet_socket":network}))
""",
            mode=0o444,
        )
        for unit in UNITS:
            source = (ROOT / "deploy/linux/credentials" / unit).read_text()
            source = source.replace("[Unit]\n", f"[Unit]\nDescription={marker}\n", 1)
            source += "\n[Service]\nExecStart=\nReadWritePaths=\n"
            if "issue" in unit:
                source += (
                    f"ExecStart={tools}/kf-ledger-credentials --config {inputs}/issuer.json "
                    f"--custody-root {inputs} --issue\nReadWritePaths={stage}\n"
                    f"ExecStartPre=/usr/bin/python3 {probe} "
                    f"{stage}/probe.json {publisher.pw_uid} 0\n"
                )
            else:
                source += (
                    f"ExecStart=/usr/bin/python3 {tools}/publish.py "
                    f"--config {inputs}/mapping.json\nReadWritePaths={destination}\n"
                    f"ExecStartPre=/usr/bin/python3 {probe} {destination}/probe.json 0 1\n"
                )
            write(unit_root / unit, source, mode=0o644)
            units.append(unit)
        run(["systemctl", "daemon-reload"])

        def refresh(success=True):
            run(["systemctl", "reset-failed", *UNITS], False)
            result = run(["systemctl", "start", UNITS[1]], False)
            require((result.returncode == 0) == success, "unexpected publication status")

        def as_user(entry, command):
            return run(
                [
                    "setpriv",
                    f"--reuid={entry.pw_uid}",
                    f"--regid={entry.pw_gid}",
                    "--clear-groups",
                    "--bounding-set=-all",
                    "--no-new-privs",
                    *command,
                ],
                False,
            )

        refresh()
        token_path = destination / "primary.token"
        token = token_path.read_text()
        read_token = (destination / "readonly.token").read_text()
        require(api("kv/range", {"key": encode("/authority/probe")}, read_token)[0] == 200)
        require(
            api(
                "kv/put",
                {"key": encode("/authority/probe"), "value": encode("forbidden")},
                read_token,
            )[0]
            == 403
        )
        require(
            token_path.stat().st_uid == service.pw_uid
            and token_path.stat().st_mode & 0o7777 == 0o400
        )
        require(api("kv/range", {"key": encode("/authority/probe")}, token)[0] == 200)
        require(api("kv/range", {"key": encode("/outside/probe")}, token)[0] == 403)
        for entry, path, allowed in [
            (service, token_path, True),
            (publisher, token_path, False),
            (agent, token_path, False),
            (agent, inputs / "ordinary.password", False),
            (service, inputs / "ordinary.password", False),
            (publisher, inputs / "jwt.key", False),
        ]:
            result = as_user(
                entry, ["/usr/bin/python3", "-c", "import sys;open(sys.argv[1],'rb').read(1)", path]
            )
            require((result.returncode == 0) == allowed)
        observations.append(
            "distinct UIDs; service-only token; agent/publisher credential denial; scoped RBAC"
        )
        observations.append("one batch with independently audited READ and READWRITE principals")
        observations.append("publisher password cannot authenticate root; signing key inaccessible")
        # Actual server token expiry, followed by a new batch and service file replacement.
        deadline = time.monotonic() + 8
        while api("kv/range", {"key": encode("/authority/probe")}, token)[0] == 200:
            require(time.monotonic() < deadline, "fixture token did not expire")
            time.sleep(0.25)
        refresh()
        renewed = token_path.read_text()
        require(renewed != token)
        require(api("kv/range", {"key": encode("/authority/probe")}, renewed)[0] == 200)
        observations.append("actual token expiry and second systemd issue/install")
        write(
            inputs / "ordinary.password",
            "wrong-password-with-at-least-thirty-two-characters",
            publisher.pw_uid,
            publisher.pw_gid,
        )
        refresh(False)
        require(token_path.read_text() == renewed)
        observations.append("issuer failure prevents sink activation and replacement")
        write(inputs / "ordinary.password", password, publisher.pw_uid, publisher.pw_gid)
        root_token = api("auth/authenticate", {"name": "root", "password": admin_password})[1][
            "token"
        ]
        require(
            api(
                "auth/role/grant",
                {
                    "name": "ordinary",
                    "perm": {
                        "permType": "READWRITE",
                        "key": encode("/outside/"),
                        "range_end": encode("/outside0"),
                    },
                },
                root_token,
            )[0]
            == 200
        )
        refresh(False)
        require(token_path.read_text() == renewed)
        observations.append(
            "extra etcd permission refuses issuance; prior token is not republished"
        )
        # Direct sink invocation still requires a fresh stage and a safe destination.
        stage_batch = stage / "batch.json"
        batch = json.loads(stage_batch.read_bytes())
        batch["created_at"] = int(time.time() * 1000) - 11000
        write(stage_batch, json.dumps(batch), publisher.pw_uid, publisher.pw_gid, 0o440)
        require(
            run(
                ["/usr/bin/python3", tools / "publish.py", "--config", inputs / "mapping.json"],
                False,
            ).returncode
            != 0
        )
        require(token_path.read_text() == renewed)
        batch["created_at"] = int(time.time() * 1000)
        write(stage_batch, json.dumps(batch), publisher.pw_uid, publisher.pw_gid, 0o440)
        token_path.unlink()
        token_path.symlink_to(inputs / "mapping.json")
        before = (inputs / "mapping.json").read_bytes()
        require(
            run(
                ["/usr/bin/python3", tools / "publish.py", "--config", inputs / "mapping.json"],
                False,
            ).returncode
            != 0
        )
        require((inputs / "mapping.json").read_bytes() == before)
        observations.append(
            "stale stage and symlink target refuse without changing protected mapping"
        )
        report["process_probes"] = {
            "issuer": json.loads((stage / "probe.json").read_bytes()),
            "sink": json.loads((destination / "probe.json").read_bytes()),
        }
        journal = run(
            ["journalctl", "-u", UNITS[0], "-u", UNITS[1], "--no-pager", "-o", "cat"]
        ).stdout
        require(
            all(
                value.encode() not in journal
                for value in (password, admin_password, token, read_token, renewed)
            )
        )
        observations.append("journal contains no issued token or password")
        report.update(
            status="qualified_credential_publisher",
            observations=observations,
            limitations=[
                "generated PKI and fixture-administered single etcd node",
                "issuance-time permission observations do not lock later administrator changes",
                "namespace policy does not establish least privilege "
                "across interleaved service keys",
                "no full managed workflow or service CA rotation qualified",
            ],
        )
    finally:
        for unit in reversed(units):
            path = unit_root / unit
            if path.exists() and f"Description={marker}\n" in path.read_text():
                run(["systemctl", "stop", unit], False)
                path.unlink()
        run(["systemctl", "daemon-reload"], False)
        run(["systemctl", "reset-failed", *units], False)
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        shutil.rmtree(base)
        for name in reversed(owned):
            run(["userdel", name])
            run(["groupdel", name], False)
        require(all(not (unit_root / unit).exists() for unit in units), "unit cleanup incomplete")
        for name in owned:
            require(run(["getent", "passwd", name], False).returncode != 0)
            require(run(["getent", "group", name], False).returncode != 0)
        report["cleanup_complete"] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ephemeral-host", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--etcd", type=Path)
    args = parser.parse_args()
    if not args.ephemeral_host:
        parser.error("requires explicit --ephemeral-host on an empty disposable systemd host")
    if args.binary is None or args.etcd is None:
        parser.error("requires --binary and --etcd")
    print(json.dumps(qualify(args.binary.resolve(), args.etcd.resolve()), indent=2))


if __name__ == "__main__":
    main()
