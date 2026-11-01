#!/usr/bin/env python3
"""Disposable Keycloak/SPIRE pilot. Exact owned containers/network are always removed."""

import argparse
import hashlib
import io
import json
import os
import secrets
import socket as network_socket
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
KEYCLOAK = (
    "quay.io/keycloak/keycloak:26.8.1@sha256:"
    "a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b"
)


def source_manifest():
    names = [
        Path(name)
        for name in (
            "Cargo.toml",
            "Cargo.lock",
            "pyproject.toml",
            "crates/kedgeflow/Cargo.toml",
            "scripts/selfhosted-pilot.py",
            "crates/kedgeflow/tests/keycloak_pilot.rs",
            "scripts/selfhosted-sql-workflow.py",
            "scripts/selfhosted-identity-lifecycle.py",
            "scripts/test-postgres.py",
            "scripts/start-etcd.sh",
            "tests/sdk/live-agent.mjs",
            "tests/sdk/keycloak-vectors.mjs",
            "tests/sdk/package.json",
            "tests/sdk/package-lock.json",
            "tests/test_selfhosted_pilot.py",
            "tests/test_postgres_isolation.py",
        )
    ]
    for directory in (
        "crates/kedgeflow/src",
        "crates/kedgeflow/tests",
        "sdk/node",
        "spec",
        "migrations",
        "config",
        "fixtures",
    ):
        names.extend(p.relative_to(ROOT) for p in (ROOT / directory).rglob("*") if p.is_file())
    names.extend(
        Path("pilots/self-hosted") / name
        for name in (
            "Dockerfile",
            ".dockerignore",
            "agent.conf",
            "server.conf",
            "realm.json",
            "workload.py",
            "lifecycle.py",
        )
    )
    return {
        str(name): hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(names)
    }


def tls_material(host="keycloak"):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "KedgeFlow disposable pilot CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return (
        ca.public_bytes(pem),
        cert.public_bytes(pem),
        key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


def run_pilot(args):
    if not args.docker_host.startswith("unix://"):
        raise ValueError("pilot requires an explicit local Docker socket")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = source_manifest()
    revision = (
        subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, check=True)
        .stdout.decode()
        .strip()
    )
    (output / "revision.txt").write_text(revision + "\n")
    (output / "source.json").write_text(json.dumps(before, indent=2) + "\n")
    with tarfile.open(output / "source.tar.gz", "w:gz") as archive:
        for name in before:
            archive.add(ROOT / name, arcname=name)
    prefix = "kf-selfhosted-" + secrets.token_hex(6)
    network, keycloak, workload = (prefix + suffix for suffix in ("-net", "-keycloak", "-workload"))
    env = {**os.environ, "DOCKER_HOST": args.docker_host}
    owned = []

    def docker(*command, data=None, check=True):
        result = subprocess.run(
            [str(args.docker), *command], input=data, env=env, capture_output=True, timeout=180
        )
        if check and result.returncode:
            # Never echo command input: it can carry bootstrap credentials.
            raise RuntimeError(
                "docker " + command[0] + " failed: " + result.stderr.decode()[-1500:]
            )
        return result

    def install(container, files, destination, uid):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, content in files.items():
                entry = tarfile.TarInfo(name)
                entry.size, entry.uid, entry.gid, entry.mode = len(content), uid, 0, 0o600
                archive.addfile(entry, io.BytesIO(content))
        docker("cp", "-a", "-", container + ":" + destination, data=stream.getvalue())

    def execute(*command, user=None, check=True):
        flags = ["--user", str(user)] if user is not None else []
        return docker("exec", *flags, workload, *command, check=check)

    def wait(command, seconds=90):
        deadline = time.monotonic() + seconds
        while True:
            result = command()
            if result.returncode == 0:
                return result
            if time.monotonic() >= deadline:
                raise RuntimeError("pilot readiness deadline exceeded")
            time.sleep(0.5)

    summary = {"status": "failed", "profile": "KF-KEYCLOAK-SPIRE-0.1-pilot"}
    try:
        docker(
            "network", "create", "--internal", "--label", "org.openkedge.pilot=selfhosted", network
        )
        ca, certificate, key = tls_material()
        secret = secrets.token_urlsafe(48)
        sql_workflow = getattr(args, "sql_workflow", False)
        lifecycle = getattr(args, "identity_lifecycle", False)
        client_config = {"client_secret": secret}
        workflow = None
        realm = json.loads((ROOT / "pilots/self-hosted/realm.json").read_text())
        realm["clients"][0]["secret"] = secret
        if sql_workflow or lifecycle:
            if sql_workflow and not args.postgres_bindir:
                raise ValueError("SQL workflow requires an explicit disposable PostgreSQL bindir")
            with network_socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                broker_path = "token" if lifecycle else "exchange"
                broker_url = f"https://127.0.0.1:{reservation.getsockname()[1]}/{broker_path}"
            scopes = (["mutate", "read", "kf.status"] if lifecycle else
                      ["capacity.reserve", "kf.admit", "kf.issue", "kf.status", "kf.evidence"])
            realm["clientScopes"] = [
                {
                    "name": name,
                    "protocol": "openid-connect",
                    "attributes": {"include.in.token.scope": "true"},
                }
                for name in scopes
            ]
            realm["clients"][0]["defaultClientScopes"] = scopes
            client_config.update(scopes=" ".join(scopes), actor_audience=broker_url)
            workflow = {"broker_url": broker_url}
        if lifecycle:
            realm["accessTokenLifespan"] = 300
            admin_secret = secrets.token_urlsafe(48)
            realm["clients"].append({
                "clientId": "kf-pilot-lifecycle-admin", "enabled": True,
                "protocol": "openid-connect", "publicClient": False, "secret": admin_secret,
                "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False, "defaultClientScopes": [],
            })
            realm["users"].append({
                "username": "service-account-kf-pilot-lifecycle-admin", "enabled": True,
                "serviceAccountClientId": "kf-pilot-lifecycle-admin",
                "clientRoles": {"realm-management": ["manage-realm", "view-realm"]},
            })
        docker(
            "create",
            "--name",
            keycloak,
            "--network",
            network,
            "--network-alias",
            "keycloak",
            "--memory",
            "1536m",
            "--pids-limit",
            "256",
            KEYCLOAK,
            "start-dev",
            "--http-enabled=false",
            "--https-port=8443",
            "--https-certificate-file=/opt/keycloak/conf/pilot.pem",
            "--https-certificate-key-file=/opt/keycloak/conf/pilot.key",
            "--hostname=https://keycloak:8443",
            "--import-realm",
            "--log-level=WARN",
        )
        owned.append(keycloak)
        install(
            keycloak,
            {
                "conf/pilot.pem": certificate,
                "conf/pilot.key": key,
                "data/import/realm.json": json.dumps(realm).encode(),
            },
            "/opt/keycloak",
            1000,
        )
        docker("start", keycloak)
        docker(
            "create",
            "--name",
            workload,
            "--network",
            network,
            "--memory",
            "512m",
            "--pids-limit",
            "256",
            args.workload_image,
        )
        owned.append(workload)
        docker("start", workload)
        execute("chown", "1002:1002", "/run/pilot")
        install(
            workload,
            {"client.json": json.dumps(client_config).encode(), "keycloak-ca.pem": ca},
            "/run/pilot",
            1002,
        )
        if lifecycle:
            install(workload, {"keycloak-admin.json": json.dumps({
                "client_secret": admin_secret,
            }).encode()}, "/run/kf-spire/private", 0)
            if execute("cat", "/run/kf-spire/private/keycloak-admin.json",
                       user=1002, check=False).returncode == 0:
                raise RuntimeError("workload UID read lifecycle administration credentials")
        wait(
            lambda: execute(
                "python3",
                "-c",
                "import ssl,urllib.request; urllib.request.urlopen('https://keycloak:8443/realms/"
                "kedgeflow-pilot/.well-known/openid-configuration',context=ssl.create_default_context("
                "cafile='/run/pilot/keycloak-ca.pem'),timeout=2).read()",
                check=False,
            )
        )
        docker(
            "exec",
            "-d",
            workload,
            "/opt/spire/bin/spire-server",
            "run",
            "-config",
            "/opt/pilot/server.conf",
        )
        server = ["/opt/spire/bin/spire-server"]
        socket = ["-socketPath", "/run/kf-spire/private/server.sock"]
        wait(lambda: execute(*server, "healthcheck", *socket, check=False))
        bundle = execute(*server, "bundle", "show", *socket).stdout
        install(workload, {"bootstrap.pem": bundle}, "/run/kf-spire", 0)
        joined = execute(
            *server,
            "token",
            "generate",
            *socket,
            "-spiffeID",
            "spiffe://pilot.kedgeflow.test/node",
            "-output",
            "json",
        )
        join = json.loads(joined.stdout)["value"]
        execute(
            *server,
            "entry",
            "create",
            *socket,
            "-parentID",
            "spiffe://pilot.kedgeflow.test/node",
            "-spiffeID",
            "spiffe://pilot.kedgeflow.test/gateway",
            "-selector",
            "unix:uid:1002",
        )
        docker(
            "exec",
            "-d",
            workload,
            "/opt/spire/bin/spire-agent",
            "run",
            "-config",
            "/opt/pilot/agent.conf",
            "-joinToken",
            join,
        )
        wait(
            lambda: execute(
                "/opt/spire/bin/spire-agent",
                "healthcheck",
                "-socketPath",
                "/run/kf-spire/agent.sock",
                check=False,
            )
        )
        issued = execute("python3", "/opt/pilot/workload.py", user=1002)
        summary["issuance"] = json.loads(issued.stdout)
        denied = execute(
            "/opt/spire/bin/spire-agent",
            "api",
            "fetch",
            "jwt",
            "-socketPath",
            "/run/kf-spire/agent.sock",
            "-audience",
            "https://broker.pilot.kedgeflow.test/token",
            user=1003,
            check=False,
        )
        if denied.returncode == 0:
            raise RuntimeError("unregistered UID obtained a JWT-SVID")
        summary["unregistered_uid_refused"] = True
        for path, uid in (
            ("/run/pilot/client.json", 1003),
            ("/var/lib/spire/server/keys.json", 1002),
        ):
            execute("test", "-s", path)
            if execute("cat", path, user=uid, check=False).returncode == 0:
                raise RuntimeError("unregistered or workload UID read protected identity material")
        if execute(*server, "bundle", "show", *socket, user=1002, check=False).returncode == 0:
            raise RuntimeError("workload UID reached the SPIRE administrative socket")
        summary["identity_custody_refusals"] = [
            "unregistered_uid_client_secret",
            "workload_uid_spire_signing_keys",
            "workload_uid_spire_admin_socket",
        ]
        public_bundle = execute(*server, "bundle", "show", *socket, "-format", "spiffe").stdout
        (output / "spire-bundle.json").write_bytes(public_bundle)
        with tempfile.TemporaryDirectory(prefix="kf-selfhosted-private-") as temporary:
            private = Path(temporary)
            docker("cp", workload + ":/run/pilot/packet.json", str(private / "packet.json"))
            if lifecycle:
                (private / "old-packet.json").write_bytes((private / "packet.json").read_bytes())
                rotated = execute("python3", "/opt/pilot/lifecycle.py", user=0)
                summary["provider_rotation"] = json.loads(rotated.stdout)
                execute("python3", "/opt/pilot/workload.py", user=1002)
                docker("cp", workload + ":/run/pilot/packet.json", str(private / "rotated.json"))
                docker("restart", keycloak)
                wait(lambda: execute(
                    "python3", "-c", "import ssl,urllib.request; urllib.request.urlopen("
                    "'https://keycloak:8443/realms/kedgeflow-pilot/.well-known/openid-configuration',"
                    "context=ssl.create_default_context(cafile='/run/pilot/keycloak-ca.pem'),"
                    "timeout=2).read()", check=False,
                ))
                execute("python3", "/opt/pilot/workload.py", user=1002)
                docker("cp", workload + ":/run/pilot/packet.json", str(private / "packet.json"))
                summary["provider_restart"] = "completed; continuity requires passing native result"
                summary["lifecycle_admin_key_refused_to_workload_uid"] = True
            published = json.loads((private / "packet.json").read_text())["keycloak_jwks"]
            if any(set(k) & {"d", "p", "q", "dp", "dq", "qi", "k"} for k in published["keys"]):
                raise RuntimeError("provider JWKS contains private key material")
            (output / "keycloak-jwks.json").write_text(json.dumps(published, indent=2) + "\n")
            docker("cp", workload + ":/run/pilot/x509", str(private / "x509"))
            if workflow:
                (private / "workflow.json").write_text(json.dumps(workflow))
            loopback_ca, loopback_cert, loopback_key = tls_material("localhost")
            for name, content in (
                ("loopback-ca.pem", loopback_ca),
                ("loopback.pem", loopback_cert),
                ("loopback.key", loopback_key),
            ):
                material = private / name
                material.write_bytes(content)
                material.chmod(0o600)
            if lifecycle:
                result = subprocess.run([
                    sys.executable, str(ROOT / "scripts/selfhosted-identity-lifecycle.py"),
                    "--input", str(private), "--bundle", str(output / "spire-bundle.json"),
                    "--output", str(output),
                ], capture_output=True, text=True, timeout=180, check=False)
                if result.returncode:
                    raise RuntimeError("identity lifecycle refused: " + result.stderr[-1500:])
                summary["identity_lifecycle"] = json.loads(result.stdout)
                if summary["identity_lifecycle"].get("status") != "passed_identity_lifecycle":
                    raise RuntimeError("identity lifecycle did not report the required pass")
            elif sql_workflow:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/selfhosted-sql-workflow.py"),
                        "--input",
                        str(private),
                        "--bundle",
                        str(output / "spire-bundle.json"),
                        "--postgres-bindir",
                        str(args.postgres_bindir.resolve()),
                        "--output",
                        str(output),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=240,
                    check=False,
                )
                if result.returncode:
                    raise RuntimeError("shipping SQL workflow refused: " + result.stderr[-1500:])
                summary["sql_workflow"] = json.loads(result.stdout)
                if summary["sql_workflow"].get("status") != "passed_sql_workflow":
                    raise RuntimeError("shipping SQL workflow did not report the required pass")
            elif args.checker:
                summary["checker_sha256"] = hashlib.sha256(args.checker.read_bytes()).hexdigest()
                result = subprocess.run(
                    [
                        str(args.checker.resolve()),
                        "--input",
                        str(private),
                        "--bundle",
                        str(output / "spire-bundle.json"),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode:
                    raise RuntimeError("native pilot checker refused: " + result.stderr[-1500:])
                summary["native"] = json.loads(result.stdout)
                if summary["native"].get("status") != "passed_identity_checks":
                    raise RuntimeError("native pilot checker did not report the required pass")
            else:
                # Inspection is explicit and cannot claim a native integration pass.
                summary["native"] = "not_run"
        summary["status"] = "passed" if args.checker or sql_workflow or lifecycle else "issued_only"
        summary["source_unchanged"] = source_manifest() == before
        if not summary["source_unchanged"]:
            summary["status"] = "failed_source_changed"
            raise RuntimeError("pilot source changed during execution")
    finally:
        cleanup = []
        for container in reversed(owned):
            if container == workload:
                docker(
                    "cp",
                    workload + ":/run/pilot/subject-shape.json",
                    str(output / "subject-shape.json"),
                    check=False,
                )
            metadata = docker("inspect", container, check=False)
            if metadata.returncode == 0:
                (output / (container.rsplit("-", 1)[-1] + "-container.json")).write_bytes(
                    metadata.stdout
                )
            docker(
                "logs", container, check=False
            )  # Never persist raw provider logs or credentials.
            cleanup.append(docker("rm", "-f", container, check=False).returncode == 0)
        cleanup.append(docker("network", "rm", network, check=False).returncode == 0)
        summary["cleanup_passed"] = all(cleanup)
        if not all(cleanup):
            summary["status"] = "failed_cleanup"
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--docker-host", required=True)
    parser.add_argument("--workload-image", default="kf-selfhosted-workload:20261030")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--checker", type=Path)
    mode.add_argument("--identity-lifecycle", action="store_true")
    mode.add_argument("--sql-workflow", action="store_true")
    parser.add_argument("--postgres-bindir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    run_pilot(parser.parse_args())
