#!/usr/bin/env python3
"""Destructive account provisioning ONLY on an explicitly disposable Linux CI host.

This fixture is not a production installer. It never accepts an existing database.
All users, files and data are new. Cleanup attempts run in finally even after
probe failure, and failed account cleanup fails the fixture.
"""

import argparse
import base64
import hashlib
import json
import os
import pwd
import secrets
import shutil
import signal
import socket as network_socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


HTTPS_PROBE = """
import json, ssl, sys, urllib.error, urllib.request
p = json.load(sys.stdin)
context = ssl.create_default_context(cafile=p['ca'])
context.minimum_version = ssl.TLSVersion.TLSv1_3
if p.get('certificate'):
    context.load_cert_chain(p['certificate'], p['key'])
request = urllib.request.Request(
    p['url'], data=json.dumps(p['body']).encode(), method='POST',
    headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + p['token']},
)
try:
    with urllib.request.urlopen(request, context=context, timeout=2) as response:
        result = {'status': response.status, 'body': json.load(response)}
except urllib.error.HTTPError as error:
    result = {'status': error.code, 'body': json.load(error)}
except (urllib.error.URLError, ssl.SSLError, ConnectionError) as error:
    cause = error.reason if isinstance(error, urllib.error.URLError) else error
    result = {'transport_error': type(cause).__name__}
print(json.dumps(result))
"""


def issue_certificate(run, base: Path, name: str, san: str, purpose: str) -> tuple[Path, Path]:
    """Issue disposable identities; only their public CA is copied to clients."""
    key, csr, cert = (base / (name + suffix) for suffix in (".key", ".csr", ".pem"))
    run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=" + name,
         "-keyout", key, "-out", csr])
    extensions = base / (name + ".ext")
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n"
    )
    run(["openssl", "x509", "-req", "-in", csr, "-CA", base / "ca.pem",
         "-CAkey", base / "ca.key", "-set_serial", str(secrets.randbits(128) or 1),
         "-days", "1", "-extfile", extensions, "-out", cert])
    key.chmod(0o600)
    return cert, key


@contextmanager
def target_process(command: list[str], env: dict):
    """Reap the entire runuser/service group before deleting fixture accounts."""
    with tempfile.TemporaryFile() as log:
        child = subprocess.Popen(
            command, env=env, stdout=log, stderr=log, start_new_session=True,
        )
        try:
            yield child
        finally:
            # The launcher can exit before its service; always signal the group.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            # A reaped launcher does not prove that every descendant exited.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def live_queries(run, command: list[str], env: dict, config: dict,
                 clients: dict[str, Path], recovery: str, agent: str, token: str) -> list[dict]:
    """Exercise real TLS/HTTP/SQL; neither probe bodies nor tokens enter evidence."""
    observations = []

    def probe(user: str, path: str = "query", credential: str = token, certificate=True):
        root = clients[user]
        packet = {
            "ca": str(root / "ca.pem"), "url": config[path + "_url"], "token": credential,
            "body": {"profile": "KF-OUTCOME-RECOVERY-0.1-draft", "operation": "query",
                     "attempt_id": "isolation-missing"},
        }
        if certificate:
            packet.update(certificate=str(root / "client.pem"), key=str(root / "client.key"))
        return json.loads(run(["python3", "-c", HTTPS_PROBE], user, json.dumps(packet)))

    with target_process(command, env) as child:
        deadline = time.monotonic() + 10
        while True:
            if child.poll() is not None:
                raise RuntimeError("protected shipping target exited before authenticated query")
            result = probe(recovery)
            if result == {"status": 404, "body": {"error": "unknown_outcome"}}:
                break
            if "transport_error" not in result or time.monotonic() >= deadline:
                raise RuntimeError(f"authenticated shipping query failed: {result}")
            time.sleep(0.05)
        observations.append({"case": "recovery_missing", **result})
        for name, user, path, credential, error in (
            ("agent_query", agent, "query", token, "invalid_workload"),
            ("agent_dispatch", agent, "dispatch", token, "invalid_workload"),
            ("recovery_wrong_token", recovery, "query", "wrong-fixture-token",
             "invalid_credential"),
        ):
            result = probe(user, path, credential)
            if result != {"status": 401, "body": {"error": error}}:
                raise RuntimeError(f"shipping {name} did not refuse at the expected gate: {result}")
            observations.append({"case": name, **result})
        result = probe(agent, certificate=False)
        if result.get("transport_error") != "SSLError":
            raise RuntimeError(f"missing client certificate did not fail TLS: {result}")
        observations.append({"case": "no_client_certificate", **result})
    return observations


def qualify(bindir: Path, target: Path, ephemeral_host: bool) -> dict:
    if not ephemeral_host or sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("requires --ephemeral-host, Linux root, and a disposable host")
    if subprocess.check_output([str(bindir / "postgres"), "--version"], text=True).strip() != (
        "postgres (PostgreSQL) 18.3"
    ):
        raise RuntimeError("requires pinned PostgreSQL 18.3")
    users = []
    passed = []
    prefix = "kf_" + secrets.token_hex(4)
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}

    def run(args: list, user: str | None = None, data: str | None = None, denied=False):
        command = ["runuser", "-u", user, "--", *map(str, args)] if user else list(map(str, args))
        result = subprocess.run(
            command, input=data, env=env, text=True, capture_output=True, timeout=30
        )
        if denied:
            if result.returncode == 0:
                raise RuntimeError("expected isolated probe refusal")
        elif result.returncode:
            raise RuntimeError(f"fixture command failed: {result.stderr[-2000:]}")
        return result.stdout.strip()

    with tempfile.TemporaryDirectory(prefix="kf-isolation-", dir="/tmp") as temporary:
        base = Path(temporary)
        # The protected loader opens each ancestor directory read-only. Keep
        # this root-owned ancestor readable; per-role secrets stay under 0700.
        base.chmod(0o755)
        db, service, agent, recovery = (
            prefix + suffix for suffix in ("_db", "_target", "_agent", "_recovery")
        )
        ctl = None
        try:
            for user in (db, service, agent, recovery):
                run(["useradd", "--no-create-home", "--user-group", "--shell", "/bin/false", user])
                users.append(user)
            identities = {name: pwd.getpwnam(name) for name in users}
            assert len({entry.pw_uid for entry in identities.values()}) == 4
            run(["usermod", "-a", "-G", db, service])
            pg = base / "postgres"
            shutil.copytree(bindir.parent, pg)
            pg.chmod(0o755)
            binary = base / "kf-postgres-target"
            shutil.copy2(target, binary)
            binary.chmod(0o755)
            data, socket, custody = (base / name for name in ("data", "socket", "custody"))
            for path, user, mode in (
                (data, db, 0o700),
                (socket, db, 0o750),
                (custody, service, 0o700),
            ):
                path.mkdir(mode=mode)
                os.chown(path, identities[user].pw_uid, identities[user].pw_gid)
            run([pg / "bin/initdb", "-D", data, "-A", "reject", "--no-locale", "-E", "UTF8"], db)
            (data / "pg_hba.conf").write_text(
                f"local all {db} peer\n"
                "local all kf_executor,kf_reader peer map=kf_target\n"
                "local all all reject\nhost all all 127.0.0.1/32 reject\n"
                "host all all ::1/128 reject\n"
            )
            (data / "pg_ident.conf").write_text(
                f"kf_target {service} kf_executor\nkf_target {service} kf_reader\n"
            )
            ctl = [pg / "bin/pg_ctl", "-D", data]
            run(
                [
                    *ctl,
                    "-l",
                    data / "server.log",
                    "-o",
                    f"-c listen_addresses='' -c unix_socket_directories={socket} "
                    "-c unix_socket_permissions=0770",
                    "-w",
                    "start",
                ],
                db,
            )
            env.update(PGHOST=str(socket), PGPORT="5432", PGDATABASE="postgres")

            def sql(statement: str, user=db, role=None, denied=False):
                return run(
                    [pg / "bin/psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", role or user],
                    user,
                    statement,
                    denied,
                )

            sql((ROOT / "migrations/postgres/0001-reservation.sql").read_text())
            sql(
                "CREATE ROLE kf_executor LOGIN; CREATE ROLE kf_reader LOGIN; "
                "REVOKE CREATE ON DATABASE postgres FROM PUBLIC; "
                "GRANT USAGE ON SCHEMA kf_reservation TO kf_executor,kf_reader; "
                "GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO kf_executor; "
                "GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO kf_reader;"
            )
            assert sql("SELECT current_user;", service, "kf_executor") == "kf_executor"
            assert sql("SELECT current_user;", service, "kf_reader") == "kf_reader"
            passed.append(
                "distinct database/target/agent/recovery kernel UIDs; exact target peer maps"
            )
            sql("SELECT current_user;", agent, "kf_executor", denied=True)
            sql("SELECT current_user;", agent, "kf_reader", denied=True)
            sql("SELECT current_user;", agent, db, denied=True)
            passed.append("agent socket access and database-owner impersonation refuse")
            # Expose the socket temporarily so a second probe reaches HBA itself.
            socket.chmod(0o755)
            (socket / ".s.PGSQL.5432").chmod(0o777)
            sql("SELECT current_user;", agent, "kf_executor", denied=True)
            sql("SELECT current_user;", agent, "kf_reader", denied=True)
            socket.chmod(0o750)
            (socket / ".s.PGSQL.5432").chmod(0o770)
            passed.append("unmapped agent reaches exposed socket but peer authentication refuses")
            sql(
                "UPDATE kf_reservation.resource SET reservation='bypass';",
                service,
                "kf_executor",
                True,
            )
            sql("SELECT * FROM kf_reservation.attempt;", service, "kf_reader", True)
            passed.append("target function-only roles refuse direct table mutation/disclosure")
            run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=isolation-fixture-ca",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                    "-keyout",
                    base / "ca.key",
                    "-out",
                    base / "ca.pem",
                ]
            )
            (base / "ca.key").chmod(0o600)
            server_cert, server_key = issue_certificate(
                run, base, "server", "IP:127.0.0.1", "serverAuth",
            )
            for source, destination in (
                (server_cert, "cert.pem"), (server_key, "key.pem"),
                (base / "ca.pem", "ca.pem"),
            ):
                shutil.copy2(source, custody / destination)
            clients = {}
            for user, workload in (
                (recovery, "spiffe://example.org/recovery"),
                (agent, "spiffe://example.org/agent"),
            ):
                cert, key = issue_certificate(run, base, user, "URI:" + workload, "clientAuth")
                client = base / user
                client.mkdir(mode=0o700)
                os.chown(client, identities[user].pw_uid, identities[user].pw_gid)
                for source, destination in (
                    (cert, "client.pem"), (key, "client.key"), (base / "ca.pem", "ca.pem"),
                ):
                    material = client / destination
                    shutil.copy2(source, material)
                    material.chmod(0o600)
                    os.chown(material, identities[user].pw_uid, identities[user].pw_gid)
                clients[user] = client
            keys = []
            for n in range(2):
                path = base / f"sign-{n}.pem"
                run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", path])
                der = subprocess.check_output(
                    ["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"], env=env,
                )
                keys.append(base64.b64encode(der[-32:]).decode())
            token = custody / "query.token"
            token.write_text(secrets.token_urlsafe(48))
            config = json.loads((ROOT / "config/postgres-target.example.json").read_text())
            with network_socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            config.update(
                listen=f"127.0.0.1:{port}",
                dispatch_url=f"https://127.0.0.1:{port}/dispatch",
                query_url=f"https://127.0.0.1:{port}/query",
                certificate=str(custody / "cert.pem"),
                private_key=str(custody / "key.pem"),
                workload_ca=str(custody / "ca.pem"),
                query_token_file=str(token),
                grant_keys={"fixture-grant": keys[0]},
                target_keys={"fixture-target": keys[1]},
            )
            config["registration"]["action"]["digest"] = "a" * 64
            config["database"].update(socket_directory=str(socket), database="postgres")
            path = custody / "target.json"
            path.write_text(json.dumps(config))
            for material in custody.iterdir():
                os.chown(material, identities[service].pw_uid, identities[service].pw_gid)
                material.chmod(0o600)
            command = [
                binary,
                "--config",
                path,
                "--custody-root",
                custody,
                "--postgres-peer-uid",
                str(identities[db].pw_uid),
            ]
            run([*command, "--check-custody"], service)
            run([*command, "--check-database"], service)
            passed.append(
                "shipping protected target verifies separate database kernel UID and SQL enrollment"
            )
            for material in (path, token, custody / "key.pem"):
                run(["cat", material], agent, denied=True)
                run(["sh", "-c", 'printf tamper >> "$1"', "probe", material], agent, denied=True)
            run([*command, "--check-database"], agent, denied=True)
            # Descendant uses real native socket/file APIs rather than parent assertions.
            run(
                [
                    "python3",
                    "-c",
                    "import pathlib,socket,sys; pathlib.Path(sys.argv[1]).read_bytes()",
                    token,
                ],
                agent,
                denied=True,
            )
            run(
                [
                    "python3",
                    "-c",
                    "import socket,sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1])",
                    socket / ".s.PGSQL.5432",
                ],
                agent,
                denied=True,
            )
            passed.append(
                "agent and shell/Python descendants refuse secret reads, config tamper, "
                "native target and socket bypass"
            )
            # Give the hostile request the correct bearer deliberately: its distinct
            # CA-issued workload identity must still refuse both endpoint roles.
            # Credentials travel via stdin, never argv or the public report.
            live = live_queries(
                run, ["runuser", "-u", service, "--", *map(str, command)], env,
                config, clients, recovery, agent, token.read_text(),
            )
            passed.append(
                "shipping target under separate UID serves authenticated query through SQL"
            )
            passed.append(
                "live agent query/dispatch, wrong bearer and missing mTLS identity refuse"
            )
            for material in (clients[recovery] / "client.key", base / "ca.key"):
                run(["cat", material], agent, denied=True)
            sql("SELECT current_user;", recovery, "kf_reader", denied=True)
            passed.append(
                "agent cannot read recovery/CA keys; recovery cannot bypass target via SQL"
            )
            assert sql("SELECT count(*) FROM kf_reservation.attempt;") == "0"
            passed.append("all isolated probes leave zero retained attempts/effects")
            return {
                "profile": "KF-POSTGRES-PEER-0.1-draft",
                "status": "passed",
                "passed": len(passed),
                "cases": passed,
                "scope": "disposable Linux account/peer/mode fixture; no enterprise acceptance",
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "live_queries": live,
                "uids": {name.rsplit("_", 1)[-1]: identities[name].pw_uid for name in users},
            }
        finally:
            cleanup_errors = []
            if ctl:
                try:
                    subprocess.run(
                        [
                            "runuser",
                            "-u",
                            db,
                            "--",
                            *map(str, ctl),
                            "-m",
                            "immediate",
                            "-w",
                            "stop",
                        ],
                        env=env,
                        capture_output=True,
                        timeout=30,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    cleanup_errors.append("database stop")
            for user in reversed(users):
                try:
                    subprocess.run(
                        ["userdel", user], env=env, check=True, capture_output=True, timeout=30,
                    )
                except (OSError, subprocess.SubprocessError):
                    cleanup_errors.append("account deletion")
                # userdel removes the matching empty private group on supported shadow-utils.
            if cleanup_errors:
                raise RuntimeError("isolated fixture cleanup failed: " + ", ".join(cleanup_errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindir", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--ephemeral-host", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            qualify(args.bindir.resolve(), args.target.resolve(), args.ephemeral_host), indent=2
        )
    )
