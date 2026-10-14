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
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C"}

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
        base.chmod(0o711)
        db, service, agent = (prefix + suffix for suffix in ("_db", "_target", "_agent"))
        ctl = None
        try:
            for user in (db, service, agent):
                run(["useradd", "--no-create-home", "--user-group", "--shell", "/bin/false", user])
                users.append(user)
            identities = {name: pwd.getpwnam(name) for name in users}
            assert len({entry.pw_uid for entry in identities.values()}) == 3
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
            passed.append("distinct database/target/agent kernel UIDs; exact target peer maps")
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
                    "/CN=localhost",
                    "-keyout",
                    custody / "key.pem",
                    "-out",
                    custody / "cert.pem",
                ]
            )
            keys = []
            for n in range(2):
                path = base / f"sign-{n}.pem"
                run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", path])
                der = subprocess.check_output(
                    ["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"]
                )
                keys.append(base64.b64encode(der[-32:]).decode())
            token = custody / "query.token"
            token.write_text(secrets.token_urlsafe(48))
            config = json.loads((ROOT / "config/postgres-target.example.json").read_text())
            config.update(
                certificate=str(custody / "cert.pem"),
                private_key=str(custody / "key.pem"),
                workload_ca=str(custody / "cert.pem"),
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
            assert sql("SELECT count(*) FROM kf_reservation.attempt;") == "0"
            passed.append("all isolated probes leave zero retained attempts/effects")
            return {
                "profile": "KF-POSTGRES-PEER-0.1-draft",
                "status": "passed",
                "passed": len(passed),
                "cases": passed,
                "scope": "disposable Linux account/peer/mode fixture; no enterprise acceptance",
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
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
                    subprocess.run(["userdel", user], check=True, capture_output=True, timeout=30)
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
