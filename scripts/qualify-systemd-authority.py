#!/usr/bin/env python3
"""Disposable managed provider workflow under separate shipping systemd roles."""

import argparse
import grp
import hashlib
import json
import os
import pwd
import runpy
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("admission", "issuer", "broker", "gateway", "sql-target", "agent", "database")


def workflow_process(command, env, timeout=150):
    """Reap the etcd launcher and every descendant even on timeout/failure."""
    with subprocess.Popen(
        command,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as child:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
            return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
        finally:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def qualify(args):
    expected = args.sha256
    package = runpy.run_path(str(ROOT / "scripts/package-linux.py"))
    raw = package["read_regular"](args.package, 512 << 20)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("bundle checksum mismatch")
    accounts = []
    with tempfile.TemporaryDirectory(prefix="kf-managed-", dir="/run") as temporary:
        base = Path(temporary)
        base.chmod(0o755)
        prefix = "kf_m" + secrets.token_hex(4)
        users = {role: prefix + "_" + role.replace("-", "_") for role in ROLES}
        env = {"PATH": os.environ["PATH"], "LANG": "C", "TMPDIR": str(base / "work")}

        def run(command, user=None, data=None, check=True, timeout=45):
            command = list(map(str, command))
            if user:
                command = ["runuser", "-u", user, "--", *command]
            return subprocess.run(
                command,
                env=env,
                input=data,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=check,
            )

        data = base / "data"
        ctl = None
        report = None
        try:
            snapshot = base / "bundle.tar.gz"
            snapshot.write_bytes(raw)
            verified = runpy.run_path(str(ROOT / "scripts/verify-linux-package.py"))["verify"](
                snapshot
            )
            with tarfile.open(snapshot) as archive:
                archive.extractall(base / "release", filter="data")
            release = next((base / "release").iterdir())
            for role, user in users.items():
                run(["useradd", "--no-create-home", "--user-group", "--shell", "/bin/false", user])
                accounts.append(user)
            identities = {role: pwd.getpwnam(user) for role, user in users.items()}
            assert len({p.pw_uid for p in identities.values()}) == len(ROLES)
            run(["usermod", "-a", "-G", users["database"], users["sql-target"]])
            pg = base / "postgres"
            shutil.copytree(args.postgres_bindir.parent, pg)
            env["LD_LIBRARY_PATH"] = str(pg / "lib")
            if (
                run([pg / "bin/postgres", "--version"]).stdout.strip()
                != "postgres (PostgreSQL) 18.3"
            ):
                raise ValueError("requires PostgreSQL 18.3")
            for path, mode in [(data, 0o700), (base / "socket", 0o750)]:
                path.mkdir(mode=mode)
                os.chown(path, identities["database"].pw_uid, identities["database"].pw_gid)
            work = base / "work"
            work.mkdir(mode=0o755)
            db = users["database"]
            run([pg / "bin/initdb", "-D", data, "-A", "reject", "--no-locale", "-E", "UTF8"], db)
            (data / "pg_hba.conf").write_text(
                f"local all {db} peer map=kf_admin\n"
                "local all kf_executor,kf_reader peer map=kf_target\n"
                "local all all reject\nhost all all 127.0.0.1/32 reject\n"
                "host all all ::1/128 reject\n"
            )
            # Root is the explicit fixture administrator. Only the shipping
            # target gets executor login; root's reader map permits verification.
            (data / "pg_ident.conf").write_text(
                f"kf_admin {db} {db}\nkf_admin root {db}\n"
                f"kf_target {users['sql-target']} kf_executor\n"
                f"kf_target {users['sql-target']} kf_reader\nkf_target root kf_reader\n"
            )
            ctl = [pg / "bin/pg_ctl", "-D", data]
            run(
                [
                    *ctl,
                    "-l",
                    data / "server.log",
                    "-o",
                    f"-c listen_addresses='' -c unix_socket_directories={base / 'socket'} "
                    "-c unix_socket_permissions=0770",
                    "-w",
                    "start",
                ],
                db,
            )
            env.update(PGHOST=str(base / "socket"), PGPORT="5432", PGDATABASE="postgres", PGUSER=db)
            run(
                [pg / "bin/psql", "-X", "-v", "ON_ERROR_STOP=1"],
                data=(
                    (ROOT / "migrations/postgres/0001-reservation.sql").read_text()
                    + "\nCREATE ROLE kf_executor LOGIN; CREATE ROLE kf_reader LOGIN;"
                    "REVOKE CREATE ON DATABASE postgres FROM PUBLIC;"
                    "GRANT USAGE ON SCHEMA kf_reservation TO kf_executor,kf_reader;"
                    "GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO kf_executor;"
                    "GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO kf_reader;"
                ),
            )
            positive_sql = run(
                [pg / "bin/psql", "-X", "-qAt", "-U", db, "-c", "SELECT current_user"], db
            )
            if positive_sql.stdout.strip() != db:
                raise RuntimeError("non-root database-owner client preflight failed")
            for role in ("agent", "admission", "issuer", "broker", "gateway"):
                for sql_role in ("kf_executor", "kf_reader", db):
                    attempted = run(
                        [
                            pg / "bin/psql",
                            "-X",
                            "-qAt",
                            "-U",
                            sql_role,
                            "-c",
                            "SELECT current_user",
                        ],
                        users[role],
                        check=False,
                    )
                    if attempted.returncode == 0:
                        raise RuntimeError("non-target account bypassed the SQL target")
            state = {
                "base": str(base),
                "release": str(release),
                "users": users,
                "postgres_uid": identities["database"].pw_uid,
            }
            registry = base / "state.json"
            registry.write_text(json.dumps(state))
            registry.chmod(0o600)
            sdk_root = base / "sdk-source"
            for source in ("sdk/node", "tests/sdk", "fixtures"):
                shutil.copytree(ROOT / source, sdk_root / source, symlinks=True)
            env.update(
                KF_SYSTEMD_PILOT_STATE=str(registry),
                KF_SYSTEMD_PILOT_HELPER=str(ROOT / "scripts/pilot-systemd-role.py"),
                KF_SYSTEMD_BINARY_DIR=str(release / "bin"),
                KF_SELFHOSTED_SOURCE_ROOT=str(sdk_root),
                KF_SYSTEMD_AGENT_UID=str(identities["agent"].pw_uid),
                KF_SYSTEMD_AGENT_GID=str(identities["agent"].pw_gid),
                KF_POSTGRES_TEST_SOCKET=str(base / "socket"),
                KF_POSTGRES_TEST_USER=db,
                KF_POSTGRES_TEST_PEER_UID=str(identities["database"].pw_uid),
                KF_SELFHOSTED_INPUT=str(args.input.resolve()),
                KF_SELFHOSTED_BUNDLE=str(args.bundle.resolve()),
                KF_SELFHOSTED_OUTPUT=str(args.output.resolve()),
                KF_REQUIRE_POSTGRES="1",
                KF_REQUIRE_SDK="1",
                ETCD_BINARY=str(args.etcd.resolve()),
            )
            # SDK source is public; provider credentials remain under the private
            # input directory and are copied only into an agent-owned 0600 file.
            result = workflow_process(
                [
                    ROOT / "scripts/start-etcd.sh",
                    "--",
                    "setpriv",
                    "--clear-groups",
                    args.test_binary.resolve(),
                    "selfhosted_sql::shipping_managed_keycloak_spire_sql",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ],
                env,
            )
            (args.output / "shipping-sql.log").write_text(result.stdout + result.stderr)
            if result.returncode or "1 passed; 0 failed; 0 ignored" not in result.stdout:
                journal = run(
                    [
                        "journalctl",
                        "--no-pager",
                        "--output=cat",
                        "--unit",
                        base.name + "-*.service",
                    ],
                    check=False,
                )
                (args.output / "systemd-journal.log").write_text(journal.stdout + journal.stderr)
                raise RuntimeError("managed systemd workflow failed; see shipping-sql.log")
            report = json.loads((args.output / "sql-workflow.json").read_text())
            if report["status"] != "passed_managed_sql_workflow":
                raise RuntimeError("managed workflow did not report complete pass")
            for case in report["cases"]:
                runtime = case["runtime"]
                actual = {
                    runtime[role]["uid"]
                    for role in ("gateway", "admission", "issuer", "broker", "sql_target")
                }
                assert len(actual) == 5 and runtime["agent_uid"] not in actual
            report.update(
                systemd=True,
                bundle_sha256=expected,
                bundle_name=verified["name"],
                uids={role: p.pw_uid for role, p in identities.items()},
                test_binary_sha256=hashlib.sha256(args.test_binary.read_bytes()).hexdigest(),
                scope=(
                    "Five shipping managed systemd roles, separate admission/issuer and SDK agent; "
                    "fixture administration/evidence/TLS ledger relays"
                ),
            )
        finally:
            errors = []
            for role in ("gateway", "admission", "issuer", "broker", "sql-target"):
                name = base.name + "-" + role + ".service"
                unit = Path("/etc/systemd/system") / name
                ownership = base / ("unit-" + role)
                if ownership.exists():
                    stopped = run(["systemctl", "stop", name], check=False)
                    if stopped.returncode:
                        errors.append("unit stop")
                    else:
                        run(["systemctl", "reset-failed", name], check=False)
                        unit.unlink()
                        ownership.unlink()
                elif unit.exists():
                    errors.append("unowned unit at fixture name left intact")
            run(["systemctl", "daemon-reload"])
            if ctl and (data / "postmaster.pid").exists():
                if run(
                    [*ctl, "-m", "immediate", "-w", "stop"], users["database"], check=False
                ).returncode:
                    errors.append("database stop")
            for user in reversed(accounts):
                if run(["userdel", user], check=False).returncode:
                    errors.append("account removal")
            # A database supplementary group can outlive its user when the
            # target still belongs to it at userdel time. Remove only groups
            # created with this fixture's successfully created accounts.
            for user in reversed(accounts):
                try:
                    grp.getgrnam(user)
                except KeyError:
                    continue
                if run(["groupdel", user], check=False).returncode:
                    errors.append("group removal")
            if errors:
                raise RuntimeError("fixture cleanup incomplete: " + ", ".join(errors))
            if report is not None:
                report["cleanup"] = {
                    "units_removed": True,
                    "database_stopped": True,
                    "accounts_removed": True,
                    "groups_removed": True,
                }
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("input", "bundle", "postgres-bindir", "output", "package", "test-binary", "etcd"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--ephemeral-host", action="store_true")
    args = parser.parse_args()
    if not args.ephemeral_host or sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires --ephemeral-host, Linux root and a disposable host")
    if sys.flags.optimize or Path("/proc/1/comm").read_text().strip() != "systemd":
        parser.error("requires assertions and actual systemd PID 1")
    args.output.mkdir(parents=True, exist_ok=True)
    print(json.dumps(qualify(args)))


if __name__ == "__main__":
    main()
