#!/usr/bin/env python3
"""Cold physical SQL backup and stale-cutover refusal in a new private fixture only.

No deployed database, authority endpoint or credential can be supplied. The external
floor is fixture-owned. This does not qualify independently administered recovery.
"""

import argparse
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def qualify(bindir: Path):
    if os.geteuid() == 0:
        raise ValueError("run as a non-root disposable fixture user")
    version = subprocess.check_output([str(bindir / "postgres"), "--version"], text=True).strip()
    if version != "postgres (PostgreSQL) 18.3":
        raise ValueError("requires PostgreSQL 18.3")
    with tempfile.TemporaryDirectory(prefix="kf-cold-sql-", dir="/tmp") as tmp:
        base = Path(tmp)
        data, socket = base / "data", base / "socket"
        socket.mkdir(mode=0o700)
        user = pwd.getpwuid(os.geteuid()).pw_name
        env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        env.update(PGHOST=str(socket), PGPORT="5432", PGDATABASE="postgres", PGUSER=user)
        ctl = [str(bindir / "pg_ctl"), "-D", str(data)]
        running = False

        def run(argv):
            return subprocess.run(
                list(map(str, argv)),
                env=env,
                check=True,
                capture_output=True,
                text=True,
                timeout=45,
            )

        def start():
            nonlocal running
            run(
                [
                    *ctl,
                    "-l",
                    base / "server.log",
                    "-o",
                    f"-c listen_addresses='' -c unix_socket_directories={socket} "
                    "-c unix_socket_permissions=0700",
                    "-w",
                    "start",
                ]
            )
            running = True

        def stop():
            nonlocal running
            if running:
                run([*ctl, "-m", "fast", "-w", "stop"])
                running = False

        def sql(statement, accepted=True, role=None):
            result = subprocess.run(
                [str(bindir / "psql"), "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
                input=statement,
                env={**env, **({"PGUSER": role} if role else {})},
                capture_output=True,
                text=True,
                timeout=20,
            )
            if (result.returncode == 0) != accepted:
                raise RuntimeError("unexpected private SQL fixture result")
            return result.stdout.strip()

        def observed():
            return {
                "resource": json.loads(
                    sql("SELECT row_to_json(r) FROM kf_reservation.resource r;")
                ),
                "attempt": sql("SELECT kf_reservation.lookup('tenant','cold-original');"),
            }

        def backup(name):
            stop()
            target = base / name
            shutil.copytree(data, target, symlinks=False)
            # Independent fixture copy is outside every restored data directory.
            files = {
                str(p.relative_to(target)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(target.rglob("*"))
                if p.is_file()
            }
            return target, hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()

        try:
            run([bindir / "initdb", "-D", data, "-A", "reject", "--no-locale", "-E", "UTF8"])
            # Only the fixture DB administrator may read restored state. Application
            # roles remain fenced throughout the cutover decision, including restart.
            (data / "pg_hba.conf").write_text(f"local all {user} peer\nlocal all all reject\n")
            start()
            sql("CREATE ROLE kf_executor; CREATE ROLE kf_reader;")
            sql((ROOT / "migrations/postgres/0001-reservation.sql").read_text())
            sql(
                "INSERT INTO kf_reservation.resource VALUES "
                "('tenant','cold','slot','incarnation-1',1,0,'free',true);"
            )
            stale, stale_hash = backup("stale")
            start()
            request = {
                "profile": "KF-POSTGRES-RESERVATION-0.1-draft",
                "action": "postgres.reservation.set.v1",
                "tenant": "tenant",
                "conflict_domain": "cold",
                "attempt_id": "cold-original",
                "grant_digest": "a" * 64,
                "root_id": "cold-root",
                "resource": {"id": "slot", "incarnation": "incarnation-1"},
                "expected_version": 1,
                "fence": 1,
                "reservation": "cold-booking",
                "gateway_workload": "spiffe://example.org/gateway",
                "expires_at": int(time.time() * 1000) + 300000,
            }
            literal = json.dumps(request).replace("'", "''")
            outcome = json.loads(sql(f"SELECT kf_reservation.apply('{literal}'::jsonb);"))
            if outcome["status"] != "committed":
                raise RuntimeError("original effect not committed")
            floor = observed()
            latest, latest_hash = backup("latest")
            retained_floor = json.dumps(floor, sort_keys=True)
            (base / "separate-fixture-floor.json").write_text(retained_floor)
            cases = []
            for snapshot, expected in [(stale, False), (latest, True)]:
                stop()
                shutil.rmtree(data)
                shutil.copytree(snapshot, data, symlinks=False)
                start()
                state = observed()
                allowed = state == floor
                if allowed != expected:
                    raise RuntimeError("cold restore did not match independent fixture floor")
                # Direct application login remains refused; the fixture never enables
                # or redispatches a target after either physical restore.
                sql("SELECT 1;", accepted=False, role="kf_executor")
                sql("SELECT 1;", accepted=False, role="kf_reader")
                if (base / "separate-fixture-floor.json").read_text() != retained_floor:
                    raise RuntimeError("restore altered the separate floor")
                cases.append(
                    {
                        "snapshot": snapshot.name,
                        "cutover_allowed_by_fixture_floor": allowed,
                        "application_login_refused": True,
                        "original_outcome_retained": bool(state["attempt"]),
                    }
                )
            if sql("SELECT count(*) FROM kf_reservation.attempt;") != "1":
                raise RuntimeError("duplicate effect or lost current outcome")
            return {
                "status": "passed_disposable_cold_sql_restore",
                "postgres": version,
                "scope": "stopped private physical data directory and separate fixture floor",
                "snapshots": {"stale_sha256": stale_hash, "latest_sha256": latest_hash},
                "cases": cases,
                "mutation_dispatches": 1,
                "restore_redispatches": 0,
                "production_qualified": False,
                "execution_authority": False,
                "independent_custody": False,
            }
        finally:
            stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindir", type=Path, required=True)
    parser.add_argument("--ephemeral-host", action="store_true")
    args = parser.parse_args()
    if not args.ephemeral_host:
        parser.error("requires --ephemeral-host; creates only a new private cluster")
    print(json.dumps(qualify(args.bindir.resolve()), indent=2))
