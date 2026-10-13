#!/usr/bin/env python3
"""RFC 0023 real SQL tests in a new disposable Unix-socket-only cluster."""

import argparse
import copy
import getpass
import hashlib
import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KF-POSTGRES-RESERVATION-0.1-draft"


def run_suite(bindir: Path) -> dict:
    for name in ("postgres", "psql", "initdb", "pg_ctl"):
        if not (bindir / name).is_file():
            raise RuntimeError(f"missing PostgreSQL binary: {name}")
    version = subprocess.check_output([str(bindir / "postgres"), "--version"], text=True).strip()
    if version != "postgres (PostgreSQL) 18.3":
        raise RuntimeError("tests require pinned PostgreSQL 18.3")
    passed = []
    with tempfile.TemporaryDirectory(prefix="kf-pg-", dir="/tmp") as tmp:
        base = Path(tmp)
        data = base / "data"
        env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        env.update(PGHOST=tmp, PGPORT="5432", PGDATABASE="postgres", PGUSER=getpass.getuser())
        # Explicit fixture authentication, no TCP listener; never an enterprise enrollment.
        subprocess.run(
            [str(bindir / "initdb"), "-D", str(data), "-A", "trust", "--no-locale", "-E", "UTF8"],
            check=True,
            capture_output=True,
            text=True,
        )
        ctl = [str(bindir / "pg_ctl"), "-D", str(data)]
        subprocess.run(
            [
                *ctl,
                "-l",
                str(base / "server.log"),
                "-o",
                f"-c listen_addresses='' -c unix_socket_directories={tmp} -c max_connections=40",
                "-w",
                "start",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        def sql(command: str, role: str | None = None, fail: bool = False) -> str:
            if role:
                command = f"SET ROLE {role};\n" + command
            p = subprocess.run(
                [str(bindir / "psql"), "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
                input=command,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if fail:
                assert p.returncode != 0, "expected SQL refusal"
            elif p.returncode:
                raise RuntimeError(p.stderr)
            return p.stdout.strip()

        def literal(value: object) -> str:
            return "'" + json.dumps(value, separators=(",", ":")).replace("'", "''") + "'::jsonb"

        def apply(q: dict, fail: bool = False) -> dict | None:
            result = sql(f"SELECT kf_reservation.apply({literal(q)});", "kf_executor", fail)
            return None if fail else json.loads(result)

        def request(n: int, resource: str = "slot") -> dict:
            return {
                "profile": PROFILE,
                "action": "postgres.reservation.set.v1",
                "tenant": "tenant",
                "conflict_domain": "reservations",
                "attempt_id": f"attempt-{n}",
                "grant_digest": f"{n:064x}",
                "root_id": f"root-{n}",
                "resource": {"id": resource, "incarnation": "incarnation-1"},
                "expected_version": 1,
                "fence": n,
                "reservation": f"booking-{n}",
                "gateway_workload": "spiffe://example.org/gateway",
                "expires_at": int(time.time() * 1000) + 300_000,
            }

        def seed(resource: str) -> None:
            sql(
                "INSERT INTO kf_reservation.resource VALUES "
                f"('tenant','reservations','{resource}','incarnation-1',1,0,'free',true);"
            )

        try:
            sql((ROOT / "migrations/postgres/0001-reservation.sql").read_text())
            sql("""
                CREATE ROLE kf_executor NOLOGIN;
                CREATE ROLE kf_reader NOLOGIN;
                CREATE ROLE kf_agent NOLOGIN;
                GRANT USAGE ON SCHEMA kf_reservation TO kf_executor,kf_reader,kf_agent;
                GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO kf_executor;
                GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO kf_reader;
            """)
            seed("slot")
            q = request(1)
            committed = apply(q)
            assert committed["status"] == "committed" and committed["post_version"] == 2
            found = json.loads(
                sql("SELECT kf_reservation.lookup('tenant','attempt-1');", "kf_reader")
            )
            assert found == committed
            assert (
                sql(
                    "SELECT version||':'||last_fence||':'||reservation "
                    "FROM kf_reservation.resource WHERE resource_id='slot';"
                )
                == "2:1:booking-1"
            )
            passed.append("atomic effect and independently queried retained outcome")

            with ThreadPoolExecutor(max_workers=8) as pool:
                replies = list(pool.map(apply, [q] * 16))
            assert all(reply == committed for reply in replies)
            assert sql("SELECT count(*) FROM kf_reservation.attempt;") == "1"
            passed.append("concurrent exact replay returns original without another update")

            for key, value in (
                ("reservation", "changed"),
                ("root_id", "changed"),
                ("grant_digest", "f" * 64),
                ("tenant", "other"),
            ):
                changed = copy.deepcopy(q)
                changed[key] = value
                if key == "tenant":
                    assert apply(changed)["status"] == "guard_rejected"
                else:
                    apply(changed, fail=True)
            for key in ("root_id", "grant_digest"):
                changed = request(2)
                changed[key] = q[key]
                apply(changed, fail=True)
            passed.append("attempt substitution and reused root or grant are refused")

            seed("race")
            with ThreadPoolExecutor(max_workers=8) as pool:
                replies = list(pool.map(apply, [request(n, "race") for n in range(10, 18)]))
            assert sum(r["status"] == "committed" for r in replies) == 1
            assert (
                sql("SELECT version FROM kf_reservation.resource WHERE resource_id='race';") == "2"
            )
            passed.append("covered writers race: one version transition")

            seed("guards")
            for n, field, value in (
                (30, "expected_version", 2),
                (31, "expires_at", 1),
                (32, "conflict_domain", "other"),
            ):
                bad = request(n, "guards")
                bad[field] = value
                assert apply(bad)["status"] == "guard_rejected"
            bad = request(33, "guards")
            bad["resource"]["incarnation"] = "old"
            assert apply(bad)["status"] == "guard_rejected"
            sql("UPDATE kf_reservation.resource SET last_fence=100 WHERE resource_id='guards';")
            assert apply(request(34, "guards"))["status"] == "guard_rejected"
            sql("UPDATE kf_reservation.resource SET active=false WHERE resource_id='guards';")
            assert apply(request(101, "guards"))["status"] == "guard_rejected"
            sql(
                "UPDATE kf_reservation.resource SET active=true,incarnation='incarnation-2' "
                "WHERE resource_id='guards';"
            )
            assert apply(request(102, "guards"))["status"] == "guard_rejected"
            assert (
                sql(
                    "SELECT version||':'||last_fence FROM kf_reservation.resource "
                    "WHERE resource_id='guards';"
                )
                == "1:100"
            )
            passed.append("version expiry domain fence deletion and recreation guards")

            seed("rollback")
            r = request(200, "rollback")
            sql(f"BEGIN; SELECT kf_reservation.apply({literal(r)}); ROLLBACK;", "kf_executor")
            assert sql("SELECT kf_reservation.lookup('tenant','attempt-200');", "kf_reader") == ""
            assert (
                sql("SELECT version FROM kf_reservation.resource WHERE resource_id='rollback';")
                == "1"
            )
            passed.append("transaction rollback retains neither effect nor outcome")

            seed("pending")
            pending = request(210, "pending")
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    sql,
                    "SET application_name='kf-pending'; BEGIN; "
                    f"SELECT kf_reservation.apply({literal(pending)}); "
                    "SELECT pg_sleep(2); COMMIT;",
                    "kf_executor",
                )
                deadline = time.monotonic() + 10
                while (
                    sql(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE application_name='kf-pending' AND wait_event='PgSleep';"
                    )
                    != "1"
                ):
                    if future.done():
                        future.result()
                        raise RuntimeError("pending transaction barrier not reached")
                    if time.monotonic() > deadline:
                        raise RuntimeError("pending transaction barrier timeout")
                    time.sleep(0.01)
                assert (
                    sql("SELECT kf_reservation.lookup('tenant','attempt-210');", "kf_reader") == ""
                )
                future.result(timeout=20)
            assert (
                json.loads(
                    sql("SELECT kf_reservation.lookup('tenant','attempt-210');", "kf_reader")
                )["status"]
                == "committed"
            )
            passed.append("absent lookup during in-flight transaction can precede commit")

            seed("lost")
            lost = request(220, "lost")
            subprocess.run(
                [str(bindir / "psql"), "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
                input=f"SET ROLE kf_executor; SELECT kf_reservation.apply({literal(lost)});",
                env=env,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
                timeout=20,
            )
            assert (
                json.loads(
                    sql("SELECT kf_reservation.lookup('tenant','attempt-220');", "kf_reader")
                )["status"]
                == "committed"
            )
            assert (
                sql("SELECT version FROM kf_reservation.resource WHERE resource_id='lost';") == "2"
            )
            passed.append("discarded commit reply resolved by lookup without dispatch")

            # If an effect is possible, an absent lookup never authorizes resend.
            assert (
                sql("SELECT kf_reservation.lookup('missing-tenant','attempt-1');", "kf_reader")
                == ""
            )
            sql("UPDATE kf_reservation.resource SET reservation='bypass';", "kf_executor", True)
            sql("DELETE FROM kf_reservation.attempt;", "kf_executor", True)
            sql(f"SELECT kf_reservation.apply({literal(q)});", "kf_reader", True)
            sql(f"SELECT kf_reservation.apply({literal(q)});", "kf_agent", True)
            sql("SELECT kf_reservation.lookup('tenant','attempt-1');", "kf_agent", True)
            sql("CREATE TABLE kf_reservation.bypass (id integer);", "kf_agent", True)
            passed.append("executor reader and agent role separation")

            for change in (
                {"sql": "DELETE"},
                {"fence": 0},
                {"expected_version": None},
                {"expires_at": 9007199254740992},
                {"resource": {"id": "slot"}},
            ):
                bad = {**request(300), **change}
                apply(bad, fail=True)
            passed.append("closed malformed SQL records refuse before effect")

            subprocess.run(
                [*ctl, "-l", str(base / "server.log"), "-m", "fast", "-w", "restart"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert (
                json.loads(sql("SELECT kf_reservation.lookup('tenant','attempt-1');", "kf_reader"))
                == committed
            )
            assert apply(q) == committed
            passed.append("server restart preserves outcome and replay conservation")
        finally:
            subprocess.run(
                [*ctl, "-m", "immediate", "-w", "stop"], check=True, capture_output=True, text=True
            )
    return {
        "status": "passed",
        "postgres": version,
        "passed": len(passed),
        "cases": passed,
        "migration_sha256": hashlib.sha256(
            (ROOT / "migrations/postgres/0001-reservation.sql").read_bytes()
        ).hexdigest(),
        "scope": "disposable same-host Unix socket, trust fixtures, no gateway integration",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindir", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run_suite(args.bindir.resolve()), indent=2))
