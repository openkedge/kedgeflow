"""Bounded logical stale-backup rehearsal in a new database, never a repair tool."""

import hashlib
import json
import math
import secrets
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rehearse(
    bindir: Path, env: dict[str, str], base: Path, operations=16, p95_budget_ms=3000
) -> dict:
    if not 1 <= operations <= 1000 or not 0 < p95_budget_ms <= 60000:
        raise RuntimeError("invalid bounded rehearsal budget")
    database = "kf_rehearsal_" + secrets.token_hex(6)
    context = {**env, "PGDATABASE": database}

    def sql(statement: str, database_env=None, role=None, denied=False):
        result = subprocess.run(
            [str(bindir / "psql"), "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
            input=statement,
            env={**(database_env or context), **({"PGUSER": role} if role else {})},
            text=True,
            capture_output=True,
            timeout=20,
        )
        if denied:
            assert result.returncode != 0, "restore connection fence did not refuse"
        elif result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout.strip()

    def request(attempt: str, resource: str, incarnation: str):
        return {
            "profile": "KF-POSTGRES-RESERVATION-0.1-draft",
            "action": "postgres.reservation.set.v1",
            "tenant": "tenant",
            "conflict_domain": "restore-rehearsal",
            "attempt_id": attempt,
            "grant_digest": hashlib.sha256(attempt.encode()).hexdigest(),
            "root_id": "root-" + attempt,
            "resource": {"id": resource, "incarnation": incarnation},
            "expected_version": 1,
            "fence": 1,
            "reservation": "booking-" + attempt,
            "gateway_workload": "spiffe://example.org/gateway",
            "expires_at": int(time.time() * 1000) + 300000,
        }

    def apply(q: dict):
        literal = json.dumps(q).replace("'", "''")
        return json.loads(
            sql(f"SET ROLE kf_executor; SELECT kf_reservation.apply('{literal}'::jsonb);")
        )

    def lookup(attempt: str):
        raw = sql(f"SET ROLE kf_reader; SELECT kf_reservation.lookup('tenant','{attempt}');")
        return json.loads(raw) if raw else None

    sql(f"CREATE DATABASE {database};", env)
    try:
        sql((ROOT / "migrations/postgres/0001-reservation.sql").read_text())

        def enroll():
            sql(
                "REVOKE ALL ON SCHEMA kf_reservation FROM PUBLIC; "
                "REVOKE ALL ON ALL TABLES IN SCHEMA kf_reservation FROM PUBLIC; "
                "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kf_reservation FROM PUBLIC; "
                "GRANT USAGE ON SCHEMA kf_reservation TO kf_executor,kf_reader; "
                "GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO kf_executor; "
                "GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO kf_reader;"
            )

        enroll()
        sql(
            "INSERT INTO kf_reservation.resource VALUES "
            "('tenant','restore-rehearsal','slot','before-restore',1,0,'free',true);"
        )
        backup = base / "stale-reservation.dump"
        subprocess.run(
            [str(bindir / "pg_dump"), "-Fc", "--file", str(backup)],
            env=context,
            check=True,
            capture_output=True,
            timeout=30,
        )
        original = request("original", "slot", "before-restore")
        committed = apply(original)
        assert committed["status"] == "committed"
        assert lookup("original") == committed
        external = {"request": original, "observed_commit": committed}
        # No target/gateway process is running against this private database.
        sql(f"DROP DATABASE {database}; CREATE DATABASE {database} CONNECTION LIMIT 0;", env)
        sql("SELECT current_user;", role="kf_executor", denied=True)
        subprocess.run(
            [
                str(bindir / "pg_restore"),
                "--exit-on-error",
                "--no-privileges",
                "--dbname",
                database,
                str(backup),
            ],
            env=context,
            check=True,
            capture_output=True,
            timeout=30,
        )
        enroll()
        assert lookup("original") is None
        sql("UPDATE kf_reservation.resource SET incarnation='after-restore';")
        enroll()
        assert (
            sql("SELECT incarnation||':'||version FROM kf_reservation.resource;")
            == "after-restore:1"
        )
        sql(f"ALTER DATABASE {database} CONNECTION LIMIT -1;", env)
        assert sql("SELECT current_user;", role="kf_executor") == "kf_executor"
        # Never redispatch original. New incarnation gets only distinct fresh fixture requests.
        dispatch_ms, query_ms = [], []
        counts = {"attempted": operations, "committed": 0, "refused": 0, "unresolved": 0}
        for n in range(operations):
            resource, attempt = f"budget-{n}", f"budget-attempt-{n}"
            sql(
                "INSERT INTO kf_reservation.resource VALUES "
                f"('tenant','restore-rehearsal','{resource}','after-restore',1,0,'free',true);"
            )
            start = time.monotonic_ns()
            outcome = apply(request(attempt, resource, "after-restore"))
            dispatch_ms.append((time.monotonic_ns() - start) / 1e6)
            counts[outcome["status"]] += 1
            start = time.monotonic_ns()
            assert lookup(attempt) == outcome
            query_ms.append((time.monotonic_ns() - start) / 1e6)
        assert counts["committed"] == operations
        assert sql("SELECT count(*) FROM kf_reservation.attempt;") == str(operations)
        assert lookup("original") is None

        def distribution(values):
            values = sorted(values)
            return {
                "p50_ms": values[math.ceil(len(values) * 0.5) - 1],
                "p95_ms": values[math.ceil(len(values) * 0.95) - 1],
                "max_ms": values[-1],
            }

        dispatch, query = distribution(dispatch_ms), distribution(query_ms)
        assert max(dispatch["p95_ms"], query["p95_ms"]) <= p95_budget_ms
        return {
            "profile": "KF-POSTGRES-RESTORE-0.1-draft",
            "status": "passed",
            "backup_sha256": hashlib.sha256(backup.read_bytes()).hexdigest(),
            "original_external_history": external,
            "original_lookup_after_stale_restore": None,
            "original_state": "unresolved_external_commit_missing_from_restored_sql",
            "authority_consumption_tested": False,
            "original_redispatches": 0,
            "application_connection_fence": "refused",
            "restored_incarnation": "after-restore",
            "storage_budget": {
                "counts": counts,
                "dispatch": dispatch,
                "query": query,
                "p95_budget_ms": p95_budget_ms,
            },
            "scope": "disposable logical SQL backup and storage-only timings; "
            "no automatic service resume or enterprise acceptance",
        }
    finally:
        sql(f"DROP DATABASE {database} WITH (FORCE);", env)
