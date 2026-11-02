#!/usr/bin/env python3
"""Run only the selected real-provider shipping SQL case in fresh PostgreSQL/etcd."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--postgres-bindir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--managed", action="store_true")
    args = parser.parse_args()
    env = {
        **os.environ,
        "KF_SELFHOSTED_INPUT": str(args.input.resolve()),
        "KF_SELFHOSTED_BUNDLE": str(args.bundle.resolve()),
        "KF_SELFHOSTED_OUTPUT": str(args.output.resolve()),
        "KF_REQUIRE_SDK": "1",
    }
    command = [
        sys.executable,
        str(ROOT / "scripts/test-postgres.py"),
        "--bindir",
        str(args.postgres_bindir.resolve()),
        "--peer",
        "--command",
        str(ROOT / "scripts/start-etcd.sh"),
        "--",
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--features",
        "selfhosted-pilot-tests",
        "--test",
        "governance",
        (
            "selfhosted_sql::shipping_managed_keycloak_spire_sql"
            if args.managed
            else "selfhosted_sql::shipping_keycloak_spire_sql"
        ),
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    log = args.output / "shipping-sql.log"
    with log.open("w") as stream:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=210,
            check=False,
        )
    text = log.read_text()
    if result.returncode or "SKIP" in text or "1 passed; 0 failed; 0 ignored" not in text:
        raise RuntimeError("required shipping SQL case failed; see shipping-sql.log")
    outcomes = json.loads((args.output / "sql-workflow.json").read_text())
    expected = "passed_managed_sql_workflow" if args.managed else "passed_sql_workflow"
    if outcomes["status"] != expected:
        raise RuntimeError("missing complete SQL workflow result")
    print(json.dumps(outcomes))


if __name__ == "__main__":
    main()
