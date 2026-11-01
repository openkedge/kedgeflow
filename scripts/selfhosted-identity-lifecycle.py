#!/usr/bin/env python3
"""Run the required real-provider shipping identity lifecycle case with fresh etcd."""

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--storage-restore", action="store_true")
    modes.add_argument("--spire-rollover", action="store_true")
    args = parser.parse_args()
    env = {
        **os.environ,
        "KF_SELFHOSTED_INPUT": str(args.input.resolve()),
        "KF_SELFHOSTED_BUNDLE": str(args.bundle.resolve()),
        "KF_SELFHOSTED_OUTPUT": str(args.output.resolve()),
        "KF_REQUIRE_ETCD": "1",
    }
    command = [
        str(ROOT / "scripts/start-etcd.sh"),
        "--",
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--features",
        "selfhosted-pilot-tests",
        "--test",
        "broker_service",
        ("selfhosted_lifecycle::shipping_spire_rollover" if args.spire_rollover
         else "selfhosted_lifecycle::shipping_identity_lifecycle"),
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    log = args.output / "identity-lifecycle.log"
    with log.open("w") as stream:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=150,
            check=False,
        )
    text = log.read_text()
    if result.returncode or "SKIP" in text or "1 passed; 0 failed; 0 ignored" not in text:
        raise RuntimeError("required identity lifecycle case failed; see identity-lifecycle.log")
    outcomes = json.loads((args.output / "identity-lifecycle.json").read_text())
    if outcomes["status"] != "passed_identity_lifecycle":
        raise RuntimeError("missing complete identity lifecycle result")
    if args.storage_restore and not (
        outcomes.get("provider_storage_restore") and outcomes.get("pre_restore_issuer_pins")
    ):
        raise RuntimeError("missing required provider storage restore result")
    if args.spire_rollover and not outcomes.get("spire_issuer_rollover"):
        raise RuntimeError("missing required SPIRE rollover result")
    print(json.dumps(outcomes))


if __name__ == "__main__":
    main()
