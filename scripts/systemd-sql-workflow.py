#!/usr/bin/env python3
"""Local disposable-host adapter for selfhosted-pilot.py --sql-runner."""

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "bundle", "postgres-bindir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--managed", action="store_true")
    args = parser.parse_args()
    required = (
        "KF_SYSTEMD_PILOT_PACKAGE",
        "KF_SYSTEMD_PILOT_SHA256",
        "KF_SYSTEMD_PILOT_TEST_BINARY",
        "ETCD_BINARY",
    )
    if not args.managed or os.environ.get("KF_SYSTEMD_PILOT_EPHEMERAL_HOST") != "1":
        parser.error("requires --managed and KF_SYSTEMD_PILOT_EPHEMERAL_HOST=1")
    if any(not os.environ.get(key) for key in required):
        parser.error(
            "requires explicit verified package, SHA256, compiled test binary and etcd paths"
        )
    command = [
        "/usr/bin/python3",
        str(ROOT / "scripts/qualify-systemd-authority.py"),
        "--ephemeral-host",
        "--input",
        str(args.input.resolve()),
        "--bundle",
        str(args.bundle.resolve()),
        "--output",
        str(args.output.resolve()),
        "--postgres-bindir",
        str(args.postgres_bindir.resolve()),
        "--package",
        os.environ["KF_SYSTEMD_PILOT_PACKAGE"],
        "--sha256",
        os.environ["KF_SYSTEMD_PILOT_SHA256"],
        "--test-binary",
        os.environ["KF_SYSTEMD_PILOT_TEST_BINARY"],
        "--etcd",
        os.environ["ETCD_BINARY"],
    ]
    if os.geteuid() != 0:
        command = ["sudo", "--non-interactive", "env", "PATH=" + os.environ["PATH"], *command]
    result = subprocess.run(command, capture_output=True, text=True, timeout=270, check=False)
    if result.returncode:
        (args.output / "systemd-runner.stderr").write_text(result.stderr)
        raise RuntimeError("managed systemd fixture failed; see systemd-runner.stderr")
    report = json.loads(result.stdout)
    (args.output / "systemd-workflow.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
