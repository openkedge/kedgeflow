#!/usr/bin/env python3
"""Qualify the exact bundle's SQL target on an explicitly disposable systemd host."""

import argparse
import hashlib
import json
import os
import runpy
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def qualify(bundle, expected_sha256, bindir):
    sources = [
        "scripts/qualify-systemd-sql.py",
        "scripts/qualify-postgres-isolation.py",
        "scripts/linux-sql-workflow.py",
        "scripts/package-linux.py",
        "scripts/verify-linux-package.py",
        "config/postgres-target.example.json",
        "fixtures/grant.json",
        "migrations/postgres/0001-reservation.sql",
    ]

    def source_hashes():
        return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources}

    before = source_hashes()
    package = runpy.run_path(str(ROOT / "scripts/package-linux.py"))
    raw = package["read_regular"](bundle, 512 << 20)
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError("bundle checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="kf-systemd-sql-") as temporary:
        base = Path(temporary)
        snapshot = base / "bundle.tar.gz"
        snapshot.write_bytes(raw)
        verified = runpy.run_path(str(ROOT / "scripts/verify-linux-package.py"))["verify"](snapshot)
        with tarfile.open(snapshot) as archive:
            archive.extractall(base / "release", filter="data")
        releases = list((base / "release").iterdir())
        if len(releases) != 1:
            raise ValueError("invalid bundle root")
        release = releases[0]
        report = runpy.run_path(str(ROOT / "scripts/qualify-postgres-isolation.py"))["qualify"](
            bindir,
            release / "bin/kf-postgres-target",
            True,
            systemd_unit=release / "share/systemd/kedgeflow-sql-target.service",
        )
        report.update(
            bundle_sha256=actual_sha256,
            bundle_name=verified["name"],
            scope="exact-bundle SQL target under systemd; generated authority",
            source_sha256=before,
        )
        if source_hashes() != before:
            raise RuntimeError("qualification source changed during run")
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--bindir", type=Path, required=True)
    parser.add_argument("--ephemeral-host", action="store_true")
    args = parser.parse_args()
    if not args.ephemeral_host or sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires --ephemeral-host, Linux root, and a disposable host")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        parser.error("requires actual systemd PID 1")
    if sys.flags.optimize:
        parser.error("qualification requires assertions enabled")
    print(json.dumps(qualify(args.package, args.sha256, args.bindir.resolve()), indent=2))


if __name__ == "__main__":
    main()
