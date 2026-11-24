#!/usr/bin/env python3
"""Stage an authenticated Linux bundle for review; never replace a live release or start units."""

import argparse
import hashlib
import json
import runpy
import shutil
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def stage(bundle: Path, expected: str, output: Path):
    verifier = runpy.run_path(str(ROOT / "scripts/verify-linux-package.py"))
    package = runpy.run_path(str(ROOT / "scripts/package-linux.py"))
    raw = package["read_regular"](bundle, 512 << 20)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("independently obtained bundle digest does not match")
    output.mkdir(mode=0o700)
    try:
        # Verify and extract the same private bytes, never reopen the caller's path.
        with tempfile.TemporaryDirectory(prefix="kf-pilot-stage-") as tmp:
            snapshot = Path(tmp) / "bundle.tar.gz"
            snapshot.write_bytes(raw)
            verified = verifier["verify"](snapshot)
            with tarfile.open(snapshot) as archive:
                archive.extractall(output, filter="data")
        record = {
            "format": "kedgeflow-pilot-staged-release-v1",
            "bundle_sha256": expected,
            "release": verified["name"],
            "architecture": verified["architecture"],
            "source_reproduction": "requires_separate_build_evidence",
            "services_started": False,
            "production_qualified": False,
            "execution_authority": False,
        }
        (output / "staging.json").write_text(json.dumps(record, indent=2) + "\n")
        return record
    except BaseException:
        shutil.rmtree(output)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(stage(args.package, args.sha256, args.output), indent=2))
