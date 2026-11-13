#!/usr/bin/env python3
"""Record an allowlisted CI/tool/source inventory; never export environment or credentials."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def capture():
    tools = {}
    for name in ("python3", "rustc", "cargo", "node", "npm", "systemd-analyze", "openssl"):
        binary = shutil.which(name)
        if binary:
            result = subprocess.run(
                [binary, "version" if name == "openssl" else "--version"],
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
            tools[name] = {
                "path": binary,
                "exit_code": result.returncode,
                "version": result.stdout[:2048].strip(),
                "launcher_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            }
    pins = [
        "Cargo.lock",
        "Cargo.toml",
        "rust-toolchain.toml",
        "requirements-ci.txt",
        "tests/sdk/package-lock.json",
        ".github/workflows/ci.yml",
    ]
    return {
        "format": "kedgeflow-ci-provenance-v1",
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "runner": {
            name: os.environ.get(name)
            for name in (
                "ImageOS",
                "ImageVersion",
                "RUNNER_OS",
                "RUNNER_ARCH",
                "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT",
                "GITHUB_JOB",
            )
        },
        "platform": platform.platform(),
        "python": sys.version,
        "tools": tools,
        "source_pins": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in pins},
        "production_qualified": False,
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as stream:
        json.dump(capture(), stream, indent=2)
        stream.write("\n")
