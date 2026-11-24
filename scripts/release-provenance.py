#!/usr/bin/env python3
"""Create a deterministic draft CycloneDX SBOM and source inventory; never sign or approve."""

import argparse
import hashlib
import json
import runpy
import subprocess
import tomllib
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def collect(bundle: Path, expected: str, output: Path, tracked_only: bool = False):
    package = runpy.run_path(str(ROOT / "scripts/package-linux.py"))
    raw = package["read_regular"](bundle, 512 << 20)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("bundle digest mismatch")
    components = []
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    for p in lock["package"]:
        component = {
            "type": "library",
            "name": p["name"],
            "version": p["version"],
            "purl": f"pkg:cargo/{quote(p['name'], safe='')}@{p['version']}",
            "properties": [{"name": "kedgeflow:license-review", "value": "unreviewed"}],
        }
        if "checksum" in p:
            component["hashes"] = [{"alg": "SHA-256", "content": p["checksum"]}]
        components.append(component)
    npm = json.loads((ROOT / "tests/sdk/package-lock.json").read_text())
    for name, p in npm["packages"].items():
        if not name:
            continue
        name = name.rsplit("node_modules/", 1)[-1]
        components.append(
            {
                "type": "library",
                "name": name,
                "version": p["version"],
                "purl": f"pkg:npm/{quote(name, safe='/')}@{p['version']}",
                "properties": [{"name": "kedgeflow:license-review", "value": "unreviewed"}],
            }
        )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "kedgeflow-sql-pilot",
                "version": tomllib.loads((ROOT / "crates/kedgeflow/Cargo.toml").read_text())[
                    "package"
                ]["version"],
                "hashes": [{"alg": "SHA-256", "content": expected}],
            },
            "properties": [
                {
                    "name": "kedgeflow:coverage",
                    "value": "Cargo.lock and official Node client lock; OS/image "
                    "packages and independent review remain required",
                }
            ],
        },
        "components": sorted(components, key=lambda p: (p["purl"], p["name"])),
    }
    source_arguments = ["git", "ls-files", "-z", "--cached"]
    if not tracked_only:
        source_arguments.extend(["--others", "--exclude-standard"])
    files = subprocess.check_output(source_arguments, cwd=ROOT).decode().split("\0")
    sources = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in sorted(set(files))
        if name and (ROOT / name).is_file() and not name.startswith(("results/", "artifacts/"))
    }
    status_arguments = ["git", "status", "--porcelain"]
    if tracked_only:
        status_arguments.append("--untracked-files=no")
    dirty = bool(subprocess.check_output(status_arguments, cwd=ROOT))
    record = {
        "format": "kedgeflow-draft-release-provenance-v1",
        "checkout_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "working_tree_dirty": dirty,
        "source_inventory": "tracked_checkout" if tracked_only else "working_tree",
        "source_sha256": sources,
        "bundle_sha256": expected,
        "state": "draft_unsigned_unreproduced",
        "production_qualified": False,
        "execution_authority": False,
        "dependency_components": len(components),
        "open_gates": [
            "immutable protected green CI source",
            "approved release signature",
            "OS/image package inventory",
            "vulnerability and license triage",
            "independent source-to-binary reproduction",
        ],
    }
    output.mkdir(mode=0o700)
    (output / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    (output / "provenance.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return {
        "state": record["state"],
        "dependency_components": len(components),
        "working_tree_dirty": dirty,
        "production_qualified": False,
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--tracked-only",
        action="store_true",
        help="inventory tracked checkout files; exclude generated CI outputs",
    )
    args = parser.parse_args()
    print(json.dumps(collect(args.package, args.sha256, args.output, args.tracked_only), indent=2))
