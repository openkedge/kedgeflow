#!/usr/bin/env python3
"""Query OSV for locked public dependencies; fail on unmatched or stale triage.

A source-bound profile exclusion is implementation triage, not independent security
acceptance. OS/image vulnerabilities and factual deployment review remain separate.
"""

import argparse
import hashlib
import json
import ssl
import time
import tomllib
import urllib.request
from datetime import datetime
from pathlib import Path

import certifi

ROOT = Path(__file__).resolve().parents[1]
VENDOR_PROVENANCE = "c8ca23c84e9565b182e8b66d7d888c0a345e95aeabe8c340fcbf0681726b53ac"


VENDORED_PACKAGES = {"cedar-policy-core": "4.7.1", "serde_with": "3.24.0"}


def verify_vendor(root):
    """Keep the patched Cedar source in both source-integrity and advisory scope."""
    vendor = root / "vendor"
    record = vendor / "provenance.json"
    if any(p.is_symlink() for p in [vendor, record]) or not record.is_file():
        raise ValueError("vendored source path is not regular")
    raw = record.read_bytes()
    if hashlib.sha256(raw).hexdigest() != VENDOR_PROVENANCE:
        raise ValueError("vendored provenance differs from reviewed source")
    manifest = json.loads(raw)
    for entry in manifest["packages"]:
        package = vendor / f"{entry['package']}-{entry['version']}"
        if package.is_symlink():
            raise ValueError("vendored source symlink")
        actual = set()
        for path in package.rglob("*"):
            if path.is_symlink():
                raise ValueError("vendored source symlink")
            if path.is_file():
                name = path.relative_to(package).as_posix()
                actual.add(name)
                if (
                    name not in entry["files"]
                    or hashlib.sha256(path.read_bytes()).hexdigest()
                    != entry["files"][name]["sha256"]
                ):
                    raise ValueError("vendored source inventory or digest differs")
        if actual != set(entry["files"]):
            raise ValueError("vendored source inventory incomplete")
    config = tomllib.loads((root / "Cargo.toml").read_text())
    if config.get("patch", {}).get("crates-io") != {
        name: {"path": f"vendor/{name}-{version}"} for name, version in VENDORED_PACKAGES.items()
    }:
        raise ValueError("unreviewed Cargo patch inventory")


def queries():
    verify_vendor(ROOT)
    items = []
    for p in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]:
        registry = p.get("source", "").startswith("registry+")
        if p["name"] in VENDORED_PACKAGES:
            if registry or p["version"] != VENDORED_PACKAGES[p["name"]] or "source" in p:
                raise ValueError("vendored package lock binding differs")
        elif not registry and p["name"] != "kedgeflow":
            raise ValueError("dependency outside advisory inventory")
        if registry or p["name"] in VENDORED_PACKAGES:
            items.append(
                {"package": {"ecosystem": "crates.io", "name": p["name"]}, "version": p["version"]}
            )
    for name, p in json.loads((ROOT / "tests/sdk/package-lock.json").read_text())[
        "packages"
    ].items():
        if name:
            items.append(
                {
                    "package": {"ecosystem": "npm", "name": name.rsplit("node_modules/", 1)[-1]},
                    "version": p["version"],
                }
            )
    for line in (ROOT / "requirements-ci.txt").read_text().splitlines():
        if "==" in line:
            name, version = line.split("==")
            items.append({"package": {"ecosystem": "PyPI", "name": name}, "version": version})
    return items


def triaged(query, advisory, entries, now):
    if advisory != "GHSA-c33x-vcv4-vg3g" or query != {
        "package": {"ecosystem": "crates.io", "name": "cedar-policy"},
        "version": "4.7.1",
    }:
        return False
    for entry in entries:
        if (
            entry["advisory"] != advisory
            or entry["package"] != query["package"]
            or entry["version"] != query["version"]
        ):
            continue
        if entry["disposition"] != "not_reachable_in_supported_profile":
            return False
        if datetime.fromisoformat(entry["valid_until"]).timestamp() <= now:
            return False
        paths = entry["source_sha256"]
        # This draft admits only the reviewed Cedar source/parser exclusion.
        if set(paths) != {"crates/kedgeflow/src/policy.rs", "crates/kedgeflow/tests/admission.rs"}:
            return False
        return all(
            hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
            for name, digest in paths.items()
        )
    return False


def audit(output: Path):
    if tuple(int(part) for part in certifi.__version__.split(".")) < (2026, 10, 19):
        raise ValueError("patched Certifi 2026.10.19 or newer is required")
    output.mkdir(mode=0o700)
    entries = json.loads((ROOT / "config/dependency-advisory-triage.json").read_text())["entries"]
    items, findings, exclusions = queries(), [], []
    context = ssl.create_default_context(cafile=certifi.where())
    now = time.time()
    for index in range(0, len(items), 100):
        batch = items[index : index + 100]
        body = json.dumps({"queries": batch}).encode()
        (output / f"query-{index // 100}.json").write_bytes(body)
        request = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            raw = response.read((32 << 20) + 1)
        if len(raw) > 32 << 20:
            raise ValueError("OSV response bound")
        (output / f"response-{index // 100}.json").write_bytes(raw)
        results = json.loads(raw)["results"]
        if len(results) != len(batch):
            raise ValueError("OSV result inventory")
        for query, result in zip(batch, results, strict=True):
            if not isinstance(result, dict) or set(result) - {"vulns"}:
                raise ValueError("incomplete or invalid OSV response")
            for advisory in result.get("vulns", []):
                finding = {"package": query, "advisory": advisory["id"]}
                (exclusions if triaged(query, advisory["id"], entries, now) else findings).append(
                    finding
                )
    report = {
        "state": ("untriaged_advisories" if findings else "locked_dependencies_triaged"),
        "checked_at": int(now),
        "queried_package_versions": len(items),
        "findings": findings,
        "source_bound_profile_exclusions": exclusions,
        "implementation_maintenance_debt": [],
        "vendored_sources": [
            {
                "package": name,
                "version": version,
                "provenance_sha256": VENDOR_PROVENANCE,
            }
            for name, version in VENDORED_PACKAGES.items()
        ],
        "scope": "Cargo.lock, official Node client lock, explicit Python CI constraints",
        "independent_security_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "os_image_scan": "BLOCKED_EXTERNAL_INPUT",
        "production_qualified": False,
        "execution_authority": False,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.output)
    print(json.dumps(report, indent=2))
    raise SystemExit(1 if report["findings"] else 0)
