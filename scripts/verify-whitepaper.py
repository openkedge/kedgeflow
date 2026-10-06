#!/usr/bin/env python3
"""Check the frozen paper bundle and its mirrored implementation contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath


def checked_path(root: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    if not value or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"invalid relative path: {value!r}")
    path = root.joinpath(*relative.parts)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"path escapes root: {value}")
    return path


def check_hash(path: Path, expected: str, label: str) -> None:
    if not path.is_file():
        raise ValueError(f"missing file: {label}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch: {label} (expected {expected}, got {actual})")


def verify(root: Path) -> tuple[int, int]:
    bundle = root / "docs/whitepaper/v0.9"
    manifest = json.loads((bundle / "FREEZE.json").read_text(encoding="utf-8"))
    if manifest["schema_version"] != 1 or manifest["whitepaper_version"] != "0.9":
        raise ValueError("unsupported freeze manifest version")

    files: dict[str, str] = {}
    for item in manifest["files"]:
        name = item["path"]
        if name in files or name == "FREEZE.json":
            raise ValueError(f"duplicate or self-referential frozen file: {name}")
        check_hash(checked_path(bundle, name), item["sha256"], f"frozen/{name}")
        files[name] = item["sha256"]
    actual_files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() and path != bundle / "FREEZE.json"
    }
    if actual_files != set(files):
        raise ValueError("frozen package inventory differs from manifest")

    expected_mapping = {
        "spec/kedgeflow.schema.json": "spec/kedgeflow.schema.json",
        "spec/GRANT_REFERENCE_PROFILE.md": "spec/GRANT_REFERENCE_PROFILE.md",
    }
    expected_mapping.update({
        name: "fixtures/" + PurePosixPath(name).name
        for name in files
        if name.startswith("spec/examples/")
    })
    contracts: dict[str, str] = {}
    for item in manifest["contracts"]:
        name, target = item["path"], item["implementation_path"]
        if name in contracts or expected_mapping.get(name) != target:
            raise ValueError(f"duplicate or unexpected contract mapping: {name} -> {target}")
        if files.get(name) != item["sha256"]:
            raise ValueError(f"contract digest differs from frozen inventory: {name}")
        check_hash(checked_path(root, target), item["sha256"], target)
        contracts[name] = target
    if contracts != expected_mapping:
        raise ValueError("contract inventory differs from frozen schema/profile/fixture set")
    pdf = manifest["pdf"]
    if files.get(pdf["path"]) != pdf["sha256"]:
        raise ValueError("PDF digest differs from frozen inventory")
    return len(files), len(contracts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        files, contracts = verify(args.root.resolve())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: frozen whitepaper v0.9; {files} files and {contracts} contract pins match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
