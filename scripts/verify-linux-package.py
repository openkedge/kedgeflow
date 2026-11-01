#!/usr/bin/env python3
"""Verify bundle paths, file hashes and architecture without extracting or executing."""

import argparse
import hashlib
import json
import re
import runpy
import tarfile
from pathlib import Path, PurePosixPath

PACKAGE = runpy.run_path(str(Path(__file__).with_name("package-linux.py")))
MAX_BYTES = 1 << 30


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


def verify(path: Path) -> dict:
    files, total, roots, names = {}, 0, set(), set()
    with tarfile.open(path, "r:gz") as archive:
        for index, member in enumerate(archive):
            name = PurePosixPath(member.name)
            if (
                index >= 256
                or str(name) != member.name
                or name.is_absolute()
                or ".." in name.parts
                or not name.parts
                or member.name in names
                or member.uid != 0
                or member.gid != 0
                or member.uname
                or member.gname
            ):
                raise ValueError("invalid bundle member")
            names.add(member.name)
            roots.add(name.parts[0])
            if len(roots) != 1:
                raise ValueError("multiple bundle roots")
            if member.isdir():
                if member.mode != 0o755:
                    raise ValueError("unsafe directory mode")
                continue
            if not member.isfile() or len(name.parts) < 2:
                raise ValueError("bundle links and special files are forbidden")
            total += member.size
            if member.size > 256 << 20 or total > MAX_BYTES:
                raise ValueError("bundle exceeds bound")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("unreadable bundle member")
            raw = stream.read(member.size + 1)
            if len(raw) != member.size:
                raise ValueError("bundle member length mismatch")
            relative = str(PurePosixPath(*name.parts[1:]))
            # Keep only the bounded manifest and the binary header after hashing.
            if relative == "manifest.json" and len(raw) > 1 << 20:
                raise ValueError("manifest exceeds bound")
            files[relative] = (
                member.mode,
                hashlib.sha256(raw).hexdigest(),
                raw if relative == "manifest.json" else raw[:64],
            )
    if "manifest.json" not in files:
        raise ValueError("missing manifest")
    manifest = json.loads(files["manifest.json"][2], object_pairs_hook=unique)
    if (
        set(manifest)
        != {
            "format",
            "bundle_id",
            "version",
            "architecture",
            "source_date_epoch",
            "production_qualified",
            "files",
        }
        or manifest["format"] != "kedgeflow-core-bundle-v1"
        or manifest["production_qualified"] is not False
        or not isinstance(manifest["version"], str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?", manifest["version"])
        or manifest["architecture"] not in ("aarch64", "x86_64")
        or type(manifest["source_date_epoch"]) is not int
        or not 0 <= manifest["source_date_epoch"] <= 0xFFFFFFFF
        or not isinstance(manifest["files"], dict)
    ):
        raise ValueError("invalid manifest")
    unsigned = {key: value for key, value in manifest.items() if key != "bundle_id"}
    expected_id = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if manifest["bundle_id"] != expected_id:
        raise ValueError("bundle content identity mismatch")
    expected_root = (
        f"kedgeflow-core-{manifest['version']}-linux-{manifest['architecture']}-{expected_id[:16]}"
    )
    if roots != {expected_root} or files["manifest.json"][0] != 0o644:
        raise ValueError("bundle identity mismatch")
    if set(manifest["files"]) != set(files) - {"manifest.json"}:
        raise ValueError("unlisted or missing bundle file")
    required = {f"bin/{name}" for name in PACKAGE["BINARIES"]} | {
        "LICENSE",
        "DEPLOYMENT.md",
        "share/systemd/kedgeflow.target",
        "share/sysusers.d/kedgeflow.conf",
        "share/tmpfiles.d/kedgeflow.conf",
        *(
            f"share/systemd/kedgeflow-{role}.service"
            for role in ("gateway", "control", "broker", "sql-target")
        ),
    }
    if not required <= set(files):
        raise ValueError("incomplete core runtime bundle")
    for name, record in manifest["files"].items():
        mode, digest, header = files[name]
        expected_mode = 0o755 if name.startswith("bin/") else 0o644
        if (
            not isinstance(record, dict)
            or set(record) != {"sha256", "mode"}
            or type(record["mode"]) is not int
            or record["mode"] != expected_mode
            or mode != expected_mode
            or record["sha256"] != digest
        ):
            raise ValueError("bundle file hash or mode mismatch")
        if (
            name.startswith("bin/")
            and PACKAGE["elf_architecture"](header) != manifest["architecture"]
        ):
            raise ValueError("binary architecture mismatch")
    return {
        "status": "verified_core_bundle",
        "name": expected_root,
        "files": len(files),
        "architecture": manifest["architecture"],
        "production_qualified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.package)))


if __name__ == "__main__":
    main()
