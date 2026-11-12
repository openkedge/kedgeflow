#!/usr/bin/env python3
"""Build or verify an opt-in Linux Terraform runtime extension; never install it."""

import argparse
import gzip
import hashlib
import io
import json
import runpy
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = runpy.run_path(str(ROOT / "scripts/package-linux.py"))
BINS = (
    "kf-proxy",
    "kf-terraform-plan",
    "kf-terraform-pair-plan",
    "kf-terraform-apply",
    "kf-terraform-pair-apply",
)
ASSETS = ("kedgeflow-terraform-gateway.service", "sysusers.conf", "tmpfiles.conf")
FILES = {*("bin/" + n for n in BINS), *("share/" + n for n in ASSETS), "DEPLOYMENT.md"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()


def package(binary_dir, output):
    blobs = {f"bin/{n}": CORE["read_regular"](binary_dir / n, 256 << 20) for n in BINS}
    arches = {CORE["elf_architecture"](b) for b in blobs.values()}
    if len(arches) != 1:
        raise ValueError("mixed Linux architectures")
    blobs.update({"share/" + n: (ROOT / "deploy/linux/terraform" / n).read_bytes() for n in ASSETS})
    blobs["DEPLOYMENT.md"] = (ROOT / "docs/TERRAFORM_LINUX_DEPLOYMENT.md").read_bytes()
    manifest = {
        "format": "kedgeflow-terraform-linux-v1",
        "architecture": arches.pop(),
        "production_qualified": False,
        "files": {
            n: {"sha256": sha(b), "mode": 0o755 if n.startswith("bin/") else 0o644}
            for n, b in sorted(blobs.items())
        },
    }
    manifest["bundle_id"] = sha(canonical(manifest))
    name = "kedgeflow-terraform-" + manifest["bundle_id"]
    blobs["manifest.json"] = json.dumps(manifest, indent=2).encode() + b"\n"
    output.mkdir(parents=True, exist_ok=True)
    path = output / (name + ".tar.gz")
    archive = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=archive, mode="wb", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as tf:
            for n, b in sorted(blobs.items()):
                info = tarfile.TarInfo(name + "/" + n)
                info.size = len(b)
                info.mode = 0o755 if n.startswith("bin/") else 0o644
                info.mtime = 0
                tf.addfile(info, io.BytesIO(b))
    blob = archive.getvalue()
    if path.exists():
        if CORE["read_regular"](path, 512 << 20) != blob:
            raise ValueError("bundle path collision")
    else:
        with path.open("xb") as stream:
            stream.write(blob)
    verify(path, sha(path.read_bytes()))
    return {
        "archive": str(path),
        "sha256": sha(path.read_bytes()),
        "bundle_id": manifest["bundle_id"],
        "architecture": manifest["architecture"],
        "production_qualified": False,
    }


def verify(path, expected):
    data = CORE["read_regular"](path, 512 << 20)
    if sha(data) != expected:
        raise ValueError("archive SHA-256 mismatch")
    files = {}
    roots = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf:
            parts = member.name.split("/")
            total += member.size
            if (
                not member.isfile()
                or member.name.startswith("/")
                or ".." in parts
                or len(parts) < 2
                or total > 512 << 20
                or member.name in files
                or member.mode & 0o7000
                or member.uid != 0
                or member.gid != 0
                or member.size < 0
            ):
                raise ValueError("unsafe bundle member")
            roots.add(parts[0])
            files[member.name] = (member.mode, tf.extractfile(member).read())
    if len(roots) != 1:
        raise ValueError("mixed bundle roots")
    root = next(iter(roots))
    if files[root + "/manifest.json"][0] != 0o644:
        raise ValueError("unsafe manifest mode")
    m = json.loads(files[root + "/manifest.json"][1])
    if (
        set(m) != {"format", "architecture", "production_qualified", "files", "bundle_id"}
        or m["format"] != "kedgeflow-terraform-linux-v1"
        or m["production_qualified"] is not False
        or set(m["files"]) != FILES
    ):
        raise ValueError("invalid manifest")
    unsigned = {k: v for k, v in m.items() if k != "bundle_id"}
    if (
        m["bundle_id"] != sha(canonical(unsigned))
        or root != "kedgeflow-terraform-" + m["bundle_id"]
        or {n[len(root) + 1 :] for n in files} != {*FILES, "manifest.json"}
    ):
        raise ValueError("bundle identity mismatch")
    for n, record in m["files"].items():
        mode, b = files[root + "/" + n]
        wanted = 0o755 if n.startswith("bin/") else 0o644
        if (
            set(record) != {"mode", "sha256"}
            or mode != wanted
            or record != {"mode": wanted, "sha256": sha(b)}
        ):
            raise ValueError("bundle file mismatch")
        if n.startswith("bin/") and CORE["elf_architecture"](b) != m["architecture"]:
            raise ValueError("ELF architecture mismatch")
    return m


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary-dir", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--verify", type=Path)
    p.add_argument("--sha256")
    a = p.parse_args()
    if a.verify:
        if not a.sha256:
            p.error("--sha256 is required to verify")
        m = verify(a.verify, a.sha256)
        print(
            json.dumps(
                {"status": "PASS", "bundle_id": m["bundle_id"], "production_qualified": False}
            )
        )
    else:
        if not a.binary_dir or not a.output:
            p.error("--binary-dir and --output are required")
        print(json.dumps(package(a.binary_dir, a.output)))
