#!/usr/bin/env python3
"""Assemble a versioned, checksummed core runtime bundle; never install or start it."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("kf-proxy", "kf-control", "kf-broker", "kf-postgres-target")
MACHINES = {62: "x86_64", 183: "aarch64"}


def read_regular(path: Path, bound: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > bound:
            raise ValueError("invalid package input")
        raw = stream.read(bound + 1)
        if len(raw) > bound:
            raise ValueError("package input exceeds bound")
        return raw


def elf_architecture(raw: bytes) -> str:
    # Only the supported little-endian ELF64 Linux executable/PIE containers.
    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01" or raw[7] not in (0, 3):
        raise ValueError("package requires Linux ELF64 binaries")
    kind, machine, version = struct.unpack_from("<HHI", raw, 16)
    if kind not in (2, 3) or machine not in MACHINES or version != 1:
        raise ValueError("unsupported Linux binary architecture")
    return MACHINES[machine]


def package(binary_dir: Path, output: Path, epoch: int) -> Path:
    version = tomllib.loads((ROOT / "crates/kedgeflow/Cargo.toml").read_text())["package"][
        "version"
    ]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?", version):
        raise ValueError("invalid package version")
    binary_bytes = {name: read_regular(binary_dir / name, 256 << 20) for name in BINARIES}
    architectures = {elf_architecture(raw) for raw in binary_bytes.values()}
    if len(architectures) != 1:
        raise ValueError("mixed binary architectures")
    architecture = architectures.pop()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output) as temporary:
        directory = Path(temporary) / "payload"
        directory.mkdir()
        for binary, raw in binary_bytes.items():
            path = directory / "bin" / binary
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o755)
        for source, destination in [
            (ROOT / "deploy/linux/systemd", "share/systemd"),
            (ROOT / "deploy/linux/sysusers.d", "share/sysusers.d"),
            (ROOT / "deploy/linux/tmpfiles.d", "share/tmpfiles.d"),
            (ROOT / "migrations", "share/migrations"),
        ]:
            shutil.copytree(source, directory / destination, symlinks=True)
        for source, destination in [
            (ROOT / "LICENSE", "LICENSE"),
            (ROOT / "docs/LINUX_DEPLOYMENT.md", "DEPLOYMENT.md"),
        ]:
            (directory / destination).write_bytes(read_regular(source, 1 << 20))
        files = {}
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("symlinks are forbidden in runtime bundles")
            if path.is_file():
                relative = str(path.relative_to(directory))
                raw = read_regular(path, 256 << 20)
                mode = 0o755 if relative.startswith("bin/") else 0o644
                path.chmod(mode)
                files[relative] = {"sha256": hashlib.sha256(raw).hexdigest(), "mode": mode}
        manifest = {
            "format": "kedgeflow-core-bundle-v1",
            "version": version,
            "architecture": architecture,
            "source_date_epoch": epoch,
            "production_qualified": False,
            "files": files,
        }
        manifest["bundle_id"] = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        name = f"kedgeflow-core-{version}-linux-{architecture}-{manifest['bundle_id'][:16]}"
        renamed = Path(temporary) / name
        directory.rename(renamed)
        directory = renamed
        archive_path = output / f"{name}.tar.gz"
        checksum = archive_path.with_suffix(archive_path.suffix + ".sha256")
        if (
            archive_path.exists()
            or archive_path.is_symlink()
            or checksum.exists()
            or checksum.is_symlink()
        ):
            raise ValueError("refusing to replace an existing package")
        (directory / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        (directory / "manifest.json").chmod(0o644)
        # A stable archive with numeric root ownership and normalized timestamps.
        tar_path = Path(temporary) / "bundle.tar"
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for path in [directory, *sorted(directory.rglob("*"))]:
                info = archive.gettarinfo(
                    str(path), arcname=str(path.relative_to(directory.parent))
                )
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = epoch
                info.pax_headers = {}
                if info.isdir():
                    info.mode = 0o755
                if info.isfile():
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    archive.addfile(info)
        import gzip

        with tar_path.open("rb") as source, (Path(temporary) / "bundle.tar.gz").open("wb") as dest:
            with gzip.GzipFile(filename="", mode="wb", fileobj=dest, mtime=epoch) as compressor:
                shutil.copyfileobj(source, compressor)
        os.link(Path(temporary) / "bundle.tar.gz", archive_path)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    with checksum.open("x") as stream:
        stream.write(f"{digest}  {archive_path.name}\n")
    return archive_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary-dir", type=Path, help="prebuilt Linux binaries; omit to build locally"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-date-epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    )
    args = parser.parse_args()
    if args.source_date_epoch < 0 or args.source_date_epoch > 0xFFFFFFFF:
        parser.error("source date epoch must fit an unsigned 32-bit timestamp")
    binary_dir = args.binary_dir
    if binary_dir is None:
        if platform.system() != "Linux":
            parser.error(
                "native build requires Linux; supply prebuilt Linux binaries on other hosts"
            )
        command = ["cargo", "build", "--locked", "--release"]
        for binary in BINARIES:
            command.extend(["--bin", binary])
        subprocess.run(command, cwd=ROOT, check=True)
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
        binary_dir = (target if target.is_absolute() else ROOT / target) / "release"
    print(package(binary_dir, args.output, args.source_date_epoch))


if __name__ == "__main__":
    main()
