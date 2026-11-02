"""Package integrity/containment checks do not qualify the contained executables."""

import hashlib
import io
import json
import runpy
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
BUILD = runpy.run_path(str(ROOT / "scripts/package-linux.py"))
VERIFY = runpy.run_path(str(ROOT / "scripts/verify-linux-package.py"))


def test_staged_linux_qualification_requires_explicit_disposable_opt_in():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/qualify-linux-package.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires --ephemeral-host" in result.stderr


def test_installed_systemd_smoke_requires_both_disposable_install_flags():
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/qualify-systemd-services.py"),
            "--package",
            "/not-read",
            "--sha256",
            "0" * 64,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires explicit --ephemeral-host --accept-test-install" in result.stderr


def binaries(directory, machine=183):
    directory.mkdir()
    raw = bytearray(64)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 3, machine, 1)
    for name in BUILD["BINARIES"]:
        (directory / name).write_bytes(raw)
    return directory


def test_archive_is_deterministic_and_complete_and_refuses_replacement(tmp_path):
    source = binaries(tmp_path / "bins")
    first = BUILD["package"](source, tmp_path / "one", 123)
    second = BUILD["package"](source, tmp_path / "two", 123)
    assert first.read_bytes() == second.read_bytes()
    report = VERIFY["verify"](first)
    assert report["status"] == "verified_core_bundle"
    assert not report["production_qualified"]
    assert report["architecture"] == "aarch64"
    with pytest.raises(ValueError, match="existing package"):
        BUILD["package"](source, tmp_path / "one", 123)
    assert first.read_bytes() == second.read_bytes()


def test_changed_payload_gets_a_distinct_immutable_release_identity(tmp_path):
    source = binaries(tmp_path / "bins")
    first = BUILD["package"](source, tmp_path / "output", 123)
    original = first.read_bytes()
    binary = source / "kf-proxy"
    binary.write_bytes(binary.read_bytes() + b"changed payload")
    second = BUILD["package"](source, tmp_path / "output", 123)
    assert first != second and first.read_bytes() == original
    assert VERIFY["verify"](first)["name"] != VERIFY["verify"](second)["name"]


@pytest.mark.parametrize("version", [1, 2])
def test_new_packager_does_not_change_legacy_required_binary_sets(tmp_path, version):
    original = BUILD["package"](binaries(tmp_path / "bins"), tmp_path / "output", 123)
    legacy = ("kf-proxy", "kf-control", "kf-broker", "kf-postgres-target")
    if version == 2:
        legacy += ("kf-recover", "kf-supervise", "kf-outcomes", "kf-governance", "kf-restore")
    with tarfile.open(original) as archive:
        payload = {
            str(Path(m.name).relative_to(Path(m.name).parts[0])): archive.extractfile(m).read()
            for m in archive
            if m.isfile()
        }
    manifest = json.loads(payload.pop("manifest.json"))
    for name in list(payload):
        if (
            (name.startswith("bin/") and name[4:] not in legacy)
            or name.startswith(("libexec/", "share/ledger-credentials/"))
            or name == "LEDGER_CREDENTIALS.md"
        ):
            payload.pop(name)
    manifest["files"] = {
        name: record for name, record in manifest["files"].items() if name in payload
    }
    manifest["format"] = f"kedgeflow-core-bundle-v{version}"
    manifest.pop("bundle_id")
    manifest["bundle_id"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    name = (
        f"kedgeflow-core-{manifest['version']}-linux-{manifest['architecture']}-"
        f"{manifest['bundle_id'][:16]}"
    )
    payload["manifest.json"] = json.dumps(manifest).encode()
    path = tmp_path / "legacy.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for relative, raw in payload.items():
            info = tarfile.TarInfo(f"{name}/{relative}")
            info.size = len(raw)
            info.mode = 0o755 if relative.startswith("bin/") else 0o644
            archive.addfile(info, io.BytesIO(raw))
    assert VERIFY["verify"](path)["status"] == "verified_core_bundle"


@pytest.mark.parametrize("variant", ["native", "mixed", "symlink", "checksum"])
def test_invalid_inputs_or_existing_checksum_never_create_a_package(tmp_path, variant):
    source = binaries(tmp_path / "bins")
    if variant == "native":
        (source / "kf-proxy").write_bytes(b"not-linux")
    elif variant == "mixed":
        raw = bytearray((source / "kf-proxy").read_bytes())
        struct.pack_into("<H", raw, 18, 62)
        (source / "kf-proxy").write_bytes(raw)
    elif variant == "symlink":
        (source / "kf-proxy").unlink()
        (source / "kf-proxy").symlink_to(source / "kf-broker")
    else:
        output = tmp_path / "output"
        output.mkdir()
        known = BUILD["package"](source, tmp_path / "known", 123)
        (output / (known.name + ".sha256")).write_text("existing")
    with pytest.raises((ValueError, OSError)):
        BUILD["package"](source, tmp_path / "output", 123)
    assert not list((tmp_path / "output").glob("*.tar.gz"))


def mutate(original, destination, variant):
    with tarfile.open(original) as source, tarfile.open(destination, "w:gz") as target:
        members = list(source)
        root = members[0].name
        for member in members:
            stream = source.extractfile(member) if member.isfile() else None
            raw = stream.read() if stream else b""
            if member.name.endswith("/bin/kf-proxy"):
                if variant == "hash":
                    raw = raw[:-1] + b"!"
                elif variant == "mode":
                    member.mode = 0o777
                elif variant == "missing":
                    continue
                elif variant == "arch":
                    raw = bytearray(raw)
                    struct.pack_into("<H", raw, 18, 62)
                    raw = bytes(raw)
            if member.name.endswith("/manifest.json") and variant == "duplicate-key":
                raw = raw.replace(b"{", b'{"format":"duplicate",', 1)
            if member.name.endswith("/manifest.json") and variant == "identity":
                manifest = json.loads(raw)
                manifest["bundle_id"] = "0" * 64
                raw = json.dumps(manifest).encode()
            member.size = len(raw)
            target.addfile(member, io.BytesIO(raw) if member.isfile() else None)
            if member.name.endswith("/bin/kf-proxy") and variant == "duplicate-path":
                target.addfile(member, io.BytesIO(raw))
        if variant in ("escape", "symlink", "hardlink", "fifo", "unlisted"):
            extra = tarfile.TarInfo(
                f"{root}/../escaped" if variant == "escape" else f"{root}/extra"
            )
            if variant in ("symlink", "hardlink"):
                extra.type = tarfile.SYMTYPE if variant == "symlink" else tarfile.LNKTYPE
                extra.linkname = "/etc/passwd"
            elif variant == "fifo":
                extra.type = tarfile.FIFOTYPE
            target.addfile(extra, io.BytesIO(b""))


@pytest.mark.parametrize(
    "variant",
    [
        "hash",
        "mode",
        "missing",
        "arch",
        "duplicate-key",
        "identity",
        "duplicate-path",
        "escape",
        "symlink",
        "hardlink",
        "fifo",
        "unlisted",
    ],
)
def test_verifier_refuses_corrupt_or_escaping_bundle_without_extraction(tmp_path, variant):
    original = BUILD["package"](binaries(tmp_path / "bins"), tmp_path / "output", 123)
    corrupt = tmp_path / "corrupt.tar.gz"
    mutate(original, corrupt, variant)
    with pytest.raises((ValueError, KeyError, json.JSONDecodeError)):
        VERIFY["verify"](corrupt)
    assert not (tmp_path / "escaped").exists()
