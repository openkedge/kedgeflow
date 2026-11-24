#!/usr/bin/env python3
"""Explicit pre-application SQL pilot binary upgrade, preserving original authority.

Verify the digest-pinned bundle using the original source-pinned verifier. Stage
an immutable release, query the same native restore head before/after activation,
and retain the original release and enrollment intent. No enrollment, SQL write,
provider rotation or enterprise acceptance is performed.
"""

import argparse
import hashlib
import json
import os
import re
import runpy
import stat
import subprocess
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
SOURCE = Path("/opt/kedgeflow/pilot-source/scripts")
CURRENT = Path("/opt/kedgeflow/current")
RELEASES = Path("/opt/kedgeflow/releases")
OLD_ID = "b68967312fb4a637a378c83436a603ec4390ed779875276e4ca30b9f0c0926e3"
HEAD = {
    "profile": "KF-RESTORE-GATE-0.1-draft",
    "namespace": "/kedgeflow/cura",
    "witness": "https://witness.cura.kedgeflow.internal:2379/kedgeflow/cura",
    "enrollment": "b919ddac9ddf4dc5af0ee8f071d5af0c75c9e149c66d8fdb80a08ec23e7e6ff6",
    "sequence": 0,
    "digest": "cec2aff9d1c341ec184105b0e9f53f321adbaf919b97689bb137e31073181f0b",
}
PHASE = "pre_application_upgrade_preconditions"


def runtime_deadline(value, *, now=None):
    """Validate an explicit runtime bound; operator approval remains separate."""
    end = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    deadline = end.timestamp()
    current = time.time() if now is None else now
    if end.strftime("%Y-%m-%dT%H:%M:%SZ") != value or not current < deadline <= current + 86400:
        raise ValueError("canonical future stop UTC within 24 hours required")
    return deadline


def run(argv, accepted=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if accepted and result.returncode:
        raise RuntimeError("bounded native upgrade operation refused")
    return result


def read_regular(path, bound, *, root_owned=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > bound
            or (root_owned and (info.st_uid != 0 or info.st_mode & 0o022))
        ):
            raise RuntimeError("native upgrade input custody differs")
        raw = stream.read(bound + 1)
        if len(raw) > bound:
            raise RuntimeError("native upgrade input bound")
        return raw


def durable_write(path, raw, mode=0o600):
    with path.open("xb") as stream:
        path.chmod(mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def restore_status(release):
    result = run(
        [
            "runuser",
            "-u",
            "kf-operator",
            "--",
            str(release / "bin/kf-restore"),
            "--config",
            "/etc/kedgeflow/operator/restore.json",
            "--custody-root",
            "/etc/kedgeflow/operator",
            "--require-managed",
            "--status",
        ]
    )
    value = json.loads(result.stdout)
    if value != HEAD:
        raise RuntimeError("original authority head differs; never reenroll or reset")
    return value


def activate_link(destination):
    temporary = CURRENT.with_name(".current-cura-url-upgrade")
    if os.path.lexists(temporary):
        raise RuntimeError("interrupted activation link exists; explicit reconciliation required")
    temporary.symlink_to(destination)
    os.replace(temporary, CURRENT)
    fd = os.open(CURRENT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def upgrade(expected_sha256, expected_size, activate, stop_utc):
    global PHASE
    stop_epoch = runtime_deadline(stop_utc)
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or time.time() >= stop_epoch
        or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
        or not 1 <= expected_size <= 256 << 20
    ):
        raise RuntimeError("exact approved retained pilot window and digest required")
    host = json.loads(read_regular(DATA / ".host-enrollment.json", 65536))["host"]
    if host not in {"Services", "Sql"}:
        raise RuntimeError("upgrade currently scoped only to Services and Sql")
    for path in [RELEASES, CURRENT.parent]:
        info = path.lstat()
        if path.is_symlink() or not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("release directory custody differs")
    if not CURRENT.is_symlink():
        raise RuntimeError("existing release selector must be an explicit symlink")
    old = CURRENT.resolve(strict=True)
    old_manifest = json.loads(read_regular(old / "manifest.json", 1 << 20))
    if old.parent != RELEASES or old_manifest["bundle_id"] != OLD_ID:
        raise RuntimeError("original pre-application release differs")
    for role in [
        "gateway",
        "control",
        "admission",
        "issuer",
        "broker",
        "sql-target",
        "recovery",
        "collector",
        "governance",
    ]:
        if (
            run(
                ["systemctl", "is-active", "--quiet", "kedgeflow-" + role + ".service"], False
            ).returncode
            == 0
        ):
            raise RuntimeError("active application unit requires a separate rolling upgrade")
    for name, digest in {
        "package-linux.py": "432daf6c92bcdb99c1d3580f3cd396ac54b05e98b1fb13602a2e5bd095dd4d89",
        "verify-linux-package.py": (
            "b3be273eef2dc47e7074c3e478bf522fc223e2b6f77374e28ff841b4b026266c"
        ),
    }.items():
        if hashlib.sha256(read_regular(SOURCE / name, 1 << 20)).hexdigest() != digest:
            raise RuntimeError("original bundle verification source pin differs")
    operations = DATA / "operations"
    if not operations.exists():
        operations.mkdir(mode=0o700)
    info = operations.lstat()
    if operations.is_symlink() or info.st_uid != 0 or info.st_mode & 0o7777 != 0o700:
        raise RuntimeError("upgrade intent custody differs")
    bundle = operations / ("native-url-patch-" + expected_sha256[:16] + ".tar.gz")
    PHASE = "digest_pinned_upload_snapshot"
    upload = Path("/run/kf-cura-release-upload/bundle.tar.gz")
    raw = (
        read_regular(upload, 256 << 20, root_owned=False)
        if os.path.lexists(upload)
        else (read_regular(bundle, 256 << 20))
    )
    if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError("received bundle differs from reviewed public artifact")
    if bundle.exists():
        if read_regular(bundle, 256 << 20) != raw:
            raise RuntimeError("retained upgrade bundle differs")
    else:
        durable_write(bundle, raw)
    PHASE = "manifest_and_architecture_verification"
    verified = runpy.run_path(str(SOURCE / "verify-linux-package.py"))["verify"](bundle)
    if verified["architecture"] != "aarch64":
        raise RuntimeError("native architecture differs")
    new = RELEASES / verified["name"]
    with tarfile.open(bundle) as archive:
        manifest_raw = archive.extractfile(verified["name"] + "/manifest.json").read()
        manifest = json.loads(manifest_raw)
        if manifest["bundle_id"] == OLD_ID:
            raise RuntimeError("replacement must be a distinct reviewed release")
        intent_path = operations / (
            "native-url-upgrade-" + manifest["bundle_id"][:16] + ".intent.json"
        )
        if os.path.lexists(new):
            if not intent_path.exists() or new.is_symlink():
                raise RuntimeError(
                    "unregistered candidate exists; explicit reconciliation required"
                )
        else:
            staging = new.with_name(new.name + ".incomplete")
            staging.mkdir(mode=0o755)
            staging.chmod(0o755)
            for member in archive:
                relative = Path(*Path(member.name).parts[1:])
                target = staging / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    target.chmod(0o755)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise RuntimeError("verified bundle member unreadable")
                    durable_write(target, source.read(), member.mode)
            staging.rename(new)
            release_fd = os.open(RELEASES, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(release_fd)
            finally:
                os.close(release_fd)
    new_info = new.lstat()
    if (
        new.is_symlink()
        or not new.is_dir()
        or new_info.st_uid != 0
        or new_info.st_mode & 0o7777 != 0o755
    ):
        raise RuntimeError("candidate release root custody differs")
    if read_regular(new / "manifest.json", 1 << 20) != manifest_raw:
        raise RuntimeError("staged manifest differs from pinned artifact")
    observed_files = set()
    for path in new.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            if info.st_uid != 0 or info.st_mode & 0o7777 != 0o755:
                raise RuntimeError("staged directory custody differs")
        elif stat.S_ISREG(info.st_mode):
            observed_files.add(str(path.relative_to(new)))
        else:
            raise RuntimeError("staged release contains link or special file")
    if observed_files != set(manifest["files"]) | {"manifest.json"}:
        raise RuntimeError("staged release has unknown or missing files")
    for relative, record in manifest["files"].items():
        path = new / relative
        if (
            hashlib.sha256(read_regular(path, 256 << 20)).hexdigest() != record["sha256"]
            or path.stat().st_mode & 0o7777 != record["mode"]
        ):
            raise RuntimeError("staged release differs from manifest")
    old_intent = None
    before = None
    if host == "Services":
        PHASE = "original_native_head_readback"
        old_intent = read_regular(operations / "restore-enrollment-intent.json", 1 << 20)
        before = restore_status(old)
        if restore_status(new) != before:
            raise RuntimeError("replacement native reader differs from original authority")
    record = {
        "profile": "kedgeflow-cura-native-url-upgrade-v1",
        "host": host,
        "old_bundle_id": OLD_ID,
        "new_bundle_id": manifest["bundle_id"],
        "bundle_sha256": expected_sha256,
        "bytes": expected_size,
        "original_head": before,
        "authority_reset": False,
        "enterprise_qualified": False,
    }
    intent_raw = json.dumps(record, sort_keys=True).encode()
    if intent_path.exists():
        if read_regular(intent_path, 1 << 20) != intent_raw:
            raise RuntimeError("staged upgrade intent differs; never replace")
    else:
        durable_write(intent_path, intent_raw)
    if not activate:
        return {**record, "status": "candidate_staged_original_selector_preserved"}
    PHASE = "bounded_pre_application_binary_activation"
    timer = (
        host == "Services"
        and run(
            ["systemctl", "is-active", "--quiet", "kedgeflow-ledger-publish.timer"], False
        ).returncode
        == 0
    )
    if timer:
        run(
            [
                "systemctl",
                "stop",
                "kedgeflow-ledger-publish.timer",
                "kedgeflow-ledger-publish.service",
            ]
        )
    try:
        if time.time() >= stop_epoch:
            raise RuntimeError("approved runtime window expired before activation")
        activate_link(new)
        if timer and time.time() < stop_epoch:
            run(["systemctl", "start", "kedgeflow-ledger-publish.service"])
            run(["systemctl", "start", "kedgeflow-ledger-publish.timer"])
        if host == "Services" and (
            restore_status(new) != before
            or read_regular(operations / "restore-enrollment-intent.json", 1 << 20) != old_intent
        ):
            raise RuntimeError("original enrollment intent/head changed; quarantine")
    except Exception:
        if CURRENT.resolve(strict=True) == new:
            activate_link(old)
        if timer and time.time() < stop_epoch:
            run(["systemctl", "start", "kedgeflow-ledger-publish.service"])
            run(["systemctl", "start", "kedgeflow-ledger-publish.timer"])
        raise
    record.update(
        status="native_release_activated_original_authority_preserved",
        original_release_retained=True,
        application_listeners_started=False,
        original_enrollment_intent_preserved=host == "Services",
    )
    durable_write(
        operations / ("native-url-upgrade-" + manifest["bundle_id"][:16] + ".complete.json"),
        json.dumps(record, sort_keys=True).encode(),
    )
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--size", type=int, required=True)
    parser.add_argument("--activate-pre-application", action="store_true")
    parser.add_argument("--stop-utc", required=True)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                upgrade(args.sha256, args.size, args.activate_pre_application, args.stop_utc)
            )
        )
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
