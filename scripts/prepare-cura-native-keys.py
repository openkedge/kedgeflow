#!/usr/bin/env python3
"""Prepare purpose-separated implementation keys; publish no authority record.

No acceptance owner keys, signatures, provider-key rotation or secret export.
An interrupted preparation requires explicit reconciliation, never regeneration.
"""

import argparse
import base64
import json
import os
import pwd
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DATA = Path("/var/lib/kedgeflow/pilot")
PURPOSES = {
    "admission": ("admission", "kf-admission"),
    "issuer": ("issuer", "kf-issuer"),
    "target-token": ("broker", "kf-broker"),
    "gateway-ack": ("gateway", "kf-gateway"),
    "receipt": ("recovery", "kf-recovery"),
    "publish-policy": ("operator", "kf-operator"),
    "register-descriptor": ("operator", "kf-operator"),
    "install": ("operator", "kf-operator"),
    "revoke": ("operator", "kf-operator"),
}
PHASE = "retained_service_preconditions"


def protected(path, uid, gid, mode):
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != uid
        or info.st_gid != gid
        or info.st_mode & 0o7777 != mode
        or info.st_nlink != 1
        or info.st_size > 1 << 20
    ):
        raise RuntimeError("native key custody differs")
    return path.read_bytes()


def write_once(path, raw, uid, gid, mode):
    if path.exists() or path.is_symlink():
        if protected(path, uid, gid, mode) != raw:
            raise RuntimeError("existing native key enrollment differs")
        return
    with path.open("xb") as stream:
        os.chown(path, uid, gid)
        path.chmod(mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def public(seed):
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()


def prepare():
    global PHASE
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Services"
        or time.time() >= 1795420800
    ):
        raise RuntimeError("approved retained Services host required")
    paths = {}
    for purpose, (role, username) in PURPOSES.items():
        user = pwd.getpwnam(username)
        directory = DATA / "configuration" / role
        projected = Path("/etc/kedgeflow") / role
        info = directory.lstat()
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or info.st_uid != 0
            or info.st_gid != user.pw_gid
            or info.st_mode & 0o7777 != 0o750
            or projected.is_symlink()
            or (info.st_dev, info.st_ino) != (projected.stat().st_dev, projected.stat().st_ino)
        ):
            raise RuntimeError("existing per-role protected configuration projection differs")
        paths[purpose] = directory / (purpose + ".seed"), user
    operations = DATA / "operations"
    info = operations.lstat()
    if operations.is_symlink() or info.st_uid != 0 or info.st_mode & 0o7777 != 0o700:
        raise RuntimeError("operator intent custody differs")
    intent_path = operations / "native-key-preparation-intent.json"
    pins_path = operations / "native-purpose-public-pins.json"
    intent = {
        "profile": "kedgeflow-cura-native-key-preparation-intent-v1",
        "purposes": sorted(PURPOSES),
        "independent_acceptance_keys": False,
    }
    raw_intent = json.dumps(intent, sort_keys=True).encode()
    first = not intent_path.exists()
    PHASE = "durable_key_preparation_intent"
    if first and (
        pins_path.exists() or any(p.exists() or p.is_symlink() for p, _ in paths.values())
    ):
        raise RuntimeError("unregistered native signing material exists; never adopt or replace")
    if not first and (not pins_path.exists() or any(not p.exists() for p, _ in paths.values())):
        raise RuntimeError("interrupted preparation or missing enrolled key; never regenerate")
    write_once(intent_path, raw_intent, 0, 0, 0o600)
    pins = {}
    PHASE = "purpose_separated_local_key_creation"
    for purpose, (path, user) in paths.items():
        if first:
            write_once(path, base64.b64encode(os.urandom(32)), user.pw_uid, user.pw_gid, 0o400)
        seed = base64.b64decode(protected(path, user.pw_uid, user.pw_gid, 0o400), validate=True)
        if len(seed) != 32:
            raise RuntimeError("invalid native signing seed length")
        pins[purpose] = {
            "key_id": "urn:kf:cura:" + purpose + ":v1",
            "public_key_base64": public(seed),
        }
    if len({p["public_key_base64"] for p in pins.values()}) != len(PURPOSES):
        raise RuntimeError("purpose key reuse refused")
    PHASE = "actual_cross_role_private_key_refusals"
    checks = 0
    for purpose, (path, owner) in paths.items():
        role = PURPOSES[purpose][0]
        projected = Path("/etc/kedgeflow") / role / path.name
        if (path.stat().st_dev, path.stat().st_ino) != (
            projected.stat().st_dev,
            projected.stat().st_ino,
        ):
            raise RuntimeError("private key projection differs")
        for username in sorted(
            {name for _, name in PURPOSES.values()} | {"kf-agent", "kf-governance"}
        ):
            result = subprocess.run(
                ["runuser", "-u", username, "--", "test", "-r", str(projected)],
                capture_output=True,
                timeout=10,
            )
            if (result.returncode == 0) != (username == owner.pw_name):
                raise RuntimeError("actual private key reader differs from purpose owner")
            checks += 1
    raw = json.dumps(pins, sort_keys=True).encode()
    write_once(pins_path, raw, 0, 0, 0o600)
    return {
        "profile": "kedgeflow-cura-native-purpose-key-observation-v1",
        "status": "purpose_separated_implementation_keys_prepared",
        "public_pins": pins,
        "actual_reader_checks": checks,
        "first_preparation": first,
        "secrets_or_secret_hashes_exported": False,
        "listeners_started": False,
        "authority_records_created": False,
        "independent_acceptance_keys": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true", required=True)
    parser.parse_args()
    try:
        print(json.dumps(prepare()))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
