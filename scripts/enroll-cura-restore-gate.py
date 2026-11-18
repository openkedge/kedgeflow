#!/usr/bin/env python3
"""Enroll a genuinely empty Cura namespace using the shipping native restore ceremony.

One protected intent record precedes the first native enrollment. A failed or
ambiguous attempt is never retried automatically. Subsequent runs query status
only, preserving the separate witness/head and all authority history.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import pwd
import re
import ssl
import subprocess
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
ROOT = Path("/etc/kedgeflow/operator")
SOURCE = DATA / "configuration/operator"
BINARY = Path("/opt/kedgeflow/current/bin/kf-restore")
INTENT = DATA / "operations/restore-enrollment-intent.json"


def config():
    material = {
        "ca": str(ROOT / "ca.pem"),
        "certificate": str(ROOT / "identity.pem"),
        "private_key": str(ROOT / "identity.key"),
    }
    return {
        "etcd_endpoint": "https://ledgera.cura.kedgeflow.internal:2379",
        "etcd_prefix": "/kedgeflow/cura",
        **{"etcd_" + k: v for k, v in material.items()},
        "etcd_token_file": str(ROOT / "credentials/primary.token"),
        "restore_gate": {
            "endpoint": "https://witness.cura.kedgeflow.internal:2379",
            "prefix": "/kedgeflow/cura",
            **material,
            "token_file": str(ROOT / "credentials/witness.token"),
        },
    }


def run(mode):
    result = subprocess.run(
        [
            "runuser",
            "-u",
            "kf-operator",
            "--",
            str(BINARY),
            "--config",
            str(ROOT / "restore.json"),
            "--custody-root",
            str(ROOT),
            "--require-managed",
            mode,
        ],
        capture_output=True,
        text=True,
        timeout=40,
    )
    return result


def require_empty(endpoint, token_file):
    context = ssl.create_default_context(cafile=str(ROOT / "ca.pem"))
    context.load_cert_chain(ROOT / "identity.pem", ROOT / "identity.key")
    from urllib.parse import urlsplit

    parsed = urlsplit(endpoint)
    connection = http.client.HTTPSConnection(
        parsed.hostname, parsed.port, context=context, timeout=8
    )
    def encode(value):
        return base64.b64encode(value.encode()).decode()
    try:
        connection.request(
            "POST",
            "/v3/kv/range",
            json.dumps(
                {
                    "key": encode("/kedgeflow/cura/"),
                    "range_end": encode("/kedgeflow/cura0"),
                    "limit": "1",
                }
            ),
            {"Content-Type": "application/json", "Authorization": token_file.read_text()},
        )
        response = connection.getresponse()
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise RuntimeError("namespace emptiness could not be observed")
        result = json.loads(raw)
        if (
            "code" in result
            or result.get("kvs")
            or result.get("more")
            or int(result.get("count", 0)) != 0
        ):
            raise RuntimeError("namespace already contains records; never enroll or reset")
    finally:
        connection.close()


def enroll(expected_sha256, allow_empty):
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Services"
    ):
        raise RuntimeError("requires privileged retained Services host")
    if (
        not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
        or BINARY.is_symlink()
        or hashlib.sha256(BINARY.read_bytes()).hexdigest() != expected_sha256
    ):
        raise ValueError("qualified native restore binary pin differs")
    user = pwd.getpwnam("kf-operator")
    if (
        not user.pw_uid
        or SOURCE.is_symlink()
        or SOURCE.stat().st_uid != 0
        or SOURCE.stat().st_gid != user.pw_gid
        or SOURCE.stat().st_mode & 0o7777 != 0o750
        or (SOURCE.stat().st_dev, SOURCE.stat().st_ino) != (ROOT.stat().st_dev, ROOT.stat().st_ino)
    ):
        raise RuntimeError("protected operator configuration projection differs")
    path, raw = SOURCE / "restore.json", json.dumps(config(), indent=2) + "\n"
    if not path.exists():
        with path.open("x") as stream:
            stream.write(raw)
        os.chown(path, 0, user.pw_gid)
        path.chmod(0o440)
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != 0
        or info.st_gid != user.pw_gid
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != 0o440
        or path.read_text() != raw
    ):
        raise RuntimeError("retained restore configuration differs")
    if run("--check").returncode:
        raise RuntimeError("native protected restore preflight failed")
    first = not INTENT.exists()
    if first:
        if not allow_empty:
            raise RuntimeError("explicit first empty-namespace enrollment required")
        c = config()
        require_empty(c["etcd_endpoint"], Path(c["etcd_token_file"]))
        require_empty(c["restore_gate"]["endpoint"], Path(c["restore_gate"]["token_file"]))
        record = {
            "format": "kedgeflow-cura-restore-intent-v1",
            "config_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "binary_sha256": expected_sha256,
            "native_enrollment_attempted": True,
            "independent_custody": "BLOCKED_EXTERNAL_INPUT",
        }
        with INTENT.open("x") as stream:
            json.dump(record, stream)
            stream.flush()
            os.fsync(stream.fileno())
        INTENT.chmod(0o600)
        if run("--enroll-empty").returncode:
            raise RuntimeError(
                "native enrollment ambiguous; preserve witness and intent; status only thereafter"
            )
    else:
        info = INTENT.lstat()
        if (
            INTENT.is_symlink()
            or not INTENT.is_file()
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o7777 != 0o600
        ):
            raise RuntimeError("restore intent custody differs")
        record = json.loads(INTENT.read_text())
        if (
            record["config_sha256"] != hashlib.sha256(raw.encode()).hexdigest()
            or record["binary_sha256"] != expected_sha256
        ):
            raise RuntimeError("retained restore enrollment differs")
    result = run("--status")
    if result.returncode:
        raise RuntimeError(
            "native restore status quarantined; never retry enrollment or reset history"
        )
    head = json.loads(result.stdout)
    if (
        head["profile"] != "KF-RESTORE-GATE-0.1-draft"
        or head["namespace"] != "/kedgeflow/cura"
        or head["witness"] != "https://witness.cura.kedgeflow.internal:2379/kedgeflow/cura"
    ):
        raise RuntimeError("native restore head binding differs")
    return {
        "format": "kedgeflow-cura-native-restore-enrollment-v1",
        "status": "native_guarded_status_passed",
        "first_native_empty_enrollment": first,
        "operator_uid": user.pw_uid,
        "binary_sha256": expected_sha256,
        "head": head,
        "authority_reset_performed": False,
        "same_operator_administers_both_stores": True,
        "independent_custody": "BLOCKED_EXTERNAL_INPUT",
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--enroll-empty", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(enroll(args.binary_sha256, args.enroll_empty), indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__}))
        raise SystemExit(1) from None
