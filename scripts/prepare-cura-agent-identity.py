#!/usr/bin/env python3
"""Create only the Agent's own proposal/DPoP identity keys; export public pins only.

These keys request authority and prove possession. They are not grant, service,
database writer or acceptance signing credentials. Existing keys never rotate on
rerun; node/service private stores remain inaccessible to this workflow UID.
"""

import argparse
import base64
import hashlib
import json
import os
import pwd
import re
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = Path("/var/lib/kedgeflow/node/workflow")
PINS = BASE.parent / "workflow-identity-pins.json"


def key(path, user):
    if not path.exists() and not path.is_symlink():
        with path.open("xb") as stream:
            stream.write(base64.b64encode(os.urandom(32)))
        os.chown(path, user.pw_uid, user.pw_gid)
        path.chmod(0o400)
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_nlink != 1
        or info.st_uid != user.pw_uid
        or info.st_gid != user.pw_gid
        or info.st_mode & 0o7777 != 0o400
    ):
        raise RuntimeError("Agent identity key custody differs; never replace or repair")
    seed = base64.b64decode(path.read_bytes(), validate=True)
    if len(seed) != 32:
        raise RuntimeError("Agent identity seed length differs")
    return Ed25519PrivateKey.from_private_bytes(seed)


def prepare(instance_id):
    if os.geteuid() != 0 or not re.fullmatch(r"i-[0-9a-f]{17}", instance_id):
        raise RuntimeError("requires privileged exact Agent host launcher")
    token = (
        urllib.request.urlopen(
            urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                method="PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            ),
            timeout=5,
        )
        .read()
        .decode()
    )
    observed = (
        urllib.request.urlopen(
            urllib.request.Request(
                "http://169.254.169.254/latest/meta-data/instance-id",
                headers={"X-aws-ec2-metadata-token": token},
            ),
            timeout=5,
        )
        .read()
        .decode()
    )
    if observed != instance_id or not Path("/run/kedgeflow-spire-agent/agent.sock").is_socket():
        raise RuntimeError("wrong Agent instance or missing enrolled workload API")
    user = pwd.getpwnam("kf-agent")
    if (
        not user.pw_uid
        or user.pw_uid != 969
        or set(os.getgrouplist(user.pw_name, user.pw_gid)) != {user.pw_gid}
    ):
        raise RuntimeError("isolated registered Agent identity required")
    if not BASE.exists():
        BASE.mkdir(mode=0o700)
        os.chown(BASE, user.pw_uid, user.pw_gid)
        BASE.chmod(0o700)
    info = BASE.lstat()
    if (
        BASE.is_symlink()
        or not BASE.is_dir()
        or info.st_uid != user.pw_uid
        or info.st_gid != user.pw_gid
        or info.st_mode & 0o7777 != 0o700
    ):
        raise RuntimeError("Agent workflow custody differs")
    if PINS.exists() and any(not (BASE / name).exists() for name in ["proposal.seed", "dpop.seed"]):
        raise RuntimeError("enrolled Agent key missing; never regenerate implicitly")
    proposal, dpop = key(BASE / "proposal.seed", user), key(BASE / "dpop.seed", user)

    def public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    jwk = {
        "crv": "Ed25519",
        "kty": "OKP",
        "x": base64.urlsafe_b64encode(public(dpop)).rstrip(b"=").decode(),
    }
    thumbprint = (
        base64.urlsafe_b64encode(
            hashlib.sha256(json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    result = {
        "format": "kedgeflow-cura-agent-public-identity-v1",
        "uid": user.pw_uid,
        "workload": "spiffe://cura.kedgeflow.internal/agent",
        "proposal_key_id": "urn:kf:cura:agent-proposal:v1",
        "proposal_public_key_base64": base64.b64encode(public(proposal)).decode(),
        "dpop_public_jwk": jwk,
        "dpop_thumbprint": thumbprint,
        "private_keys_exported": False,
        "service_or_writer_credentials_created": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }
    expected = {
        "instance_id": instance_id,
        **{
            k: result[k]
            for k in [
                "proposal_key_id",
                "proposal_public_key_base64",
                "dpop_public_jwk",
                "dpop_thumbprint",
            ]
        },
    }
    if PINS.exists() or PINS.is_symlink():
        info = PINS.lstat()
        if (
            PINS.is_symlink()
            or not PINS.is_file()
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o7777 != 0o600
            or json.loads(PINS.read_text()) != expected
        ):
            raise RuntimeError(
                "registered Agent public pins changed; explicit reenrollment required"
            )
    else:
        with PINS.open("x") as stream:
            json.dump(expected, stream)
        PINS.chmod(0o600)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-id", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.instance_id), indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__}))
        raise SystemExit(1) from None
