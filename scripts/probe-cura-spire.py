#!/usr/bin/env python3
"""Probe actual registered-UID JWT/X509 issuance; output public claims and booleans only."""

import argparse
import base64
import json
import os
import pwd
import re
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtensionOID

AGENT = "/opt/kedgeflow/runtime/spire/bin/spire-agent"
SOCKET = "/run/kedgeflow-spire-agent/agent.sock"
AUDIENCE = "https://services.cura.kedgeflow.internal:8448/token"


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=20)


def verify_jwt(token, public_bundle, expected_subject, now):
    if any(set(key) & {"d", "p", "q", "dp", "dq", "qi", "k"} for key in public_bundle["keys"]):
        raise ValueError("public bundle contains private fields")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("ambiguous issued JWT")
    header, claims = (json.loads(decode(p)) for p in parts[:2])
    keys = [k for k in public_bundle["keys"] if k.get("kid") == header.get("kid")]
    if (
        len(keys) != 1
        or header.get("alg") != "ES256"
        or not isinstance(header.get("kid"), str)
        or not header["kid"]
    ):
        raise ValueError("actual issuer key unavailable in pinned public bundle")
    key = keys[0]
    if key.get("kty") != "EC" or key.get("crv") != "P-256" or key.get("use") != "jwt-svid":
        raise ValueError("unexpected workload signing algorithm")
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(decode(key["x"]), "big"),
        int.from_bytes(decode(key["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    signature = decode(parts[2])
    if len(signature) != 64:
        raise ValueError("unexpected signature shape")
    signature = utils.encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    public.verify(signature, (parts[0] + "." + parts[1]).encode(), ec.ECDSA(hashes.SHA256()))
    audience = claims.get("aud")
    if isinstance(audience, str):
        audience = [audience]
    if (
        claims.get("sub") != expected_subject
        or audience != [AUDIENCE]
        or type(claims.get("exp")) is not int
        or claims["exp"] <= now
        or claims.get("iat", now) > now + 2
        or claims.get("nbf", now) > now + 2
    ):
        raise ValueError("issued workload claims do not match the exact profile")
    return {
        "algorithm": header["alg"],
        "issuer_key_id": header["kid"],
        "subject": expected_subject,
        "audience": AUDIENCE,
        "remaining_seconds": claims["exp"] - now,
        "signature_verified": True,
    }


def probe(manifest, name, bundle, ca_file):
    if os.geteuid() != 0:
        raise RuntimeError("requires privileged read-only launcher")
    node = manifest["nodes"][name]
    user = pwd.getpwnam(node["user"])
    if user.pw_uid != node["uid"]:
        raise RuntimeError("registered UID differs")
    args = ["api", "fetch", "jwt", "-socketPath", SOCKET, "-timeout", "5s", "-audience", AUDIENCE]
    positive = run(["runuser", "-u", user.pw_name, "--", AGENT, *args])
    tokens = re.findall(
        r"\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{40,})\b", positive.stdout
    )
    if positive.returncode or len(tokens) != 1:
        raise RuntimeError("registered UID workload issuance refused or ambiguous")
    claims = verify_jwt(tokens[0], bundle, node["workload"], int(time.time()))
    negative_user = "kf-gateway" if name == "Agent" else "kf-agent"
    negative = run(["runuser", "-u", negative_user, "--", AGENT, *args])
    if negative.returncode == 0:
        raise RuntimeError("cross-host unregistered UID unexpectedly obtained workload credential")
    with tempfile.TemporaryDirectory(prefix="kf-cura-x509-", dir="/run") as temporary:
        destination = Path(temporary)
        os.chown(destination, user.pw_uid, user.pw_gid)
        destination.chmod(0o700)
        fetched = run(
            [
                "runuser",
                "-u",
                user.pw_name,
                "--",
                AGENT,
                "api",
                "fetch",
                "x509",
                "-socketPath",
                SOCKET,
                "-timeout",
                "5s",
                "-silent",
                "-write",
                temporary,
            ]
        )
        if fetched.returncode:
            raise RuntimeError("registered UID X509 issuance refused")
        leaves = []
        private_files = []
        for path in destination.iterdir():
            if "key" in path.name:
                private_files.append(path)
                info = path.lstat()
                if path.is_symlink() or info.st_uid != user.pw_uid or info.st_mode & 0o077:
                    raise RuntimeError("generated workload key custody rejected")
            elif path.suffix == ".pem":
                for certificate in x509.load_pem_x509_certificates(path.read_bytes()):
                    try:
                        uris = certificate.extensions.get_extension_for_oid(
                            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        ).value.get_values_for_type(x509.UniformResourceIdentifier)
                    except x509.ExtensionNotFound:
                        continue
                    if uris == [node["workload"]]:
                        leaves.append(path)
        if len(set(leaves)) != 1 or not private_files:
            raise RuntimeError("X509 identity or private-key output ambiguous")
        certificate = next(iter(set(leaves)))
        verified = run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca_file),
                "-untrusted",
                str(certificate),
                str(certificate),
            ]
        )
        if verified.returncode:
            raise RuntimeError("actual X509 certificate does not chain to pinned SPIRE root")
        x509_verified = True
    base = Path(
        "/var/lib/kedgeflow/pilot/spire-agent" if name == "Services" else "/var/lib/kedgeflow/node"
    )
    if run(["runuser", "-u", user.pw_name, "--", "test", "-r", str(base / "keys")]).returncode == 0:
        raise RuntimeError("workload can read privileged node keys")
    if (
        run(
            [
                "runuser",
                "-u",
                user.pw_name,
                "--",
                "test",
                "-r",
                str(base / "configuration/join-token"),
            ]
        ).returncode
        == 0
    ):
        raise RuntimeError("workload can read node bootstrap token")
    return {
        "format": "kedgeflow-cura-spire-uid-probe-v1",
        "status": "passed_actual_issuance_checks",
        "node": name,
        "registered_uid": user.pw_uid,
        "jwt": claims,
        "x509_chain_and_uri_verified": x509_verified,
        "generated_workload_keys_owner_only": True,
        "node_keys_denied_to_workload": True,
        "bootstrap_token_denied_to_workload": True,
        "cross_host_unregistered_uid_refused": True,
        "tokens_or_private_keys_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--node", choices=["Services", "Agent"], required=True)
    parser.add_argument("--public-bundle", type=Path, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                probe(
                    json.loads(args.manifest.read_text()),
                    args.node,
                    json.loads(args.public_bundle.read_text()),
                    args.ca,
                ),
                indent=2,
            )
        )
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__}))
        raise SystemExit(1) from None
