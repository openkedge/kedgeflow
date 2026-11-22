#!/usr/bin/env python3
"""Mint/verify one actual ephemeral DPoP subject probe; never export credentials.

The proof key exists only in Identity process memory. This is not Agent delivery
or execution authority. Keycloak may initialize its configured EdDSA signing key
on first use; prior public keys and all provider storage remain in place.
"""

import base64
import hashlib
import json
import os
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DATA = Path("/var/lib/kedgeflow/pilot")
ISSUER = "https://identity.cura.kedgeflow.internal:8443/realms/kedgeflow-pilot"
SCOPES = {"reservation:request", "kf.admit", "kf.issue", "kf.status", "kf.evidence"}
PHASE = "protected_provider_preconditions"


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode(raw):
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def protected(path):
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != 0o400
        or info.st_size > 4096
    ):
        raise RuntimeError("protected client credential required")
    return path.read_text().strip()


def verify_token(token, jwks, thumbprint, now):
    if len(token) > 16 << 10 or len(token.split(".")) != 3:
        raise RuntimeError("bounded subject token required")
    h, c, s = token.split(".")
    header, claims = json.loads(decode(h)), json.loads(decode(c))
    if (
        set(header) != {"alg", "typ", "kid"}
        or header["alg"] != "EdDSA"
        or header["typ"] != "JWT"
        or set(claims) != {"iss", "sub", "aud", "exp", "iat", "scope", "cnf", "typ", "azp", "jti"}
    ):
        raise RuntimeError("closed native subject profile differs")
    keys = [k for k in jwks["keys"] if k.get("kid") == header["kid"]]
    if len(keys) != 1 or any(set(k) & {"d", "p", "q", "dp", "dq", "qi", "k"} for k in jwks["keys"]):
        raise RuntimeError("unambiguous public issuer required")
    key = keys[0]
    if (
        key.get("alg") != "EdDSA"
        or key.get("kty") != "OKP"
        or key.get("crv") != "Ed25519"
        or key.get("use") != "sig"
    ):
        raise RuntimeError("configured Ed25519 subject issuer differs")
    Ed25519PublicKey.from_public_bytes(decode(key["x"])).verify(decode(s), (h + "." + c).encode())
    scopes = claims["scope"].split()
    if (
        claims["iss"] != ISSUER
        or claims["sub"] != "d0b36f01-1188-4f01-907a-000000000001"
        or claims["aud"] != "urn:kedgeflow:delegated-admission"
        or claims["typ"] != "DPoP"
        or claims["azp"] != "kf-pilot-agent"
        or not claims["jti"]
        or claims["cnf"] != {"jkt": thumbprint, "kc-jkt-type": "DPoP"}
        or len(scopes) != len(SCOPES)
        or set(scopes) != SCOPES
        or type(claims["exp"]) is not int
        or type(claims["iat"]) is not int
        or claims["iat"] > now + 5
        or claims["iat"] >= claims["exp"]
        or claims["exp"] <= now
        or claims["exp"] - now > 300
    ):
        raise RuntimeError("actual subject claims differ")
    return {
        "algorithm": header["alg"],
        "key_id": header["kid"],
        "subject": {"iss": claims["iss"], "sub": claims["sub"]},
        "audience": claims["aud"],
        "scopes": sorted(scopes),
        "remaining_seconds": claims["exp"] - now,
        "signature_verified": True,
        "dpop_confirmation_verified": True,
        "closed_native_claim_profile_verified": True,
    }


def probe():
    global PHASE
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Identity"
    ):
        raise RuntimeError("requires retained Identity host")
    context = ssl.create_default_context(cafile="/etc/kedgeflow-provider/keycloak/ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    def request(url, body=None, proof=None):
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else {}
        if proof:
            headers["DPoP"] = proof
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, data=body, headers=headers), context=context, timeout=10
            ) as response:
                raw = response.read((1 << 20) + 1)
                if len(raw) > 1 << 20:
                    raise RuntimeError("provider response exceeded bound")
                return json.loads(raw)
        except urllib.error.HTTPError:
            raise RuntimeError("protected subject provider refused") from None

    before = request(ISSUER + "/protocol/openid-connect/certs")
    key = Ed25519PrivateKey.generate()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ),
    }
    thumbprint = b64(
        hashlib.sha256(json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()).digest()
    )
    endpoint = ISSUER + "/protocol/openid-connect/token"
    unsigned = ".".join(
        b64(json.dumps(v, separators=(",", ":")).encode())
        for v in [
            {"alg": "EdDSA", "typ": "dpop+jwt", "jwk": jwk},
            {"jti": secrets.token_hex(16), "htm": "POST", "htu": endpoint, "iat": int(time.time())},
        ]
    )
    proof = unsigned + "." + b64(key.sign(unsigned.encode()))
    form = {
        "grant_type": "client_credentials",
        "client_id": "kf-pilot-agent",
        "client_secret": protected(DATA / "configuration/identity-operator/agent-client-secret"),
        "scope": " ".join(sorted(SCOPES)),
    }
    PHASE = "actual_protected_subject_issuance"
    issued = request(endpoint, urllib.parse.urlencode(form).encode(), proof)
    if issued["token_type"].lower() != "dpop":
        raise RuntimeError("sender constrained subject required")
    PHASE = "actual_signature_and_closed_claim_verification"
    after = request(ISSUER + "/protocol/openid-connect/certs")
    verified = verify_token(issued["access_token"], after, thumbprint, int(time.time()))
    if not all(k in after["keys"] for k in before["keys"]):
        raise RuntimeError("prior public issuer history changed")
    return {
        "format": "kedgeflow-cura-subject-provider-probe-v1",
        "status": "actual_subject_probe_passed",
        "verified": verified,
        "prior_public_keys_preserved": True,
        "public_keys_added_on_first_signing": len(after["keys"]) - len(before["keys"]),
        "public_jwks": after,
        "ephemeral_probe_key_persisted": False,
        "agent_request_credentials_issued": False,
        "credentials_returned": False,
        "execution_authority": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(probe()))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
