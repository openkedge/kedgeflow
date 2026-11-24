"""Workload probes verify signatures and purpose rather than trusting decoded claims."""

import base64
import copy
import json
import runpy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/probe-cura-spire.py"))
SUBJECT = "spiffe://cura.kedgeflow.internal/agent"


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def packet(changes=None):
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    jwk = {
        "kid": "fixture-key",
        "use": "jwt-svid",
        "kty": "EC",
        "crv": "P-256",
        "x": b64(public.x.to_bytes(32, "big")),
        "y": b64(public.y.to_bytes(32, "big")),
    }
    claims = {"sub": SUBJECT, "aud": [SCRIPT["AUDIENCE"]], "exp": 1200, "iat": 999}
    claims.update(changes or {})
    raw = ".".join(
        b64(json.dumps(v).encode()) for v in [{"kid": "fixture-key", "alg": "ES256"}, claims]
    )
    r, s = utils.decode_dss_signature(key.sign(raw.encode(), ec.ECDSA(hashes.SHA256())))
    return raw + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big")), {"keys": [jwk]}


def test_actual_probe_rejects_wrong_identity_audience_expiry_and_key_purpose():
    token, bundle = packet()
    assert SCRIPT["verify_jwt"](token, bundle, SUBJECT, 1000)["signature_verified"]
    for changes in [{"sub": SUBJECT + "-other"}, {"aud": ["https://wrong.invalid"]}, {"exp": 999}]:
        token, bundle = packet(changes)
        with pytest.raises(ValueError):
            SCRIPT["verify_jwt"](token, bundle, SUBJECT, 1000)
    token, bundle = packet()
    wrong = copy.deepcopy(bundle)
    wrong["keys"][0]["use"] = "x509-svid"
    with pytest.raises(ValueError):
        SCRIPT["verify_jwt"](token, wrong, SUBJECT, 1000)
    with pytest.raises(Exception):
        SCRIPT["verify_jwt"](token[:-10] + "A" * 10, bundle, SUBJECT, 1000)


def test_probe_refuses_duplicate_or_private_trust_material():
    token, bundle = packet()
    with pytest.raises(ValueError):
        SCRIPT["verify_jwt"](token, {"keys": bundle["keys"] * 2}, SUBJECT, 1000)
    private = copy.deepcopy(bundle)
    private["keys"][0]["d"] = "fixture-private-field-must-refuse"
    with pytest.raises(ValueError):
        SCRIPT["verify_jwt"](token, private, SUBJECT, 1000)
