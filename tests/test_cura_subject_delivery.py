"""Least-privilege handoff and actual cryptographic proof/profile refusal checks."""

import base64
import hashlib
import json
import runpy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parents[1]
DELIVERY = runpy.run_path(str(ROOT / "scripts/deliver-cura-subject-request.py"))
PROVIDER = runpy.run_path(str(ROOT / "scripts/probe-cura-subject-provider.py"))
TEMPLATE = runpy.run_path(str(ROOT / "scripts/pilot-subject-delivery.py"))["template"]()


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def jwt(key, header, claims):
    raw = ".".join(encoded(json.dumps(v).encode()) for v in [header, claims])
    return raw + "." + encoded(key.sign(raw.encode()))


def identity():
    key = Ed25519PrivateKey.generate()
    jwk = {
        "crv": "Ed25519",
        "kty": "OKP",
        "x": encoded(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ),
    }
    thumb = encoded(hashlib.sha256(DELIVERY["canonical"](jwk)).digest())
    return key, jwk, thumb


def test_host_roles_cannot_reverse_channels_or_decrypt_another_channel():
    resources = TEMPLATE["Resources"]
    assert all(r["Type"] == "AWS::IAM::Policy" for r in resources.values())
    assert set(resources) == {"IdentityDelivery", "AgentDelivery"}
    statements = resources["AgentDelivery"]["Properties"]["PolicyDocument"]["Statement"]
    ssm = {
        s["Action"][0]: s["Resource"][0]["Fn::Sub"].split("/")[-1]
        for s in statements
        if isinstance(s["Action"], list)
    }
    assert ssm == {"ssm:PutParameter": "Proof", "ssm:GetParameter": "Token"}
    kms = {
        s["Action"]: s["Condition"]["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"][
            "Fn::Sub"
        ].split("/")[-1]
        for s in statements
        if isinstance(s["Action"], str)
    }
    assert kms == {"kms:Encrypt": "Proof", "kms:Decrypt": "Token"}
    for r in resources.values():
        for statement in r["Properties"]["PolicyDocument"]["Statement"]:
            assert statement["Condition"]["DateLessThan"] == {
                "aws:CurrentTime": {"Ref": "DeliveryExpiresUTC"}
            }
            assert "*" not in json.dumps(statement["Resource"])


def test_identity_accepts_only_actual_agent_key_exact_endpoint_and_fresh_closed_proof():
    key, jwk, thumb = identity()
    contract = {"dpopThumbprint": thumb, "subject": {"iss": PROVIDER["ISSUER"]}}
    header = {"alg": "EdDSA", "typ": "dpop+jwt", "jwk": jwk}
    claims = {
        "jti": "unit-request-12345678",
        "htm": "POST",
        "iat": 1000,
        "htu": PROVIDER["ISSUER"] + "/protocol/openid-connect/token",
    }
    DELIVERY["verify_proof"](jwt(key, header, claims), contract, 1000)
    for change in [
        {"htu": "https://unregistered.invalid/token"},
        {"iat": 939},
        {"htm": "GET"},
        {"ath": "not-a-token-request-proof"},
    ]:
        with pytest.raises(RuntimeError):
            DELIVERY["verify_proof"](jwt(key, header, claims | change), contract, 1000)
    other, _, _ = identity()
    with pytest.raises(Exception):
        DELIVERY["verify_proof"](jwt(other, header, claims), contract, 1000)
    with pytest.raises(RuntimeError):
        DELIVERY["verify_proof"](
            jwt(key, header, claims), contract | {"dpopThumbprint": "other"}, 1000
        )


def test_subject_probe_verifies_signature_sender_binding_and_closed_native_scopes():
    key, jwk, thumb = identity()
    header = {"alg": "EdDSA", "typ": "JWT", "kid": "unit-signing-key"}
    claims = {
        "iss": PROVIDER["ISSUER"],
        "sub": "d0b36f01-1188-4f01-907a-000000000001",
        "aud": "urn:kedgeflow:delegated-admission",
        "exp": 1120,
        "iat": 1000,
        "scope": " ".join(sorted(PROVIDER["SCOPES"])),
        "cnf": {"jkt": thumb, "kc-jkt-type": "DPoP"},
        "typ": "DPoP",
        "azp": "kf-pilot-agent",
        "jti": "unit-subject-token",
    }
    keys = {"keys": [jwk | {"kid": header["kid"], "use": "sig", "alg": "EdDSA"}]}
    assert PROVIDER["verify_token"](jwt(key, header, claims), keys, thumb, 1000)[
        "signature_verified"
    ]
    for change in [
        {"exp": 999},
        {"scope": "kf.evidence"},
        {"sub": "another-subject"},
        {"cnf": {"jkt": "other", "kc-jkt-type": "DPoP"}},
        {"extra": True},
    ]:
        with pytest.raises(RuntimeError):
            PROVIDER["verify_token"](jwt(key, header, claims | change), keys, thumb, 1000)


def test_handoff_json_never_silently_discards_duplicate_security_fields():
    for raw in ['{"proof":"first","proof":"second"}', '{"issued_at":1.5}', '{"iat":NaN}']:
        with pytest.raises(ValueError):
            DELIVERY["strict"](raw)
