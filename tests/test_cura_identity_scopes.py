"""Scope enrollment cannot repurpose a browser/public client or a private key set."""

import copy
import runpy
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/enroll-cura-identity-scopes.py"))


def test_sql_scope_enrollment_requires_the_existing_confidential_dpop_client():
    client = {
        "id": "d0b36f01-1188-4f01-907a-000000000002",
        "clientId": "kf-pilot-agent",
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "attributes": {
            "dpop.bound.access.tokens": "true",
            "access.token.signed.response.alg": "EdDSA",
        },
    }
    assert SCRIPT["enrolled_client"](client) == client["id"]
    for field, value in [
        ("clientId", "admin-cli"),
        ("publicClient", True),
        ("serviceAccountsEnabled", False),
        ("standardFlowEnabled", True),
        ("directAccessGrantsEnabled", True),
        ("attributes", {}),
    ]:
        bad = copy.deepcopy(client)
        bad[field] = value
        with pytest.raises(RuntimeError, match="client contract differs"):
            SCRIPT["enrolled_client"](bad)
    assert SCRIPT["SCOPES"] == {
        "reservation:request",
        "kf.admit",
        "kf.issue",
        "kf.status",
        "kf.evidence",
    }


def test_issuer_continuity_refuses_private_key_material():
    assert SCRIPT["public_keys"]({"keys": [{"kid": "fixture-public", "kty": "OKP"}]})
    for key in [{"kid": "fixture", "d": "fixture-private"}, {"kty": "oct", "k": "fixture-private"}]:
        with pytest.raises(RuntimeError):
            SCRIPT["public_keys"]({"keys": [key]})


def test_first_eddsa_initialization_cannot_hide_scope_change_or_existing_key_replacement():
    prior = {
        "keys": [
            {"kid": "rsa-encryption", "kty": "RSA", "use": "enc"},
            {"kid": "rsa-signature", "kty": "RSA", "use": "sig"},
        ]
    }
    added = {"kid": "first-ed25519", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig"}
    current = {"keys": [*prior["keys"], added]}
    old = {
        "scopes": sorted(SCRIPT["SCOPES"]),
        "issuer_public_key_ids": sorted(k["kid"] for k in prior["keys"]),
    }
    new = old | {"issuer_public_key_ids": sorted(k["kid"] for k in current["keys"])}
    assert SCRIPT["initial_signing_key"](old, new, prior, current) == added["kid"]
    for change, keys in [
        (new | {"scopes": ["wider"]}, current),
        (new, {"keys": [prior["keys"][0], prior["keys"][1] | {"n": "changed"}, added]}),
        (new, {"keys": [*prior["keys"], added | {"alg": "RS256"}]}),
    ]:
        with pytest.raises(RuntimeError):
            SCRIPT["initial_signing_key"](old, change, prior, keys)
