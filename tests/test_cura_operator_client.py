"""Technical governance enrollment must not borrow Agent or acceptance authority."""

import copy
import runpy
from pathlib import Path

import pytest

MODULE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/enroll-cura-operator-client.py"))


def definition():
    return MODULE["client_definition"]("f139430b-9574-40ec-9a6c-ef4432452b2c", "test-only")


def test_operator_client_cannot_use_browser_password_or_unconstrained_tokens():
    expected = definition()
    MODULE["require_client"](expected, expected)
    for field in [
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "publicClient",
        "fullScopeAllowed",
    ]:
        changed = copy.deepcopy(expected)
        changed[field] = True
        with pytest.raises(RuntimeError):
            MODULE["require_client"](changed, expected)
    for field in [
        "dpop.bound.access.tokens",
        "access.token.signed.response.alg",
        "access.token.lifespan",
    ]:
        changed = copy.deepcopy(expected)
        changed["attributes"][field] = "unexpected"
        with pytest.raises(RuntimeError):
            MODULE["require_client"](changed, expected)


def test_operator_is_distinct_and_has_only_fixed_governance_scopes():
    assert MODULE["CLIENT"] == "kf-pilot-operator"
    assert MODULE["SCOPES"] == {
        "kf.publish_policy",
        "kf.register_descriptor",
        "kf.install",
        "kf.revoke",
        "kf.query",
    }
    assert not MODULE["SCOPES"] & {"reservation:request", "kf.admit", "kf.issue", "kf.evidence"}
    expected = definition()
    for field, value in [("clientId", "kf-pilot-agent"), ("id", "other-client")]:
        changed = {**expected, field: value}
        with pytest.raises(RuntimeError):
            MODULE["require_client"](changed, expected)


def test_claim_mappers_cannot_add_roles_or_change_audience():
    expected = definition()
    changed = copy.deepcopy(expected)
    changed["protocolMappers"][0]["config"]["included.custom.audience"] = "other-audience"
    with pytest.raises(RuntimeError):
        MODULE["require_client"](changed, expected)
    changed = copy.deepcopy(expected)
    changed["protocolMappers"].append({"protocolMapper": "oidc-usermodel-realm-role-mapper"})
    with pytest.raises(RuntimeError):
        MODULE["require_client"](changed, expected)


def test_protected_intent_rejects_links_and_different_existing_material(tmp_path):
    path = tmp_path / "intent.json"
    MODULE["write_once"](path, b"original", 0o600)
    with pytest.raises(RuntimeError):
        MODULE["write_once"](path, b"replacement", 0o600)
    assert path.read_bytes() == b"original"
    target = tmp_path / "link"
    target.symlink_to(path)
    with pytest.raises(RuntimeError):
        MODULE["protected"](target, 0o600)
