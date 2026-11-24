"""Enrollment cannot widen workload scope or silently reuse ambiguous registrations."""

import copy
import runpy
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/enroll-cura-spire.py"))
MANIFEST = {
    "format": "kedgeflow-cura-spire-enrollment-v1",
    "pilot_stack": "kedgeflow-cura-pilot-20261117",
    "kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc",
    "nodes": {
        "Services": {
            "instance_id": "i-0123456789abcdef0",
            "user": "kf-gateway",
            "uid": 988,
            "workload": "spiffe://cura.kedgeflow.internal/gateway",
        },
        "Agent": {
            "instance_id": "i-0123456789abcdef1",
            "user": "kf-agent",
            "uid": 969,
            "workload": "spiffe://cura.kedgeflow.internal/agent",
        },
    },
}


def test_closed_node_enrollment_requires_separate_hosts_and_expected_workloads():
    SCRIPT["validate"](MANIFEST)
    for change in ["same-host", "root-uid", "wrong-workload", "extra-node"]:
        m = copy.deepcopy(MANIFEST)
        if change == "same-host":
            m["nodes"]["Agent"]["instance_id"] = m["nodes"]["Services"]["instance_id"]
        elif change == "root-uid":
            m["nodes"]["Agent"]["uid"] = 0
        elif change == "wrong-workload":
            m["nodes"]["Agent"]["workload"] = m["nodes"]["Services"]["workload"]
        else:
            m["nodes"]["Unknown"] = m["nodes"]["Agent"]
        with pytest.raises(ValueError):
            SCRIPT["validate"](m)


def entry():
    node = MANIFEST["nodes"]["Agent"]
    return {
        "spiffe_id": {"trust_domain": "cura.kedgeflow.internal", "path": "/agent"},
        "parent_id": SCRIPT["parent"](node),
        "selectors": [{"type": "unix", "value": "uid:969"}],
    }


def test_registration_reconciliation_refuses_other_parent_or_additional_selector():
    node = MANIFEST["nodes"]["Agent"]
    assert SCRIPT["matching"]([entry()], node)
    assert not SCRIPT["matching"]([], node)
    other = entry()
    other["parent_id"] = SCRIPT["parent"](MANIFEST["nodes"]["Services"])
    with pytest.raises(RuntimeError):
        SCRIPT["matching"]([other], node)
    other = entry()
    other["selectors"].append({"type": "unix", "value": "uid:0"})
    with pytest.raises(RuntimeError):
        SCRIPT["matching"]([other], node)
    with pytest.raises(RuntimeError, match="ambiguous"):
        SCRIPT["matching"]([entry(), entry()], node)


def test_bootstrap_parameter_names_are_individual_not_recursive_secret_trees():
    assert SCRIPT["parameter_name"](MANIFEST, "Agent") == (
        "/kedgeflow/cura/kedgeflow-cura-pilot-20261117/bootstrap/Agent"
    )
    assert SCRIPT["parameter_name"](MANIFEST, "Services") != SCRIPT["parameter_name"](
        MANIFEST, "Agent"
    )


def test_node_uses_vpc_dns_without_opening_loopback_or_metadata():
    base, target = Path("/var/lib/kedgeflow/node"), Path("/etc/kedgeflow-provider/spire-agent")
    unit = SCRIPT["agent_unit"](base, target)
    assert f"BindReadOnlyPaths={target}/resolv.conf:/etc/resolv.conf" in unit
    assert "Environment=GODEBUG=netdns=go" in unit
    assert "IPAddressDeny=any\nIPAddressAllow=10.87.0.0/16" in unit
    assert "IPAddressAllow=localhost" not in unit
    assert "169.254" not in unit and "join-token" not in unit
    original = SCRIPT["agent_unit"](base, target, False)
    assert (
        unit.replace(f"BindReadOnlyPaths={target}/resolv.conf:/etc/resolv.conf\n", "").replace(
            "Environment=GODEBUG=netdns=go\n", ""
        )
        == original
    )


def test_token_created_alias_cannot_be_repurposed_for_admin_or_another_node():
    identity = "spiffe://cura.kedgeflow.internal/spire/agent/join_token/not-a-live-token"
    alias = {
        "spiffe_id": SCRIPT["parent"](MANIFEST["nodes"]["Agent"]),
        "parent_id": identity,
        "selectors": [{"type": "spiffe_id", "value": identity}],
        "admin": False,
        "downstream": False,
        "federates_with": [],
        "dns_names": [],
        "store_svid": False,
    }
    assert SCRIPT["initial_alias"](alias, MANIFEST)
    for field in ["admin", "downstream", "store_svid"]:
        assert not SCRIPT["initial_alias"]({**alias, field: True}, MANIFEST)
    assert not SCRIPT["initial_alias"](
        {**alias, "spiffe_id": MANIFEST["nodes"]["Agent"]["workload"]}, MANIFEST
    )
    assert not SCRIPT["initial_alias"](
        {**alias, "selectors": [{"type": "unix", "value": "uid:0"}]}, MANIFEST
    )


def test_delivery_clock_skew_is_small_and_expired_tokens_still_refuse():
    valid = SCRIPT["delivery_time_valid"]
    assert valid(1002, 1000) and valid(1000, 1000) and valid(1000, 1599)
    assert not valid(1003, 1000) and not valid(1000, 1600)
    assert not valid(True, 1000)
