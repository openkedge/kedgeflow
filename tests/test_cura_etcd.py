"""Primary and witness storage remain distinct; no recovery reset or broad token scope."""

import base64
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
MEMBER = runpy.run_path(str(ROOT / "scripts/enroll-cura-etcd.py"))
AUTH = runpy.run_path(str(ROOT / "scripts/enroll-cura-ledger-auth.py"))


def test_topology_cannot_mix_primary_members_with_witness_storage():
    primary, witness = MEMBER["specification"]("LedgerA"), MEMBER["specification"]("Witness")
    assert "witness" not in primary["initial_cluster"]
    assert all(n in primary["initial_cluster"] for n in ["ledgera", "ledgerb", "ledgerc"])
    assert witness["initial_cluster"] == "witness=https://witness.cura.kedgeflow.internal:2380"
    assert primary["initial_cluster_token"] != witness["initial_cluster_token"]
    assert primary["data"] != witness["data"] and primary["user"] != witness["user"]
    with pytest.raises(ValueError):
        MEMBER["specification"]("Services")
    unit = MEMBER["unit"](primary, "10.87.1.10")
    assert "--force-new-cluster" not in unit and "--unsafe-no-fsync" not in unit
    assert "--peer-client-cert-auth=true" in unit and "--client-cert-auth=true" in unit
    assert "--listen-client-urls=https://10.87.1.10:2379" in unit
    assert "--auth-token-ttl=300" in unit
    assert "IPAddressAllow=localhost" not in unit
    assert "BindReadOnlyPaths=/etc/kedgeflow/etcd/resolv.conf:/etc/resolv.conf" in unit


def test_ordinary_permissions_cannot_read_or_write_outside_the_pilot_namespace():
    for reader in [True, False]:
        permissions = AUTH["permissions"](reader)
        assert len(permissions) == 1
        p = permissions[0]
        assert base64.b64decode(p["key"]) == b"/kedgeflow/cura/"
        assert base64.b64decode(p["range_end"]) == b"/kedgeflow/cura0"
        assert p["permType"] == ("READ" if reader else "READWRITE")
        assert AUTH["normalize"](permissions) == AUTH["normalize"](
            [{**p, "permType": 0 if reader else 2}]
        )
    with pytest.raises(RuntimeError):
        AUTH["normalize"]([{"permType": "ALL", "key": "AA=="}])
    with pytest.raises(RuntimeError):
        AUTH["normalize"]([{"permType": "READ", "key": "AA==", "unknown": True}])


def test_auth_status_default_false_requires_complete_typed_response():
    response = {"header": {"cluster_id": 1}, "authRevision": 0}
    assert AUTH["auth_enabled"](response) is False
    assert AUTH["auth_enabled"]({**response, "enabled": True}) is True
    for bad in [
        {},
        {"enabled": False},
        {**response, "enabled": None},
        {**response, "enabled": "false"},
        {**response, "authRevision": True},
        {**response, "error": "unavailable"},
    ]:
        with pytest.raises(RuntimeError):
            AUTH["auth_enabled"](bad)
