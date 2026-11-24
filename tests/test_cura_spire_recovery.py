"""Expired node recovery preserves authority history and refuses live-node replacement."""

import base64
import copy
import json
import runpy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).parents[1]
SCRIPT = runpy.run_path(str(ROOT / "scripts/recover-cura-spire.py"))
BASE = runpy.run_path(str(ROOT / "scripts/enroll-cura-spire.py"))
FIXTURE = runpy.run_path(str(ROOT / "tests/test_cura_spire.py"))


def certificate(*, ca, expired=False, domain="spiffe://cura.kedgeflow.internal"):
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "disposable fixture")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(domain)]), False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def state(expired=True):
    return {
        "svid": [base64.b64encode(certificate(ca=False, expired=expired)).decode()],
        "bundle": [base64.b64encode(certificate(ca=True, expired=True)).decode()],
        "reattestable": False,
        "bootstrap_use": 7,
        "bootstrap_start_time": "2026-11-18T00:00:00Z",
        "connection_attempts": 11,
    }


def test_recovery_updates_only_public_cache_and_preserves_expired_svid_and_counters():
    original = state()
    public = certificate(ca=True)
    changed = json.loads(
        SCRIPT["renew_public_cache"](
            json.dumps(original).encode(), public, datetime.now(timezone.utc).timestamp()
        )
    )
    assert changed["bundle"] == [base64.b64encode(public).decode()]
    assert {k: v for k, v in changed.items() if k != "bundle"} == {
        k: v for k, v in original.items() if k != "bundle"
    }


def test_expired_recovery_refuses_live_node_unknown_cache_and_wrong_trust():
    now = datetime.now(timezone.utc).timestamp()
    with pytest.raises(RuntimeError, match="live node"):
        SCRIPT["renew_public_cache"](json.dumps(state(False)).encode(), certificate(ca=True), now)
    for change in [{"extra": True}, {"svid": []}, {"bundle": []}]:
        with pytest.raises(RuntimeError, match="cache differs"):
            SCRIPT["renew_public_cache"](
                json.dumps(state() | change).encode(), certificate(ca=True), now
            )
    for wrong in [
        certificate(ca=False),
        certificate(ca=True, expired=True),
        certificate(ca=True, domain="spiffe://other.invalid"),
    ]:
        with pytest.raises(ValueError):
            SCRIPT["renew_public_cache"](json.dumps(state()).encode(), wrong, now)


def inventory(live=0):
    manifest = FIXTURE["MANIFEST"]
    entries, agents = [], []
    for name, node in manifest["nodes"].items():
        entries.append(
            {
                "spiffe_id": node["workload"],
                "parent_id": BASE["parent"](node),
                "selectors": [{"type": "unix", "value": "uid:" + str(node["uid"])}],
            }
        )
        for i in range(2 if live else 1):
            identity = (
                "spiffe://cura.kedgeflow.internal/spire/agent/join_token/fixture-" + name + str(i)
            )
            entries.append(
                {
                    "spiffe_id": BASE["parent"](node),
                    "parent_id": identity,
                    "selectors": [{"type": "spiffe_id", "value": identity}],
                }
            )
            agents.append(
                {
                    "id": identity,
                    "attestation_type": "join_token",
                    "banned": False,
                    "can_reattest": False,
                    "x509svid_expires_at": str(2000 if i else 500),
                }
            )
    return manifest, entries, agents


def test_closed_recovery_keeps_expired_history_and_exact_workload_selectors():
    manifest, entries, agents = inventory()
    SCRIPT["check_inventory"](BASE, manifest, entries, agents, 1000)
    manifest, entries, agents = inventory(1)
    SCRIPT["check_inventory"](BASE, manifest, entries, agents, 1000, recovered=True)
    for change in ["live-old-node", "wrong-selector", "extra-entry", "missing-history"]:
        e, a = copy.deepcopy(entries), copy.deepcopy(agents)
        if change == "live-old-node":
            a[0]["x509svid_expires_at"] = "2000"
        elif change == "wrong-selector":
            e[0]["selectors"] = [{"type": "unix", "value": "uid:0"}]
        elif change == "extra-entry":
            e.append(copy.deepcopy(e[0]))
        else:
            a.pop(0)
        with pytest.raises(RuntimeError):
            SCRIPT["check_inventory"](BASE, manifest, e, a, 1000, recovered=True)


def test_snapshot_refuses_links_without_following_or_reading_them(tmp_path):
    for name in ["state", "keys", "configuration"]:
        (tmp_path / name).mkdir()
    (tmp_path / ".node-enrollment.json").write_text("{}")
    (tmp_path / "keys/linked-private-key").symlink_to("/must-not-be-read")
    with pytest.raises(RuntimeError, match="refuse links"):
        SCRIPT["archive"](tmp_path, tmp_path / "snapshot.tar")
    assert not (tmp_path / "snapshot.tar").exists()


def test_ubuntu_legacy_certificate_time_accessor_uses_utc():
    class LegacyCertificate:
        not_valid_after = datetime(2026, 11, 23, 8, 0, 0)

    assert (
        SCRIPT["cert_time"](LegacyCertificate(), "not_valid_after")
        == datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc).timestamp()
    )
