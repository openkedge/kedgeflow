"""The deliberate expiry drill refuses live application services and unknown tokens."""

import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = runpy.run_path(
    str(Path(__file__).parents[1] / "scripts/probe-cura-credential-lifecycle.py")
)


def test_expiry_drill_cannot_stop_renewal_under_a_live_gateway(tmp_path, monkeypatch):
    (tmp_path / ".host-enrollment.json").write_text(json.dumps({"host": "Services"}))
    check = SCRIPT["check_host"]
    monkeypatch.setitem(check.__globals__, "DATA", tmp_path)
    monkeypatch.setattr(check.__globals__["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(Path, "is_mount", lambda p: p == tmp_path)
    calls = []

    def run(argv, check=True):
        calls.append(argv)
        return SimpleNamespace(returncode=0)

    monkeypatch.setitem(check.__globals__, "run", run)
    with pytest.raises(RuntimeError, match="live application services forbid"):
        check()
    assert calls == [["systemctl", "is-active", "--quiet", "kedgeflow-gateway.service"]]


def test_token_rehearsal_refuses_unregistered_roles_and_topologies_before_opening_material():
    for name in ["root-primary", "control-primary", "gateway-public", "admission-../../secrets"]:
        with pytest.raises(RuntimeError, match="unregistered lifecycle token"):
            SCRIPT["credential_status"](name, "fixture-not-a-real-token")
