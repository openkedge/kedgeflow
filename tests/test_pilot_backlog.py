"""Missing, stale and truncated retained state cannot become zero unknowns."""

import copy
import json
import runpy
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
MODULE = runpy.run_path(str(ROOT / "scripts/pilot-backlog.py"))


def report():
    return {
        "profile": "KF-SUPERVISION-BACKLOG-0.1-draft",
        "scope": "bounded_retained_observation",
        "checked_at": 100000,
        "elapsed_ms": 10,
        "complete": True,
        "examined": 1,
        "claimed_not_dispatched": 0,
        "unresolved_dispatches": 0,
        "unknown": 1,
        "unknown_oldest_age_ms": 5000,
        "unknown_owner_deadline_exceeded": 1,
        "incidents_open": 1,
        "receipts_pending": 2,
        "production_qualified": False,
        "execution_authority": False,
    }


def test_complete_observation_exports_aggregate_age_deadline_and_backlogs():
    text = MODULE["metrics"](report(), 100001)
    for expected in (
        "kf_unknown_count 1\n",
        "kf_unknown_oldest_age_seconds 5.000\n",
        "kf_unknown_owner_deadline_exceeded 1\n",
        "kf_incident_backlog 1\n",
        "kf_receipt_delivery_backlog 2\n",
        "kf_backlog_observation_complete 1\n",
    ):
        assert expected in text
    assert "{" not in text  # no per-attempt, subject, resource or secret labels


def test_partial_observation_never_exports_zero_global_unknowns():
    r = report()
    r.update(complete=False, unknown=0, unknown_oldest_age_ms=0, unknown_owner_deadline_exceeded=0)
    text = MODULE["metrics"](r, 100001)
    assert "kf_backlog_observation_complete 0\n" in text
    assert "kf_unknown" not in text and "kf_incident_backlog" not in text


@pytest.mark.parametrize(
    "change",
    [
        {"checked_at": 69999},
        {"checked_at": 101001},
        {"checked_at": True},
        {"elapsed_ms": 20001},
        {"complete": 1},
        {"examined": 65},
        {"unknown": -1},
        {"unknown": 0},
        {"unknown_owner_deadline_exceeded": 2},
        {"receipts_pending": 65},
        {"execution_authority": True},
        {"production_qualified": True},
        {"secret": "private"},
    ],
)
def test_malformed_stale_or_authoritative_reports_refuse(change):
    r = copy.deepcopy(report())
    r.update(change)
    with pytest.raises(ValueError):
        MODULE["metrics"](r, 100000)


def test_failed_native_command_publishes_invalid_without_private_diagnostics(monkeypatch):
    def run(*args, **kwargs):
        assert args[0][-2:] == ["--require-managed", "--observe"]
        assert kwargs["timeout"] == 25 and kwargs["env"]["PATH"] == "/usr/bin:/bin"
        return subprocess.CompletedProcess(args[0], 1, b"private-native-output", b"private-token")

    monkeypatch.setattr(subprocess, "run", run)
    text = MODULE["observe"](Path("/bin/kf-supervise"), Path("/config"), Path("/custody"))
    assert text == "kf_backlog_observation_valid 0\n"


def test_atomic_replacement_removes_old_age_values_after_failed_observation(tmp_path):
    tmp_path.chmod(0o750)
    target = tmp_path / "backlog.prom"
    MODULE["publish"](target, MODULE["metrics"](report(), 100000))
    MODULE["publish"](target, "kf_backlog_observation_valid 0\n")
    assert target.read_text() == "kf_backlog_observation_valid 0\n"
    assert list(tmp_path.iterdir()) == [target]
    tmp_path.chmod(0o777)
    with pytest.raises(ValueError, match="protected"):
        MODULE["publish"](target, "unused")


def test_template_keeps_external_owner_thresholds_absent():
    slo = json.loads((ROOT / "deploy/pilot/cura/slo-template.json").read_text())
    assert slo["unknown_owner_deadline_seconds"] is None and slo["owner"] is None
