"""Advisory triage is narrow, expiring and source-bound; it is not owner acceptance."""

import copy
import hashlib
import json
import runpy
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parents[1]
AUDIT = runpy.run_path(str(ROOT / "scripts/audit-dependencies.py"))
TRIAGE = json.loads((ROOT / "config/dependency-advisory-triage.json").read_text())["entries"]
QUERY = {"package": {"ecosystem": "crates.io", "name": "cedar-policy"}, "version": "4.7.1"}
NOW = datetime.fromisoformat("2026-11-12T00:00:00+00:00").timestamp()


def test_cedar_profile_exclusion_requires_unchanged_source_and_regression():
    assert AUDIT["triaged"](QUERY, "GHSA-c33x-vcv4-vg3g", TRIAGE, NOW)
    assert TRIAGE[0]["independent_security_acceptance"] == "BLOCKED_EXTERNAL_INPUT"
    for name, expected in TRIAGE[0]["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected


def test_triage_cannot_be_repurposed_for_another_advisory_or_package():
    changed = copy.deepcopy(TRIAGE)
    changed[0].update(advisory="fake-advisory", package={"ecosystem": "npm", "name": "zod"})
    assert not AUDIT["triaged"](
        {"package": changed[0]["package"], "version": "4.7.1"}, "fake-advisory", changed, NOW
    )
    assert not AUDIT["triaged"]({**QUERY, "version": "4.8.0"}, "GHSA-c33x-vcv4-vg3g", TRIAGE, NOW)


def test_expired_or_changed_source_triage_blocks_release():
    assert not AUDIT["triaged"](QUERY, "GHSA-c33x-vcv4-vg3g", TRIAGE, NOW + 90 * 86400)
    changed = copy.deepcopy(TRIAGE)
    changed[0]["source_sha256"]["crates/kedgeflow/src/policy.rs"] = "0" * 64
    assert not AUDIT["triaged"](QUERY, "GHSA-c33x-vcv4-vg3g", changed, NOW)


MAINTENANCE_QUERY = {"package": {"ecosystem": "crates.io", "name": "chrono"}, "version": "0.4.45"}
MAINTENANCE_DETAIL = {
    "id": "RUSTSEC-2026-0543",
    "summary": "chrono is unmaintained",
    "affected": [
        {
            "package": MAINTENANCE_QUERY["package"],
            "database_specific": {"informational": "unmaintained", "cvss": None},
        }
    ],
}


def maintenance(entries=TRIAGE, detail=MAINTENANCE_DETAIL, now=NOW):
    return AUDIT["maintenance_triaged"](
        MAINTENANCE_QUERY, "RUSTSEC-2026-0543", entries, now, detail
    )


def test_maintenance_debt_is_separate_from_vulnerability_nonreachability():
    assert maintenance()
    assert not AUDIT["triaged"](MAINTENANCE_QUERY, "RUSTSEC-2026-0543", TRIAGE, NOW)
    assert not AUDIT["maintenance_triaged"](
        QUERY, "GHSA-c33x-vcv4-vg3g", TRIAGE, NOW, MAINTENANCE_DETAIL
    )
    assert not AUDIT["maintenance_triaged"](
        {**MAINTENANCE_QUERY, "version": "0.4.46"},
        "RUSTSEC-2026-0543",
        TRIAGE,
        NOW,
        MAINTENANCE_DETAIL,
    )


def test_maintenance_expiry_and_source_changes_fail_closed():
    assert not maintenance(now=datetime.fromisoformat("2026-11-24T00:00:00+00:00").timestamp())
    changed = copy.deepcopy(TRIAGE)
    changed[1]["valid_until"] = "2026-12-12T00:00:00+00:00"
    assert not maintenance(entries=changed)
    changed = copy.deepcopy(TRIAGE)
    changed[1]["source_sha256"]["Cargo.lock"] = "0" * 64
    assert not maintenance(entries=changed)


def test_maintenance_classification_cannot_hide_vulnerability_or_owner_approval():
    for field, value in [("severity", [{"score": "HIGH"}]), ("aliases", ["CVE-2026-test"])]:
        assert not maintenance(detail={**MAINTENANCE_DETAIL, field: value})
    changed = copy.deepcopy(MAINTENANCE_DETAIL)
    changed["affected"][0]["database_specific"]["informational"] = "unsound"
    assert not maintenance(detail=changed)
    changed = copy.deepcopy(TRIAGE)
    changed[1]["independent_security_acceptance"] = "approved"
    assert not maintenance(entries=changed)


def test_protected_runner_makes_implicit_tempdir_parents_private(tmp_path):
    import subprocess
    import sys

    probe = (
        "import os,tempfile; from pathlib import Path; "
        "d=tempfile.TemporaryDirectory(); "
        "print(oct(Path(d.name).stat().st_mode & 0o777)); "
        "print(oct(os.umask(0o077)))"
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/run-protected-tests.py"),
            "--",
            sys.executable,
            "-c",
            probe,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "protected_fixture_umask=0077" in result.stdout
    assert result.stdout.splitlines()[-2:] == ["0o700", "0o77"]
