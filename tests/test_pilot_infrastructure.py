"""Infrastructure, packaging and monitor failures must remain explicit."""

import copy
import hashlib
import json
import runpy
import shlex
import struct
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
IAC = runpy.run_path(str(ROOT / "scripts/pilot-infrastructure.py"))
STAGE = runpy.run_path(str(ROOT / "scripts/stage-pilot-release.py"))
BUILD = runpy.run_path(str(ROOT / "scripts/package-linux.py"))
MONITOR = runpy.run_path(str(ROOT / "scripts/pilot-monitor.py"))
PROVENANCE = runpy.run_path(str(ROOT / "scripts/release-provenance.py"))
JUNIT = runpy.run_path(str(ROOT / "scripts/verify-test-results.py"))
PREFLIGHT = runpy.run_path(str(ROOT / "scripts/preflight-sql-pilot.py"))


def test_pilot_preflight_checks_the_binary_installed_by_each_service_unit():
    for role, binary in PREFLIGHT["ROLES"].items():
        name = "restore-status" if role == "operator" else role
        unit = ROOT / "deploy/linux/systemd" / f"kedgeflow-{name}.service"
        commands = [
            line.removeprefix("ExecStart=")
            for line in unit.read_text().splitlines()
            if line.startswith("ExecStart=")
        ]
        assert len(commands) == 1
        assert Path(shlex.split(commands[0])[0]).name == binary


def test_aws_infrastructure_has_no_public_routes_secrets_or_database_tcp():
    template = IAC["template"]()
    assert template == json.loads((ROOT / "deploy/pilot/cura/infrastructure-v1.json").read_text())
    resources = template["Resources"]
    assert not any(
        r["Type"]
        in {
            "AWS::EC2::InternetGateway",
            "AWS::EC2::NatGateway",
            "AWS::EC2::VPCPeeringConnection",
            "AWS::EC2::Route",
        }
        for r in resources.values()
    )
    hosts = [r["Properties"] for r in resources.values() if r["Type"] == "AWS::EC2::Instance"]
    assert len(hosts) == 9
    assert all(h["MetadataOptions"]["HttpTokens"] == "required" for h in hosts)
    assert all("KeyName" not in h and "UserData" not in h for h in hosts)
    assert all(h["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] for h in hosts)
    assert not any(r["Properties"].get("FromPort") in (22, 5432) for r in resources.values())
    for resource in resources.values():
        if resource["Type"] == "AWS::EC2::SecurityGroup":
            assert resource["Properties"]["SecurityGroupEgress"] == [
                {"IpProtocol": "-1", "CidrIp": "127.0.0.1/32"}
            ]
        if resource["Type"] == "AWS::EC2::Volume":
            assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
        if resource["Type"] == "AWS::IAM::Role":
            actions = resource["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0][
                "Action"
            ]
            assert not any(
                a.startswith(("kms:", "s3:", "secretsmanager:", "ec2:", "iam:"))
                or a == "sts:AssumeRole"
                for a in actions
            )
    assert "Default" not in template["Parameters"]["ApprovedAccountId"]
    assert "Default" not in template["Parameters"]["MonthlyBudgetUsd"]


def test_staging_requires_external_hash_and_never_overwrites(tmp_path):
    binaries = tmp_path / "bins"
    binaries.mkdir()
    raw = bytearray(64)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 3, 183, 1)
    for name in BUILD["BINARIES"]:
        (binaries / name).write_bytes(raw)
    bundle = BUILD["package"](binaries, tmp_path / "packages", 123)
    out = tmp_path / "staged"
    with pytest.raises(ValueError, match="digest"):
        STAGE["stage"](bundle, "0" * 64, out)
    assert not out.exists()
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    report = STAGE["stage"](bundle, digest, out)
    assert not report["services_started"] and not report["production_qualified"]
    with pytest.raises(FileExistsError):
        STAGE["stage"](bundle, digest, out)
    assert json.loads((out / "staging.json").read_text()) == report
    provenance = tmp_path / "provenance"
    record = PROVENANCE["collect"](bundle, digest, provenance)
    assert record["state"] == "draft_unsigned_unreproduced"
    sbom = json.loads((provenance / "sbom.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX"
    assert len(sbom["components"]) > 100
    assert all(c["properties"][0]["value"] == "unreviewed" for c in sbom["components"])
    assert any(c["purl"].startswith("pkg:npm/%40") for c in sbom["components"])
    tracked = tmp_path / "tracked-provenance"
    PROVENANCE["collect"](bundle, digest, tracked, tracked_only=True)
    pinned = json.loads((tracked / "provenance.json").read_text())
    assert pinned["source_inventory"] == "tracked_checkout"
    assert "Cargo.lock" in pinned["source_sha256"]
    assert not any(name.startswith("ci-evidence/") for name in pinned["source_sha256"])


def report():
    return {
        "profile": "KF-SERVICE-READINESS-0.1-draft",
        "role": "control",
        "scope": "local_prerequisites",
        "checked_at": 100000,
        "elapsed_ms": 1,
        "ready": True,
        "execution_authority": False,
        "checks": [
            {"dependency": "authority_reads", "condition": "ready"},
            {"dependency": "managed_control", "condition": "ready"},
        ],
    }


def test_monitor_validates_fresh_complete_report_and_typed_refusal():
    r = report()
    assert MONITOR["validate_report"](r, "control", 200, "no-store", 100000)
    r["ready"] = False
    r["checks"][0]["condition"] = "unavailable"
    assert MONITOR["validate_report"](r, "control", 503, "no-store", 100000)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(checked_at=89999),
        lambda r: r.update(checked_at=101001),
        lambda r: r.update(role="gateway"),
        lambda r: r.update(execution_authority=True),
        lambda r: r.update(checks=[]),
        lambda r: r["checks"].append(copy.deepcopy(r["checks"][0])),
        lambda r: r["checks"][0].update(condition="unavailable"),
        lambda r: r["checks"].pop(),
        lambda r: r.update(checked_at=True),
    ],
)
def test_monitor_never_reports_false_healthy_for_changed_or_incomplete_report(mutation):
    r = report()
    mutation(r)
    assert not MONITOR["validate_report"](r, "control", 200, "no-store", 100000)


@pytest.mark.parametrize(
    "body",
    [
        "<testsuite/>",
        "<testsuite><testcase><skipped/></testcase></testsuite>",
        "<testsuite><testcase><failure/></testcase></testsuite>",
        "<testsuite><testcase><error/></testcase></testsuite>",
    ],
)
def test_required_junit_never_accepts_empty_skipped_or_failed_tests(tmp_path, body):
    path = tmp_path / "report.xml"
    path.write_text(body)
    with pytest.raises(ValueError):
        JUNIT["verify"](path)


def test_required_junit_counts_only_passed_cases(tmp_path):
    path = tmp_path / "report.xml"
    path.write_text("<testsuites><testsuite><testcase/><testcase/></testsuite></testsuites>")
    assert JUNIT["verify"](path) == 2
