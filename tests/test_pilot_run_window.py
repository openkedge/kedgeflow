"""An expired pilot needs a new bounded stop-only schedule, never start/IAM authority."""

import copy
import json
import runpy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/pilot-run-window.py"))
NOW = datetime(2026, 11, 22, 9, tzinfo=timezone.utc)


def inputs():
    return {
        "ApprovedAccountId": "123456789012",
        "PilotStopUTC": "2026-11-23T09:00:00Z",
        "ExistingLifetimeGroup": "kedgeflow-cura-pilot-20261117-LifetimeGroup-Abc",
        "ExistingLifetimeRoleArn": (
            "arn:aws:iam::123456789012:role/kedgeflow-cura-pilot-20261117-LifetimeRole-Abc"
        ),
        **{name + "InstanceId": "i-" + f"{i:017x}" for i, name in enumerate(SCRIPT["HOSTS"], 1)},
    }


def test_renewal_reuses_existing_stop_role_and_group_without_compute_or_iam():
    template = SCRIPT["template"]()
    assert len(template["Resources"]) == 1
    resource = template["Resources"]["RenewedStop"]
    assert resource["Type"] == "AWS::Scheduler::Schedule"
    p = resource["Properties"]
    assert p["GroupName"] == {"Ref": "ExistingLifetimeGroup"}
    assert p["Target"]["RoleArn"] == {"Ref": "ExistingLifetimeRoleArn"}
    assert p["Target"]["Arn"] == "arn:aws:scheduler:::aws-sdk:ec2:stopInstances"
    assert len(json.loads(p["Target"]["Input"]["Fn::Sub"])["InstanceIds"]) == 9
    assert "ActionAfterCompletion" not in p
    assert p["ScheduleExpressionTimezone"] == "UTC"
    assert not any("Default" in v for v in template["Parameters"].values())
    assert template["Metadata"]["ExplicitRenewalApprovalRequired"] is True


def test_window_refuses_late_past_duplicate_instances_and_foreign_account_roles():
    assert SCRIPT["validate_window"](inputs(), NOW) == NOW + timedelta(hours=24)
    for delta in [timedelta(0), timedelta(minutes=15), timedelta(hours=24, seconds=1)]:
        value = inputs()
        value["PilotStopUTC"] = (NOW + delta).strftime("%Y-%m-%dT%H:%M:%SZ")
        with pytest.raises(ValueError):
            SCRIPT["validate_window"](value, NOW)
    for field, value in [
        ("AgentInstanceId", inputs()["ServicesInstanceId"]),
        (
            "ExistingLifetimeRoleArn",
            inputs()["ExistingLifetimeRoleArn"].replace("123456789012", "123456789013"),
        ),
        ("extra", "not-approved"),
    ]:
        values = copy.deepcopy(inputs())
        values[field] = value
        with pytest.raises(ValueError):
            SCRIPT["validate_window"](values, NOW)
