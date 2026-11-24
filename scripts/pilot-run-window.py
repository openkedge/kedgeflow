#!/usr/bin/env python3
"""Render a renewed stop-only window in the existing pilot schedule group.

No AWS calls or starts. Separate approval is required after an earlier approved
window elapses. Reuse the existing exact-fleet stop role/group while retaining
the original window record; create no additional IAM/compute authority.
"""

import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOSTS = (
    "Services",
    "Sql",
    "Identity",
    "Agent",
    "LedgerA",
    "LedgerB",
    "LedgerC",
    "Witness",
    "Audit",
)


def validate_window(values, now):
    fields = {
        "ApprovedAccountId",
        "PilotStopUTC",
        "ExistingLifetimeGroup",
        "ExistingLifetimeRoleArn",
    }
    fields |= {name + "InstanceId" for name in HOSTS}
    if set(values) != fields or not re.fullmatch(r"[0-9]{12}", values["ApprovedAccountId"]):
        raise ValueError("closed account and exact-fleet window inputs required")
    role = (
        r"arn:aws:iam::"
        + values["ApprovedAccountId"]
        + r":role/kedgeflow-cura-pilot-[0-9]{8}-LifetimeRole-[A-Za-z0-9]+"
    )
    if not re.fullmatch(role, values["ExistingLifetimeRoleArn"]) or not re.fullmatch(
        r"kedgeflow-cura-pilot-[0-9]{8}-LifetimeGroup-[A-Za-z0-9]+", values["ExistingLifetimeGroup"]
    ):
        raise ValueError("existing pilot stop-only role and group required")
    ids = [values[n + "InstanceId"] for n in HOSTS]
    if len(set(ids)) != 9 or not all(re.fullmatch(r"i-[a-f0-9]{17}", i) for i in ids):
        raise ValueError("nine distinct exact instance identities required")
    end = datetime.strptime(values["PilotStopUTC"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    if now.tzinfo is None or not now + timedelta(minutes=15) < end <= now + timedelta(hours=24):
        raise ValueError("renewed window must be future and at most 24 hours")
    return end


def template():
    def ref(name):
        return {"Ref": name}

    parameters = {
        "ApprovedAccountId": {"Type": "String", "AllowedPattern": "[0-9]{12}"},
        "PilotStopUTC": {
            "Type": "String",
            "AllowedPattern": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        },
        "ExistingLifetimeGroup": {
            "Type": "String",
            "AllowedPattern": "kedgeflow-cura-pilot-[0-9]{8}-LifetimeGroup-[A-Za-z0-9]+",
        },
        "ExistingLifetimeRoleArn": {
            "Type": "String",
            "AllowedPattern": (
                "arn:aws:iam::[0-9]{12}:role/"
                "kedgeflow-cura-pilot-[0-9]{8}-LifetimeRole-[A-Za-z0-9]+"
            ),
        },
        **{n + "InstanceId": {"Type": "String", "AllowedPattern": "i-[a-f0-9]{17}"} for n in HOSTS},
    }
    # Scheduler at() omits Z; the time zone is separately, explicitly UTC.
    expression = {
        "Fn::Join": [
            "",
            ["at(", {"Fn::Select": [0, {"Fn::Split": ["Z", ref("PilotStopUTC")]}]}, ")"],
        ]
    }
    instance_json = json.dumps({"InstanceIds": ["${" + n + "InstanceId}" for n in HOSTS]})
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Approved renewed Cura stop window; no start or new fleet authority",
        "Parameters": parameters,
        "Rules": {
            name: {
                "Assertions": [
                    {"Assert": {"Fn::Equals": [ref(pseudo), target]}, "AssertDescription": name}
                ]
            }
            for name, pseudo, target in [
                ("ApprovedAccount", "AWS::AccountId", ref("ApprovedAccountId")),
                ("ApprovedRegion", "AWS::Region", "us-west-2"),
            ]
        },
        "Resources": {
            "RenewedStop": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "GroupName": ref("ExistingLifetimeGroup"),
                    "State": "ENABLED",
                    "ScheduleExpression": expression,
                    "ScheduleExpressionTimezone": "UTC",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": "arn:aws:scheduler:::aws-sdk:ec2:stopInstances",
                        "RoleArn": ref("ExistingLifetimeRoleArn"),
                        "Input": {"Fn::Sub": instance_json},
                        "RetryPolicy": {
                            "MaximumEventAgeInSeconds": 3600,
                            "MaximumRetryAttempts": 3,
                        },
                    },
                },
            }
        },
        "Outputs": {"StopUTC": {"Value": ref("PilotStopUTC")}},
        "Metadata": {
            "ExplicitRenewalApprovalRequired": True,
            "CreatesComputeOrIAM": False,
            "StopsOnlyExactFleet": True,
            "IndependentAcceptance": "BLOCKED_EXTERNAL_INPUT",
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as stream:
        json.dump(template(), stream, indent=2)
        stream.write("\n")
