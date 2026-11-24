#!/usr/bin/env python3
"""Render expiring two-host subject-request delivery; no credentials or principals.

Agent sends its signed DPoP proof, Identity retains the client secret and returns
only a short-lived sender-constrained token. Remove both parameters and policies
after the bounded test. Services receives no delivery permission.
"""

import argparse
import json
from pathlib import Path


def template():
    def ref(name):
        return {"Ref": name}

    def arn(name):
        return {
            "Fn::Sub": "arn:${AWS::Partition}:ssm:us-west-2:${AWS::AccountId}:parameter/"
            "kedgeflow/cura/${PilotStackName}/subject-probe/" + name
        }

    resources = {}
    for host in ["Identity", "Agent"]:
        read, write = ("Proof", "Token") if host == "Identity" else ("Token", "Proof")
        time_condition = {"DateLessThan": {"aws:CurrentTime": ref("DeliveryExpiresUTC")}}
        statements = [
            {
                "Effect": "Allow",
                "Action": ["ssm:GetParameter"],
                "Resource": [arn(read)],
                "Condition": time_condition,
            },
            {
                "Effect": "Allow",
                "Action": ["ssm:PutParameter"],
                "Resource": [arn(write)],
                "Condition": time_condition,
            },
        ]
        if host == "Identity":
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": ["ssm:DeleteParameter"],
                    "Resource": [arn("Proof"), arn("Token")],
                    "Condition": time_condition,
                }
            )
        for action, parameter in [("kms:Decrypt", read), ("kms:Encrypt", write)]:
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": action,
                    "Resource": ref("DataKmsKeyArn"),
                    "Condition": {
                        **time_condition,
                        "StringEquals": {
                            "kms:ViaService": "ssm.us-west-2.amazonaws.com",
                            "kms:EncryptionContext:PARAMETER_ARN": arn(parameter),
                        },
                    },
                }
            )
        resources[host + "Delivery"] = {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "PolicyName": "cura-temporary-subject-request",
                "Roles": [ref(host + "RoleName")],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
            },
        }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Expiring exact-host DPoP subject probe delivery; delete after use",
        "Parameters": {
            "ApprovedAccountId": {"Type": "String", "AllowedPattern": "[0-9]{12}"},
            "PilotStackName": {"Type": "String", "AllowedPattern": "kedgeflow-cura-pilot-[0-9]{8}"},
            "DeliveryExpiresUTC": {
                "Type": "String",
                "AllowedPattern": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            },
            "DataKmsKeyArn": {
                "Type": "String",
                "AllowedPattern": "arn:aws:kms:us-west-2:[0-9]{12}:key/[a-zA-Z0-9-]+",
            },
            **{
                host + "RoleName": {
                    "Type": "String",
                    "AllowedPattern": "kedgeflow-cura-pilot-[0-9]{8}-" + host + "Role-[A-Za-z0-9]+",
                }
                for host in ["Identity", "Agent"]
            },
        },
        "Rules": {
            name: {
                "Assertions": [
                    {"Assert": {"Fn::Equals": [ref(pseudo), expected]}, "AssertDescription": name}
                ]
            }
            for name, pseudo, expected in [
                ("ApprovedAccount", "AWS::AccountId", ref("ApprovedAccountId")),
                ("ApprovedRegion", "AWS::Region", "us-west-2"),
            ]
        },
        "Resources": resources,
        "Metadata": {
            "RequiredCleanup": "Remove exact Proof/Token parameters and this stack",
            "ExecutionAuthority": False,
            "IndependentAcceptance": "BLOCKED_EXTERNAL_INPUT",
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    with args.output.open("x") as output:
        json.dump(template(), output, indent=2)
        output.write("\n")
