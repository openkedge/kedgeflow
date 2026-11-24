#!/usr/bin/env python3
"""Render temporary, exact-parameter SPIRE bootstrap delivery grants; no secrets.

Delete this auxiliary stack and its two SecureStrings after node enrollment.
It modifies no duty-role trust and creates no identity or acceptance authority.
"""

import argparse
import json
from pathlib import Path


def ref(name):
    return {"Ref": name}


def sub(value):
    return {"Fn::Sub": value}


def parameter_arn(node):
    return sub(
        "arn:${AWS::Partition}:ssm:us-west-2:${AWS::AccountId}:parameter/"
        "kedgeflow/cura/${PilotStackName}/bootstrap/" + node
    )


def template():
    resources = {}
    for node in ("Identity", "Services", "Agent"):
        arns = (
            [parameter_arn(n) for n in ("Services", "Agent")]
            if node == "Identity"
            else [parameter_arn(node)]
        )
        actions = (
            ["ssm:PutParameter", "ssm:DeleteParameter"]
            if node == "Identity"
            else ["ssm:GetParameter"]
        )
        resources[node + "Bridge"] = {
            "Type": "AWS::IAM::Policy",
            "Properties": {
                "PolicyName": "cura-temporary-node-bootstrap",
                "Roles": [ref(node + "RoleName")],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": actions,
                            "Resource": arns,
                            "Condition": {
                                "DateLessThan": {"aws:CurrentTime": ref("BootstrapExpiresUTC")}
                            },
                        },
                        {
                            "Effect": "Allow",
                            "Action": "kms:Encrypt" if node == "Identity" else "kms:Decrypt",
                            "Resource": ref("DataKmsKeyArn"),
                            "Condition": {
                                "DateLessThan": {"aws:CurrentTime": ref("BootstrapExpiresUTC")},
                                "StringEquals": {
                                    "kms:ViaService": "ssm.us-west-2.amazonaws.com",
                                    "kms:EncryptionContext:PARAMETER_ARN": arns,
                                },
                            },
                        },
                    ],
                },
            },
        }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Temporary Cura node bootstrap; delete grants after enrollment",
        "Parameters": {
            "ApprovedAccountId": {"Type": "String", "AllowedPattern": "[0-9]{12}"},
            "PilotStackName": {"Type": "String", "AllowedPattern": "kedgeflow-cura-pilot-[0-9]{8}"},
            "BootstrapExpiresUTC": {
                "Type": "String",
                "AllowedPattern": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                "Description": "Explicit short expiry within the approved pilot window",
            },
            "DataKmsKeyArn": {
                "Type": "String",
                "AllowedPattern": "arn:aws:kms:us-west-2:[0-9]{12}:key/[a-zA-Z0-9-]+",
            },
            **{
                node + "RoleName": {
                    "Type": "String",
                    "AllowedPattern": "kedgeflow-cura-pilot-[0-9]{8}-" + node + "Role-[A-Za-z0-9]+",
                }
                for node in ("Identity", "Services", "Agent")
            },
        },
        "Rules": {
            "ApprovedAccount": {
                "Assertions": [
                    {
                        "Assert": {"Fn::Equals": [ref("AWS::AccountId"), ref("ApprovedAccountId")]},
                        "AssertDescription": "Approved account only",
                    }
                ]
            },
            "ApprovedRegion": {
                "Assertions": [
                    {
                        "Assert": {"Fn::Equals": [ref("AWS::Region"), "us-west-2"]},
                        "AssertDescription": "us-west-2 only",
                    }
                ]
            },
        },
        "Resources": resources,
        "Metadata": {
            "Purpose": "One-time node enrollment; generated tokens stay in protected cloud storage",
            "RequiredCleanup": "Delete both parameters and this stack after node enrollment",
            "IndependentAcceptance": "BLOCKED_EXTERNAL_INPUT",
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as output:
        json.dump(template(), output, indent=2)
        output.write("\n")
