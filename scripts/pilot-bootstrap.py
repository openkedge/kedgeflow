#!/usr/bin/env python3
"""Render Cura artifact/key bootstrap; never call AWS or enroll authority."""

import argparse
import json
from pathlib import Path


def template():
    def ref(name):
        return {"Ref": name}

    def sub(value):
        return {"Fn::Sub": value}

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Cura nonproduction artifact/key bootstrap; no runtime authority",
        "Parameters": {
            "ApprovedAccountId": {"Type": "String", "AllowedPattern": "[0-9]{12}"},
            "MonthlyBudgetUsd": {"Type": "Number", "MinValue": 1, "MaxValue": 2000},
            "BudgetEmail": {"Type": "String", "NoEcho": True, "AllowedPattern": "[^@ ]+@[^@ ]+"},
        },
        "Rules": {
            "ApprovedAccount": {
                "Assertions": [
                    {
                        "Assert": {"Fn::Equals": [ref("AWS::AccountId"), ref("ApprovedAccountId")]},
                        "AssertDescription": "Explicit approved nonproduction account only",
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
        "Resources": {
            "DataKey": {
                "Type": "AWS::KMS::Key",
                "DeletionPolicy": "Retain",
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "Description": "Cura nonproduction artifacts and encrypted pilot storage",
                    "EnableKeyRotation": True,
                    "PendingWindowInDays": 30,
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AccountIAMAdministration",
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:root")
                                },
                                "Action": "kms:*",
                                "Resource": "*",
                            }
                        ],
                    },
                    "Tags": [{"Key": "kedgeflow:profile", "Value": "cura"}],
                },
            },
            "DataKeyAlias": {
                "Type": "AWS::KMS::Alias",
                "Properties": {
                    "AliasName": "alias/kedgeflow-cura-pilot",
                    "TargetKeyId": ref("DataKey"),
                },
            },
            "Artifacts": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Retain",
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "VersioningConfiguration": {"Status": "Enabled"},
                    "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    },
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [
                            {
                                "ServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "aws:kms",
                                    "KMSMasterKeyID": {"Fn::GetAtt": ["DataKey", "Arn"]},
                                },
                                "BucketKeyEnabled": True,
                            }
                        ]
                    },
                    "Tags": [{"Key": "kedgeflow:profile", "Value": "cura"}],
                },
            },
            "ArtifactPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": ref("Artifacts"),
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "RequireTLS",
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:*",
                                "Resource": [
                                    {"Fn::GetAtt": ["Artifacts", "Arn"]},
                                    sub("${Artifacts.Arn}/*"),
                                ],
                                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                            }
                        ],
                    },
                },
            },
            "PilotBudget": {
                "Type": "AWS::Budgets::Budget",
                "Properties": {
                    "Budget": {
                        "BudgetName": "kedgeflow-cura-pilot",
                        "BudgetType": "COST",
                        "TimeUnit": "MONTHLY",
                        "BudgetLimit": {"Amount": ref("MonthlyBudgetUsd"), "Unit": "USD"},
                    },
                    # Account-total observations are conservative. This does not
                    # replace the preexisting account budget or claim a hard cap.
                    "NotificationsWithSubscribers": [
                        {
                            "Notification": {
                                "NotificationType": "ACTUAL",
                                "ComparisonOperator": "GREATER_THAN",
                                "ThresholdType": "PERCENTAGE",
                                "Threshold": value,
                            },
                            "Subscribers": [
                                {"SubscriptionType": "EMAIL", "Address": ref("BudgetEmail")}
                            ],
                        }
                        for value in (25, 50, 80, 100)
                    ],
                },
            },
        },
        "Outputs": {
            "DataKeyArn": {"Value": {"Fn::GetAtt": ["DataKey", "Arn"]}},
            "ArtifactBucket": {"Value": ref("Artifacts")},
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as output:
        json.dump(template(), output, indent=2)
        output.write("\n")
