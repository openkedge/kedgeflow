#!/usr/bin/env python3
"""Render unassigned acceptance IAM roles and segregated custody stores, not approvals."""

import argparse
import json
from pathlib import Path

DUTIES = {
    "Deployment": "deployment",
    "IdentitySecurity": "identity-security",
    "Resource": "resource",
    "Storage": "storage",
    "Audit": "audit",
    "Sre": "sre",
    "IndependentReproducer": "independent-reproducer",
}


def ref(name):
    return {"Ref": name}


def sub(value):
    return {"Fn::Sub": value}


def template():
    resources = {}
    for logical, duty in DUTIES.items():
        statements = [
            {
                "Effect": "Allow",
                "Action": ["cloudformation:DescribeStacks", "cloudformation:ListStackResources"],
                "Resource": sub(
                    "arn:${AWS::Partition}:cloudformation:us-west-2:${AWS::AccountId}:stack/kedgeflow-cura-*/*"
                ),
            }
        ]
        if duty in ("deployment", "identity-security", "resource", "sre"):
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:DescribeVolumes",
                        "ec2:DescribeImages",
                    ],
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-west-2"}},
                }
            )
        if duty == "identity-security":
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies"],
                    "Resource": sub(
                        "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/kedgeflow-cura-*"
                    ),
                }
            )
        if duty in ("deployment", "independent-reproducer"):
            statements.extend(
                [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                        "Resource": sub(
                            "arn:${AWS::Partition}:s3:::${ArtifactBucket}/runtime-v1/*"
                        ),
                    },
                    {
                        "Effect": "Allow",
                        "Action": "kms:Decrypt",
                        "Resource": ref("ArtifactKeyArn"),
                        "Condition": {
                            "StringEquals": {
                                "kms:ViaService": "s3.us-west-2.amazonaws.com",
                                "kms:EncryptionContext:aws:s3:arn": sub(
                                    "arn:${AWS::Partition}:s3:::${ArtifactBucket}"
                                ),
                            }
                        },
                    },
                ]
            )
        if duty == "sre":
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": "ec2:StopInstances",
                    "Resource": sub(
                        "arn:${AWS::Partition}:ec2:us-west-2:${AWS::AccountId}:instance/*"
                    ),
                    "Condition": {"StringEquals": {"ec2:ResourceTag/kedgeflow:profile": "cura"}},
                }
            )
        if duty in ("storage", "audit"):
            store = "Backup" if duty == "storage" else "Audit"
            statements.extend(
                [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket", "s3:GetBucketVersioning"],
                        "Resource": {"Fn::GetAtt": [store + "Bucket", "Arn"]},
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],
                        "Resource": sub("${" + store + "Bucket.Arn}/*"),
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
                        "Resource": {"Fn::GetAtt": [store + "Key", "Arn"]},
                        "Condition": {
                            "StringEquals": {
                                "kms:ViaService": "s3.us-west-2.amazonaws.com",
                                "kms:EncryptionContext:aws:s3:arn": {
                                    "Fn::GetAtt": [store + "Bucket", "Arn"]
                                },
                            }
                        },
                    },
                ]
            )
        resources[logical + "Role"] = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": "kedgeflow-cura-" + duty,
                "Description": "Unassigned Cura "
                + duty
                + "; requires explicit real-principal enrollment",
                "MaxSessionDuration": 3600,
                # Deliberately unassumable. Never invent a person or trusted
                # principal to make an acceptance role look enrolled.
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "Policies": [
                    {
                        "PolicyName": "duty-scope",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": statements,
                        },
                    }
                ],
                "Tags": [
                    {"Key": "kedgeflow:profile", "Value": "cura"},
                    {"Key": "kedgeflow:duty", "Value": duty},
                    {"Key": "kedgeflow:enrollment", "Value": "unassigned"},
                ],
            },
        }
    for store in ("Backup", "Audit"):
        resources[store + "Key"] = {
            "Type": "AWS::KMS::Key",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "Description": "Cura "
                + store.lower()
                + " custody; independent administrator enrollment pending",
                "EnableKeyRotation": True,
                "PendingWindowInDays": 30,
                "KeyPolicy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
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
        }
        resources[store + "Bucket"] = {
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
                                "KMSMasterKeyID": {"Fn::GetAtt": [store + "Key", "Arn"]},
                            },
                            "BucketKeyEnabled": True,
                        }
                    ]
                },
                "Tags": [
                    {"Key": "kedgeflow:profile", "Value": "cura"},
                    {"Key": "kedgeflow:custody", "Value": store.lower()},
                ],
            },
        }
        resources[store + "Policy"] = {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": ref(store + "Bucket"),
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [
                                {"Fn::GetAtt": [store + "Bucket", "Arn"]},
                                sub("${" + store + "Bucket.Arn}/*"),
                            ],
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        },
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                            "Resource": sub("${" + store + "Bucket.Arn}/*"),
                        },
                    ],
                },
            },
        }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": (
            "Cura unassigned administrative duties and separated custody stores; no owner approvals"
        ),
        "Parameters": {
            "ApprovedAccountId": {"Type": "String", "AllowedPattern": "[0-9]{12}"},
            "ArtifactBucket": {"Type": "String", "AllowedPattern": "[a-z0-9.-]+"},
            "ArtifactKeyArn": {
                "Type": "String",
                "AllowedPattern": "arn:aws:kms:us-west-2:[0-9]{12}:key/[a-zA-Z0-9-]+",
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
        "Outputs": {
            **{
                logical + "RoleArn": {"Value": {"Fn::GetAtt": [logical + "Role", "Arn"]}}
                for logical in DUTIES
            },
            **{store + "Bucket": {"Value": ref(store + "Bucket")} for store in ("Backup", "Audit")},
            **{
                store + "KeyArn": {"Value": {"Fn::GetAtt": [store + "Key", "Arn"]}}
                for store in ("Backup", "Audit")
            },
        },
        "Metadata": {
            "OwnerAcceptance": "NOT_ENROLLED",
            "CrossAccountIndependence": "NOT_ESTABLISHED",
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as output:
        json.dump(template(), output, indent=2)
        output.write("\n")
