#!/usr/bin/env python3
"""Render the cura reference CloudFormation infrastructure; never call AWS or launch services."""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOSTS = {
    "Services": ("services", 0),
    "Sql": ("sql", 1),
    "Identity": ("identity", 2),
    "Agent": ("agent", 0),
    "LedgerA": ("ledger", 0),
    "LedgerB": ("ledger", 1),
    "LedgerC": ("ledger", 2),
    "Witness": ("witness", 1),
    "Audit": ("audit", 2),
}


def ref(name):
    return {"Ref": name}


def sub(value):
    return {"Fn::Sub": value}


def template():
    parameters = {
        "ApprovedAccountId": {"Type": "String", "AllowedPattern": "[0-9]{12}"},
        "PinnedArm64Ami": {
            "Type": "AWS::EC2::Image::Id",
            "Description": "Approved Ubuntu 24.04 ARM64 image with pinned packages and SSM",
        },
        "DataKmsKeyArn": {
            "Type": "String",
            "AllowedPattern": "arn:aws:kms:us-west-2:[0-9]{12}:key/[a-zA-Z0-9-]+",
        },
        "MonthlyBudgetUsd": {"Type": "Number", "MinValue": 1, "MaxValue": 2000},
        "BudgetEmail": {"Type": "String", "AllowedPattern": "[^@ ]+@[^@ ]+"},
    }
    resources = {
        "Vpc": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
                "CidrBlock": "10.87.0.0/16",
                "EnableDnsSupport": True,
                "EnableDnsHostnames": True,
                "Tags": [{"Key": "Name", "Value": "kedgeflow-cura-nonproduction"}],
            },
        },
        "PrivateRoutes": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": ref("Vpc")}},
    }
    for i in range(3):
        resources[f"Subnet{i}"] = {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": ref("Vpc"),
                "CidrBlock": f"10.87.{i}.0/24",
                "MapPublicIpOnLaunch": False,
                "AvailabilityZone": {"Fn::Select": [i, {"Fn::GetAZs": ""}]},
            },
        }
        resources[f"RouteAssociation{i}"] = {
            "Type": "AWS::EC2::SubnetRouteTableAssociation",
            "Properties": {"SubnetId": ref(f"Subnet{i}"), "RouteTableId": ref("PrivateRoutes")},
        }
    for role in ("services", "sql", "identity", "agent", "ledger", "witness", "audit", "endpoints"):
        # An explicit loopback-only rule suppresses AWS's implicit allow-all egress.
        resources[role.title() + "SecurityGroup"] = {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "VpcId": ref("Vpc"),
                "GroupDescription": f"cura {role} closed egress",
                "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "127.0.0.1/32"}],
            },
        }
    edges = [
        ("agent", "services", 8443),
        ("agent", "services", 9443),
        ("agent", "services", 9448),
        ("agent", "services", 8444),
        ("agent", "identity", 8443),
        ("agent", "identity", 8081),
        ("services", "sql", 8451),
        ("services", "ledger", 2379),
        ("services", "witness", 2379),
        ("services", "audit", 8447),
        ("services", "identity", 8443),
        ("services", "identity", 8081),
        ("audit", "ledger", 2379),
        ("audit", "witness", 2379),
        ("ledger", "ledger", 2380),
    ]
    # Host-level systemd/IP restrictions further separate co-located service UIDs.
    # SG reachability does not confer application authorization.
    for role in ("services", "sql", "identity", "agent", "ledger", "witness", "audit"):
        edges.append((role, "endpoints", 443))
    for i, (source, target, port) in enumerate(edges):
        sg_source, sg_target = (
            ref(source.title() + "SecurityGroup"),
            ref(target.title() + "SecurityGroup"),
        )
        resources[f"Ingress{i}"] = {
            "Type": "AWS::EC2::SecurityGroupIngress",
            "Properties": {
                "GroupId": sg_target,
                "SourceSecurityGroupId": sg_source,
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
            },
        }
        resources[f"Egress{i}"] = {
            "Type": "AWS::EC2::SecurityGroupEgress",
            "Properties": {
                "GroupId": sg_source,
                "DestinationSecurityGroupId": sg_target,
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
            },
        }
    for service in ("ssm", "ssmmessages", "logs"):
        resources[service.title() + "Endpoint"] = {
            "Type": "AWS::EC2::VPCEndpoint",
            "Properties": {
                "VpcId": ref("Vpc"),
                "VpcEndpointType": "Interface",
                "PrivateDnsEnabled": True,
                "ServiceName": sub("com.amazonaws.${AWS::Region}." + service),
                "SubnetIds": [ref(f"Subnet{i}") for i in range(3)],
                "SecurityGroupIds": [ref("EndpointsSecurityGroup")],
            },
        }
    for name, (role, subnet) in HOSTS.items():
        # SSM node channels are the only IAM authority given to a host. No S3,
        # secrets, KMS decrypt, EC2, IAM, backup, or other role assumption rights.
        resources[name + "Role"] = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "Policies": [
                    {
                        "PolicyName": "ssm-node-only",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Resource": "*",
                                    "Action": [
                                        "ssm:UpdateInstanceInformation",
                                        "ssmmessages:CreateControlChannel",
                                        "ssmmessages:CreateDataChannel",
                                        "ssmmessages:OpenControlChannel",
                                        "ssmmessages:OpenDataChannel",
                                    ],
                                }
                            ],
                        },
                    }
                ],
            },
        }
        resources[name + "Profile"] = {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {"Roles": [ref(name + "Role")]},
        }
        resources[name] = {
            "Type": "AWS::EC2::Instance",
            "Properties": {
                "ImageId": ref("PinnedArm64Ami"),
                "InstanceType": "t4g.small" if role == "agent" else "t4g.medium",
                "IamInstanceProfile": ref(name + "Profile"),
                "SubnetId": ref(f"Subnet{subnet}"),
                "SecurityGroupIds": [ref(role.title() + "SecurityGroup")],
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpPutResponseHopLimit": 1,
                    "HttpProtocolIpv6": "disabled",
                    "InstanceMetadataTags": "disabled",
                },
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/sda1",
                        "Ebs": {
                            "Encrypted": True,
                            "KmsKeyId": ref("DataKmsKeyArn"),
                            "VolumeType": "gp3",
                            "VolumeSize": 24,
                            "DeleteOnTermination": True,
                        },
                    }
                ],
                "Tags": [
                    {"Key": "Name", "Value": "kedgeflow-cura-" + name.lower()},
                    {"Key": "kedgeflow:profile", "Value": "cura"},
                    {"Key": "kedgeflow:role", "Value": role},
                ],
            },
        }
        if role != "agent":
            # Separate retained data volume. Image/bootstrap must mount it by ID;
            # formatting or service launch is intentionally not put in user data.
            resources[name + "Data"] = {
                "Type": "AWS::EC2::Volume",
                "DeletionPolicy": "Retain",
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "AvailabilityZone": {"Fn::GetAtt": [name, "AvailabilityZone"]},
                    "Encrypted": True,
                    "KmsKeyId": ref("DataKmsKeyArn"),
                    "Size": 32,
                    "VolumeType": "gp3",
                    "Tags": [{"Key": "kedgeflow:profile", "Value": "cura"}],
                },
            }
            resources[name + "DataAttachment"] = {
                "Type": "AWS::EC2::VolumeAttachment",
                "Properties": {
                    "Device": "/dev/sdf",
                    "InstanceId": ref(name),
                    "VolumeId": ref(name + "Data"),
                },
            }
    resources["PrivateZone"] = {
        "Type": "AWS::Route53::HostedZone",
        "Properties": {
            "Name": "cura.kedgeflow.internal",
            "VPCs": [{"VPCId": ref("Vpc"), "VPCRegion": ref("AWS::Region")}],
        },
    }
    for name in HOSTS:
        resources[name + "Dns"] = {
            "Type": "AWS::Route53::RecordSet",
            "Properties": {
                "HostedZoneId": ref("PrivateZone"),
                "Name": name.lower() + ".cura.kedgeflow.internal",
                "Type": "A",
                "TTL": "60",
                "ResourceRecords": [{"Fn::GetAtt": [name, "PrivateIp"]}],
            },
        }
    resources["MonthlyBudget"] = {
        "Type": "AWS::Budgets::Budget",
        "Properties": {
            "Budget": {
                "BudgetType": "COST",
                "TimeUnit": "MONTHLY",
                "BudgetLimit": {"Amount": ref("MonthlyBudgetUsd"), "Unit": "USD"},
            },
            "NotificationsWithSubscribers": [
                {
                    "Notification": {
                        "NotificationType": "ACTUAL",
                        "ComparisonOperator": "GREATER_THAN",
                        "ThresholdType": "PERCENTAGE",
                        "Threshold": threshold,
                    },
                    "Subscribers": [{"SubscriptionType": "EMAIL", "Address": ref("BudgetEmail")}],
                }
                for threshold in (50, 80, 100)
            ],
        },
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "cura SQL pilot infrastructure v1; unenrolled, unqualified",
        "Parameters": parameters,
        "Rules": {
            "ApprovedAccount": {
                "Assertions": [
                    {
                        "Assert": {"Fn::Equals": [ref("AWS::AccountId"), ref("ApprovedAccountId")]},
                        "AssertDescription": "Explicitly approved nonproduction account only",
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
        "Outputs": {name + "Instance": {"Value": ref(name)} for name in HOSTS},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Never overwrite an operator's reviewed template.
    with args.output.open("x") as stream:
        json.dump(template(), stream, indent=2)
        stream.write("\n")
