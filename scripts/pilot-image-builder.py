#!/usr/bin/env python3
"""Render a two-hour disposable Cura ARM64 image builder; no runtime authority."""

import argparse
import json
from pathlib import Path


def ref(name):
    return {"Ref": name}


def sub(value):
    return {"Fn::Sub": value}


def template():
    resources = {
        "Vpc": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
                "CidrBlock": "10.88.0.0/24",
                "EnableDnsSupport": True,
                "EnableDnsHostnames": True,
                "Tags": [{"Key": "kedgeflow:profile", "Value": "cura"}],
            },
        },
        "Subnet": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": ref("Vpc"),
                "CidrBlock": "10.88.0.0/26",
                "MapPublicIpOnLaunch": True,
            },
        },
        "InternetGateway": {"Type": "AWS::EC2::InternetGateway"},
        "GatewayAttachment": {
            "Type": "AWS::EC2::VPCGatewayAttachment",
            "Properties": {
                "VpcId": ref("Vpc"),
                "InternetGatewayId": ref("InternetGateway"),
            },
        },
        "Routes": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": ref("Vpc")}},
        "InternetRoute": {
            "Type": "AWS::EC2::Route",
            "DependsOn": "GatewayAttachment",
            "Properties": {
                "RouteTableId": ref("Routes"),
                "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": ref("InternetGateway"),
            },
        },
        "RouteAssociation": {
            "Type": "AWS::EC2::SubnetRouteTableAssociation",
            "Properties": {
                "SubnetId": ref("Subnet"),
                "RouteTableId": ref("Routes"),
            },
        },
        "SecurityGroup": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "VpcId": ref("Vpc"),
                "GroupDescription": "Temporary builder; no ingress, HTTPS egress only",
                "SecurityGroupEgress": [
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"}
                ],
            },
        },
        "BuilderRole": {
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
                        "PolicyName": "builder-only",
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
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": sub(
                                        "arn:${AWS::Partition}:s3:::${ArtifactBucket}/runtime-v1/*"
                                    ),
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:PutObject",
                                    "Resource": sub(
                                        "arn:${AWS::Partition}:s3:::${ArtifactBucket}/build-reports/*"
                                    ),
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
                                    "Resource": ref("DataKmsKeyArn"),
                                    "Condition": {
                                        "StringEquals": {
                                            "kms:ViaService": "s3.us-west-2.amazonaws.com",
                                            "kms:EncryptionContext:aws:s3:arn": sub(
                                                "arn:${AWS::Partition}:s3:::${ArtifactBucket}"
                                            ),
                                        }
                                    },
                                },
                            ],
                        },
                    }
                ],
            },
        },
        "BuilderProfile": {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {
                "Roles": [ref("BuilderRole")],
            },
        },
        "Builder": {
            "Type": "AWS::EC2::Instance",
            "DependsOn": ["InternetRoute", "RouteAssociation"],
            "Properties": {
                "ImageId": ref("BaseArm64Ami"),
                "InstanceType": "t4g.medium",
                "CreditSpecification": {"CPUCredits": "standard"},
                "IamInstanceProfile": ref("BuilderProfile"),
                "SubnetId": ref("Subnet"),
                "SecurityGroupIds": [ref("SecurityGroup")],
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
                # No credentials or runtime service configuration in user data.
                "UserData": {
                    "Fn::Base64": "#!/bin/bash\nset -eu\numask 077\n"
                    "systemctl disable --now ssh.service ssh.socket || true\n"
                    "shutdown -h +120 'Cura image build lifetime limit'\n"
                },
                "Tags": [
                    {"Key": "Name", "Value": "kedgeflow-cura-image-builder"},
                    {"Key": "kedgeflow:profile", "Value": "cura"},
                    {"Key": "kedgeflow:phase", "Value": "image-builder"},
                ],
            },
        },
        "LifetimeGroup": {"Type": "AWS::Scheduler::ScheduleGroup"},
        "LifetimeRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "scheduler.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {
                                    "aws:SourceAccount": ref("AWS::AccountId"),
                                    "aws:SourceArn": {"Fn::GetAtt": ["LifetimeGroup", "Arn"]},
                                }
                            },
                        }
                    ],
                },
                "Policies": [
                    {
                        "PolicyName": "terminate-only-this-builder",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "ec2:TerminateInstances",
                                    "Resource": sub(
                                        "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${Builder}"
                                    ),
                                }
                            ],
                        },
                    }
                ],
            },
        },
        "Lifetime": {
            "Type": "AWS::Scheduler::Schedule",
            "Properties": {
                "GroupName": ref("LifetimeGroup"),
                "FlexibleTimeWindow": {"Mode": "OFF"},
                "ScheduleExpression": sub("at(${BuildExpiresUTC})"),
                "ScheduleExpressionTimezone": "UTC",
                "State": "ENABLED",
                "Target": {
                    "Arn": "arn:aws:scheduler:::aws-sdk:ec2:terminateInstances",
                    "RoleArn": {"Fn::GetAtt": ["LifetimeRole", "Arn"]},
                    "Input": sub('{"InstanceIds":["${Builder}"]}'),
                    "RetryPolicy": {"MaximumEventAgeInSeconds": 3600, "MaximumRetryAttempts": 3},
                },
            },
        },
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Cura temporary ARM64 image builder; no ingress or runtime enrollment",
        "Parameters": {
            "ApprovedAccountId": {"Type": "String", "AllowedPattern": "[0-9]{12}"},
            "BaseArm64Ami": {"Type": "AWS::EC2::Image::Id"},
            "DataKmsKeyArn": {
                "Type": "String",
                "AllowedPattern": "arn:aws:kms:us-west-2:[0-9]{12}:key/[a-zA-Z0-9-]+",
            },
            "ArtifactBucket": {"Type": "String", "AllowedPattern": "[a-z0-9.-]+"},
            "BuildExpiresUTC": {
                "Type": "String",
                "AllowedPattern": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}",
            },
        },
        "Rules": {
            "ApprovedAccount": {
                "Assertions": [
                    {
                        "Assert": {"Fn::Equals": [ref("AWS::AccountId"), ref("ApprovedAccountId")]},
                        "AssertDescription": "Approved nonproduction account only",
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
            "BuilderInstance": {"Value": ref("Builder")},
            "LifetimeSchedule": {"Value": ref("Lifetime")},
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as output:
        json.dump(template(), output, indent=2)
        output.write("\n")
