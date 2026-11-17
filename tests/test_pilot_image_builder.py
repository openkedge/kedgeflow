"""Builder isolation and automatic termination remain separate from runtime authority."""

import runpy
from pathlib import Path

ROOT = Path(__file__).parents[1]
BUILDER = runpy.run_path(str(ROOT / "scripts/pilot-image-builder.py"))


def test_image_builder_has_no_ingress_and_only_artifact_scoped_permissions():
    t = BUILDER["template"]()
    r = t["Resources"]
    group = r["SecurityGroup"]["Properties"]
    assert "SecurityGroupIngress" not in group
    assert group["SecurityGroupEgress"] == [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"}
    ]
    instance = r["Builder"]["Properties"]
    assert instance["CreditSpecification"] == {"CPUCredits": "standard"}
    assert "KeyName" not in instance
    assert instance["MetadataOptions"]["HttpTokens"] == "required"
    assert instance["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] is True
    assert "shutdown -h +120" in instance["UserData"]["Fn::Base64"]
    assert "--config" not in instance["UserData"]["Fn::Base64"]
    statements = r["BuilderRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    s3 = [s for s in statements if isinstance(s["Action"], str) and s["Action"].startswith("s3:")]
    assert {s["Action"] for s in s3} == {"s3:GetObject", "s3:PutObject"}
    assert all(s["Resource"] != "*" for s in s3)
    assert "runtime-v1/" in s3[0]["Resource"]["Fn::Sub"]
    assert "build-reports/" in s3[1]["Resource"]["Fn::Sub"]


def test_termination_guard_can_only_terminate_its_builder():
    r = BUILDER["template"]()["Resources"]
    target = r["Lifetime"]["Properties"]["Target"]
    assert target["Arn"] == "arn:aws:scheduler:::aws-sdk:ec2:terminateInstances"
    assert target["Input"] == {"Fn::Sub": '{"InstanceIds":["${Builder}"]}'}
    statement = r["LifetimeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert len(statement) == 1
    assert statement[0]["Action"] == "ec2:TerminateInstances"
    assert statement[0]["Resource"]["Fn::Sub"].endswith(":instance/${Builder}")
