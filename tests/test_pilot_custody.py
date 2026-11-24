"""Administrative scaffolding must not impersonate acceptance or independent custody."""

import json
import runpy
from pathlib import Path

ROOT = Path(__file__).parents[1]
CUSTODY = runpy.run_path(str(ROOT / "scripts/pilot-custody.py"))


def test_all_seven_duties_require_real_principal_enrollment():
    template = CUSTODY["template"]()
    roles = [r for r in template["Resources"].values() if r["Type"] == "AWS::IAM::Role"]
    assert len(roles) == 7
    for role in roles:
        trust = role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
        assert trust == [{"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]
        tags = {t["Key"]: t["Value"] for t in role["Properties"]["Tags"]}
        assert tags["kedgeflow:enrollment"] == "unassigned"
    assert template["Metadata"] == {
        "OwnerAcceptance": "NOT_ENROLLED",
        "CrossAccountIndependence": "NOT_ESTABLISHED",
    }
    assert not any(
        r["Type"] in {"AWS::IAM::User", "AWS::IAM::AccessKey", "AWS::Organizations::Account"}
        for r in template["Resources"].values()
    )


def test_custody_stores_are_distinct_retained_encrypted_and_delete_denied():
    resources = CUSTODY["template"]()["Resources"]
    for store, other in [("Audit", "Backup"), ("Backup", "Audit")]:
        bucket = resources[store + "Bucket"]
        key = resources[store + "Key"]
        assert bucket["DeletionPolicy"] == key["DeletionPolicy"] == "Retain"
        assert key["Properties"]["EnableKeyRotation"] is True
        props = bucket["Properties"]
        assert all(props["PublicAccessBlockConfiguration"].values())
        assert props["VersioningConfiguration"]["Status"] == "Enabled"
        encryption = props["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]
        assert encryption["ServerSideEncryptionByDefault"]["KMSMasterKeyID"] == {
            "Fn::GetAtt": [store + "Key", "Arn"]
        }
        policy = resources[store + "Policy"]["Properties"]["PolicyDocument"]["Statement"]
        assert policy[1]["Effect"] == "Deny"
        assert set(policy[1]["Action"]) == {"s3:DeleteObject", "s3:DeleteObjectVersion"}
        role = resources[("Storage" if store == "Backup" else store) + "Role"]
        permissions = role["Properties"]["Policies"][0]["PolicyDocument"]
        raw = json.dumps(permissions)
        assert other + "Key" not in raw and other + "Bucket" not in raw
        assert "DeleteObject" not in raw and "kms:Sign" not in raw
        assert "kms:ViaService" in raw and "kms:EncryptionContext:aws:s3:arn" in raw
