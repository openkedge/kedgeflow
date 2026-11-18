"""Bootstrap grants cannot expose another node, a whole secret tree or KMS directly."""

import json
import runpy
from pathlib import Path

BRIDGE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/pilot-enrollment-bridge.py"))


def test_bridge_has_only_three_temporary_policies_and_no_principals_or_secret_values():
    template = BRIDGE["template"]()
    assert len(template["Resources"]) == 3
    assert all(r["Type"] == "AWS::IAM::Policy" for r in template["Resources"].values())
    assert not any("Default" in p for p in template["Parameters"].values())
    assert "AssumeRole" not in json.dumps(template)
    assert template["Metadata"]["IndependentAcceptance"] == "BLOCKED_EXTERNAL_INPUT"
    for resource in template["Resources"].values():
        for statement in resource["Properties"]["PolicyDocument"]["Statement"]:
            assert statement["Condition"]["DateLessThan"] == {
                "aws:CurrentTime": {"Ref": "BootstrapExpiresUTC"}
            }


def test_nodes_can_only_read_their_own_secure_parameter_through_ssm():
    resources = BRIDGE["template"]()["Resources"]
    for node, other in [("Services", "Agent"), ("Agent", "Services")]:
        statements = resources[node + "Bridge"]["Properties"]["PolicyDocument"]["Statement"]
        assert statements[0]["Action"] == ["ssm:GetParameter"]
        assert len(statements[0]["Resource"]) == 1
        assert statements[0]["Resource"][0]["Fn::Sub"].endswith("/" + node)
        assert "/" + other not in json.dumps(statements)
        kms = statements[1]
        assert kms["Action"] == "kms:Decrypt"
        assert kms["Resource"] == {"Ref": "DataKmsKeyArn"}
        assert kms["Condition"]["StringEquals"] == {
            "kms:ViaService": "ssm.us-west-2.amazonaws.com",
            "kms:EncryptionContext:PARAMETER_ARN": statements[0]["Resource"],
        }


def test_identity_cannot_read_bootstrap_parameters_or_decrypt_others_keys():
    statements = BRIDGE["template"]()["Resources"]["IdentityBridge"]["Properties"]
    statements = statements["PolicyDocument"]["Statement"]
    assert set(statements[0]["Action"]) == {"ssm:PutParameter", "ssm:DeleteParameter"}
    assert len(statements[0]["Resource"]) == 2
    assert statements[1]["Action"] == "kms:Encrypt"
    assert (
        statements[1]["Condition"]["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"]
        == (statements[0]["Resource"])
    )
    assert "*" not in json.dumps(statements)
