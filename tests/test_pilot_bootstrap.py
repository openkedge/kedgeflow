"""Bootstrap provisions artifact custody, never protocol authority or public access."""

import runpy
from pathlib import Path

ROOT = Path(__file__).parents[1]
BOOTSTRAP = runpy.run_path(str(ROOT / "scripts/pilot-bootstrap.py"))


def test_bootstrap_has_closed_account_region_and_no_runtime_compute_or_credentials():
    t = BOOTSTRAP["template"]()
    assert set(t["Parameters"]) == {"ApprovedAccountId", "MonthlyBudgetUsd", "BudgetEmail"}
    assert t["Parameters"]["BudgetEmail"]["NoEcho"] is True
    assert "Default" not in t["Parameters"]["ApprovedAccountId"]
    assert "Default" not in t["Parameters"]["MonthlyBudgetUsd"]
    assert set(t["Rules"]) == {"ApprovedAccount", "ApprovedRegion"}
    assert not any(
        r["Type"].startswith(("AWS::EC2::", "AWS::IAM::")) for r in t["Resources"].values()
    )
    bucket = t["Resources"]["Artifacts"]
    assert bucket["DeletionPolicy"] == bucket["UpdateReplacePolicy"] == "Retain"
    assert all(bucket["Properties"]["PublicAccessBlockConfiguration"].values())
    assert bucket["Properties"]["VersioningConfiguration"]["Status"] == "Enabled"
    key = t["Resources"]["DataKey"]
    assert key["DeletionPolicy"] == key["UpdateReplacePolicy"] == "Retain"
    assert key["Properties"]["EnableKeyRotation"] is True
    assert key["Properties"]["Tags"] == [{"Key": "kedgeflow:profile", "Value": "cura"}]
    assert (
        t["Resources"]["ArtifactPolicy"]["Properties"]["PolicyDocument"]["Statement"][0]["Effect"]
        == "Deny"
    )
    assert len(t["Resources"]["PilotBudget"]["Properties"]["NotificationsWithSubscribers"]) == 4
