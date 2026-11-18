"""Restore bootstrap uses the existing scoped credentials and a separate origin."""

import runpy
from pathlib import Path

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/enroll-cura-restore-gate.py"))


def test_native_restore_configuration_keeps_primary_and_witness_credentials_separate():
    config = SCRIPT["config"]()
    assert config["etcd_endpoint"] != config["restore_gate"]["endpoint"]
    assert config["etcd_prefix"] == config["restore_gate"]["prefix"] == "/kedgeflow/cura"
    assert config["etcd_token_file"] == "/etc/kedgeflow/operator/credentials/primary.token"
    assert (
        config["restore_gate"]["token_file"] == "/etc/kedgeflow/operator/credentials/witness.token"
    )
    assert {config["etcd_certificate"], config["restore_gate"]["certificate"]} == {
        "/etc/kedgeflow/operator/identity.pem"
    }
