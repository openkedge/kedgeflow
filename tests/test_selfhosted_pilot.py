"""Pilot orchestration must clean up on bootstrap failure and keep secrets off argv/logs."""

import argparse
import json
import runpy
import secrets
import subprocess
import tarfile
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/selfhosted-pilot.py"))


def test_pilot_refuses_remote_daemon_before_creating_output(tmp_path):
    args = argparse.Namespace(output=tmp_path / "evidence", docker_host="tcp://production:2375")
    with pytest.raises(ValueError, match="explicit local Docker socket"):
        SCRIPT["run_pilot"](args)
    assert not args.output.exists()


@pytest.mark.parametrize("mode", ["identity", "lifecycle", "storage"])
def test_bootstrap_failure_removes_only_owned_resources_and_redacts_secrets(
    monkeypatch, tmp_path, mode,
):
    calls = []
    secret = secrets.token_hex(32)
    monkeypatch.setattr(SCRIPT["secrets"], "token_urlsafe", lambda _size: secret)

    def run(command, **kwargs):
        assert secret not in " ".join(command)
        calls.append(command[1:])
        fail = command[1] == "exec" and (
            ("token" in command and "generate" in command)
            or ("cat" in command and "/run/kf-spire/private/keycloak-admin.json" in command)
        )
        stdout = b"[]" if command[1] == "inspect" else b""
        if command[1] == "logs":
            stdout = secret.encode()
        return subprocess.CompletedProcess(
            command, 1 if fail else 0, stdout, b"injected bootstrap failure" if fail else b""
        )

    monkeypatch.setattr(SCRIPT["subprocess"], "run", run)
    args = argparse.Namespace(
        output=tmp_path / "evidence",
        docker_host="unix:///tmp/pilot.sock",
        docker=Path("docker"),
        workload_image="owned-test-image",
        checker=None,
        identity_lifecycle=mode == "lifecycle",
        identity_storage_restore=mode == "storage",
    )
    with pytest.raises(RuntimeError, match="injected bootstrap failure"):
        SCRIPT["run_pilot"](args)
    summary = json.loads((args.output / "summary.json").read_text())
    assert summary["status"] == "failed" and summary["cleanup_passed"]
    removed = [call[-1] for call in calls if call[:2] == ["rm", "-f"]]
    assert len(removed) == 2 and all(name.startswith("kf-selfhosted-") for name in removed)
    networks = [call[-1] for call in calls if call[:2] == ["network", "rm"]]
    assert len(networks) == 1 and networks[0].startswith("kf-selfhosted-")
    assert all(secret.encode() not in p.read_bytes() for p in args.output.iterdir())
    with tarfile.open(args.output / "source.tar.gz") as archive:
        assert all(
            secret.encode() not in archive.extractfile(p).read()
            for p in archive.getmembers()
            if p.isfile()
        )
