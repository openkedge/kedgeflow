"""Guard destructive fixture operations and preserve units the fixture never created."""

import argparse
import os
import runpy
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = runpy.run_path(str(ROOT / "scripts/pilot-systemd-role.py"))


@pytest.mark.parametrize("action", ["stop", "restart"])
def test_adapter_never_stops_or_restarts_a_unit_it_does_not_own(tmp_path, monkeypatch, action):
    base = tmp_path / "kf-managed-test"
    material = base / "work/control"
    material.mkdir(parents=True)
    units = tmp_path / "units"
    units.mkdir()
    unit = units / "kf-managed-test-control.service"
    unit.write_text("unrelated unit\n")
    calls = []
    monkeypatch.setattr(
        SCRIPT["pwd"], "getpwnam", lambda _: SimpleNamespace(pw_uid=501, pw_gid=501)
    )
    monkeypatch.setattr(SCRIPT["subprocess"], "run", lambda *args, **kwargs: calls.append(args))
    state = {"base": str(base), "users": {"control": "fixture-control"}}
    if action == "restart":
        with pytest.raises(ValueError, match="does not own"):
            SCRIPT["act"](state, "kf-control", material, action, unit_directory=units)
    else:
        SCRIPT["act"](state, "kf-control", material, action, unit_directory=units)
    assert calls == [] and unit.read_text() == "unrelated unit\n"


def test_registry_refuses_symlinks_and_exposed_files(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{}")
    path.chmod(0o644)
    with pytest.raises(ValueError, match="unprotected"):
        SCRIPT["registry"](path)
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        SCRIPT["registry"](alias)


def test_authority_fixture_requires_explicit_disposable_host_opt_in():
    arguments = [sys.executable, str(ROOT / "scripts/qualify-systemd-authority.py")]
    for flag in ("input", "bundle", "postgres-bindir", "output", "package", "test-binary", "etcd"):
        arguments.extend(["--" + flag, "/not-read"])
    result = subprocess.run(
        arguments + ["--sha256", "0" * 64], capture_output=True, text=True, check=False
    )
    assert result.returncode == 2 and "requires --ephemeral-host" in result.stderr


def test_local_adapter_requires_an_explicit_host_opt_in():
    arguments = [sys.executable, str(ROOT / "scripts/systemd-sql-workflow.py"), "--managed"]
    for flag in ("input", "bundle", "postgres-bindir", "output"):
        arguments.extend(["--" + flag, "/not-read"])
    env = {key: value for key, value in os.environ.items() if not key.startswith("KF_SYSTEMD_")}
    result = subprocess.run(arguments, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 2 and "KF_SYSTEMD_PILOT_EPHEMERAL_HOST=1" in result.stderr


def test_checksum_mismatch_refuses_before_creating_linux_resources(tmp_path):
    bundle = tmp_path / "bundle.tar.gz"
    bundle.write_bytes(b"changed bundle")
    qualifier = runpy.run_path(str(ROOT / "scripts/qualify-systemd-authority.py"))
    with pytest.raises(ValueError, match="checksum mismatch"):
        qualifier["qualify"](argparse.Namespace(package=bundle, sha256="0" * 64))


def test_workflow_timeout_reaps_launcher_and_descendants(tmp_path):
    qualifier = runpy.run_path(str(ROOT / "scripts/qualify-systemd-authority.py"))
    pidfile = tmp_path / "launcher.pid"
    command = [
        sys.executable,
        "-c",
        (
            "import os,pathlib,subprocess,sys,time; "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "time.sleep(60)"
        ),
        str(pidfile),
    ]
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            qualifier["workflow_process"](command, dict(os.environ), timeout=0.5)
        pid = int(pidfile.read_text())
        deadline = time.monotonic() + 2
        while True:
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                break
            assert time.monotonic() < deadline, "workflow descendants survived cleanup"
            time.sleep(0.02)
    finally:
        if pidfile.exists():
            try:
                os.killpg(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
