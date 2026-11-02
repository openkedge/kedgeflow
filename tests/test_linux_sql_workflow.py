"""Root fixture ownership and failed-start cleanup; never call a real systemctl."""

import runpy
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = runpy.run_path(str(ROOT / "scripts/linux-sql-workflow.py"))


@pytest.fixture
def systemd(tmp_path, monkeypatch):
    monkeypatch.setattr(SCRIPT["os"], "geteuid", lambda: 0)
    read_text = Path.read_text

    def read(path, *args, **kwargs):
        return "systemd\n" if str(path) == "/proc/1/comm" else read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert kwargs["timeout"] == 45
        if args[1] == "start":
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(SCRIPT["subprocess"], "run", run)
    units = tmp_path / "units"
    units.mkdir()
    return calls, units


def test_failed_start_stops_service_before_removing_owned_unit(tmp_path, systemd):
    calls, units = systemd
    source = ROOT / "deploy/linux/systemd/kedgeflow-sql-target.service"
    with pytest.raises(subprocess.CalledProcessError):
        with SCRIPT["systemd_process"](
            ["/opt/fixture/bin/kf-postgres-target", "--require-managed"],
            {},
            source,
            "kf_fixture_target",
            tmp_path / "kf-isolation-test",
            unit_directory=units,
        ):
            pytest.fail("failed start cannot yield a running service")
    assert [call[1] for call in calls] == [
        "daemon-reload",
        "start",
        "stop",
        "reset-failed",
        "daemon-reload",
    ]
    assert list(units.iterdir()) == []


def test_preexisting_unit_is_never_changed_or_stopped(tmp_path, systemd):
    calls, units = systemd
    existing = units / "kf-isolation-test.service"
    existing.write_text("unrelated service\n")
    with pytest.raises(FileExistsError):
        with SCRIPT["systemd_process"](
            ["/opt/fixture/target"],
            {},
            ROOT / "deploy/linux/systemd/kedgeflow-sql-target.service",
            "kf_fixture_target",
            tmp_path / "kf-isolation-test",
            unit_directory=units,
        ):
            pytest.fail("preexisting service must refuse")
    assert existing.read_text() == "unrelated service\n" and calls == []


@pytest.mark.parametrize("argument", ["/tmp/%n", "$CREDENTIAL", "a b", 'a"b', "a\nb"])
def test_systemd_argument_expansion_is_refused_before_creating_unit(tmp_path, systemd, argument):
    calls, units = systemd
    with pytest.raises(ValueError, match="unsafe systemd fixture argument"):
        with SCRIPT["systemd_process"](
            [argument],
            {},
            ROOT / "deploy/linux/systemd/kedgeflow-sql-target.service",
            "kf_fixture_target",
            tmp_path / "kf-isolation-test",
            unit_directory=units,
        ):
            pytest.fail("systemd expansion must refuse")
    assert calls == [] and list(units.iterdir()) == []


def test_exact_bundle_fixture_requires_explicit_disposable_opt_in():
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/qualify-systemd-sql.py"),
            "--package",
            "/not-read",
            "--sha256",
            "0" * 64,
            "--bindir",
            "/not-read",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires --ephemeral-host" in result.stderr


def test_bundle_checksum_mismatch_refuses_before_archive_or_account_work(tmp_path):
    bundle = tmp_path / "bundle.tar.gz"
    bundle.write_bytes(b"changed bundle; not even an archive")
    wrapper = runpy.run_path(str(ROOT / "scripts/qualify-systemd-sql.py"))
    with pytest.raises(ValueError, match="bundle checksum mismatch"):
        wrapper["qualify"](bundle, "0" * 64, tmp_path / "absent-postgres")
