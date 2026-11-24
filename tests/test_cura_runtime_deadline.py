"""Expired runtime guards fail before touching retained hosts or authority."""

import runpy
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parents[1] / "scripts"


@pytest.mark.parametrize(
    "script", ["upgrade-cura-native-release.py", "prepare-cura-native-keys.py"]
)
def test_explicit_runtime_deadline_is_canonical_future_and_bounded(script):
    guard = runpy.run_path(str(SCRIPTS / script))["runtime_deadline"]
    end = 1795420800
    assert guard("2026-11-23T08:00:00Z", now=end - 1) == end
    assert guard("2026-11-23T08:00:00Z", now=end - 86400) == end
    for value, now in [
        ("2026-11-23T08:00:00Z", end),
        ("2026-11-23T08:00:00Z", end + 1),
        ("2026-11-23T08:00:00Z", end - 86401),
        ("2026-11-23T08:00:00+00:00", end - 1),
        ("2026-11-23T8:00:00Z", end - 1),
        ("2026-02-30T08:00:00Z", end - 1),
    ]:
        with pytest.raises(ValueError):
            guard(value, now=now)


@pytest.mark.parametrize(
    "script", ["upgrade-cura-native-release.py", "prepare-cura-native-keys.py"]
)
def test_expired_window_refuses_before_accessing_host_state(script, monkeypatch):
    module = runpy.run_path(str(SCRIPTS / script))
    action = module["upgrade"] if "upgrade" in module else module["prepare"]

    class InaccessibleHost:
        def is_mount(self):
            pytest.fail("expired command touched retained storage")

    monkeypatch.setitem(action.__globals__, "DATA", InaccessibleHost())
    monkeypatch.setattr(module["time"], "time", lambda: 1795420800)
    args = (
        ("a" * 64, 1, True, "2026-11-23T08:00:00Z")
        if "upgrade" in module
        else ("2026-11-23T08:00:00Z",)
    )
    with pytest.raises(ValueError, match="future stop"):
        action(*args)
