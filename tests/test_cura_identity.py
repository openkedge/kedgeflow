"""Provider reruns must retain secrets and reject widened or ambiguous custody."""

import os
import pwd
import runpy
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/setup-cura-identity.py"))
OWNER = pwd.getpwuid(os.getuid()).pw_name


def test_provider_secret_is_created_private_without_output_and_never_rotated_implicitly(
    tmp_path, capsys
):
    path = tmp_path / "credential"
    SCRIPT["owned_write"](path, "fixture-original", OWNER)
    SCRIPT["owned_write"](path, "fixture-replacement-must-not-win", OWNER)
    assert path.read_text() == "fixture-original"
    assert path.stat().st_mode & 0o7777 == 0o400
    assert capsys.readouterr().out == ""


def test_provider_refuses_widened_secret_mode(tmp_path):
    path = tmp_path / "credential"
    path.write_text("fixture-only")
    path.chmod(0o640)
    with pytest.raises(RuntimeError, match="unsafe existing provider file"):
        SCRIPT["owned_write"](path, "replacement", OWNER)
    assert path.read_text() == "fixture-only"


def test_provider_refuses_linked_secret_without_touching_original(tmp_path):
    original = tmp_path / "original"
    original.write_text("fixture-only")
    original.chmod(0o400)
    link = tmp_path / "link"
    link.symlink_to(original)
    with pytest.raises(RuntimeError):
        SCRIPT["owned_write"](link, "replacement", OWNER)
    link.unlink()
    os.link(original, link)
    with pytest.raises(RuntimeError):
        SCRIPT["owned_write"](link, "replacement", OWNER)
    assert original.read_text() == "fixture-only"


def test_provider_cannot_bootstrap_without_selected_retained_mount(tmp_path):
    with pytest.raises(RuntimeError, match="retained Cura Identity data mount"):
        SCRIPT["setup"](tmp_path / "not-a-realm")
