"""Upgrade primitives refuse unsafe inputs and preserve immutable previous files."""

import os
import runpy
from pathlib import Path

import pytest

MODULE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/upgrade-cura-native-release.py"))


def test_upload_reader_refuses_links_and_special_files_without_waiting(tmp_path):
    path = tmp_path / "bundle"
    path.write_bytes(b"public")
    assert MODULE["read_regular"](path, 64, root_owned=False) == b"public"
    with pytest.raises(RuntimeError):
        MODULE["read_regular"](path, 2, root_owned=False)
    link = tmp_path / "linked"
    link.symlink_to(path)
    with pytest.raises(OSError):
        MODULE["read_regular"](link, 64, root_owned=False)
    link.unlink()
    os.link(path, link)
    with pytest.raises(RuntimeError):
        MODULE["read_regular"](path, 64, root_owned=False)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(RuntimeError):
        MODULE["read_regular"](fifo, 64, root_owned=False)


def test_durable_upgrade_record_is_exclusive_and_cannot_replace_history(tmp_path):
    path = tmp_path / "intent.json"
    MODULE["durable_write"](path, b"original")
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        MODULE["durable_write"](path, b"new")
    assert path.read_bytes() == b"original"


def test_atomic_selector_keeps_original_release_and_refuses_interrupted_link(tmp_path, monkeypatch):
    original, candidate = tmp_path / "old", tmp_path / "new"
    original.mkdir()
    candidate.mkdir()
    current = tmp_path / "current"
    current.symlink_to(original)
    monkeypatch.setitem(MODULE["activate_link"].__globals__, "CURRENT", current)
    MODULE["activate_link"](candidate)
    assert current.resolve() == candidate and original.is_dir()
    MODULE["activate_link"](original)
    assert current.resolve() == original and candidate.is_dir()
    interrupted = current.with_name(".current-cura-url-upgrade")
    interrupted.symlink_to(candidate)
    with pytest.raises(RuntimeError):
        MODULE["activate_link"](candidate)
    assert current.resolve() == original
