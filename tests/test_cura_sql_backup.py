"""Physical-copy integrity and path refusal without touching a deployed database."""

import os
import runpy
from pathlib import Path

import pytest

MODULE = runpy.run_path(str(Path(__file__).parents[1] / "scripts/backup-cura-sql.py"))


def test_cold_copy_detects_changed_bytes_and_inventory(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "PG_VERSION").write_bytes(b"18\n")
    files, size = MODULE["inventory"](data)
    first = MODULE["digests"](data, files)
    assert size == 3 and len(first) == 1
    (data / "PG_VERSION").write_bytes(b"17\n")
    assert MODULE["digests"](data, files) != first
    (data / "PG_VERSION").write_bytes(b"unexpected size")
    with pytest.raises(RuntimeError):
        MODULE["digests"](data, files)


def test_cold_inventory_refuses_symbolic_and_hard_links(tmp_path):
    target = tmp_path / "outside"
    target.write_bytes(b"protected")
    root = tmp_path / "data"
    root.mkdir()
    link = root / "link"
    link.symlink_to(target)
    with pytest.raises(RuntimeError):
        MODULE["inventory"](root)
    link.unlink()
    os.link(target, link)
    with pytest.raises(RuntimeError):
        MODULE["inventory"](root)


def test_cold_inventory_refuses_fifo_without_opening_or_waiting(tmp_path):
    os.mkfifo(tmp_path / "special")
    with pytest.raises(RuntimeError):
        MODULE["inventory"](tmp_path)


def test_cold_inventory_refuses_linked_root(tmp_path):
    root = tmp_path / "actual"
    root.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(root, target_is_directory=True)
    with pytest.raises(RuntimeError):
        MODULE["inventory"](linked)
