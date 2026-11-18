"""Retained SQL enrollment refuses replacement, widened custody, and unpinned input."""

import copy
import hashlib
import os
import pwd
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = runpy.run_path(str(ROOT / "scripts/enroll-cura-postgres.py"))
OWNER = pwd.getpwuid(os.getuid()).pw_name


def test_enrollment_requires_sql_mount_identity_and_closed_incarnation():
    manifest = {
        "format": "kedgeflow-cura-new-storage-v1",
        "host": "Sql",
        "instance_id": "i-0123456789abcdef0",
        "filesystem_uuid": "fixture-volume",
    }
    incarnation = "cura-reservation-" + "a" * 32
    assert SCRIPT["registration"](manifest, incarnation)["incarnation"] == incarnation
    for field, value in [("host", "Identity"), ("instance_id", "i-incorrect")]:
        changed = copy.deepcopy(manifest)
        changed[field] = value
        with pytest.raises(ValueError):
            SCRIPT["registration"](changed, incarnation)
    for invalid in ["", "x'; DROP DATABASE kedgeflow; --", "cura-reservation-" + "a" * 33]:
        with pytest.raises(ValueError):
            SCRIPT["registration"](manifest, invalid)
    assert (
        hashlib.sha256((ROOT / "migrations/postgres/0001-reservation.sql").read_bytes()).hexdigest()
        == SCRIPT["MIGRATION_SHA256"]
    )


def test_existing_configuration_is_never_replaced_or_silently_repaired(tmp_path):
    path = tmp_path / "configuration"
    SCRIPT["write_once"](path, "original", OWNER)
    SCRIPT["write_once"](path, "original", OWNER)
    with pytest.raises(RuntimeError):
        SCRIPT["write_once"](path, "replacement", OWNER)
    path.chmod(0o644)
    with pytest.raises(RuntimeError):
        SCRIPT["write_once"](path, "original", OWNER)
    assert path.read_text() == "original"


def test_configuration_refuses_symlink_and_hardlink(tmp_path):
    source, link = tmp_path / "source", tmp_path / "link"
    SCRIPT["write_once"](source, "original", OWNER)
    link.symlink_to(source)
    with pytest.raises(RuntimeError):
        SCRIPT["write_once"](link, "original", OWNER)
    link.unlink()
    os.link(source, link)
    with pytest.raises(RuntimeError):
        SCRIPT["write_once"](link, "original", OWNER)


def test_authentication_has_only_fixed_peer_maps_and_no_tcp_listener():
    assert (
        SCRIPT["ident"]()
        == "kf_target kf-sql-target kf_executor\nkf_target kf-sql-target kf_reader\n"
    )
    assert "local kedgeflow kf_executor,kf_reader peer map=kf_target" in SCRIPT["hba"]()
    assert "trust" not in SCRIPT["hba"]() and "scram" not in SCRIPT["hba"]()
    assert "listen_addresses = ''" in SCRIPT["server_configuration"]()
    assert "RestrictAddressFamilies=AF_UNIX" in SCRIPT["unit"]()
    assert "User=kf-postgres" in SCRIPT["unit"]()


def test_bootstrap_refuses_host_without_enrolled_mount(tmp_path):
    with pytest.raises(RuntimeError, match="enrolled Linux Sql host"):
        SCRIPT["enroll"](tmp_path / "missing.sql", "cura-reservation-" + "a" * 32)
