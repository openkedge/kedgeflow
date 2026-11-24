"""Fresh-volume initialization must refuse any ambiguous host or retained state."""

import copy
import io
import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/enroll-cura-storage.py"))
ENROLL = SCRIPT["enroll"]
GLOBAL = ENROLL.__globals__
MANIFEST = {
    "format": "kedgeflow-cura-new-storage-v1",
    "instance_id": "i-0123456789abcdef0",
    "host": "Sql",
    "volume_id": "vol-0123456789abcdef0",
    "filesystem_uuid": "12345678-1234-4234-9234-123456789abc",
    "approved_new_empty_volume": True,
}


@pytest.mark.parametrize(
    "change", [{"approved_new_empty_volume": False}, {"host": "Agent"}, {"extra": "ignored"}]
)
def test_storage_requires_closed_explicit_data_volume_manifest(change):
    with pytest.raises(ValueError):
        SCRIPT["validate"]({**MANIFEST, **change})


def setup_probe(
    monkeypatch, *, instance=MANIFEST["instance_id"], disk=None, existing_uuid="", signatures=None
):
    monkeypatch.setattr(GLOBAL["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(GLOBAL["sys"], "platform", "linux")
    responses = iter([b"not-a-live-token", instance.encode()])
    monkeypatch.setattr(
        GLOBAL["urllib"].request, "urlopen", lambda *_a, **_k: io.BytesIO(next(responses))
    )
    if disk is None:
        disk = {
            "name": "nvme1n1",
            "size": 32 * 1024**3,
            "type": "disk",
            "fstype": None,
            "mountpoints": [None],
            "serial": MANIFEST["volume_id"].replace("-", ""),
        }
    calls = []

    def run(argv, check=True):
        calls.append(argv)
        if argv[0] == "lsblk":
            raw = json.dumps({"blockdevices": [disk]})
        elif argv[0] == "blkid":
            raw = existing_uuid
        elif argv[0] == "wipefs":
            raw = json.dumps({"signatures": signatures or []})
        else:
            pytest.fail("unexpected mutation: " + argv[0])
        return SimpleNamespace(stdout=raw, returncode=0)

    monkeypatch.setitem(GLOBAL, "run", run)
    return calls


def test_wrong_instance_never_inspects_or_formats_volume(monkeypatch):
    calls = setup_probe(monkeypatch, instance="i-11111111111111111")
    with pytest.raises(RuntimeError, match="instance does not match"):
        ENROLL(copy.deepcopy(MANIFEST))
    assert calls == []


def test_root_sized_volume_is_never_formatted(monkeypatch):
    disk = {
        "name": "nvme0n1",
        "size": 24 * 1024**3,
        "type": "disk",
        "fstype": "ext4",
        "mountpoints": ["/"],
        "serial": MANIFEST["volume_id"].replace("-", ""),
    }
    calls = setup_probe(monkeypatch, disk=disk)
    with pytest.raises(RuntimeError, match="unexpected volume layout"):
        ENROLL(copy.deepcopy(MANIFEST))
    assert [c[0] for c in calls] == ["lsblk"]


def test_unknown_signature_and_existing_filesystem_never_erased(monkeypatch):
    setup_probe(monkeypatch, signatures=[{"type": "LVM2_member"}])
    with pytest.raises(RuntimeError, match="volume is not blank"):
        ENROLL(copy.deepcopy(MANIFEST))
    setup_probe(monkeypatch, existing_uuid="aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
    with pytest.raises(RuntimeError, match="never erase"):
        ENROLL(copy.deepcopy(MANIFEST))


def test_matching_uuid_cannot_shadow_retained_files(monkeypatch, tmp_path):
    disk = {
        "name": "nvme1n1",
        "size": 32 * 1024**3,
        "type": "disk",
        "fstype": "ext4",
        "mountpoints": [None],
        "serial": MANIFEST["volume_id"].replace("-", ""),
    }
    setup_probe(monkeypatch, disk=disk, existing_uuid=MANIFEST["filesystem_uuid"])
    (tmp_path / "retained-attempt-history").write_text("must remain")
    monkeypatch.setitem(GLOBAL, "MOUNT", tmp_path)
    with pytest.raises(RuntimeError, match="refusing shadowing"):
        ENROLL(copy.deepcopy(MANIFEST))
    assert (tmp_path / "retained-attempt-history").read_text() == "must remain"
