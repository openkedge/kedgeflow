#!/usr/bin/env python3
"""Initialize only an explicitly approved new Cura EBS data volume on its exact host.

Requires a fresh-volume manifest and opt-in. Existing filesystems are never erased;
idempotent recovery requires the exact declared UUID and matching enrollment.
No service, protocol authority, credential or owner acceptance is created.
"""

import argparse
import grp
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import urllib.request
import uuid
from pathlib import Path

MOUNT = Path("/var/lib/kedgeflow/pilot")
LAYOUT = {
    "Services": {"pki": "root", "configuration": "root", "operations": "root"},
    "Sql": {"postgresql": "kf-postgres", "configuration": "root"},
    "Identity": {
        "identity-db": "kf-identity-db",
        "keycloak": "kf-keycloak",
        "spire-server": "kf-spire-server",
        "configuration": "root",
    },
    "LedgerA": {"etcd": "kf-etcd", "configuration": "root"},
    "LedgerB": {"etcd": "kf-etcd", "configuration": "root"},
    "LedgerC": {"etcd": "kf-etcd", "configuration": "root"},
    "Witness": {"witness": "kf-witness", "configuration": "root"},
    "Audit": {"collector": "kf-collector", "configuration": "root"},
}


def run(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if check and result.returncode:
        raise RuntimeError("storage operation failed: " + argv[0])
    return result


def validate(manifest):
    if set(manifest) != {
        "format",
        "instance_id",
        "host",
        "volume_id",
        "filesystem_uuid",
        "approved_new_empty_volume",
    }:
        raise ValueError("closed storage manifest required")
    if (
        manifest["format"] != "kedgeflow-cura-new-storage-v1"
        or manifest["host"] not in LAYOUT
        or manifest["approved_new_empty_volume"] is not True
        or not re.fullmatch(r"i-[0-9a-f]{17}", manifest["instance_id"])
        or not re.fullmatch(r"vol-[0-9a-f]{17}", manifest["volume_id"])
        or str(uuid.UUID(manifest["filesystem_uuid"])) != manifest["filesystem_uuid"]
    ):
        raise ValueError("explicit exact host, volume and filesystem identity required")


def enroll(manifest):
    validate(manifest)
    if os.geteuid() != 0 or sys.platform != "linux":
        raise RuntimeError("requires privileged Linux launcher")
    token = (
        urllib.request.urlopen(
            urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                method="PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            ),
            timeout=5,
        )
        .read()
        .decode()
    )
    instance = (
        urllib.request.urlopen(
            urllib.request.Request(
                "http://169.254.169.254/latest/meta-data/instance-id",
                headers={"X-aws-ec2-metadata-token": token},
            ),
            timeout=5,
        )
        .read()
        .decode()
    )
    if instance != manifest["instance_id"]:
        raise RuntimeError("instance does not match storage enrollment")
    disks = json.loads(
        run(
            ["lsblk", "--json", "--bytes", "--output", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,SERIAL"]
        ).stdout
    )["blockdevices"]
    matches = [
        d
        for d in disks
        if (d.get("serial") or "").replace("-", "") == manifest["volume_id"].replace("-", "")
    ]
    if len(matches) != 1:
        raise RuntimeError("exact approved EBS serial not found")
    disk = matches[0]
    if disk["type"] != "disk" or disk["size"] != 32 * 1024**3 or disk.get("children"):
        raise RuntimeError("unexpected volume layout; refusing initialization")
    device = "/dev/" + disk["name"]
    current_uuid = run(["blkid", "-p", "-s", "UUID", "-o", "value", device], False).stdout.strip()
    if not current_uuid:
        signatures = json.loads(run(["wipefs", "--no-act", "--json", device]).stdout)
        if disk.get("fstype") or any(disk["mountpoints"]) or signatures.get("signatures"):
            raise RuntimeError("volume is not blank; refusing initialization")
        run(
            [
                "mkfs.ext4",
                "-q",
                "-L",
                "kfcura-" + manifest["host"].lower(),
                "-U",
                manifest["filesystem_uuid"],
                device,
            ]
        )
    elif current_uuid != manifest["filesystem_uuid"] or disk["fstype"] != "ext4":
        raise RuntimeError("existing filesystem identity differs; never erase it")
    if not MOUNT.exists():
        MOUNT.mkdir(mode=0o711, parents=True)
    if not MOUNT.is_mount() and any(MOUNT.iterdir()):
        raise RuntimeError("unmounted path contains files; refusing shadowing")
    common = MOUNT.parent
    if common.is_symlink() or common.stat().st_uid != 0:
        raise RuntimeError("shared data ancestor must be root owned")
    # Private umask applies to secrets, not this shared traversal ancestor.
    # Per-provider directories remain owner-only 0700 below the mount.
    common.chmod(0o711)
    fstab = Path("/etc/fstab")
    line = (
        f"UUID={manifest['filesystem_uuid']} {MOUNT} ext4 "
        "defaults,nodev,nosuid,noexec,nofail,x-systemd.device-timeout=30s 0 2"
    )
    existing = fstab.read_text()
    entries = [
        row
        for row in existing.splitlines()
        if row.strip()
        and not row.lstrip().startswith("#")
        and len(row.split()) > 1
        and row.split()[1] == str(MOUNT)
    ]
    if entries and entries != [line]:
        raise RuntimeError("existing mount declaration differs")
    if not entries:
        temporary = Path("/etc/fstab.kedgeflow-cura-new")
        with temporary.open("x") as output:
            output.write(existing.rstrip() + "\n# kedgeflow-cura-approved-data-v1\n" + line + "\n")
        temporary.chmod(0o644)
        temporary.replace(fstab)
        run(["systemctl", "daemon-reload"])
    if not MOUNT.is_mount():
        run(["mount", str(MOUNT)])
    mounted = json.loads(run(["findmnt", "--json", "--mountpoint", str(MOUNT)]).stdout)[
        "filesystems"
    ]
    if len(mounted) != 1 or mounted[0]["source"] != device:
        raise RuntimeError("mounted source differs from approved volume")
    if not {"nodev", "nosuid", "noexec"}.issubset(set(mounted[0]["options"].split(","))):
        raise RuntimeError("required data mount restrictions absent")
    marker = MOUNT / ".host-enrollment.json"
    if marker.exists():
        if json.loads(marker.read_text()) != manifest:
            raise RuntimeError("retained enrollment differs; refusing changes")
    else:
        if set(p.name for p in MOUNT.iterdir()) - {"lost+found"}:
            raise RuntimeError("unexpected retained files; refusing new enrollment")
        with marker.open("x") as output:
            json.dump(manifest, output, indent=2)
            output.write("\n")
        marker.chmod(0o600)
    MOUNT.chmod(0o711)
    for name, owner in LAYOUT[manifest["host"]].items():
        directory = MOUNT / name
        user, group = pwd.getpwnam(owner), grp.getgrnam(owner)
        if not directory.exists():
            directory.mkdir(mode=0o700)
            os.chown(directory, user.pw_uid, group.gr_gid)
        info = directory.lstat()
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or info.st_uid != user.pw_uid
            or info.st_gid != group.gr_gid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise RuntimeError("retained directory custody differs")
    return {
        "format": "kedgeflow-cura-storage-observation-v1",
        "status": "mounted_new_data",
        "host": manifest["host"],
        "volume_id": manifest["volume_id"],
        "filesystem_uuid": manifest["filesystem_uuid"],
        "services_started": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--initialize-approved-new-volume", action="store_true")
    args = parser.parse_args()
    if not args.initialize_approved_new_volume:
        parser.error("requires explicit approved-new-volume initialization")
    try:
        print(json.dumps(enroll(json.loads(args.manifest.read_text())), indent=2))
    except Exception as error:
        print(json.dumps({"status": "refused", "reason": str(error)}))
        raise SystemExit(1) from None
