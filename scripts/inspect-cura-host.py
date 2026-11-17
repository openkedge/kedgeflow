#!/usr/bin/env python3
"""Read-only inspection of an unenrolled Cura image on its actual Linux host.

Run as root through the approved management path. Prints hashes, public versions,
UIDs and booleans only; never prints configuration, tokens or management state.
This checks installed infrastructure, not enterprise action acceptance.
"""

import hashlib
import json
import os
import platform
import pwd
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"public runtime probe failed: {argv[0]} ({result.returncode})")
    return (result.stdout + result.stderr).strip()


def inspect():
    if os.geteuid() != 0 or platform.system() != "Linux":
        raise RuntimeError("requires root inspection on the selected Linux host")
    release = Path("/opt/kedgeflow/current").resolve(strict=True)
    manifest = json.loads((release / "manifest.json").read_text())
    for relative, entry in manifest["files"].items():
        path = release / relative
        if path.is_symlink() or not path.is_file() or not path.is_relative_to(release):
            raise RuntimeError("invalid installed bundle member")
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise RuntimeError("installed bundle hash differs")
        if stat.S_IMODE(path.stat().st_mode) != entry["mode"]:
            raise RuntimeError("installed bundle mode differs")
    users = {user.pw_name: user for user in pwd.getpwall() if user.pw_name.startswith("kf-")}
    if not users or len({u.pw_uid for u in users.values()}) != len(users):
        raise RuntimeError("service identities are absent or overlap")
    if any(u.pw_uid == 0 or u.pw_shell != "/usr/sbin/nologin" for u in users.values()):
        raise RuntimeError("invalid runtime service identity")
    versions = {}
    for binary in sorted((release / "bin").iterdir()):
        flag = "--help" if binary.name == "kf-ledger-credentials" else "--version"
        versions[binary.name] = command(["runuser", "-u", "kf-agent", "--", str(binary), flag])
    for component, user, binary in (
        ("postgres", "kf-postgres", "postgres/bin/postgres"),
        ("node", "kf-agent", "node/bin/node"),
        ("etcd", "kf-etcd", "etcd/etcd"),
        ("spire", "kf-spire-server", "spire/bin/spire-server"),
        ("keycloak", "kf-keycloak", "keycloak/bin/kc.sh"),
    ):
        versions[component] = command(
            ["runuser", "-u", user, "--", "/opt/kedgeflow/runtime/" + binary, "--version"]
        )
    units = sorted(
        p.name
        for p in Path("/etc/systemd/system").glob("kedgeflow*")
        if p.suffix in (".service", ".timer", ".target")
    )
    active, enabled, unit_states = [], [], {}
    for unit in [*units, "ssh.service", "ssh.socket"]:
        states = {}
        for action in ("is-active", "is-enabled"):
            result = subprocess.run(
                ["systemctl", action, unit], capture_output=True, text=True, timeout=10
            )
            states[action] = result.stdout.strip()
        unit_states[unit] = states
        if states["is-active"] != "inactive":
            active.append(unit)
        # systemctl returns zero for static helpers too. Check the state name;
        # their activating timers/targets are independently checked above.
        if states["is-enabled"] not in ("disabled", "static", "masked"):
            enabled.append(unit)
    configuration_files = sum(p.is_file() for p in Path("/etc/kedgeflow").rglob("*"))
    if active or enabled or configuration_files:
        raise RuntimeError("host is not an unenrolled, disabled application image")
    return {
        "format": "kedgeflow-cura-host-inspection-v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed_unenrolled_host_checks",
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "machine_id_sha256": hashlib.sha256(Path("/etc/machine-id").read_bytes()).hexdigest(),
        "bundle_id": manifest["bundle_id"],
        "bundle_files_verified": len(manifest["files"]),
        "service_uids": {name: u.pw_uid for name, u in users.items()},
        "versions": versions,
        "active_application_or_ssh_units": active,
        "enabled_application_or_ssh_units": enabled,
        "unit_states": unit_states,
        "application_configuration_files": configuration_files,
        "ssm_version": command(["amazon-ssm-agent", "-version"]),
        "dpkg_inventory_sha256": hashlib.sha256(
            command(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"]).encode()
        ).hexdigest(),
        "block_devices": json.loads(
            command(
                [
                    "lsblk",
                    "--json",
                    "--bytes",
                    "--output",
                    "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,SERIAL",
                ]
            )
        )["blockdevices"],
        "production_qualified": False,
        "execution_authority": False,
    }


if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2))
