#!/usr/bin/env python3
"""Read-only native service preflight under the actual kernel identities; no enrollment."""

import argparse
import grp
import json
import os
import pwd
import stat
import subprocess
from pathlib import Path

ROLES = {
    "gateway": "kf-proxy",
    "control": "kf-control",
    "broker": "kf-broker",
    "sql-target": "kf-postgres-target",
    "recovery": "kf-supervise",
    "collector": "kf-outcomes",
    "governance": "kf-governance",
    "operator": "kf-restore",
}


def preflight(binaries: Path, configuration: Path, peer_uid: int, selected=None):
    if os.geteuid() != 0 or peer_uid <= 0:
        raise ValueError("requires privileged read-only launcher and nonzero approved database UID")
    results = []
    roles = list(ROLES) if selected is None else selected
    if not roles or len(roles) != len(set(roles)) or any(r not in ROLES for r in roles):
        raise ValueError("explicit unique supported roles required")
    for role in roles:
        binary = ROLES[role]
        accepted = False
        try:
            user = pwd.getpwnam("kf-" + role)
            root = configuration / role
            info = root.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_gid != grp.getgrnam("kf-" + role).gr_gid
                or stat.S_IMODE(info.st_mode) != 0o750
            ):
                raise ValueError("protected root ownership or mode")
            # Native custody validation checks every referenced file and schema.
            command = [
                "runuser",
                "-u",
                user.pw_name,
                "--",
                str(binaries / binary),
                "--config",
                str(root / "config.json"),
                "--custody-root",
                str(root),
                "--require-managed",
                "--check",
            ]
            if role == "sql-target":
                command.extend(["--postgres-peer-uid", str(peer_uid)])
            result = subprocess.run(command, capture_output=True, timeout=30, check=False)
            accepted = result.returncode == 0
        except (OSError, KeyError, ValueError, subprocess.SubprocessError):
            pass
        # Do not export loader diagnostics, credentials or configuration contents.
        results.append({"role": role, "local_material_validated": accepted})
    return {
        "state": "local_material_validated"
        if all(r["local_material_validated"] for r in results)
        else "blocked",
        "roles": results,
        "live_dependencies_verified": False,
        "production_qualified": False,
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--configuration-root", type=Path, required=True)
    parser.add_argument("--postgres-peer-uid", type=int, required=True)
    parser.add_argument("--roles", nargs="+", choices=list(ROLES))
    args = parser.parse_args()
    if not args.configuration_root.is_absolute() or "\n" in str(args.configuration_root):
        parser.error("configuration root must be absolute")
    result = preflight(
        args.binary_dir.resolve(), args.configuration_root, args.postgres_peer_uid, args.roles
    )
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["state"] == "local_material_validated" else 1)
