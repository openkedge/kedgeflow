#!/usr/bin/env python3
"""Private launch adapter for the disposable managed-authority qualification."""

import argparse
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
from pathlib import Path

ROLES = {
    "kf-proxy": "gateway",
    "kf-control": "control",
    "kf-broker": "broker",
    "kf-postgres-target": "sql-target",
}


def registry(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if (
            meta.st_uid != 0
            or stat.S_IMODE(meta.st_mode) != 0o600
            or not stat.S_ISREG(meta.st_mode)
        ):
            raise ValueError("unprotected fixture registry")
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("fixture registry exceeds bound")
    state = json.loads(raw)
    base = Path(state["base"])
    if base.parent != Path("/run") or not base.name.startswith("kf-managed-"):
        raise ValueError("invalid fixture root")
    if path.resolve() != base / "state.json" or base.stat().st_uid != 0:
        raise ValueError("fixture registry root mismatch")
    return state


def act(state, binary, material, action, *, unit_directory=Path("/etc/systemd/system")):
    role = ROLES[binary]
    base = Path(state["base"])
    material = material.resolve(strict=True)
    if not material.is_relative_to(base / "work"):
        raise ValueError("service material escapes fixture root")
    if binary == "kf-control" and "admission" in state["users"]:
        role = json.loads((material / "config.json").read_bytes()).get("runtime_role")
        if role not in ("admission", "issuer"):
            raise ValueError("separated control role required")
    user = state["users"][role]
    identity = pwd.getpwnam(user)
    if identity.pw_uid == 0:
        raise ValueError("fixture service cannot run as root")
    name = base.name + "-" + role + ".service"
    unit = unit_directory / name
    ownership = base / ("unit-" + role)

    def systemctl(*args, check=True):
        return subprocess.run(
            ["systemctl", *args], capture_output=True, text=True, check=check, timeout=45
        )

    if action == "stop":
        if ownership.exists():
            systemctl("stop", name)
            systemctl("reset-failed", name, check=False)
            unit.unlink()
            ownership.unlink()
            systemctl("daemon-reload")
        return {"stopped": True}
    if action == "restart":
        if not ownership.exists():
            raise ValueError("fixture does not own this unit")
        systemctl("restart", name)
        return {"restarted": True}
    release = Path(state["release"])
    command = [
        str(release / "bin" / binary),
        "--config",
        str(material / "config.json"),
        "--custody-root",
        str(material),
        "--require-managed",
    ]
    if role == "sql-target":
        command.extend(["--postgres-peer-uid", str(state["postgres_uid"])])
    if role in ("admission", "issuer"):
        command.extend(["--runtime-role", role])
    if any(not re.fullmatch(r"[A-Za-z0-9_./:=\-]+", arg) for arg in command):
        raise ValueError("unsafe fixture unit argument")
    for path in material.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("unexpected service material")
        os.chown(path, identity.pw_uid, identity.pw_gid)
        path.chmod(0o400)
    os.chown(material, identity.pw_uid, identity.pw_gid)
    material.chmod(0o700)
    agent = state["users"]["agent"]
    probe = subprocess.run(
        [
            "runuser",
            "-u",
            agent,
            "--",
            "python3",
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes()",
            str(material / "identity.key"),
        ],
        capture_output=True,
        timeout=5,
    )
    if probe.returncode == 0:
        raise RuntimeError("agent read another role's private key")
    template = release / "share/systemd" / f"kedgeflow-{role}.service"
    if role in ("admission", "issuer"):
        template = release / "share/pilot/cura/systemd" / f"kedgeflow-{role}.service"
    preflight = "--check-database" if role == "sql-target" else "--check"
    text = template.read_text() + (
        f"\n[Service]\nUser={user}\nGroup={user}\nEnvironmentFile=\n"
        "ExecStartPre=\nExecStart=\n"
        f"ExecStartPre={' '.join(command)} {preflight}\n"
        f"ExecStart={' '.join(command)}\nRestart=no\n"
    )
    with unit.open("x") as stream:
        stream.write(text)
    ownership.touch(mode=0o600, exist_ok=False)
    try:
        systemctl("daemon-reload")
        systemctl("start", name)
        properties = dict(
            line.split("=", 1)
            for line in systemctl(
                "show",
                name,
                "-p",
                "MainPID,User,Group,ProtectSystem,PrivateTmp,"
                "NoNewPrivileges,CapabilityBoundingSet,RestrictNamespaces",
            ).stdout.splitlines()
            if "=" in line
        )
        status = dict(
            line.split(":", 1)
            for line in Path(f"/proc/{properties['MainPID']}/status").read_text().splitlines()
            if ":" in line
        )
        if not (
            int(status["Uid"].split()[1]) == identity.pw_uid
            and int(status["CapEff"].strip(), 16) == 0
            and status["Seccomp"].strip() == "2"
            and status["NoNewPrivs"].strip() == "1"
            and properties["ProtectSystem"] == "strict"
            and properties["PrivateTmp"] == "yes"
            and properties["NoNewPrivileges"] == "yes"
            and properties["RestrictNamespaces"] == "yes"
            and properties["CapabilityBoundingSet"] == ""
        ):
            raise RuntimeError("shipping unit sandbox not effective")
        return {
            "unit": name,
            "uid": identity.pw_uid,
            "properties": properties,
            "agent_private_key_read_refused": True,
            "binary_sha256": hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(),
        }
    except BaseException:
        systemctl("stop", name)
        systemctl("reset-failed", name, check=False)
        unit.unlink()
        ownership.unlink()
        systemctl("daemon-reload")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--action", choices=("start", "restart", "stop"), required=True)
    parser.add_argument("--material", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        parser.error("private fixture adapter requires Linux root and actual systemd")
    print(json.dumps(act(registry(args.state), args.role, args.material, args.action)))


if __name__ == "__main__":
    main()
