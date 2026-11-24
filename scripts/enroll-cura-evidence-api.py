#!/usr/bin/env python3
"""Install only the fixed-row read-only source/relay and a technical registry candidate.

No database DDL, writer permission, protocol authority enrollment or acceptance.
Secrets stay on their owning hosts; stdout is bounded public metadata only.
"""

import argparse
import base64
import hashlib
import json
import os
import pwd
import re
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DATA = Path("/var/lib/kedgeflow/pilot")
NODE = Path("/opt/kedgeflow/runtime/node/bin/node")
SOURCE_FILES = {
    "scripts/cura-sql-evidence.mjs",
    "scripts/cura-sql-profile.mjs",
    "sdk/node/records.mjs",
    "sdk/node/identity-profile.mjs",
    "sdk/node/sql-leaf.mjs",
    "spec/drafts/cedar-leaf-v0.1.schema.json",
}
PHASE = "protected_preconditions"


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError("bounded evidence operation refused")
    return result.stdout


def protected(path, uid, mode):
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_nlink != 1
        or info.st_uid != uid
        or info.st_mode & 0o7777 != mode
        or info.st_size > 1 << 20
    ):
        raise RuntimeError("evidence configuration custody differs")
    return path.read_bytes()


def write_once(path, raw, uid=0, gid=0, mode=0o600):
    raw = raw.encode() if isinstance(raw, str) else raw
    if path.exists() or path.is_symlink():
        if protected(path, uid, mode) != raw or path.stat().st_gid != gid:
            raise RuntimeError("existing evidence enrollment differs; never replace")
        return
    with path.open("xb") as stream:
        os.chown(path, uid, gid)
        path.chmod(mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def directory(path, uid, gid, mode):
    if not path.exists():
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        path.chmod(mode)
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_dir()
        or info.st_uid != uid
        or info.st_gid != gid
        or info.st_mode & 0o7777 != mode
    ):
        raise RuntimeError("evidence directory custody differs")


def verify_source(root, manifest, node_sha256):
    if (
        not re.fullmatch(r"/opt/kedgeflow/cura-runtime/sql-observer-[a-f0-9]{12}", str(root))
        or set(manifest) != SOURCE_FILES
        or not re.fullmatch(r"[a-f0-9]{64}", node_sha256)
        or NODE.is_symlink()
        or NODE.stat().st_uid != 0
        or NODE.stat().st_mode & 0o022
        or hashlib.sha256(NODE.read_bytes()).hexdigest() != node_sha256
    ):
        raise RuntimeError("pinned runtime/source scope differs")
    for relative, expected in manifest.items():
        if (
            not re.fullmatch(r"[a-f0-9]{64}", expected)
            or hashlib.sha256(protected(root / relative, 0, 0o444)).hexdigest() != expected
        ):
            raise RuntimeError("installed observation module source differs")
        for parent in (root / relative).parents:
            info = parent.lstat()
            if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("unsafe executable source ancestor")
            if parent == Path("/opt"):
                break


def prepare_profile(root, input_path):
    global PHASE
    PHASE = "protected_registry_identity"
    operator = DATA / "operations"
    user = pwd.getpwnam("kf-governance")
    seed = DATA / "configuration/governance/registry.seed"
    pins = operator / "sql-registration-public-pins.json"
    if pins.exists() and not seed.exists():
        raise RuntimeError("enrolled registry key missing; never regenerate")
    if not seed.exists():
        write_once(seed, base64.b64encode(os.urandom(32)), user.pw_uid, user.pw_gid, 0o400)
    raw = base64.b64decode(protected(seed, user.pw_uid, 0o400), validate=True)
    if len(raw) != 32:
        raise RuntimeError("registry seed length differs")
    public = (
        base64.urlsafe_b64encode(
            Ed25519PrivateKey.from_private_bytes(raw)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        .decode()
        .rstrip("=")
    )
    PHASE = "nonroot_registry_signing"
    projected_seed = Path("/etc/kedgeflow/governance/registry.seed")
    if (seed.stat().st_dev, seed.stat().st_ino) != (
        projected_seed.stat().st_dev,
        projected_seed.stat().st_ino,
    ):
        raise RuntimeError("registry readonly custody projection differs")
    result = json.loads(
        run(
            [
                "runuser",
                "-u",
                user.pw_name,
                "--",
                str(NODE),
                "--jitless",
                str(root / "scripts/cura-sql-profile.mjs"),
                str(input_path),
                str(projected_seed),
            ]
        )
    )
    if result["registryKeys"] != {"urn:kf:cura:registry:v1": public}:
        raise RuntimeError("registry identity differs")
    public_pins = {
        "registryKeys": result["registryKeys"],
        "descriptor_digest": result["contract"]["descriptorDigest"],
        "contract": result["contract"],
    }
    write_once(pins, json.dumps(public_pins, sort_keys=True) + "\n")
    write_once(operator / "sql-registration.json", json.dumps(result, sort_keys=True) + "\n")
    result["registry_private_key_returned"] = False
    return result


def unit(root, role):
    source = role == "source"
    config = "sql-observer" if source else "evidence-relay"
    state = "ReadWritePaths=/var/lib/kedgeflow/pilot/sql-observer\n" if source else ""
    extra = (
        "After=kedgeflow-postgres.service\nRequires=kedgeflow-postgres.service\n" if source else ""
    )
    groups = "SupplementaryGroups=kf-postgres\n" if source else ""
    command = (
        f"{NODE} --jitless {root}/scripts/cura-sql-evidence.mjs /etc/kedgeflow/{config}/config.json"
    )
    return f"""[Unit]
Description=Cura fixed-row SQL evidence {role}
After=network-online.target
Wants=network-online.target
RequiresMountsFor={DATA} /etc/kedgeflow/{config}
{extra}[Service]
Type=exec
User=kf-observer
Group=kf-observer
{groups}WorkingDirectory=/
UMask=0077
BindReadOnlyPaths=/etc/kedgeflow/{config}/resolv.conf:/etc/resolv.conf
ExecStartPre={command} --check
ExecStart={command}
{state}Restart=on-failure
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=15s
KillMode=control-group
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_UNIX AF_INET
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
IPAddressDeny=any
IPAddressAllow=10.87.0.0/16
RemoveIPC=yes
MemoryMax=256M
TasksMax=64
LimitNOFILE=512
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
"""


def install(root, host, registration, spire_bundle):
    global PHASE
    PHASE = "fixed_row_source_or_relay_enrollment"
    user = pwd.getpwnam("kf-observer")
    if user.pw_uid != 971:
        raise RuntimeError("registered observer UID differs")
    role = "source" if host == "Sql" else "relay"
    name = "sql-observer" if host == "Sql" else "evidence-relay"
    source, target = DATA / "configuration" / name, Path("/etc/kedgeflow") / name
    for path in [source, target]:
        info = path.stat()
        if (
            path.is_symlink()
            or info.st_uid != 0
            or info.st_gid != user.pw_gid
            or info.st_mode & 0o7777 != 0o750
        ):
            raise RuntimeError("host-local observation PKI custody differs")
    if (source.stat().st_dev, source.stat().st_ino) != (target.stat().st_dev, target.stat().st_ino):
        raise RuntimeError("readonly configuration bind differs")
    if registration["format"] != "kedgeflow-cura-sql-registration-v1":
        raise RuntimeError("technical registration format differs")
    if host == "Sql":
        enrollment = json.loads(
            protected(DATA / "configuration/postgres-operator/enrollment.json", 0, 0o600)
        )
        if registration["contract"]["resource"]["incarnation"] != enrollment["incarnation"]:
            raise RuntimeError("Sql registered incarnation differs")
        state = DATA / "sql-observer"
        directory(state, user.pw_uid, user.pw_gid, 0o700)
        directory(state / "replay", user.pw_uid, user.pw_gid, 0o700)
    else:
        if set(os.getgrouplist(user.pw_name, user.pw_gid)) != {user.pw_gid}:
            raise RuntimeError("relay must inherit no database or service group")
        from cryptography import x509

        certificates = x509.load_pem_x509_certificates(spire_bundle)
        if not certificates or b"PRIVATE" in spire_bundle:
            raise RuntimeError("canonical public workload trust required")
        write_once(source / "spire-ca.pem", spire_bundle, mode=0o444)
    config = {
        "mode": role,
        "contract": registration["contract"],
        "tlsRoot": str(target),
        "replayRoot": "/var/lib/kedgeflow/pilot/sql-observer/replay",
    }
    write_once(
        source / "config.json",
        json.dumps(config, sort_keys=True) + "\n",
        gid=user.pw_gid,
        mode=0o440,
    )
    write_once(
        source / "resolv.conf", "nameserver 10.87.0.2\noptions timeout:2 attempts:2\n", mode=0o444
    )
    path = Path("/etc/systemd/system") / ("kedgeflow-" + name + ".service")
    write_once(path, unit(root, role), mode=0o644)
    PHASE = "nonroot_protected_configuration_check"
    checked = json.loads(
        run(
            [
                "runuser",
                "-u",
                user.pw_name,
                "--",
                str(NODE),
                "--jitless",
                str(root / "scripts/cura-sql-evidence.mjs"),
                str(target / "config.json"),
                "--check",
            ]
        )
    )
    if checked["status"] != "protected_configuration_passed":
        raise RuntimeError("protected runtime preflight refused")
    run(["systemctl", "daemon-reload"])
    run(["systemd-analyze", "verify", str(path)])
    run(["systemctl", "start", path.name])
    run(["systemctl", "is-active", "--quiet", path.name])
    run(["systemctl", "enable", path.name])
    return {
        "status": "managed_read_only_observer_started",
        "host": host,
        "role": role,
        "uid": user.pw_uid,
        "port": 8452 if host == "Sql" else 8444,
        "database_writes_granted": False,
        "dispatches_issued": 0,
        "signed_response_qualification": "PENDING",
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, choices=["Services", "Sql"])
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--node-sha256", required=True)
    parser.add_argument("--profile-input", type=Path)
    parser.add_argument("--registration", type=Path)
    parser.add_argument("--spire-bundle", type=Path)
    args = parser.parse_args()
    try:
        if (
            os.geteuid() != 0
            or not DATA.is_mount()
            or json.loads(protected(DATA / ".host-enrollment.json", 0, 0o600))["host"] != args.host
        ):
            raise RuntimeError("exact retained service host required")
        verify_source(
            args.runtime_root, json.loads(args.source_manifest.read_text()), args.node_sha256
        )
        if args.profile_input:
            if args.host != "Services" or args.registration or args.spire_bundle:
                raise ValueError("registry preparation requires exact Services input")
            result = prepare_profile(args.runtime_root, args.profile_input)
        else:
            if not args.registration or (args.host == "Services" and not args.spire_bundle):
                raise ValueError("public registration and workload trust required")
            result = install(
                args.runtime_root,
                args.host,
                json.loads(args.registration.read_text()),
                args.spire_bundle.read_bytes() if args.spire_bundle else None,
            )
        print(json.dumps(result))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
