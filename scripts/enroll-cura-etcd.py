#!/usr/bin/env python3
"""Prepare retained operator-managed Cura etcd members without resetting authority.

The primary cluster and separate witness have distinct data and bootstrap tokens.
Requires host-local signed service TLS. Authentication/role enrollment on Services
must immediately follow initial cluster readiness, before any protocol service starts.
"""

import argparse
import ipaddress
import json
import os
import pwd
import socket
import subprocess
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
DOMAIN = "cura.kedgeflow.internal"
ETCD = "/opt/kedgeflow/runtime/etcd/etcd"
HOSTS = ("LedgerA", "LedgerB", "LedgerC", "Witness")


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError("etcd enrollment operation failed")
    return result


def specification(host):
    if host not in HOSTS:
        raise ValueError("unregistered ledger host")
    witness = host == "Witness"
    members = [host] if witness else list(HOSTS[:3])
    return {
        "host": host,
        "name": host.lower(),
        "user": "kf-witness" if witness else "kf-etcd",
        "role": "witness-etcd" if witness else "etcd",
        "data": str(DATA / ("witness" if witness else "etcd")),
        "initial_cluster": ",".join(
            f"{m.lower()}=https://{m.lower()}.{DOMAIN}:2380" for m in members
        ),
        "initial_cluster_token": "cura-witness-20261117-v1"
        if witness
        else "cura-authority-20261117-v1",
    }


def bind_address(host):
    address = socket.gethostbyname(host.lower() + "." + DOMAIN)
    if ipaddress.ip_address(address) not in ipaddress.ip_network("10.87.0.0/16"):
        raise RuntimeError("ledger DNS does not resolve inside approved private VPC")
    return address


def unit(spec, address):
    role, user, name = spec["role"], spec["user"], spec["name"]
    material = "/etc/kedgeflow/" + role
    command = " ".join(
        [
            ETCD,
            "--name=" + name,
            "--data-dir=" + spec["data"],
            "--listen-client-urls=https://" + address + ":2379",
            "--advertise-client-urls=https://" + name + "." + DOMAIN + ":2379",
            "--listen-peer-urls=https://" + address + ":2380",
            "--initial-advertise-peer-urls=https://" + name + "." + DOMAIN + ":2380",
            "--initial-cluster=" + spec["initial_cluster"],
            "--initial-cluster-token=" + spec["initial_cluster_token"],
            "--initial-cluster-state=new",
            "--strict-reconfig-check=true",
            "--client-cert-auth=true",
            "--peer-client-cert-auth=true",
            "--cert-file=" + material + "/identity.pem",
            "--key-file=" + material + "/identity.key",
            "--trusted-ca-file=" + material + "/ca.pem",
            "--peer-cert-file=" + material + "/identity.pem",
            "--peer-key-file=" + material + "/identity.key",
            "--peer-trusted-ca-file=" + material + "/ca.pem",
            "--tls-min-version=TLS1.3",
            "--enable-grpc-gateway=true",
            "--auth-token=simple",
            "--auth-token-ttl=300",
            "--quota-backend-bytes=1073741824",
            "--snapshot-count=10000",
            "--max-snapshots=3",
            "--max-wals=3",
            "--log-level=error",
        ]
    )
    return f"""[Unit]
Description=KedgeFlow Cura retained {name} etcd member
After=network-online.target
Wants=network-online.target
RequiresMountsFor={DATA} {material}
ConditionPathIsMountPoint={DATA}
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
Type=exec
User={user}
Group={user}
ExecStart={command}
BindReadOnlyPaths={material}/resolv.conf:/etc/resolv.conf
Environment=GODEBUG=netdns=go
ReadWritePaths={spec["data"]}
UMask=0077
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
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET
IPAddressDeny=any
IPAddressAllow=10.87.0.0/16
Restart=on-failure
RestartSec=5s
TimeoutStopSec=60s
KillMode=control-group
MemoryMax=1G
TasksMax=256
LimitNOFILE=4096
[Install]
WantedBy=multi-user.target
"""


def write_once(path, raw, mode):
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_nlink != 1
            or info.st_uid != 0
            or info.st_mode & 0o7777 != mode
            or path.read_text() != raw
        ):
            raise RuntimeError("existing etcd enrollment configuration differs; never replace")
        return
    with path.open("x") as stream:
        stream.write(raw)
    path.chmod(mode)


def enroll(host):
    if os.geteuid() != 0 or not DATA.is_mount():
        raise RuntimeError("requires privileged retained ledger host")
    state = json.loads((DATA / ".host-enrollment.json").read_text())
    if state["host"] != host:
        raise RuntimeError("wrong enrolled ledger host")
    spec = specification(host)
    address = bind_address(host)
    user = pwd.getpwnam(spec["user"])
    if user.pw_uid == 0:
        raise RuntimeError("non-root ledger identity required")
    if "etcd Version: 3.6.5" not in run([ETCD, "--version"]).stdout:
        raise RuntimeError("pinned etcd version differs")
    data = Path(spec["data"])
    if (
        data.is_symlink()
        or data.stat().st_uid != user.pw_uid
        or data.stat().st_mode & 0o7777 != 0o700
    ):
        raise RuntimeError("retained ledger data custody differs")
    source = DATA / "configuration" / spec["role"]
    material = Path("/etc/kedgeflow") / spec["role"]
    if (
        source.is_symlink()
        or source.stat().st_uid != 0
        or material.stat().st_ino != source.stat().st_ino
        or material.stat().st_dev != source.stat().st_dev
    ):
        raise RuntimeError("protected TLS configuration projection differs")
    for name in ["identity.key", "identity.pem", "ca.pem"]:
        path = source / name
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_nlink != 1
            or info.st_mode & 0o7777 != (0o400 if name.endswith("key") else 0o444)
            or info.st_uid != (user.pw_uid if name.endswith("key") else 0)
        ):
            raise RuntimeError("ledger transport file custody differs")
    marker = DATA / "configuration" / (spec["role"] + "-enrollment.json")
    expected = {
        **spec,
        "instance_id": state["instance_id"],
        "filesystem_uuid": state["filesystem_uuid"],
        "bind_address": address,
    }
    if not marker.exists() and any(data.iterdir()):
        raise RuntimeError("unenrolled ledger already contains data; never reset")
    write_once(marker, json.dumps(expected, sort_keys=True) + "\n", 0o600)
    write_once(
        source / "resolv.conf", "nameserver 10.87.0.2\noptions timeout:2 attempts:2\n", 0o444
    )
    name = "kedgeflow-" + spec["role"] + ".service"
    write_once(Path("/etc/systemd/system") / name, unit(spec, address), 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "start", name])
    # Do not enable yet: cluster health, RBAC and restart continuity are separate gates.
    return {
        "format": "kedgeflow-cura-etcd-member-v1",
        "status": "member_process_started",
        "host": host,
        "uid": user.pw_uid,
        "tls_client_and_peer_authentication": True,
        "gateway_listener": "private_host_ipv4_only",
        "unit_enabled": False,
        "force_new_cluster": False,
        "authority_records_created": False,
        "authentication_enrollment": "PENDING_OPERATOR_BOOTSTRAP",
        "independent_custody": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", choices=HOSTS, required=True)
    parser.add_argument("--operator-bootstrap", action="store_true")
    args = parser.parse_args()
    if not args.operator_bootstrap:
        parser.error("explicit operator bootstrap required")
    try:
        print(json.dumps(enroll(args.host), indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__}))
        raise SystemExit(1) from None
