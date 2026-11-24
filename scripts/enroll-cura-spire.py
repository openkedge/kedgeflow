#!/usr/bin/env python3
"""Enroll the two exact Cura SPIRE nodes through temporary encrypted SSM delivery.

Join tokens never enter command arguments, SSM command text, stdout or the local
workspace. Workload JWT/private-key output remains on-host. No owner signatures
or enterprise approvals are generated.
"""

import argparse
import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

DOMAIN = "cura.kedgeflow.internal"
SERVER = "/opt/kedgeflow/runtime/spire/bin/spire-server"
AGENT = "/opt/kedgeflow/runtime/spire/bin/spire-agent"
SOCKET = "/run/kedgeflow-spire-server/server.sock"
WORKLOAD_SOCKET = "/run/kedgeflow-spire-agent/agent.sock"
PHASE = "preconditions"


def phase(value):
    global PHASE
    PHASE = value


def run(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if check and result.returncode:
        raise RuntimeError("local SPIRE operation refused")
    return result


def instance_id():
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
    return (
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


def validate(manifest):
    if set(manifest) != {"format", "pilot_stack", "kms_key_arn", "nodes"}:
        raise ValueError("closed enrollment manifest required")
    if (
        manifest["format"] != "kedgeflow-cura-spire-enrollment-v1"
        or not re.fullmatch(r"kedgeflow-cura-pilot-[0-9]{8}", manifest["pilot_stack"])
        or not re.fullmatch(
            r"arn:aws:kms:us-west-2:[0-9]{12}:key/[0-9a-f-]+", manifest["kms_key_arn"]
        )
        or set(manifest["nodes"]) != {"Services", "Agent"}
    ):
        raise ValueError("exact isolated pilot scope required")
    for name, user, workload in [
        ("Services", "kf-gateway", "gateway"),
        ("Agent", "kf-agent", "agent"),
    ]:
        node = manifest["nodes"][name]
        if (
            set(node) != {"instance_id", "user", "uid", "workload"}
            or not re.fullmatch(r"i-[0-9a-f]{17}", node["instance_id"])
            or node["user"] != user
            or type(node["uid"]) is not int
            or node["uid"] <= 0
            or node["workload"] != f"spiffe://{DOMAIN}/{workload}"
        ):
            raise ValueError("exact node and Unix workload identity required")
    if len({n["instance_id"] for n in manifest["nodes"].values()}) != 2:
        raise ValueError("nodes must use different hosts")


def parameter_name(manifest, name):
    return "/kedgeflow/cura/" + manifest["pilot_stack"] + "/bootstrap/" + name


def parent(node):
    return f"spiffe://{DOMAIN}/node/{node['instance_id']}"


def spiffe(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "spiffe://" + value.get("trust_domain", "") + value.get("path", "")
    raise ValueError("unrecognized public SPIFFE ID")


def admin(*args):
    return run(["runuser", "-u", "kf-spire-server", "--", SERVER, *args, "-socketPath", SOCKET])


def inventory():
    result = json.loads(admin("entry", "show", "-output", "json").stdout)
    if result.get("next_page_token") or not isinstance(result.get("entries"), list):
        raise RuntimeError("incomplete registration inventory")
    return result["entries"]


def matching(entries, node):
    found = [e for e in entries if spiffe(e.get("spiffe_id")) == node["workload"]]
    if len(found) > 1:
        raise RuntimeError("ambiguous workload registration")
    if found:
        entry = found[0]
        if spiffe(entry.get("parent_id")) != parent(node) or entry.get("selectors") != [
            {"type": "unix", "value": "uid:" + str(node["uid"])}
        ]:
            raise RuntimeError("existing workload registration scope differs")
    return bool(found)


def initial_alias(entry, manifest):
    """Recognize only SPIRE's token-created alias for an exact declared node."""
    if spiffe(entry.get("spiffe_id")) not in {parent(n) for n in manifest["nodes"].values()}:
        return False
    identity = spiffe(entry.get("parent_id"))
    return (
        identity.startswith(f"spiffe://{DOMAIN}/spire/agent/join_token/")
        and entry.get("selectors") == [{"type": "spiffe_id", "value": identity}]
        and not entry.get("admin")
        and not entry.get("downstream")
        and not entry.get("federates_with")
        and not entry.get("dns_names")
        and not entry.get("store_svid")
    )


def server_enroll(manifest, retry_expired=False, retry_node=None):
    import boto3

    if (
        json.loads(Path("/var/lib/kedgeflow/pilot/.host-enrollment.json").read_text())["host"]
        != "Identity"
    ):
        raise RuntimeError("requires retained Identity host")
    phase("closed_workload_registration")
    entries = inventory()
    allowed = {n["workload"] for n in manifest["nodes"].values()}
    if any(
        spiffe(e.get("spiffe_id")) not in allowed and not initial_alias(e, manifest)
        for e in entries
    ):
        raise RuntimeError("unregistered workloads exist outside the closed pilot")
    for node in manifest["nodes"].values():
        if not matching(entries, node):
            admin(
                "entry",
                "create",
                "-parentID",
                parent(node),
                "-spiffeID",
                node["workload"],
                "-selector",
                "unix:uid:" + str(node["uid"]),
                "-output",
                "json",
            )
            entries = inventory()
            if not matching(entries, node):
                raise RuntimeError("workload registration not retained")
    raw_bundle = admin("bundle", "show").stdout
    if "PRIVATE KEY" in raw_bundle or "-----BEGIN CERTIFICATE-----" not in raw_bundle:
        raise RuntimeError("invalid public trust bundle")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    bundle = "".join(
        certificate.public_bytes(serialization.Encoding.PEM).decode()
        for certificate in x509.load_pem_x509_certificates(raw_bundle.encode())
    )
    if not bundle:
        raise RuntimeError("empty public trust bundle")
    ssm = boto3.client("ssm", region_name="us-west-2")
    state_path = Path("/var/lib/kedgeflow/pilot/configuration/identity-operator/node-delivery.json")
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    selected = list(manifest["nodes"])
    if retry_node:
        selected = [retry_node]
        aliases = [
            e
            for e in entries
            if initial_alias(e, manifest)
            and spiffe(e["spiffe_id"]) == parent(manifest["nodes"][retry_node])
        ]
        if (
            len(aliases) != 1
            or retry_node not in state
            or (state[retry_node]["issued_at"] + 600 > int(time.time()))
        ):
            raise RuntimeError("target delivery is not a unique expired initial enrollment")
        agents = json.loads(admin("agent", "list", "-output", "json").stdout)
        if agents.get("next_page_token") or not isinstance(agents.get("agents"), list):
            raise RuntimeError("incomplete agent inventory")
        target_identity = spiffe(aliases[0]["parent_id"])
        for agent in agents["agents"]:
            identity = spiffe(agent.get("id", agent.get("spiffe_id")))
            if identity == target_identity:
                raise RuntimeError("target node is already attested; never reset its identity")
        history = state_path.with_name("partial-delivery-history.jsonl")
        with history.open("a") as output:
            output.write(
                json.dumps(
                    {
                        "retried_at": int(time.time()),
                        "node": retry_node,
                        "expired_delivery": state[retry_node],
                        "expired_alias": aliases[0],
                    }
                )
                + "\n"
            )
        history.chmod(0o600)
        admin("entry", "delete", "-entryID", aliases[0]["id"])
        ssm.delete_parameter(Name=parameter_name(manifest, retry_node))
        state.pop(retry_node)
        state_path.write_text(json.dumps(state) + "\n")
    if retry_expired:
        agents = json.loads(admin("agent", "list", "-output", "json").stdout)
        if agents.get("next_page_token") or agents.get("agents") != []:
            raise RuntimeError("cannot retry initial delivery after any node attested")
        if set(state) != {"Services", "Agent"} or any(
            record["issued_at"] + 600 > int(time.time()) for record in state.values()
        ):
            raise RuntimeError("only fully expired initial deliveries can be retried")
        history = state_path.with_name("node-delivery-history.jsonl")
        with history.open("a") as output:
            output.write(
                json.dumps({"expired_delivery": state, "retried_at": int(time.time())}) + "\n"
            )
        history.chmod(0o600)
        # token generate creates an alias entry as well as an ephemeral token.
        # Revoke only those expired, never-attested initial aliases; retain their
        # complete private metadata locally before removal, not in tool output.
        aliases = [e for e in entries if initial_alias(e, manifest)]
        if len(aliases) != 2 or {spiffe(e["spiffe_id"]) for e in aliases} != {
            parent(n) for n in manifest["nodes"].values()
        }:
            raise RuntimeError("expired initial alias inventory differs")
        archive = state_path.with_name("expired-initial-aliases.jsonl")
        with archive.open("a") as output:
            output.write(json.dumps({"archived_at": int(time.time()), "entries": aliases}) + "\n")
        archive.chmod(0o600)
        for entry in aliases:
            admin("entry", "delete", "-entryID", entry["id"])
        for name in manifest["nodes"]:
            ssm.delete_parameter(Name=parameter_name(manifest, name))
        state = {}
        state_path.write_text("{}\n")
    for name in selected:
        node = manifest["nodes"][name]
        if name in state:
            if state[name]["issued_at"] + 600 <= int(time.time()):
                raise RuntimeError(
                    "expired pending delivery requires explicit operator reconciliation"
                )
            continue
        phase("protected_one_time_node_delivery")
        generated = json.loads(
            admin(
                "token", "generate", "-spiffeID", parent(node), "-ttl", "600", "-output", "json"
            ).stdout
        )
        issued = int(time.time())
        packet = {
            "format": "kedgeflow-cura-node-bootstrap-v1",
            "node": name,
            "instance_id": node["instance_id"],
            "parent_id": parent(node),
            "join_token": generated["value"],
            "issued_at": issued,
            "bundle_sha256": hashlib.sha256(bundle.encode()).hexdigest(),
        }
        body = json.dumps(packet)
        if len(body.encode()) > 4096:
            raise RuntimeError("bootstrap parameter bound")
        ssm.put_parameter(
            Name=parameter_name(manifest, name),
            Type="SecureString",
            Tier="Standard",
            KeyId=manifest["kms_key_arn"],
            Value=body,
            Overwrite=False,
        )
        state[name] = {
            "issued_at": issued,
            "instance_id": node["instance_id"],
            "parent_id": parent(node),
        }
        temporary = state_path.with_suffix(".new")
        with temporary.open("x") as output:
            json.dump(state, output, indent=2)
        temporary.chmod(0o600)
        temporary.replace(state_path)
    return {
        "format": "kedgeflow-cura-spire-delivery-v1",
        "status": "protected_parameters_written",
        "node_count": 2,
        "delivery_nodes": selected,
        "token_ttl_seconds": 600,
        "bootstrap_bundle_pem": bundle,
        "bootstrap_bundle_sha256": hashlib.sha256(bundle.encode()).hexdigest(),
        "registered_workloads": sorted(allowed),
        "tokens_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


def agent_configuration(base):
    return f'''agent {{
 trust_domain = "{DOMAIN}"
 server_address = "identity.cura.kedgeflow.internal"
 server_port = 8081
 trust_bundle_path = "/etc/kedgeflow-provider/spire-agent/bootstrap.pem"
 join_token_file = "/etc/kedgeflow-provider/spire-agent/join-token"
 socket_path = "{WORKLOAD_SOCKET}"
 data_dir = "{base}/state"
 log_level = "WARN"
}}
plugins {{
 NodeAttestor "join_token" {{ plugin_data {{}} }}
 KeyManager "disk" {{ plugin_data {{ directory = "{base}/keys" }} }}
 WorkloadAttestor "unix" {{ plugin_data {{}} }}
}}
'''


def agent_unit(base, target, direct_dns=True):
    config = Path(base) / "configuration"
    dns = (
        (
            f"BindReadOnlyPaths={target}/resolv.conf:/etc/resolv.conf\n"
            "Environment=GODEBUG=netdns=go\n"
        )
        if direct_dns
        else ""
    )
    return f"""[Unit]
Description=Cura nonroot SPIRE node attestor
After=network-online.target
RequiresMountsFor={base} {target}
ConditionPathExists={config}/agent.conf
[Service]
Type=exec
User=kf-spire-agent
Group=kf-spire-agent
RuntimeDirectory=kedgeflow-spire-agent
RuntimeDirectoryMode=0755
{dns}ExecStart={AGENT} run -config {target}/agent.conf
ReadWritePaths={base}/state {base}/keys /run/kedgeflow-spire-agent
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
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=10.87.0.0/16
MemoryMax=384M
TasksMax=128
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
[Install]
WantedBy=multi-user.target
"""


def private_write(path, raw, uid, mode):
    if path.exists():
        raise RuntimeError("explicit reconciliation required for existing bootstrap file")
    with path.open("xb") as output:
        output.write(raw if isinstance(raw, bytes) else raw.encode())
    os.chown(path, uid, pwd.getpwuid(uid).pw_gid)
    path.chmod(mode)


def delivery_time_valid(issued_at, now):
    # Independent hosts can straddle a one-second boundary. SPIRE independently
    # enforces the real token TTL; this envelope permits only two seconds skew.
    return type(issued_at) is int and -2 <= now - issued_at < 600


def read_node_packet(manifest, name, bundle_path):
    import boto3

    node = manifest["nodes"][name]
    if instance_id() != node["instance_id"] or pwd.getpwnam(node["user"]).pw_uid != node["uid"]:
        raise RuntimeError("actual host or workload UID differs from enrollment")
    phase("exact_node_secure_parameter_read")
    response = boto3.client("ssm", region_name="us-west-2").get_parameter(
        Name=parameter_name(manifest, name), WithDecryption=True
    )["Parameter"]
    if response["Type"] != "SecureString":
        raise RuntimeError("protected bootstrap parameter required")
    packet = json.loads(response["Value"])
    bundle = bundle_path.read_bytes()
    if (
        packet["format"] != "kedgeflow-cura-node-bootstrap-v1"
        or packet["node"] != name
        or packet["instance_id"] != node["instance_id"]
        or packet["parent_id"] != parent(node)
        or packet["bundle_sha256"] != hashlib.sha256(bundle).hexdigest()
        or not delivery_time_valid(packet["issued_at"], int(time.time()))
    ):
        raise RuntimeError("bootstrap identity, trust bundle or time differs")
    return node, packet, bundle


def node_enroll(manifest, name, bundle_path):
    node, packet, bundle = read_node_packet(manifest, name, bundle_path)
    user = pwd.getpwnam("kf-spire-agent")
    common = Path("/var/lib/kedgeflow")
    common.mkdir(mode=0o711, exist_ok=True)
    if common.is_symlink() or common.stat().st_uid != 0:
        raise RuntimeError("unsafe shared data ancestor")
    common.chmod(0o711)
    if name == "Services":
        retained = Path("/var/lib/kedgeflow/pilot")
        if not retained.is_mount():
            raise RuntimeError("Services requires retained data mount")
        base = retained / "spire-agent"
    else:
        base = common / "node"
    base.mkdir(mode=0o711, exist_ok=True)
    if base.is_symlink() or base.stat().st_uid != 0:
        raise RuntimeError("unsafe node storage")
    base.chmod(0o711)
    marker = base / ".node-enrollment.json"
    if marker.exists():
        raise RuntimeError("node already enrolled; never reset its identity or key store")
    for directory in [base / "state", base / "keys"]:
        if directory.exists() and any(directory.iterdir()):
            raise RuntimeError("retained node identity exists; refusing new enrollment")
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chown(directory, user.pw_uid, user.pw_gid)
        directory.chmod(0o700)
    config = base / "configuration"
    config.mkdir(mode=0o750, exist_ok=True)
    os.chown(config, 0, user.pw_gid)
    config.chmod(0o750)
    private_write(config / "join-token", packet["join_token"], user.pw_uid, 0o400)
    private_write(config / "bootstrap.pem", bundle, 0, 0o444)
    private_write(
        config / "resolv.conf", "nameserver 10.87.0.2\noptions timeout:2 attempts:2\n", 0, 0o444
    )
    provider = Path("/etc/kedgeflow-provider")
    provider.mkdir(mode=0o711, exist_ok=True)
    provider.chmod(0o711)
    target = provider / "spire-agent"
    target.mkdir(mode=0o750, exist_ok=True)
    if target.is_mount() or any(target.iterdir()):
        raise RuntimeError("existing node configuration mount; refusing shadowing")
    os.chown(target, 0, user.pw_gid)
    target.chmod(0o750)
    contents = agent_configuration(base)
    private_write(config / "agent.conf", contents, 0, 0o444)
    run(["mount", "--bind", str(config), str(target)])
    run(["mount", "-o", "remount,bind,ro", str(target)])
    fstab = Path("/etc/fstab")
    row = f"{config} {target} none bind,ro,nofail,x-systemd.requires-mounts-for={base} 0 0"
    existing = fstab.read_text()
    if any(len(r.split()) > 1 and r.split()[1] == str(target) for r in existing.splitlines()):
        raise RuntimeError("existing node mount declaration")
    with fstab.open("a") as output:
        output.write(row + "\n")
    unit = agent_unit(base, target)
    private_write(Path("/etc/systemd/system/kedgeflow-spire-agent.service"), unit, 0, 0o644)
    phase("nonroot_node_attestation")
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "start", "kedgeflow-spire-agent.service"])
    for _ in range(45):
        if Path(WORKLOAD_SOCKET).is_socket():
            status = run([AGENT, "healthcheck", "-socketPath", WORKLOAD_SOCKET], False)
            if status.returncode == 0:
                break
        time.sleep(1)
    else:
        raise RuntimeError("node attestation deadline")
    private_write(
        marker,
        json.dumps({"host": name, "instance_id": node["instance_id"], "parent_id": parent(node)}),
        0,
        0o600,
    )
    return {
        "format": "kedgeflow-cura-spire-node-v1",
        "status": "node_attested",
        "node": name,
        "workload": node["workload"],
        "node_attestor_uid": user.pw_uid,
        "disk_key_store": True,
        "secrets_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


def resume_partial_node(manifest, name, bundle_path):
    """Repair only a known failed initial attestation; never reset an enrolled node."""
    node, packet, bundle = read_node_packet(manifest, name, bundle_path)
    base = Path(
        "/var/lib/kedgeflow/pilot/spire-agent" if name == "Services" else "/var/lib/kedgeflow/node"
    )
    if name == "Services" and not Path("/var/lib/kedgeflow/pilot").is_mount():
        raise RuntimeError("retained Services mount required")
    if (base / ".node-enrollment.json").exists():
        raise RuntimeError("cannot repair initial enrollment after node attested")
    user = pwd.getpwnam("kf-spire-agent")
    config, target = base / "configuration", Path("/etc/kedgeflow-provider/spire-agent")
    for directory, uid, mode in [
        (base, 0, 0o711),
        (config, 0, 0o750),
        (base / "keys", user.pw_uid, 0o700),
        (base / "state", user.pw_uid, 0o700),
    ]:
        info = directory.lstat()
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or info.st_uid != uid
            or (info.st_mode & 0o7777) != mode
        ):
            raise RuntimeError("partial node custody differs")
    mounted = run(["findmnt", "--json", "--mountpoint", str(target)], False)
    if mounted.returncode or (target.stat().st_dev, target.stat().st_ino) != (
        config.stat().st_dev,
        config.stat().st_ino,
    ):
        raise RuntimeError("partial node configuration mount differs")
    if (config / "agent.conf").read_text() != agent_configuration(base) or (
        config / "bootstrap.pem"
    ).read_bytes() != bundle:
        raise RuntimeError("partial node configuration or pinned trust differs")
    path = Path("/etc/systemd/system/kedgeflow-spire-agent.service")
    if path.read_text() not in [agent_unit(base, target, False), agent_unit(base, target, True)]:
        raise RuntimeError("unreviewed existing node unit")
    old_token = config / "join-token"
    info = old_token.lstat()
    if (
        old_token.is_symlink()
        or info.st_uid != user.pw_uid
        or info.st_nlink != 1
        or (info.st_mode & 0o7777) != 0o400
    ):
        raise RuntimeError("partial bootstrap credential custody differs")
    phase("preserve_partial_node_and_repair_private_dns")
    before = {
        p.name: (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
        for p in (base / "keys").iterdir()
        if p.is_file()
    }
    run(["systemctl", "stop", "kedgeflow-spire-agent.service"])
    replacement = config / ".join-token.new"
    private_write(replacement, packet["join_token"], user.pw_uid, 0o400)
    replacement.replace(old_token)
    resolver = config / "resolv.conf"
    expected = "nameserver 10.87.0.2\noptions timeout:2 attempts:2\n"
    if resolver.exists():
        if resolver.read_text() != expected:
            raise RuntimeError("resolver configuration differs")
    else:
        private_write(resolver, expected, 0, 0o444)
    replacement = path.with_suffix(".service.cura-new")
    private_write(replacement, agent_unit(base, target), 0, 0o644)
    replacement.replace(path)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "start", "kedgeflow-spire-agent.service"])
    phase("resumed_nonroot_node_attestation")
    for _ in range(45):
        if (
            Path(WORKLOAD_SOCKET).is_socket()
            and run([AGENT, "healthcheck", "-socketPath", WORKLOAD_SOCKET], False).returncode == 0
        ):
            break
        time.sleep(1)
    else:
        raise RuntimeError("resumed node attestation deadline")
    private_write(
        base / ".node-enrollment.json",
        json.dumps({"host": name, "instance_id": node["instance_id"], "parent_id": parent(node)}),
        0,
        0o600,
    )
    after = {
        p.name: (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
        for p in (base / "keys").iterdir()
        if p.is_file()
    }
    return {
        "format": "kedgeflow-cura-spire-node-v1",
        "status": "node_attested",
        "node": name,
        "workload": node["workload"],
        "node_attestor_uid": user.pw_uid,
        "disk_key_store": True,
        "existing_key_file_metadata_unchanged": before == after,
        "key_store_reset": False,
        "direct_vpc_dns_with_loopback_still_denied": True,
        "secrets_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


def finalize_node(manifest, name, bundle_path):
    """Remove consumed bootstrap material and restart using retained disk identity."""
    node = manifest["nodes"][name]
    if instance_id() != node["instance_id"]:
        raise RuntimeError("wrong actual host for node finalization")
    base = Path(
        "/var/lib/kedgeflow/pilot/spire-agent" if name == "Services" else "/var/lib/kedgeflow/node"
    )
    marker = base / ".node-enrollment.json"
    if json.loads(marker.read_text()) != {
        "host": name,
        "instance_id": node["instance_id"],
        "parent_id": parent(node),
    }:
        raise RuntimeError("retained node enrollment differs")
    config = base / "configuration"
    if (config / "bootstrap.pem").read_bytes() != bundle_path.read_bytes():
        raise RuntimeError("retained node trust differs")
    original = agent_configuration(base)
    final = original.replace(
        ' join_token_file = "/etc/kedgeflow-provider/spire-agent/join-token"\n', ""
    )
    path = config / "agent.conf"
    if path.read_text() not in [original, final]:
        raise RuntimeError("node configuration differs before finalization")
    phase("retained_identity_restart_without_bootstrap")
    run(["systemctl", "stop", "kedgeflow-spire-agent.service"])
    replacement = config / ".agent.conf.finalizing"
    private_write(replacement, final, 0, 0o444)
    replacement.replace(path)
    token = config / "join-token"
    if token.exists():
        info = token.lstat()
        if (
            token.is_symlink()
            or info.st_uid != pwd.getpwnam("kf-spire-agent").pw_uid
            or (info.st_mode & 0o7777) != 0o400
        ):
            raise RuntimeError("bootstrap file custody changed")
        token.unlink()
    run(["systemctl", "start", "kedgeflow-spire-agent.service"])
    for _ in range(30):
        if (
            Path(WORKLOAD_SOCKET).is_socket()
            and run([AGENT, "healthcheck", "-socketPath", WORKLOAD_SOCKET], False).returncode == 0
        ):
            break
        time.sleep(1)
    else:
        raise RuntimeError("retained node restart failed")
    return {
        "format": "kedgeflow-cura-spire-finalization-v1",
        "status": "retained_identity_restart_passed",
        "node": name,
        "bootstrap_file_removed": not token.exists(),
        "key_store_reset": False,
        "secrets_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


def cleanup_delivery(manifest):
    import boto3

    phase("remove_consumed_encrypted_delivery")
    entries = inventory()
    aliases = [e for e in entries if initial_alias(e, manifest)]
    if len(aliases) != 2 or {spiffe(e["spiffe_id"]) for e in aliases} != {
        parent(n) for n in manifest["nodes"].values()
    }:
        raise RuntimeError("node aliases differ before delivery cleanup")
    agents = json.loads(admin("agent", "list", "-output", "json").stdout)
    expected = {spiffe(e["parent_id"]) for e in aliases}
    if agents.get("next_page_token") or not isinstance(agents.get("agents"), list):
        raise RuntimeError("incomplete agent inventory")
    actual = {spiffe(a.get("id", a.get("spiffe_id"))) for a in agents["agents"]}
    if actual != expected or len(agents["agents"]) != 2:
        raise RuntimeError("both exact nodes must be attested before cleanup")
    ssm = boto3.client("ssm", region_name="us-west-2")
    removed = 0
    for name in manifest["nodes"]:
        try:
            ssm.delete_parameter(Name=parameter_name(manifest, name))
            removed += 1
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") != "ParameterNotFound":
                raise
    return {
        "format": "kedgeflow-cura-spire-delivery-cleanup-v1",
        "status": "delivery_parameters_removed",
        "attested_nodes": 2,
        "parameters_removed_now": removed,
        "server_keys_or_registrations_deleted": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--node", choices=["Services", "Agent"])
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--retry-expired-delivery", action="store_true")
    parser.add_argument("--resume-partial-node", action="store_true")
    parser.add_argument("--retry-node", choices=["Services", "Agent"])
    parser.add_argument("--finalize-node", action="store_true")
    parser.add_argument("--cleanup-delivery", action="store_true")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0 or sys.platform != "linux":
            raise RuntimeError("privileged Linux bootstrap required")
        manifest = json.loads(args.manifest.read_text())
        validate(manifest)
        if args.node and not args.bundle:
            raise RuntimeError("pinned public bundle required")
        if args.node:
            if args.retry_expired_delivery or args.retry_node or args.cleanup_delivery:
                raise RuntimeError("server-only delivery operation")
            if args.finalize_node and args.resume_partial_node:
                raise RuntimeError("choose one explicit node operation")
            operation = (
                finalize_node
                if args.finalize_node
                else resume_partial_node
                if args.resume_partial_node
                else node_enroll
            )
            report = operation(manifest, args.node, args.bundle)
        else:
            if args.resume_partial_node or args.finalize_node:
                raise RuntimeError("node-only resume operation")
            if args.retry_expired_delivery and args.retry_node:
                raise RuntimeError("choose one explicit retry scope")
            if args.cleanup_delivery and (args.retry_expired_delivery or args.retry_node):
                raise RuntimeError("choose one explicit server operation")
            report = (
                cleanup_delivery(manifest)
                if args.cleanup_delivery
                else server_enroll(manifest, args.retry_expired_delivery, args.retry_node)
            )
        print(json.dumps(report, indent=2))
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        allowed = {
            "AccessDeniedException",
            "ParameterNotFound",
            "ParameterAlreadyExists",
            "InvalidKeyId",
        }
        guards = {
            "cannot retry initial delivery after any node attested": "node_inventory_not_empty",
            "only fully expired initial deliveries can be retried": "delivery_not_fully_expired",
            "existing workload registration scope differs": "registration_scope_mismatch",
            "ambiguous workload registration": "duplicate_registration",
            "unregistered workloads exist outside the closed pilot": "outside_registered_scope",
            "local SPIRE operation refused": "local_api_refused",
            "partial node configuration or pinned trust differs": "partial_config_mismatch",
            "unreviewed existing node unit": "unexpected_node_unit",
            "resumed node attestation deadline": "attestation_deadline",
        }
        print(
            json.dumps(
                {
                    "status": "failed",
                    "phase": PHASE,
                    "error_class": type(error).__name__,
                    "service_error": code if code in allowed else None,
                    "guard_reason": guards.get(str(error)),
                }
            )
        )
        raise SystemExit(1) from None
