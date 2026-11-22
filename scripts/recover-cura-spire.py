#!/usr/bin/env python3
"""Explicit expired-node recovery; retain history and never clear the disk store.

SPIRE 1.15.5 rotates an expired node key during native attestation. We archive
the old store on its owning host, preserve the original enrollment marker and
workload registrations, and replace only the public trust bundle in its cache.
Fresh join tokens travel solely through the existing exact-host SecureStrings.
Token-derived internal node IDs and private diagnostics never leave Identity.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import runpy
import stat
import sys
import tarfile
import time
from datetime import timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

BASE = Path("/usr/local/sbin/kf-enroll-cura-spire.py")
DATA = Path("/var/lib/kedgeflow/pilot")
PHASE = "preconditions"


def load_base(expected):
    info = BASE.lstat()
    if (
        os.geteuid() != 0
        or sys.platform != "linux"
        or BASE.is_symlink()
        or info.st_uid != 0
        or info.st_mode & 0o7777 != 0o600
        or not re.fullmatch(r"[a-f0-9]{64}", expected)
        or hashlib.sha256(BASE.read_bytes()).hexdigest() != expected
    ):
        raise RuntimeError("requires pinned protected Linux enrollment source")
    return runpy.run_path(str(BASE))


def protected(path, uid=0, mode=0o600):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != uid
        or info.st_mode & 0o7777 != mode
        or info.st_size > 4 << 20
    ):
        raise RuntimeError("protected recovery file custody differs")
    return path.read_bytes()


def write_once(path, raw, uid=0, gid=0, mode=0o600):
    raw = raw.encode() if isinstance(raw, str) else raw
    if path.exists() or path.is_symlink():
        if protected(path, uid, mode) != raw:
            raise RuntimeError("existing recovery record differs; reconcile explicitly")
        return
    with path.open("xb") as stream:
        os.chown(path, uid, gid)
        path.chmod(mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def replace(path, raw, uid, gid, mode):
    protected(path, uid, mode)
    temporary = path.with_name("." + path.name + ".recovering")
    write_once(temporary, raw, uid, gid, mode)
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def private_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o7777 != 0o700:
        raise RuntimeError("unsafe recovery history directory")


def canonical_bundle(raw, now):
    certificates = x509.load_pem_x509_certificates(raw)
    if not certificates or b"PRIVATE" in raw:
        raise ValueError("public SPIRE trust required")
    live = 0
    for cert in certificates:
        if cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.ca is not True or cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier) != [
            "spiffe://cura.kedgeflow.internal"
        ]:
            raise ValueError("SPIRE trust domain differs")
        cert.verify_directly_issued_by(cert)
        live += cert_time(cert, "not_valid_before") <= now < cert_time(cert, "not_valid_after")
    if not live:
        raise ValueError("current live SPIRE authority missing")
    canonical = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certificates)
    if raw != canonical:
        raise ValueError("canonical public trust bundle required")
    return certificates


def cert_time(cert, field):
    if hasattr(cert, field + "_utc"):
        return getattr(cert, field + "_utc").timestamp()
    # Ubuntu 24.04's pinned distro cryptography predates the UTC accessors.
    return getattr(cert, field).replace(tzinfo=timezone.utc).timestamp()


def renew_public_cache(raw, bundle, now):
    """Preserve every enrolled state field except the explicit public CA list."""
    state = json.loads(raw)
    fields = {
        "svid",
        "bundle",
        "reattestable",
        "bootstrap_use",
        "bootstrap_start_time",
        "connection_attempts",
    }
    if set(state) != fields or not state["svid"] or not state["bundle"]:
        raise RuntimeError("retained SPIRE 1.15.5 cache differs")
    old = [
        x509.load_pem_x509_certificate(base64.b64decode(c, validate=True)) for c in state["svid"]
    ]
    if cert_time(old[0], "not_valid_after") >= now:
        raise RuntimeError("live node must use ordinary renewal, not expired recovery")
    certificates = canonical_bundle(bundle, now)
    state["bundle"] = [
        base64.b64encode(c.public_bytes(serialization.Encoding.PEM)).decode() for c in certificates
    ]
    return json.dumps(state).encode()


def check_inventory(base, manifest, entries, agents, now, *, recovered=False):
    aliases = [e for e in entries if base["initial_alias"](e, manifest)]
    count = 4 if recovered else 2
    if (
        len(entries) != count + 2
        or len(aliases) != count
        or len(agents) != count
        or any(not base["matching"](entries, n) for n in manifest["nodes"].values())
    ):
        raise RuntimeError("closed retained registration inventory differs")
    identities = {base["spiffe"](e["parent_id"]) for e in aliases}
    if len(identities) != count or identities != {base["spiffe"](a["id"]) for a in agents}:
        raise RuntimeError("closed retained node inventory differs")
    for node in manifest["nodes"].values():
        selected = [e for e in aliases if base["spiffe"](e["spiffe_id"]) == base["parent"](node)]
        if len(selected) != (2 if recovered else 1):
            raise RuntimeError("exact node alias history differs")
        node_agents = [
            a
            for a in agents
            if base["spiffe"](a["id"]) in {base["spiffe"](e["parent_id"]) for e in selected}
        ]
        if any(
            a.get("attestation_type") != "join_token" or a.get("banned") or a.get("can_reattest")
            for a in node_agents
        ):
            raise RuntimeError("node attestation policy differs")
        live = sum(int(a["x509svid_expires_at"]) > now for a in node_agents)
        if live != (1 if recovered else 0):
            raise RuntimeError("expired/history versus recovered node lifetime differs")


def server_inventory(base):
    entries = base["inventory"]()
    response = json.loads(base["admin"]("agent", "list", "-output", "json").stdout)
    if response.get("next_page_token") or not isinstance(response.get("agents"), list):
        raise RuntimeError("incomplete node inventory")
    return entries, response["agents"]


def server(base, manifest, generation, cleanup):
    import boto3

    global PHASE
    PHASE = "closed_expired_node_inventory"
    if (
        not DATA.is_mount()
        or json.loads(protected(DATA / ".host-enrollment.json"))["host"] != "Identity"
    ):
        raise RuntimeError("requires retained Identity host")
    root = DATA / "configuration/identity-operator/spire-recovery" / generation
    private_directory(root)
    entries, agents = server_inventory(base)
    if cleanup:
        original = json.loads(protected(root / "original-inventory.json"))
        check_inventory(base, manifest, entries, agents, int(time.time()), recovered=True)
        # Exact original workload entries and all original identities/aliases remain.
        if not all(e in entries for e in original["entries"]) or not {
            base["spiffe"](a["id"]) for a in original["agents"]
        } <= {base["spiffe"](a["id"]) for a in agents}:
            raise RuntimeError("original history was changed during recovery")
        PHASE = "remove_exact_protected_delivery"
        ssm = boto3.client("ssm", region_name="us-west-2")
        for name in manifest["nodes"]:
            ssm.delete_parameter(Name=base["parameter_name"](manifest, name))
        write_once(root / "cleaned.json", json.dumps({"generation": generation, "cleaned": True}))
        return {
            "status": "expired_node_recovery_delivery_removed",
            "retained_old_nodes": 2,
            "current_nodes": 2,
            "workload_entries_unchanged": True,
            "old_registrations_deleted": False,
            "parameters_removed": 2,
        }
    check_inventory(base, manifest, entries, agents, int(time.time()))
    # Once an intent exists, never silently generate replacement tokens.
    if (root / "original-inventory.json").exists():
        raise RuntimeError("recovery intent exists; explicit reconciliation required")
    bundle_raw = base["admin"]("bundle", "show").stdout.encode()
    certificates = x509.load_pem_x509_certificates(bundle_raw)
    bundle = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certificates)
    canonical_bundle(bundle, int(time.time()))
    write_once(root / "original-inventory.json", json.dumps({"entries": entries, "agents": agents}))
    write_once(root / "public-bundle.pem", bundle)
    ssm = boto3.client("ssm", region_name="us-west-2")
    PHASE = "protected_one_time_recovery_delivery"
    for name, node in manifest["nodes"].items():
        generated = json.loads(
            base["admin"](
                "token",
                "generate",
                "-spiffeID",
                base["parent"](node),
                "-ttl",
                "600",
                "-output",
                "json",
            ).stdout
        )
        packet = {
            "format": "kedgeflow-cura-node-bootstrap-v1",
            "node": name,
            "instance_id": node["instance_id"],
            "parent_id": base["parent"](node),
            "join_token": generated["value"],
            "issued_at": int(time.time()),
            "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
        }
        ssm.put_parameter(
            Name=base["parameter_name"](manifest, name),
            Type="SecureString",
            Tier="Standard",
            KeyId=manifest["kms_key_arn"],
            Value=json.dumps(packet),
            Overwrite=False,
        )
        write_once(root / (name + "-delivered.json"), json.dumps({"delivered": True}))
    return {
        "status": "expired_node_recovery_delivery_ready",
        "bootstrap_bundle_pem": bundle.decode(),
        "nodes": 2,
        "token_ttl_seconds": 600,
        "original_registration_history_retained": True,
    }


def archive(base, destination):
    # These files remain on the original host and are never included in stdout.
    names = ["state", "keys", "configuration", ".node-enrollment.json"]
    for name in names:
        root = base / name
        for path in [root, *root.rglob("*")] if root.is_dir() else [root]:
            mode = path.lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)) or path.is_symlink():
                raise RuntimeError("refuse links or special files in retained node store")
    with destination.open("xb") as output:
        destination.chmod(0o600)
        with tarfile.open(fileobj=output, mode="w") as snapshot:
            for name in names:
                snapshot.add(base / name, arcname=name, recursive=True)
        output.flush()
        os.fsync(output.fileno())


def node(base, manifest, name, generation, bundle_path, finalize):
    global PHASE
    PHASE = "retained_exact_node_preconditions"
    item = manifest["nodes"][name]
    if base["instance_id"]() != item["instance_id"]:
        raise RuntimeError("wrong enrolled instance")
    root = Path(
        "/var/lib/kedgeflow/pilot/spire-agent" if name == "Services" else "/var/lib/kedgeflow/node"
    )
    marker = protected(root / ".node-enrollment.json")
    if json.loads(marker) != {
        "host": name,
        "instance_id": item["instance_id"],
        "parent_id": base["parent"](item),
    }:
        raise RuntimeError("original node marker differs")
    history = root / "recovery" / generation
    private_directory(history)
    if finalize:
        protected(history / "installed.json")
        result = base["finalize_node"](manifest, name, bundle_path)
        if protected(root / ".node-enrollment.json") != marker:
            raise RuntimeError("original node marker changed")
        write_once(history / "finalized.json", json.dumps({"finalized": True}))
        return result
    if (history / "snapshot.tar").exists() or (history / "installed.json").exists():
        raise RuntimeError("node recovery intent exists; explicit reconciliation required")
    user = base["pwd"].getpwnam("kf-spire-agent")
    config = root / "configuration"
    original = base["agent_configuration"](root)
    final = original.replace(
        ' join_token_file = "/etc/kedgeflow-provider/spire-agent/join-token"\n', ""
    )
    if protected(config / "agent.conf", 0, 0o444).decode() != final:
        raise RuntimeError("only finalized original configuration can recover")
    if (config / "join-token").exists() or not (root / "keys").is_dir():
        raise RuntimeError("pending delivery or missing retained keystore")
    if name == "Services":
        for role in ["gateway", "admission", "issuer", "broker", "recovery", "governance"]:
            if (
                base["run"](
                    ["systemctl", "is-active", "--quiet", "kedgeflow-" + role + ".service"], False
                ).returncode
                == 0
            ):
                raise RuntimeError("expired node recovery is pre-application only")
    _, packet, bundle = base["read_node_packet"](manifest, name, bundle_path)
    canonical_bundle(bundle, int(time.time()))
    PHASE = "stop_and_archive_expired_node"
    base["run"](["systemctl", "stop", "kedgeflow-spire-agent.service"])
    cache = root / "state/agent-data.json"
    raw = protected(cache, user.pw_uid, 0o600)
    renewed = renew_public_cache(raw, bundle, int(time.time()))
    archive(root, history / "snapshot.tar")
    PHASE = "install_public_trust_without_state_reset"
    replace(cache, renewed, user.pw_uid, user.pw_gid, 0o600)
    replace(config / "bootstrap.pem", bundle, 0, 0, 0o444)
    base["private_write"](config / "join-token", packet["join_token"], user.pw_uid, 0o400)
    replace(config / "agent.conf", original.encode(), 0, 0, 0o444)
    write_once(
        history / "installed.json",
        json.dumps(
            {
                "generation": generation,
                "public_bundle_sha256": hashlib.sha256(bundle).hexdigest(),
                "original_marker_sha256": hashlib.sha256(marker).hexdigest(),
            }
        ),
    )
    PHASE = "native_attestation_with_retained_store"
    base["run"](["systemctl", "start", "kedgeflow-spire-agent.service"])
    for _ in range(40):
        if (
            base["run"](
                [base["AGENT"], "healthcheck", "-socketPath", base["WORKLOAD_SOCKET"]], False
            ).returncode
            == 0
        ):
            break
        time.sleep(1)
    else:
        raise RuntimeError("native expired node recovery deadline")
    if protected(root / ".node-enrollment.json") != marker:
        raise RuntimeError("original marker changed")
    return {
        "status": "expired_node_native_attestation_passed",
        "node": name,
        "original_marker_preserved": True,
        "private_snapshot_retained_on_host": True,
        "key_store_cleared": False,
        "native_key_rotation_expected": True,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--base-sha256", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--node", choices=["Services", "Agent"])
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--finalize", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[a-z0-9-]{1,40}", args.generation):
            raise ValueError("explicit recovery generation required")
        source = load_base(args.base_sha256)
        manifest = json.loads(args.manifest.read_text())
        source["validate"](manifest)
        if args.node:
            if not args.bundle or args.cleanup:
                raise ValueError("exact node public bundle required")
            result = node(source, manifest, args.node, args.generation, args.bundle, args.finalize)
        else:
            if args.bundle or args.finalize:
                raise ValueError("server-only recovery operation")
            result = server(source, manifest, args.generation, args.cleanup)
        result.update({"owner_acceptance": "BLOCKED_EXTERNAL_INPUT", "secrets_returned": False})
        print(json.dumps(result))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
