#!/usr/bin/env python3
"""Restart retained Cura providers; export only public key continuity and refusal checks."""

import argparse
import hashlib
import json
import os
import re
import runpy
import ssl
import subprocess
import time
import urllib.request
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
ISSUER = "https://identity.cura.kedgeflow.internal:8443/realms/kedgeflow-pilot"
SPIRE = "/opt/kedgeflow/runtime/spire/bin/spire-server"
SOCKET = "/run/kedgeflow-spire-server/server.sock"


def run(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    if check and result.returncode:
        raise RuntimeError("provider continuity operation failed")
    return result


def public_key_set(bundle):
    if not isinstance(bundle.get("keys"), list) or not bundle["keys"]:
        raise ValueError("provider public key set missing")
    if any(set(k) & {"d", "p", "q", "dp", "dq", "qi", "k"} for k in bundle["keys"]):
        raise ValueError("provider public key set contains private fields")
    return sorted(json.dumps(k, sort_keys=True) for k in bundle["keys"])


def observe(context):
    with urllib.request.urlopen(
        ISSUER + "/.well-known/openid-configuration", context=context, timeout=5
    ) as response:
        metadata = json.load(response)
    if (
        metadata["issuer"] != ISSUER
        or metadata["jwks_uri"] != ISSUER + "/protocol/openid-connect/certs"
    ):
        raise RuntimeError("provider public issuer differs")
    with urllib.request.urlopen(metadata["jwks_uri"], context=context, timeout=5) as response:
        keycloak = json.load(response)
    args = ["runuser", "-u", "kf-spire-server", "--", SPIRE]
    bundle = json.loads(
        run([*args, "bundle", "show", "-socketPath", SOCKET, "-format", "spiffe"]).stdout
    )
    # Registration output can contain bootstrap token-derived selectors; compare
    # only in local memory and never emit entry/agent records or their hashes.
    entries = json.loads(
        run([*args, "entry", "show", "-socketPath", SOCKET, "-output", "json"]).stdout
    )
    agents = json.loads(
        run([*args, "agent", "list", "-socketPath", SOCKET, "-output", "json"]).stdout
    )
    return {
        "keycloak": public_key_set(keycloak),
        "spire": public_key_set(bundle),
        "entries": entries,
        "agents": sorted(json.dumps(a["id"], sort_keys=True) for a in agents.get("agents", [])),
    }


def recovery_inventory_check(generation, source_sha256, enrollment_sha256, manifest_path):
    source = Path("/usr/local/sbin/kf-recover-cura-spire.py")
    info = source.lstat()
    if (
        not re.fullmatch(r"[a-z0-9-]{1,40}", generation)
        or not re.fullmatch(r"[a-f0-9]{64}", source_sha256)
        or source.is_symlink()
        or not source.is_file()
        or info.st_uid != 0
        or info.st_mode & 0o7777 != 0o600
        or hashlib.sha256(source.read_bytes()).hexdigest() != source_sha256
    ):
        raise RuntimeError("protected recovery source pin differs")
    recovery = runpy.run_path(str(source))
    base = recovery["load_base"](enrollment_sha256)
    manifest = json.loads(manifest_path.read_text())
    base["validate"](manifest)
    original = json.loads(
        recovery["protected"](
            DATA
            / "configuration/identity-operator/spire-recovery"
            / generation
            / "original-inventory.json"
        )
    )

    def check():
        entries, agents = recovery["server_inventory"](base)
        recovery["check_inventory"](
            base, manifest, entries, agents, int(time.time()), recovered=True
        )
        if not all(entry in entries for entry in original["entries"]) or not {
            base["spiffe"](agent["id"]) for agent in original["agents"]
        } <= {base["spiffe"](agent["id"]) for agent in agents}:
            raise RuntimeError("original node history changed")

    return check


def probe(recovered_check=None):
    if os.geteuid() != 0 or not DATA.is_mount():
        raise RuntimeError("requires privileged retained Identity host")
    if json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Identity":
        raise RuntimeError("wrong enrolled host")
    context = ssl.create_default_context(cafile="/etc/kedgeflow-provider/keycloak/ca.pem")
    before = observe(context)
    if recovered_check is None:
        if len(before["agents"]) != 2:
            raise RuntimeError("exactly two attested nodes required before restart")
    else:
        recovered_check()
    run(["systemctl", "stop", "kedgeflow-keycloak.service"])
    run(["systemctl", "restart", "kedgeflow-identity-db.service"])
    run(["systemctl", "start", "kedgeflow-keycloak.service"])
    run(["systemctl", "restart", "kedgeflow-spire-server.service"])
    for _ in range(90):
        try:
            after = observe(context)
            break
        except (OSError, ValueError, RuntimeError):
            time.sleep(1)
    else:
        raise RuntimeError("provider restart readiness deadline")
    if before != after:
        raise RuntimeError("provider keys or enrollment changed across restart")
    if recovered_check is not None:
        recovered_check()
    refusals = {}
    for user in ["kf-agent", "kf-gateway", "kf-keycloak"]:
        for label, path in [
            ("operator_secret", DATA / "configuration/identity-operator/admin-password"),
            ("spire_keys", DATA / "spire-server/keys.json"),
            ("identity_database", DATA / "identity-db/PG_VERSION"),
        ]:
            refusals[user + ":" + label] = (
                run(["runuser", "-u", user, "--", "test", "-r", str(path)], check=False).returncode
                != 0
            )
    if not all(refusals.values()):
        raise RuntimeError("provider private file boundary failed")
    units = [
        "kedgeflow-identity-db.service",
        "kedgeflow-keycloak.service",
        "kedgeflow-spire-server.service",
    ]
    for unit in units:
        run(["systemctl", "is-active", "--quiet", unit])
    run(["systemctl", "enable", *units])
    return {
        "format": "kedgeflow-cura-provider-restart-v1",
        "status": "retained_provider_restart_passed",
        "keycloak_public_keys_preserved": True,
        "spire_public_keys_preserved": True,
        "spire_registration_and_node_ids_preserved": True,
        "attested_nodes": len(after["agents"]),
        "expired_history_nodes": 2 if recovered_check is not None else 0,
        "private_file_refusals": refusals,
        "provider_units_enabled": True,
        "secrets_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recovery-generation")
    parser.add_argument("--recovery-source-sha256")
    parser.add_argument("--enrollment-source-sha256")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        inputs = [
            args.recovery_generation,
            args.recovery_source_sha256,
            args.enrollment_source_sha256,
            args.manifest,
        ]
        if any(inputs) and not all(inputs):
            raise ValueError("all source-pinned recovery inventory references required")
        check = recovery_inventory_check(*inputs) if all(inputs) else None
        print(json.dumps(probe(check), indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__}))
        raise SystemExit(1) from None
