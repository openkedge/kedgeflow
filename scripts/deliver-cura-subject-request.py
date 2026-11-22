#!/usr/bin/env python3
"""Bounded exact-host subject-token handoff; no client secret reaches Agent.

Only encrypted parameter values and protected on-host files carry DPoP proofs
or bearer material. stdout contains fixed checkpoints and public checks only.
Delete the two parameters and auxiliary IAM policies after the bounded probe.
"""

import argparse
import base64
import hashlib
import json
import os
import pwd
import re
import runpy
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DATA = Path("/var/lib/kedgeflow/pilot")
FLOW = Path("/var/lib/kedgeflow/node/workflow")
PROBE = Path("/usr/local/sbin/kf-probe-cura-subject-provider.py")
NODE = "/opt/kedgeflow/runtime/node/bin/node"
PHASE = "closed_delivery_preconditions"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def protected(path, uid=0, mode=0o600):
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_nlink != 1
        or info.st_uid != uid
        or info.st_mode & 0o7777 != mode
        or info.st_size > 1 << 20
    ):
        raise RuntimeError("protected delivery custody differs")
    return path.read_bytes()


def write_once(path, raw, uid=0, gid=0, mode=0o600):
    if path.exists() or path.is_symlink():
        if protected(path, uid, mode) != raw:
            raise RuntimeError("existing delivery differs; explicit reconciliation required")
        return
    with path.open("xb") as stream:
        os.chown(path, uid, gid)
        path.chmod(mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def strict(raw):
    def pairs(values):
        result = {}
        for k, v in values:
            if k in result:
                raise ValueError("duplicate field")
            result[k] = v
        return result

    def number(value):
        raise ValueError("non-integer JSON")

    return json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=number)


def context(path):
    c = strict(protected(path))
    if (
        set(c)
        != {
            "contract",
            "generation",
            "kms_key_arn",
            "pilot_stack",
            "agent_instance_id",
            "runtime_root",
            "source_files_sha256",
            "subject_probe_source_sha256",
            "service_ca_pem",
        }
        or not re.fullmatch(r"[a-z0-9-]{1,40}", c["generation"])
        or c["pilot_stack"] != "kedgeflow-cura-pilot-20261117"
        or c["agent_instance_id"] != "i-0004dee402aa2386b"
        or c["kms_key_arn"]
        != "arn:aws:kms:us-west-2:756041605110:key/02a06212-e263-4550-984f-2bed4e3b6059"
        or c["contract"]["until"] != 1795420800000
        or int(time.time() * 1000) >= c["contract"]["until"]
        or not re.fullmatch(
            r"/opt/kedgeflow/cura-runtime/agent-observation-[a-f0-9]{12}", c["runtime_root"]
        )
    ):
        raise ValueError("exact approved subject request context required")
    if hashlib.sha256(protected(PROBE)).hexdigest() != c["subject_probe_source_sha256"]:
        raise RuntimeError("subject verification source pin differs")
    c["contract_digest"] = hashlib.sha256(canonical(c["contract"])).hexdigest()
    return c, runpy.run_path(str(PROBE))


def name(c, kind):
    return "/kedgeflow/cura/" + c["pilot_stack"] + "/subject-probe/" + kind


def secure_read(ssm, c, kind):
    result = ssm.get_parameter(Name=name(c, kind), WithDecryption=True)["Parameter"]
    if result["Type"] != "SecureString" or len(result["Value"].encode()) > 4096:
        raise RuntimeError("bounded encrypted delivery required")
    packet = strict(result["Value"])
    if (
        packet["generation"] != c["generation"]
        or packet["contract_digest"] != c["contract_digest"]
        or type(packet["issued_at"]) is not int
        or not -2000 <= int(time.time() * 1000) - packet["issued_at"] < 55000
    ):
        raise RuntimeError("delivery generation or age differs")
    return packet


def secure_write(ssm, c, kind, packet):
    raw = canonical(packet).decode()
    if len(raw.encode()) > 4096:
        raise RuntimeError("encrypted delivery bound")
    ssm.put_parameter(
        Name=name(c, kind),
        Type="SecureString",
        Tier="Standard",
        KeyId=c["kms_key_arn"],
        Value=raw,
        Overwrite=False,
    )


def verify_proof(raw, contract, now):
    if not isinstance(raw, str) or len(raw) > 16 << 10 or len(raw.split(".")) != 3:
        raise ValueError("bounded proof required")

    def decode(value):
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if base64.urlsafe_b64encode(result).decode().rstrip("=") != value:
            raise ValueError("canonical proof encoding required")
        return result

    h, p, s = raw.split(".")
    header, claims = strict(decode(h)), strict(decode(p))
    if (
        set(header) != {"alg", "typ", "jwk"}
        or header["alg"] != "EdDSA"
        or header["typ"] != "dpop+jwt"
        or set(header["jwk"]) != {"crv", "kty", "x"}
        or header["jwk"]["crv"] != "Ed25519"
        or header["jwk"]["kty"] != "OKP"
        or base64.urlsafe_b64encode(hashlib.sha256(canonical(header["jwk"])).digest())
        .decode()
        .rstrip("=")
        != contract["dpopThumbprint"]
        or set(claims) != {"jti", "htm", "htu", "iat"}
        or claims["htm"] != "POST"
        or claims["htu"] != contract["subject"]["iss"] + "/protocol/openid-connect/token"
        or not isinstance(claims["jti"], str)
        or not 16 <= len(claims["jti"]) <= 512
        or type(claims["iat"]) is not int
        or not now - 60 <= claims["iat"] <= now + 5
    ):
        raise RuntimeError("actual Agent subject proof differs")
    Ed25519PublicKey.from_public_bytes(decode(header["jwk"]["x"])).verify(
        decode(s), (h + "." + p).encode()
    )


def run_agent(c, mode):
    global PHASE
    PHASE = "managed_agent_" + mode
    root = Path(c["runtime_root"])
    expected = {
        "scripts/cura-agent-observation.mjs",
        "sdk/node/records.mjs",
        "sdk/node/identity-profile.mjs",
    }
    if set(c["source_files_sha256"]) != expected:
        raise RuntimeError("closed Agent module inventory required")
    for relative, sha in c["source_files_sha256"].items():
        if hashlib.sha256(protected(root / relative, 0, 0o444)).hexdigest() != sha:
            raise RuntimeError("Agent source pin differs")
    folder = Path("/etc/kedgeflow/agent-observation")
    if not folder.exists():
        folder.mkdir(mode=0o750)
        os.chown(folder, 0, 969)
        folder.chmod(0o750)
    info = folder.lstat()
    if (
        folder.is_symlink()
        or info.st_uid != 0
        or info.st_gid != 969
        or info.st_mode & 0o7777 != 0o750
    ):
        raise RuntimeError("Agent request configuration custody differs")
    write_once(folder / "service-ca.pem", c["service_ca_pem"].encode(), mode=0o444)
    write_once(
        folder / "resolv.conf", b"nameserver 10.87.0.2\noptions timeout:2 attempts:2\n", mode=0o444
    )
    config = {
        "generation": c["generation"],
        "contract": c["contract"],
        "serviceCa": str(folder / "service-ca.pem"),
    }
    config_path = folder / ("config-" + c["generation"] + ".json")
    write_once(config_path, canonical(config), gid=969, mode=0o440)
    properties = {
        "Type": "exec",
        "User": "kf-agent",
        "Group": "kf-agent",
        "UMask": "0077",
        "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "yes",
        "ProtectControlGroups": "yes",
        "ProtectClock": "yes",
        "ProtectProc": "invisible",
        "ProcSubset": "pid",
        "RestrictAddressFamilies": "AF_UNIX AF_INET",
        "RestrictNamespaces": "yes",
        "RestrictSUIDSGID": "yes",
        "MemoryDenyWriteExecute": "yes",
        "SystemCallFilter": "@system-service",
        "SystemCallErrorNumber": "EPERM",
        "IPAddressDeny": "any",
        "IPAddressAllow": "10.87.0.0/16",
        "ReadWritePaths": str(FLOW),
        "BindReadOnlyPaths": str(folder / "resolv.conf") + ":/etc/resolv.conf",
        "WorkingDirectory": "/",
        "KillMode": "control-group",
        "MemoryMax": "256M",
        "TasksMax": "64",
        "RuntimeMaxSec": "90",
        "TimeoutStopSec": "10",
    }
    command = [
        "systemd-run",
        "--wait",
        "--pipe",
        "--collect",
        "--quiet",
        "--unit=kedgeflow-cura-observer-" + c["generation"] + "-" + mode,
        *["--property=" + k + "=" + v for k, v in properties.items()],
        NODE,
        "--jitless",
        str(root / "scripts/cura-agent-observation.mjs"),
        mode,
        str(config_path),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=100)
    parsed = strict(result.stdout)
    if result.returncode:
        allowed = {
            "protected_agent_preconditions",
            "own_sender_constrained_proof",
            "current_subject_token_verification",
            "actual_workload_x509_fetch",
            "actual_fixed_row_baseline",
            "actual_replay_and_arbitrary_input_refusals",
            "actual_signed_fresh_sql_evidence",
            "actual_tampered_proposal_refusal",
            "actual_agent_network_and_custody_refusals",
        }
        if parsed.get("phase") in allowed:
            PHASE = parsed["phase"]
        raise RuntimeError("managed Agent observation refused")
    return parsed


def deliver(c, verifier, action):
    import boto3

    global PHASE
    ssm = boto3.client("ssm", region_name="us-west-2")
    if action in ["prepare", "receive", "agent-cleanup"]:
        marker = strict(protected(Path("/var/lib/kedgeflow/node/.node-enrollment.json")))
        if marker["host"] != "Agent" or marker["instance_id"] != c["agent_instance_id"]:
            raise RuntimeError("exact enrolled Agent required")
        user = pwd.getpwnam("kf-agent")
        if user.pw_uid != 969 or user.pw_gid != 969:
            raise RuntimeError("registered isolated Agent required")
    else:
        if (
            not DATA.is_mount()
            or strict(protected(DATA / ".host-enrollment.json"))["host"] != "Identity"
        ):
            raise RuntimeError("exact retained Identity required")
    if action == "prepare":
        run_agent(c, "prepare")
        packet = strict(
            protected(FLOW / ("subject-proof-" + c["generation"] + ".json"), 969, 0o400)
        )
        verify_proof(packet["proof"], c["contract"], int(time.time()))
        secure_write(ssm, c, "Proof", packet)
        return {"status": "actual_agent_proof_delivered", "proof_returned": False}
    if action == "mint":
        PHASE = "protected_actual_agent_subject_issuance"
        packet = secure_read(ssm, c, "Proof")
        if (
            set(packet) != {"format", "generation", "contract_digest", "issued_at", "proof"}
            or packet["format"] != "kedgeflow-cura-subject-proof-v1"
        ):
            raise RuntimeError("closed proof delivery required")
        verify_proof(packet["proof"], c["contract"], int(time.time()))
        issuer = c["contract"]["subject"]["iss"]
        endpoint = issuer + "/protocol/openid-connect/token"
        context = ssl.create_default_context(cafile="/etc/kedgeflow-provider/keycloak/ca.pem")
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        form = {
            "grant_type": "client_credentials",
            "client_id": "kf-pilot-agent",
            "client_secret": verifier["protected"](
                DATA / "configuration/identity-operator/agent-client-secret"
            ),
            "scope": " ".join(sorted(verifier["SCOPES"])),
        }
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    endpoint,
                    data=urllib.parse.urlencode(form).encode(),
                    headers={
                        "DPoP": packet["proof"],
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                ),
                context=context,
                timeout=10,
            ) as response:
                issued = strict(response.read(65537))
        except urllib.error.HTTPError:
            raise RuntimeError("protected subject request refused") from None
        public = {
            "keys": [
                {
                    "kid": c["contract"]["authorizationKeyId"],
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "use": "sig",
                    "x": c["contract"]["authorizationKey"],
                }
            ]
        }
        verified = verifier["verify_token"](
            issued["access_token"], public, c["contract"]["dpopThumbprint"], int(time.time())
        )
        if issued["token_type"].lower() != "dpop":
            raise RuntimeError("sender constrained token required")
        delivered = {
            "format": "kedgeflow-cura-subject-token-v1",
            "generation": c["generation"],
            "contract_digest": c["contract_digest"],
            "issued_at": int(time.time() * 1000),
            "access_token": issued["access_token"],
        }
        secure_write(ssm, c, "Token", delivered)
        return {
            "status": "actual_sender_constrained_subject_delivered",
            "verified": verified,
            "client_secret_delivered": False,
            "token_returned": False,
        }
    if action == "receive":
        PHASE = "protected_agent_subject_receipt"
        packet = secure_read(ssm, c, "Token")
        if (
            set(packet) != {"format", "generation", "contract_digest", "issued_at", "access_token"}
            or packet["format"] != "kedgeflow-cura-subject-token-v1"
        ):
            raise RuntimeError("closed token delivery required")
        public = {
            "keys": [
                {
                    "kid": c["contract"]["authorizationKeyId"],
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "use": "sig",
                    "x": c["contract"]["authorizationKey"],
                }
            ]
        }
        verified = verifier["verify_token"](
            packet["access_token"], public, c["contract"]["dpopThumbprint"], int(time.time())
        )
        if verified["remaining_seconds"] < 20:
            raise RuntimeError("fresh bounded subject required")
        write_once(
            FLOW / ("subject-token-" + c["generation"] + ".json"),
            canonical(packet),
            969,
            969,
            0o400,
        )
        return run_agent(c, "probe")
    if action == "cleanup":
        PHASE = "remove_exact_subject_delivery"
        count = 0
        for kind in ["Proof", "Token"]:
            try:
                ssm.delete_parameter(Name=name(c, kind))
                count += 1
            except Exception as error:
                if (
                    getattr(error, "response", {}).get("Error", {}).get("Code")
                    != "ParameterNotFound"
                ):
                    raise
        return {"status": "subject_delivery_parameters_removed", "removed_now": count}
    if action == "agent-cleanup":
        removed = 0
        for kind in ["proof", "token"]:
            path = FLOW / ("subject-" + kind + "-" + c["generation"] + ".json")
            if path.exists():
                packet = strict(protected(path, 969, 0o400))
                if (
                    packet["generation"] != c["generation"]
                    or packet["contract_digest"] != c["contract_digest"]
                ):
                    raise RuntimeError("pending Agent request differs")
                path.unlink()
                removed += 1
        return {"status": "agent_ephemeral_request_credentials_removed", "removed_now": removed}
    raise ValueError("unsupported delivery action")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument(
        "--action",
        required=True,
        choices=["prepare", "mint", "receive", "cleanup", "agent-cleanup"],
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError("privileged exact-host delivery launcher required")
        c, verifier = context(args.context)
        result = deliver(c, verifier, args.action)
        result.update(
            {
                "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
                "credentials_returned": False,
                "execution_authority": False,
            }
        )
        print(json.dumps(result))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
