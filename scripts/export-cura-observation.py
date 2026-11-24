#!/usr/bin/env python3
"""Export only signature-verified public observation artifacts, never a private log.

Historical artifacts cannot authorize a new operation. The protected context
pins their resource, policy and two provider keys; requester-supplied keys or
unsigned fields cannot select what leaves the Agent host.
"""

import argparse
import base64
import hashlib
import json
import os
import runpy
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SOURCE = Path("/usr/local/sbin/kf-deliver-cura-subject-request.py")


def export(context_path, source_sha256):
    info = SOURCE.lstat()
    if (
        os.geteuid() != 0
        or SOURCE.is_symlink()
        or not SOURCE.is_file()
        or info.st_uid != 0
        or info.st_mode & 0o7777 != 0o600
        or hashlib.sha256(SOURCE.read_bytes()).hexdigest() != source_sha256
    ):
        raise RuntimeError("protected collection source pin differs")
    helper = runpy.run_path(str(SOURCE))
    c, _ = helper["context"](context_path)
    contract = c["contract"]
    path = Path("/var/lib/kedgeflow/node/workflow") / (
        "observation-public-proof-" + c["generation"] + ".json"
    )
    packet = helper["strict"](helper["protected"](path, 969, 0o400))
    if set(packet) != {"manifest", "witnesses"} or len(packet["witnesses"]) != 1:
        raise RuntimeError("closed public artifact collection required")
    values = {}
    for kind, raw in [("manifest", packet["manifest"]), ("evidence", packet["witnesses"][0])]:
        value = helper["strict"](raw)
        definition = "Evidence" if kind == "evidence" else "WitnessManifest"
        if (
            set(value) != {"profile", "kind", "schema", "key_id", "payload", "signature"}
            or value["profile"] != "KF-JSON-0.2"
            or value["kind"] != kind
            or value["schema"]
            != "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/" + definition
            or value["key_id"] != contract[kind + "KeyId"]
        ):
            raise RuntimeError("pinned public record profile differs")
        unsigned = {k: v for k, v in value.items() if k != "signature"}
        key = base64.urlsafe_b64decode(contract[kind + "PublicKey"] + "==")
        signature = base64.urlsafe_b64decode(value["signature"] + "==")
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature, b"KedgeFlow/KF-JSON-0.2\0" + helper["canonical"](unsigned)
        )
        values[kind] = value
    e, m = values["evidence"]["payload"], values["manifest"]["payload"]
    if (
        set(e)
        != {
            "wid",
            "provider_id",
            "provider_version",
            "question_ref",
            "proposal_digest",
            "state_scope",
            "state_digest",
            "result_schema",
            "result",
            "observed_at",
            "expires_at",
            "provenance_refs",
            "exposure_domains",
        }
        or e["state_scope"] != [contract["resource"]]
        or e["provider_id"] != contract["providerId"]
        or e["provider_version"] != "1.0"
        or e["question_ref"] != contract["question"]
        or e["result_schema"] != contract["resultSchema"]
        or e["result"]
        != {"version": "1", "reservation": "available", "active": True, "satisfied": True}
        or e["provenance_refs"] != []
        or e["exposure_domains"] != ["cura-pilot:postgres"]
        or set(m) != {"mid", "proposal_digest", "policy", "witnesses", "assembled_at"}
        or m["proposal_digest"] != e["proposal_digest"]
        or m["policy"] != contract["policy"]
        or len(m["witnesses"]) != 1
        or m["witnesses"][0]["witness"]["id"] != e["wid"]
    ):
        raise RuntimeError("public observation payload differs from fixed enrolled cohort")
    digests = {
        kind: hashlib.sha256(
            ("KedgeFlow/KF-JSON-0.2/" + kind + "\0").encode() + helper["canonical"](value)
        ).hexdigest()
        for kind, value in values.items()
    }
    if m["witnesses"][0]["witness"]["digest"] != digests["evidence"]:
        raise RuntimeError("public manifest link differs")
    return {
        "format": "kedgeflow-cura-historical-observation-artifacts-v1",
        "generation": c["generation"],
        "historical": True,
        "records": packet,
        "record_digests": digests,
        "credentials_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--delivery-source-sha256", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(export(args.context, args.delivery_source_sha256)))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__}))
        raise SystemExit(1) from None
