#!/usr/bin/env python3
"""Replay owned Terraform backend fixture evidence; grants no execution authority."""

import argparse
import hashlib
import json
from pathlib import Path


def load(path):
    def closed_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate evidence key")
            value[key] = item
        return value

    return json.loads(path.read_text(), object_pairs_hook=closed_pairs)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_case(root, name):
    case = root / "cases" / name
    baseline = case / "state.json"
    original = load(baseline)
    manifest = load(case / "manifest.json")
    report = load(case / "sdk-native-report.json")
    completion = load(case / "backend-completion.json")
    target = load(case / "target-observation.json")
    baseline_hash = hashlib.sha256(baseline.read_bytes()).hexdigest()
    require(baseline_hash == manifest["files"]["state.json"], "baseline bytes changed")
    require(target["before"] == target["after"], "unexpected target change")
    require(
        report["native_state"] == report["resumed"]["state"] == "unknown", "native phase changed"
    )
    require(report["first"]["grant_digest"] == report["resumed"]["grant_digest"], "grant changed")
    require(report["first"]["attempt_id"] == report["resumed"]["attempt_id"], "attempt changed")
    require(
        all(
            report[key] is True
            for key in (
                "grant_expired_at_query",
                "domain_revoked_at_query",
                "broker_stopped_at_query",
                "writer_absent_at_query",
            )
        ),
        "cold-query conditions missing",
    )
    require(
        all(
            wire["method"] in ("server/discover", "kedgeflow/status")
            and wire["grantPresent"] is False
            for wire in report["resumed"]["wire"]
        ),
        "recovery attempted execution",
    )
    has_intent = name != "precheck"
    counts = dict(claims=1, permits=1, dispatches=1, intents=int(has_intent))
    require(report["native_counts"] == counts, "execution population changed")
    require(
        report["counters"]
        == {
            **counts,
            "intent_requests": int(has_intent),
            "intent_outcomes": int(has_intent),
            "ordinary_outcomes": 1,
        },
        "native write population changed",
    )
    injection = report["injection"]["backend_intervention"]
    require(report["injection"]["grant_valid_at_boundary"] is True, "invalid boundary grant")
    require(completion["grant_still_valid_at_refusal"] is True, "expiry masked refusal")
    require(
        completion["backend_unchanged_after_injection"] is True, "backend moved after injection"
    )
    expected_hash = baseline_hash
    if name == "lock":
        require(
            injection["os_lock_acquired"] is True
            and injection["independent_lock_probe_refused"] is True
            and completion["lock_held_through_refusal"] is True
            and completion["lock_available_after_holder_release"] is True,
            "lock lifecycle not certified",
        )
    else:
        require(injection["resources_unchanged"] is True, "resource contents changed")
        require(
            injection["before_serial"] == original["serial"]
            and injection["before_lineage"] == original["lineage"],
            "injection baseline changed",
        )
        if name == "lineage":
            require(injection["lineage"] != original["lineage"], "lineage did not change")
            require(injection["serial"] == original["serial"], "serial unexpectedly changed")
            original["lineage"] = injection["lineage"]
        else:
            require(injection["serial"] == original["serial"] + 1, "serial did not advance once")
            require(injection["lineage"] == original["lineage"], "lineage unexpectedly changed")
            original["serial"] = injection["serial"]
        expected_hash = hashlib.sha256(
            json.dumps(original, indent=2, ensure_ascii=False).encode()
        ).hexdigest()
    require(
        expected_hash
        == injection["sha256"]
        == completion["backend_sha256"]
        == report["backend_sha256"],
        "metadata-only byte reconstruction failed",
    )
    if has_intent:
        intent = report["intent"]
        diagnostic = {
            "lock": "apply state lock refused",
            "serial": "apply saved plan stale",
            "lineage": "apply state lineage refused",
        }[name]
        require(
            intent["state"] == "unknown"
            and intent["last_error"] == "authority refused: Terraform plan: " + diagnostic
            and intent["backend_before_sha256"] == baseline_hash
            and intent["backend_after_sha256"] is None
            and intent["observed_after_digest"] is None
            and intent["attempt_id"] == report["resumed"]["attempt_id"]
            and intent["grant_digest"] == report["resumed"]["grant_digest"],
            "original intent or diagnostic changed",
        )
    else:
        require(report["intent"] is None, "pre-check refusal acquired an intent")
    return {"case": name, "state": "unknown", "metadata_replay_sha256": expected_hash}


def verify(root):
    return {
        "status": "PASS",
        "scope": "local fixture replay; no execution authority or independent attestation",
        "cases": [verify_case(root, name) for name in ("lock", "precheck", "serial", "lineage")],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence.resolve()), indent=2))
