#!/usr/bin/env python3
"""Export protected native read-only backlog observations, never raw diagnostics."""

import argparse
import json
import os
import secrets
import stat
import subprocess
import time
from pathlib import Path

COUNTS = {
    "claimed_not_dispatched": "kf_claimed_not_dispatched",
    "unresolved_dispatches": "kf_unresolved_dispatches",
    "unknown": "kf_unknown_count",
    "unknown_owner_deadline_exceeded": "kf_unknown_owner_deadline_exceeded",
    "incidents_open": "kf_incident_backlog",
    "receipts_pending": "kf_receipt_delivery_backlog",
}


def metrics(report, now):
    fields = {
        "profile",
        "scope",
        "checked_at",
        "elapsed_ms",
        "complete",
        "examined",
        "unknown_oldest_age_ms",
        "production_qualified",
        "execution_authority",
        *COUNTS,
    }
    if (
        not isinstance(report, dict)
        or set(report) != fields
        or report["profile"] != "KF-SUPERVISION-BACKLOG-0.1-draft"
        or report["scope"] != "bounded_retained_observation"
        or report["production_qualified"] is not False
        or report["execution_authority"] is not False
        or type(report["complete"]) is not bool
        or type(report["checked_at"]) is not int
        or not now - 30000 <= report["checked_at"] <= now + 1000
        or type(report["elapsed_ms"]) is not int
        or not 0 <= report["elapsed_ms"] <= 20000
        or type(report["examined"]) is not int
        or not 0 <= report["examined"] <= 64
        or type(report["unknown_oldest_age_ms"]) is not int
        or not 0 <= report["unknown_oldest_age_ms"] <= report["checked_at"]
    ):
        raise ValueError("invalid or stale native backlog observation")
    for field in COUNTS:
        maximum = report["examined"] * (64 if field == "receipts_pending" else 1)
        if type(report[field]) is not int or not 0 <= report[field] <= maximum:
            raise ValueError("invalid backlog count")
    if (
        report["unknown_owner_deadline_exceeded"] > report["unknown"]
        or (report["unknown"] == 0 and report["unknown_oldest_age_ms"] != 0)
        or sum(report[k] for k in ("claimed_not_dispatched", "unresolved_dispatches", "unknown"))
        > report["examined"]
    ):
        raise ValueError("inconsistent backlog observation")
    lines = [
        "kf_backlog_observation_valid 1",
        f"kf_backlog_observation_timestamp_seconds {report['checked_at'] / 1000:.3f}",
        f"kf_backlog_observation_complete {int(report['complete'])}",
        f"kf_backlog_examined {report['examined']}",
    ]
    # A bounded partial scan is useful diagnostically but cannot publish a zero
    # global unknown count or oldest age. Completeness has its own critical alert.
    if report["complete"]:
        lines.extend(f"{name} {report[field]}" for field, name in COUNTS.items())
        lines.append(f"kf_unknown_oldest_age_seconds {report['unknown_oldest_age_ms'] / 1000:.3f}")
    return "\n".join(lines) + "\n"


def observe(binary, config, custody_root):
    try:
        result = subprocess.run(
            [
                str(binary),
                "--config",
                str(config),
                "--custody-root",
                str(custody_root),
                "--require-managed",
                "--observe",
            ],
            capture_output=True,
            timeout=25,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if result.returncode or len(result.stdout) > 8192:
            raise ValueError("native observation unavailable")
        return metrics(json.loads(result.stdout), int(time.time() * 1000))
    except (OSError, ValueError, subprocess.SubprocessError):
        # Never echo credential paths, private native output or exception text.
        return "kf_backlog_observation_valid 0\n"


def publish(path, contents):
    parent = path.parent
    meta = parent.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o022:
        raise ValueError("protected telemetry output directory required")
    temporary = parent / (".backlog-" + secrets.token_hex(12))
    try:
        with temporary.open("x") as stream:
            os.chmod(temporary, 0o644)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--custody-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    paths = [args.binary, args.config, args.custody_root]
    if args.output is not None:
        paths.append(args.output)
    if any(not p.is_absolute() or "\n" in str(p) for p in paths):
        parser.error("absolute protected paths required")
    output = observe(args.binary, args.config, args.custody_root)
    if args.output is None:
        print(output, end="")
    else:
        publish(args.output, output)
