#!/usr/bin/env python3
"""Read-only mTLS readiness probes -> Prometheus text. No credentials or responses are logged."""

import argparse
import http.client
import json
import math
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit

ROLES = {
    "gateway",
    "control",
    "broker",
    "sql_target",
    "governance",
    "collector",
    "recovery",
    "supervision",
}

EXPECTED_CHECKS = {
    "control": {"authority_reads", "managed_control"},
    "broker": {"authority_reads", "managed_control", "identity_material"},
    "collector": {"authority_reads"},
    "governance": {"authority_reads"},
    "gateway": {"authority_reads", "managed_control", "broker", "target"},
    "sql_target": {"database_execution", "database_query"},
    "recovery": {"authority_reads", "target_query"},
    "supervision": {"authority_reads", "target_query", "delivery_material", "collector"},
}


def validate_report(report, role, status, cache_control, now):
    if (
        not isinstance(report, dict)
        or report.get("profile") != "KF-SERVICE-READINESS-0.1-draft"
        or report.get("role") != role
        or report.get("scope") != "local_prerequisites"
        or report.get("execution_authority") is not False
        or cache_control != "no-store"
        or type(report.get("ready")) is not bool
        or status not in (200, 503)
        or (status == 200) != report["ready"]
    ):
        return False
    checked = report.get("checked_at")
    if type(checked) is not int or not now - 10000 <= checked <= now + 1000:
        return False
    elapsed = report.get("elapsed_ms")
    if type(elapsed) is not int or not 0 <= elapsed <= 5000:
        return False
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        return False
    if any(
        not isinstance(c, dict)
        or set(c) != {"dependency", "condition"}
        or not isinstance(c["dependency"], str)
        or c["condition"] not in ("ready", "refused", "unavailable", "unverified")
        for c in checks
    ):
        return False
    if len(set(c["dependency"] for c in checks)) != len(checks):
        return False
    dependencies = {c["dependency"] for c in checks}
    if dependencies != EXPECTED_CHECKS.get(role):
        # Native shutdown/timeout reports have a single failed probe and remain unready.
        return (
            not report["ready"]
            and dependencies == {"probe"}
            and checks[0]["condition"] in {"refused", "unavailable"}
        )
    return report["ready"] == all(c["condition"] == "ready" for c in checks)


def observe(config):
    lines, roles = [], set()
    if not isinstance(config, dict) or set(config) != {"profile", "endpoints"}:
        raise ValueError("closed monitor configuration required")
    if config["profile"] != "cura" or not isinstance(config["endpoints"], list):
        raise ValueError("cura monitor configuration required")
    for endpoint in config["endpoints"]:
        if set(endpoint) != {"role", "url", "ca", "certificate", "private_key"}:
            raise ValueError("closed endpoint configuration required")
        role = endpoint["role"]
        if role not in ROLES or role in roles:
            raise ValueError("unknown or duplicate role")
        roles.add(role)
        url = urlsplit(endpoint["url"])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path != "/ops/ready"
            or not all(
                Path(endpoint[k]).is_absolute() for k in ("ca", "certificate", "private_key")
            )
        ):
            raise ValueError("explicit HTTPS monitor and absolute protected material required")
        valid, ready, elapsed = False, False, 0.0
        start = time.monotonic()
        connection = None
        try:
            context = ssl.create_default_context(cafile=endpoint["ca"])
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(endpoint["certificate"], endpoint["private_key"])
            connection = http.client.HTTPSConnection(
                url.hostname, url.port or 443, context=context, timeout=5
            )
            connection.request("GET", url.path, headers={"Host": url.netloc, "Connection": "close"})
            response = connection.getresponse()
            body = response.read(16385)
            if len(body) <= 16384:
                report = json.loads(body)
                valid = validate_report(
                    report,
                    role,
                    response.status,
                    response.getheader("Cache-Control"),
                    int(time.time() * 1000),
                )
                ready = valid and report["ready"]
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
            pass
        finally:
            if connection:
                connection.close()
            elapsed = time.monotonic() - start
        if not math.isfinite(elapsed):
            elapsed = 5.0
        lines.extend(
            [
                f'kf_pilot_probe_valid{{role="{role}"}} {int(valid)}',
                f'kf_pilot_ready{{role="{role}"}} {int(ready)}',
                f'kf_pilot_probe_seconds{{role="{role}"}} {elapsed:.6f}',
            ]
        )
    if roles != ROLES:
        raise ValueError("all managed pilot monitoring roles must be enrolled")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    if not args.config.is_absolute() or "\n" in str(args.config):
        parser.error("protected absolute configuration path required")
    print(observe(json.loads(args.config.read_text())), end="")
