#!/usr/bin/env python3
"""Bounded pre-application credential failure/expiry rehearsal on Cura Services.

Prepare stops renewal temporarily with a 420-second recovery watchdog. Finish no
earlier than 330 seconds later checks actual old-token expiry and fresh renewal.
Opaque credentials and the fault backup stay in a protected on-host record.
"""

import argparse
import http.client
import json
import os
import pwd
import secrets
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
STATE = DATA / "operations/credential-lifecycle.private.json"
TIMER = "kedgeflow-ledger-publish.timer"
PUBLISH = "kedgeflow-ledger-publish.service"
ISSUE = "kedgeflow-ledger-issue.service"
WATCHDOG = "kedgeflow-cura-credentials-resume"
MAPPING = Path("/etc/kedgeflow/ledger-credentials/mapping.json")
PASSWORD = DATA / "configuration/ledger-credentials/gateway-primary.password"


def run(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    if check and result.returncode:
        raise RuntimeError("credential lifecycle operation failed")
    return result


def check_host():
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Services"
    ):
        raise RuntimeError("requires privileged retained Services host")
    # This deliberate expiry test is allowed only before application authority is live.
    for role in ["gateway", "admission", "issuer", "broker", "recovery", "governance"]:
        if (
            run(
                ["systemctl", "is-active", "--quiet", "kedgeflow-" + role + ".service"], False
            ).returncode
            == 0
        ):
            raise RuntimeError("live application services forbid pre-application expiry drill")


def write_state(value, first=False):
    if first and (STATE.exists() or STATE.is_symlink()):
        raise RuntimeError("existing rehearsal must be reviewed or recovered, never overwritten")
    if STATE.exists():
        read_state()
    temporary = STATE.with_suffix(".new")
    with temporary.open("x") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    temporary.replace(STATE)


def read_state():
    info = STATE.lstat()
    if (
        STATE.is_symlink()
        or not STATE.is_file()
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != 0o600
        or info.st_size > 65536
    ):
        raise RuntimeError("unprotected lifecycle record")
    return json.loads(STATE.read_text())


def current_tokens():
    result = {}
    mapping = json.loads(MAPPING.read_text())
    if mapping["profile"] != "KF-LEDGER-CREDENTIALS-0.1" or len(mapping["destinations"]) != 14:
        raise RuntimeError("closed seven-role credential mapping required")
    for item in mapping["destinations"]:
        role = item["role"]
        if role not in {
            "gateway",
            "admission",
            "issuer",
            "broker",
            "recovery",
            "governance",
            "operator",
        } or item["filename"] not in {"primary.token", "witness.token"}:
            raise RuntimeError("unexpected credential destination")
        path = Path("/etc/kedgeflow") / role / "credentials" / item["filename"]
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_nlink != 1
            or info.st_uid != pwd.getpwnam("kf-" + role).pw_uid
            or info.st_mode & 0o7777 != 0o400
        ):
            raise RuntimeError("published credential custody differs")
        result[item["name"]] = path.read_text()
    if len(result) != 14:
        raise RuntimeError("ambiguous credential destinations")
    return result


def credential_status(name, token):
    role, domain = name.rsplit("-", 1)
    if role not in {
        "gateway",
        "admission",
        "issuer",
        "broker",
        "recovery",
        "governance",
        "operator",
    } or domain not in {"primary", "witness"}:
        raise RuntimeError("unregistered lifecycle token")
    host = "ledgera" if domain == "primary" else "witness"
    root = Path("/etc/kedgeflow") / role
    context = ssl.create_default_context(cafile=str(root / "ca.pem"))
    context.load_cert_chain(root / "identity.pem", root / "identity.key")
    connection = http.client.HTTPSConnection(
        host + ".cura.kedgeflow.internal", 2379, context=context, timeout=8
    )
    try:
        connection.request(
            "POST",
            "/v3/kv/range",
            '{"key":"L2tlZGdlZmxvdy9jdXJhL3ByZWZsaWdodA=="}',
            {"Content-Type": "application/json", "Authorization": token},
        )
        response = connection.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536:
            raise RuntimeError("lifecycle response exceeded bound")
        result = json.loads(raw)
        return response.status, result.get("code", 0)
    finally:
        connection.close()


def password_contents(value=None):
    info = PASSWORD.lstat()
    user = pwd.getpwnam("kf-credentials")
    if (
        PASSWORD.is_symlink()
        or not PASSWORD.is_file()
        or info.st_uid != user.pw_uid
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != 0o400
    ):
        raise RuntimeError("publisher password custody differs")
    if value is not None:
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise RuntimeError("invalid retained fault backup")
        with PASSWORD.open("w") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    return PASSWORD.read_text()


def resume(state):
    password_contents(state["password_backup"])
    run(["systemctl", "reset-failed", ISSUE, PUBLISH], False)
    try:
        run(["systemctl", "start", PUBLISH])
    finally:
        run(["systemctl", "start", TIMER])


def prepare():
    check_host()
    if STATE.exists() or STATE.is_symlink():
        raise RuntimeError("existing rehearsal must be reviewed or recovered")
    run(["systemctl", "stop", TIMER])
    try:
        run(["systemctl", "start", PUBLISH])
        old = current_tokens()
        if not all(credential_status(name, token) == (200, 0) for name, token in old.items()):
            raise RuntimeError("fresh credential positive control failed")
        now = int(time.time())
        state = {
            "format": "kedgeflow-cura-credential-lifecycle-private-v1",
            "created_at": now,
            "not_before": now + 330,
            "watchdog_at": now + 420,
            "old_tokens": old,
            "password_backup": password_contents(),
            "phase": "prepared",
        }
        write_state(state, first=True)
        run(
            [
                "systemd-run",
                "--quiet",
                "--collect",
                "--unit=" + WATCHDOG,
                "--on-active=420s",
                "/usr/bin/python3",
                "/usr/local/sbin/kf-probe-cura-credential-lifecycle.py",
                "--action",
                "recover",
            ]
        )
        try:
            password_contents(secrets.token_hex(32))
            failed = run(["systemctl", "start", PUBLISH], False).returncode != 0
            retained = current_tokens() == old
            if not failed or not retained:
                raise RuntimeError("authentication failure did not prevent credential publication")
        finally:
            password_contents(state["password_backup"])
            run(["systemctl", "reset-failed", ISSUE, PUBLISH], False)
        return {
            "format": "kedgeflow-cura-credential-lifecycle-prepare-v1",
            "status": "prepared",
            "positive_token_controls": len(old),
            "native_authentication_failure_refused": True,
            "all_prior_destination_tokens_retained": True,
            "renewal_temporarily_stopped": True,
            "finish_not_before_utc": datetime.fromtimestamp(
                state["not_before"], timezone.utc
            ).isoformat(),
            "automatic_recovery_utc": datetime.fromtimestamp(
                state["watchdog_at"], timezone.utc
            ).isoformat(),
            "tokens_or_passwords_returned": False,
        }
    except Exception:
        if STATE.exists():
            resume(read_state())
        else:
            run(["systemctl", "start", TIMER])
        raise


def finish():
    check_host()
    state = read_state()
    if int(time.time()) < state["not_before"]:
        raise RuntimeError("actual token-expiry observation is not due yet")
    try:
        for name, token in state["old_tokens"].items():
            status, code = credential_status(name, token)
            if status == 200 or code != 16:
                raise RuntimeError("old token was not explicitly unauthenticated")
        resume(state)
        fresh = current_tokens()
        if set(fresh) != set(state["old_tokens"]) or any(
            fresh[n] == state["old_tokens"][n] for n in fresh
        ):
            raise RuntimeError("fresh publication did not replace expired credentials")
        if not all(credential_status(name, token) == (200, 0) for name, token in fresh.items()):
            raise RuntimeError("renewed credential positive control failed")
        run(["systemctl", "is-active", "--quiet", TIMER])
    except Exception:
        resume(state)
        raise
    run(["systemctl", "stop", WATCHDOG + ".timer"], False)
    STATE.unlink()
    return {
        "format": "kedgeflow-cura-credential-lifecycle-v1",
        "status": "passed_actual_failure_expiry_and_renewal",
        "expired_tokens_explicitly_unauthenticated": len(fresh),
        "renewed_tokens_allowed": len(fresh),
        "native_authentication_failure_retained_prior_destinations": True,
        "renewal_timer_active": True,
        "private_rehearsal_record_removed": True,
        "protocol_authority_writes": 0,
        "tokens_or_passwords_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=["prepare", "finish", "recover"], required=True)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            result = prepare()
        elif args.action == "finish":
            result = finish()
        else:
            if os.geteuid() != 0:
                raise RuntimeError("privileged watchdog required")
            resume(read_state())
            result = {"status": "renewal_resumed", "secrets_returned": False}
        print(json.dumps(result, indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__}))
        raise SystemExit(1) from None
