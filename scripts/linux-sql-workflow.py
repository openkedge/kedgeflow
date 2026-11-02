"""Live SQL component qualification; generated authority is never a broker claim."""

import base64
import copy
import hashlib
import json
import os
import re
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
MONITOR = "spiffe://example.org/operations/monitor"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def url64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def digest(kind, value):
    return hashlib.sha256(f"KedgeFlow/KF-JSON-0.2/{kind}\0".encode() + canonical(value)).hexdigest()


def material(config):
    """Match the shipping target's wire contract, using disposable signing seeds."""
    registration = config["registration"]
    envelope = json.loads((ROOT / "fixtures/grant.json").read_text())
    grant = envelope["payload"]
    now = int(time.time() * 1000)
    parameters = {
        "resource_id": registration["resource"]["id"],
        "expected_version": 1,
        "reservation": "booking:systemd",
    }
    grant.update(
        gid="systemd-sql-grant",
        root_id="systemd-sql-root",
        nonce="systemd-sql-nonce",
        issued_at=now - 1000,
        valid_from=now - 1000,
        expires_at=now + 15000,
        audience=config["gateway_audience"],
        action=registration["action"],
        resources=[registration["resource"]],
        conflict_domain=registration["conflict_domain"],
        adapter_contract=registration["adapter_contract"],
        completion_mode="dispatch_bound",
        parent_grant_digest=None,
        saga_budget=None,
        fence=10,
        parameters_digest=digest("parameters", parameters),
        predicate_descriptor={
            "id": registration["predicate_id"],
            "version": registration["predicate_version"],
            "language": "kf-conjunction-v1",
            "clauses": [
                {
                    "kind": "version_eq",
                    "resource": registration["resource"],
                    "expected_version": "1",
                }
            ],
        },
    )
    envelope.update(key_id="fixture-grant")
    envelope.pop("signature", None)
    envelope["signature"] = url64(
        Ed25519PrivateKey.from_private_bytes(bytes([6]) * 32).sign(
            b"KedgeFlow/KF-JSON-0.2\0" + canonical(envelope)
        )
    )
    grant_digest = digest("grant", envelope)
    # A generated target JWT qualifies target binding only. No broker/ledger is
    # involved, and this fixture must not report an independently consumed permit.
    claims = {
        "profile": "KF-TARGET-TOKEN-0.1-draft",
        "iss": config["token_issuer"],
        "aud": registration["target_audience"],
        "scope": registration["target_scope"],
        "iat": now // 1000,
        "exp": grant["expires_at"] // 1000,
        "permit_id": "a" * 64,
        "grant_digest": grant_digest,
        "root_id": grant["root_id"],
        "attempt_id": "systemd-sql-original",
        "gateway_workload": registration["gateway_workload"],
    }
    header = {"alg": "EdDSA", "typ": "kf-target+jwt", "kid": "fixture-target"}
    signing_input = url64(canonical(header)) + "." + url64(canonical(claims))
    token = (
        signing_input
        + "."
        + url64(Ed25519PrivateKey.from_private_bytes(bytes([29]) * 32).sign(signing_input.encode()))
    )
    request = {
        "profile": "KF-POSTGRES-TARGET-HTTP-0.1-draft",
        "operation": "dispatch",
        "signed_grant": url64(canonical(envelope)),
        "attempt_id": claims["attempt_id"],
        "parameters": parameters,
    }
    return request, token, claims


def public(seed):
    raw = (
        Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    return base64.b64encode(raw).decode()


@contextmanager
def systemd_process(
    command, env, unit_source, user, base, *, unit_directory=Path("/etc/systemd/system")
):
    """Retain the shipping sandbox; replace only fixture identity/paths/commands."""
    if Path("/proc/1/comm").read_text().strip() != "systemd" or os.geteuid() != 0:
        raise RuntimeError("systemd SQL fixture requires Linux root and systemd PID 1")
    name = base.name + ".service"
    path = unit_directory / name
    # These are entirely fixture-generated paths/flags, not shell input. Reject
    # systemd expansion characters rather than interpolating arbitrary arguments.
    if any(not re.fullmatch(r"[A-Za-z0-9_./:=\-]+", str(arg)) for arg in [user, *command]):
        raise ValueError("unsafe systemd fixture argument")

    def run(*args, check=True):
        return subprocess.run(
            ["systemctl", *args],
            env=env,
            capture_output=True,
            text=True,
            check=check,
            timeout=45,
        )

    class Service:
        def poll(self):
            state = run("show", "--value", "-p", "ActiveState", name).stdout.strip()
            return None if state in ("active", "activating", "reloading") else 1

        def restart(self):
            run("restart", name)

        def properties(self):
            properties = (
                "User",
                "Group",
                "MainPID",
                "NoNewPrivileges",
                "PrivateTmp",
                "ProtectSystem",
                "CapabilityBoundingSet",
                "RestrictNamespaces",
            )
            result = run("show", name, *[f"--property={p}" for p in properties])
            return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)

    unit = unit_source.read_text() + (
        f"\n[Service]\nUser={user}\nGroup={user}\nEnvironmentFile=\n"
        "ExecStartPre=\nExecStart=\n"
        f"ExecStartPre={' '.join(map(str, command))} --check-database\n"
        f"ExecStart={' '.join(map(str, command))}\nRestart=no\n"
    )
    # Exclusive creation occurs before cleanup ownership is assumed.
    with path.open("x") as stream:
        stream.write(unit)
    try:
        run("daemon-reload")
        run("start", name)
        yield Service()
    finally:
        # A failed start may still have children: stop/reap before deleting data
        # or accounts. Do not disguise a failed stop as successful cleanup.
        run("stop", name)
        run("reset-failed", name, check=False)
        path.unlink()
        run("daemon-reload")


def live_workflow(config, probe, sql, service):
    """Actual COMMIT, body loss/replay, restart, role withdrawal and expiry."""
    events = []

    def inventory():
        return [
            sql(f"SELECT to_jsonb(r) FROM kf_reservation.{table} r ORDER BY 1;")
            for table in ("resource", "attempt")
        ]

    def monitor(expected, executor, query):
        # Type=exec confirms execve, before the TLS socket necessarily binds.
        # Retry only a closed listener, never a typed unready/TLS refusal.
        deadline = time.monotonic() + 8
        while True:
            result = probe("monitor", "ready")
            if result != {"transport_error": "ConnectionRefusedError"}:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("systemd target monitor listener did not start")
            time.sleep(0.05)
        report = result["body"]
        assert result["status"] == expected and result["cache_control"] == "no-store", result
        assert report["profile"] == "KF-SERVICE-READINESS-0.1-draft"
        assert report["role"] == "sql_target" and report["scope"] == "local_prerequisites"
        assert report["ready"] == (expected == 200) and report["execution_authority"] is False
        assert report["elapsed_ms"] <= 5000
        assert abs(report["checked_at"] - int(time.time() * 1000)) <= 10000
        assert report["checks"] == [
            {"dependency": "database_execution", "condition": executor},
            {"dependency": "database_query", "condition": query},
        ], report
        events.append({"case": "readiness", **result})

    before = inventory()
    properties = service.properties()
    assert properties["NoNewPrivileges"] == "yes" and properties["PrivateTmp"] == "yes"
    assert properties["ProtectSystem"] == "strict" and properties["CapabilityBoundingSet"] == ""
    assert properties["RestrictNamespaces"] == "yes"
    status = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{properties['MainPID']}/status").read_text().splitlines()
        if ":" in line
    )
    assert int(status["Uid"].split()[1]) != 0
    assert int(status["CapEff"].strip(), 16) == 0
    assert status["NoNewPrivs"].strip() == "1" and status["Seccomp"].strip() == "2"
    monitor(200, "ready", "ready")
    assert inventory() == before
    assert probe("agent", "ready") == {
        "status": 403,
        "body": "request refused",
        "cache_control": "no-store",
    }
    assert inventory() == before
    body, token, claims = material(config)
    # Observe only HTTP headers, deliberately discard the successful body. The
    # outcome must then be recovered by original attempt, without another write.
    lost = probe("gateway", "dispatch", token, body, discard=True)
    assert lost == {"status": 200, "body_discarded": True}, lost
    outcome = probe(
        "recovery",
        "query",
        body={
            "profile": "KF-OUTCOME-RECOVERY-0.1-draft",
            "operation": "query",
            "attempt_id": claims["attempt_id"],
        },
    )
    assert outcome["status"] == 200, outcome
    original = outcome["body"]
    registration = config["registration"]
    assert original == {
        "AttemptID": claims["attempt_id"],
        "RootID": claims["root_id"],
        "GrantDigest": claims["grant_digest"],
        "Status": "committed",
        "TargetReference": (
            f"postgres:{registration['tenant']}:"
            f"{registration['resource']['id']}:{claims['attempt_id']}"
        ),
    }, original
    committed = inventory()
    replay = probe("gateway", "dispatch", token, body)
    assert replay["status"] == 200 and inventory() == committed, replay
    stored = replay["body"]
    assert stored["status"] == "committed" and stored["post_version"] == 2
    assert stored["request"] == {
        "profile": "KF-POSTGRES-RESERVATION-0.1-draft",
        "action": "postgres.reservation.set.v1",
        "tenant": registration["tenant"],
        "conflict_domain": registration["conflict_domain"],
        "attempt_id": claims["attempt_id"],
        "grant_digest": claims["grant_digest"],
        "root_id": claims["root_id"],
        "resource": registration["resource"],
        "expected_version": 1,
        "fence": 10,
        "reservation": "booking:systemd",
        "gateway_workload": registration["gateway_workload"],
        "expires_at": claims["exp"] * 1000,
    }
    events.append(
        {
            "case": "body_loss_original_query_and_replay",
            "attempt_id": claims["attempt_id"],
            "grant_digest": claims["grant_digest"],
            "outcome": original,
        }
    )
    service.restart()
    monitor(200, "ready", "ready")
    assert (
        probe(
            "recovery",
            "query",
            body={
                "profile": "KF-OUTCOME-RECOVERY-0.1-draft",
                "operation": "query",
                "attempt_id": claims["attempt_id"],
            },
        )
        == outcome
    )
    events.append({"case": "systemd_restart_original_query", "same_outcome": True})
    query_body = {
        "profile": "KF-OUTCOME-RECOVERY-0.1-draft",
        "operation": "query",
        "attempt_id": claims["attempt_id"],
    }
    try:
        sql("ALTER ROLE kf_executor NOLOGIN;")
        monitor(503, "unavailable", "ready")
        assert probe("recovery", "query", body=query_body) == outcome
        assert probe("gateway", "dispatch", token, body)["status"] != 200
        assert inventory() == committed
        events.append({"case": "executor_withdrawal_query_survives", "inventory_unchanged": True})
    finally:
        sql("ALTER ROLE kf_executor LOGIN;")
    monitor(200, "ready", "ready")
    try:
        sql("ALTER ROLE kf_reader NOLOGIN;")
        monitor(503, "ready", "unavailable")
        assert probe("recovery", "query", body=query_body)["status"] != 200
        assert inventory() == committed
        events.append({"case": "query_role_withdrawal", "inventory_unchanged": True})
    finally:
        sql("ALTER ROLE kf_reader LOGIN;")
    monitor(200, "ready", "ready")
    changed = copy.deepcopy(body)
    changed["parameters"]["reservation"] = "tampered"
    assert probe("gateway", "dispatch", token, changed)["status"] != 200
    # Execution expires; retained outcome disclosure remains query-only.
    while int(time.time() * 1000) <= claims["exp"] * 1000:
        time.sleep(0.05)
    assert probe("gateway", "dispatch", token, body)["status"] != 200
    assert probe("recovery", "query", body=query_body) == outcome
    assert inventory() == committed
    assert sql("SELECT count(*) FROM kf_reservation.attempt;") == "1"
    events.append(
        {
            "case": "expired_execution_original_query",
            "inventory_unchanged": True,
            "attempts": 1,
            "post_version": 2,
        }
    )
    return {
        "scope": "generated grant/target JWT; real shipping systemd target and PostgreSQL",
        "managed_authority": False,
        "events": events,
        "unit_properties": properties,
    }
