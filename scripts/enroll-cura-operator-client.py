#!/usr/bin/env python3
"""Enroll a technical governance client without broadening the untrusted Agent.

The client secret and administrator bearer stay on Identity. This client is an
implementation operator, never one of the independent enterprise acceptors.
Intent precedes creation; unknown existing clients and missing secrets fail closed.
"""

import json
import os
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
ORIGIN = "https://identity.cura.kedgeflow.internal:8443"
REALM = "kedgeflow-pilot"
CLIENT = "kf-pilot-operator"
SCOPES = {"kf.publish_policy", "kf.register_descriptor", "kf.install", "kf.revoke", "kf.query"}
DEADLINE = 1795420800
PHASE = "protected_identity_preconditions"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def protected(path, mode):
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != mode
        or info.st_size > 1 << 20
    ):
        raise RuntimeError("operator client custody differs")
    return path.read_bytes()


def write_once(path, raw, mode):
    if path.exists() or path.is_symlink():
        if protected(path, mode) != raw:
            raise RuntimeError("retained operator identity differs; never replace")
        return
    with path.open("xb") as stream:
        path.chmod(mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def client_definition(client_uuid, secret):
    return {
        "id": client_uuid,
        "clientId": CLIENT,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "secret": secret,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "fullScopeAllowed": False,
        "defaultClientScopes": [],
        "optionalClientScopes": [],
        "attributes": {
            "dpop.bound.access.tokens": "true",
            "access.token.signed.response.alg": "EdDSA",
            "access.token.lifespan": "120",
        },
        "protocolMappers": [
            {
                "name": "kedgeflow-delegation-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": "urn:kedgeflow:delegated-admission",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "userinfo.token.claim": "false",
                },
            }
        ],
    }


def require_client(value, expected):
    # Ignore server-generated metadata only; all authority-relevant inputs are exact.
    for key, wanted in expected.items():
        if key in {"secret", "defaultClientScopes", "optionalClientScopes", "protocolMappers"}:
            continue
        if key == "attributes":
            if any(value.get(key, {}).get(k) != v for k, v in wanted.items()):
                raise RuntimeError("operator client security attributes differ")
        elif value.get(key) != wanted:
            raise RuntimeError("operator client identity or enabled flows differ")
    mappers = value.get("protocolMappers", [])
    if len(mappers) != 1 or any(
        mappers[0].get(k) != v for k, v in expected["protocolMappers"][0].items()
    ):
        raise RuntimeError("operator claims mapper differs")


def enroll():
    global PHASE
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Identity"
        or time.time() >= DEADLINE
    ):
        raise RuntimeError("approved retained Identity window required")
    root = DATA / "configuration/identity-operator"
    info = root.lstat()
    if root.is_symlink() or info.st_uid != 0 or info.st_mode & 0o7777 != 0o700:
        raise RuntimeError("protected operator directory differs")
    context = ssl.create_default_context(cafile="/etc/kedgeflow-provider/keycloak/ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    def request(path, method="GET", body=None, bearer=None, form=None):
        headers = {}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if form is not None:
            raw = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        try:
            with urllib.request.urlopen(
                urllib.request.Request(ORIGIN + path, data=raw, headers=headers, method=method),
                context=context,
                timeout=10,
            ) as response:
                data = response.read((1 << 20) + 1)
                if len(data) > 1 << 20:
                    raise RuntimeError("bounded administration response required")
                return json.loads(data) if data else None
        except urllib.error.HTTPError:
            raise RuntimeError("fixed operator client operation refused") from None

    PHASE = "protected_administrator_login"
    admin = request(
        "/realms/master/protocol/openid-connect/token",
        "POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "cura-bootstrap-operator",
            "password": protected(root / "admin-password", 0o400).decode().strip(),
        },
    )["access_token"]
    base = "/admin/realms/" + REALM
    before = request("/realms/" + REALM + "/protocol/openid-connect/certs")
    agents_before = request(base + "/clients?clientId=kf-pilot-agent", bearer=admin)
    if len(agents_before) != 1:
        raise RuntimeError("retained Agent client ambiguous")
    agent_id = str(uuid.UUID(agents_before[0]["id"]))
    agent_scopes = request(base + "/clients/" + agent_id + "/default-client-scopes", bearer=admin)
    current = request(base + "/clients?clientId=" + CLIENT, bearer=admin)
    intent_path, secret_path = root / "operator-client-intent.json", root / "operator-client-secret"
    PHASE = "durable_operator_client_intent"
    if not intent_path.exists():
        if current or secret_path.exists():
            raise RuntimeError(
                "unregistered operator material exists; explicit reconciliation required"
            )
        intent = {
            "profile": "kedgeflow-cura-technical-operator-v1",
            "client_uuid": str(uuid.uuid4()),
            "client_id": CLIENT,
            "scopes": sorted(SCOPES),
            "independent_acceptor": False,
        }
        write_once(intent_path, canonical(intent), 0o600)
        write_once(secret_path, secrets.token_hex(32).encode(), 0o400)
    intent = json.loads(protected(intent_path, 0o600))
    if (
        intent.get("profile") != "kedgeflow-cura-technical-operator-v1"
        or intent.get("client_id") != CLIENT
        or intent.get("scopes") != sorted(SCOPES)
        or intent.get("independent_acceptor") is not False
    ):
        raise RuntimeError("operator intent differs")
    client_uuid = str(uuid.UUID(intent["client_uuid"]))
    secret = protected(secret_path, 0o400).decode()
    if len(secret) != 64 or any(c not in "0123456789abcdef" for c in secret):
        raise RuntimeError("operator client secret invalid")
    expected = client_definition(client_uuid, secret)
    PHASE = "technical_operator_client_creation"
    if not current:
        request(base + "/clients", "POST", body=expected, bearer=admin)
    elif len(current) != 1 or current[0]["id"] != client_uuid:
        raise RuntimeError("unknown existing operator client; never adopt")
    client_path = base + "/clients/" + client_uuid
    require_client(request(client_path, bearer=admin), expected)
    PHASE = "closed_operator_scope_binding"
    definitions = request(base + "/client-scopes", bearer=admin)
    for name in sorted(SCOPES):
        matches = [s for s in definitions if s.get("name") == name]
        if not matches:
            request(
                base + "/client-scopes",
                "POST",
                body={
                    "name": name,
                    "protocol": "openid-connect",
                    "attributes": {"include.in.token.scope": "true"},
                },
                bearer=admin,
            )
        elif (
            len(matches) != 1
            or matches[0].get("protocol") != "openid-connect"
            or (matches[0].get("attributes", {}).get("include.in.token.scope") != "true")
        ):
            raise RuntimeError("preexisting operator scope differs")
    definitions = request(base + "/client-scopes", bearer=admin)
    ids = {s["name"]: str(uuid.UUID(s["id"])) for s in definitions if s.get("name") in SCOPES}
    if set(ids) != SCOPES:
        raise RuntimeError("operator scope inventory incomplete")
    path = client_path + "/default-client-scopes"
    current_scopes = request(path, bearer=admin)
    if any(s["name"] not in SCOPES for s in current_scopes):
        raise RuntimeError("unexpected operator default scopes; never silently remove")
    for name in sorted(SCOPES - {s["name"] for s in current_scopes}):
        request(path + "/" + ids[name], "PUT", body={}, bearer=admin)
    observed = request(path, bearer=admin)
    if len(observed) != 5 or {s["name"] for s in observed} != SCOPES:
        raise RuntimeError("operator scope readback differs")
    if request(client_path + "/optional-client-scopes", bearer=admin):
        raise RuntimeError("optional operator scopes forbidden")
    if request(client_path + "/client-secret", bearer=admin).get("value") != secret:
        raise RuntimeError("operator secret differs; never rotate implicitly")
    user = request(client_path + "/service-account-user", bearer=admin)
    if user.get("username") != "service-account-" + CLIENT or user["id"] == (
        "d0b36f01-1188-4f01-907a-000000000001"
    ):
        raise RuntimeError("technical operator must be distinct from Agent")
    user_id = str(uuid.UUID(user["id"]))
    PHASE = "retained_agent_and_issuer_readback"
    if (
        canonical(before)
        != canonical(request("/realms/" + REALM + "/protocol/openid-connect/certs"))
        or canonical(agents_before)
        != canonical(request(base + "/clients?clientId=kf-pilot-agent", bearer=admin))
        or canonical(agent_scopes)
        != canonical(
            request(base + "/clients/" + agent_id + "/default-client-scopes", bearer=admin)
        )
    ):
        raise RuntimeError("retained Agent or issuer changed during operator enrollment")
    record = {
        "profile": "kedgeflow-cura-technical-operator-enrollment-v1",
        "status": "technical_operator_enrolled",
        "client_id": CLIENT,
        "subject": {"iss": ORIGIN + "/realms/" + REALM, "sub": user_id},
        "workload": "spiffe://cura.kedgeflow.internal/operator",
        "scopes": sorted(SCOPES),
        "dpop_required": True,
        "token_lifetime_seconds": 120,
        "agent_and_issuer_unchanged": True,
        "secret_or_tokens_returned": False,
        "independent_acceptor": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }
    write_once(root / "operator-client-enrollment.json", canonical(record), 0o600)
    return record


if __name__ == "__main__":
    try:
        print(json.dumps(enroll()))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
