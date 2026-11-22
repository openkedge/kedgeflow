#!/usr/bin/env python3
"""Bind the existing DPoP client to the five closed SQL-pilot scopes.

Uses the protected on-host technical administrator; its bearer stays in memory.
No new user, client secret, signing key, reviewer identity or approval is created.
Existing realm/client keys and disabled browser/password flows are preserved.
"""

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
ORIGIN = "https://identity.cura.kedgeflow.internal:8443"
REALM = "kedgeflow-pilot"
CLIENT = "kf-pilot-agent"
SCOPES = {"reservation:request", "kf.admit", "kf.issue", "kf.status", "kf.evidence"}
PHASE = "preconditions"


def public_keys(value):
    if (
        not isinstance(value.get("keys"), list)
        or not value["keys"]
        or any(set(k) & {"d", "p", "q", "dp", "dq", "qi", "k"} for k in value["keys"])
    ):
        raise RuntimeError("issuer public keys missing or contain private fields")
    return sorted(json.dumps(k, sort_keys=True) for k in value["keys"])


def enrolled_client(value):
    if (
        value.get("clientId") != CLIENT
        or value.get("publicClient") is not False
        or value.get("serviceAccountsEnabled") is not True
        or value.get("standardFlowEnabled") is not False
        or value.get("directAccessGrantsEnabled") is not False
        or value.get("attributes", {}).get("dpop.bound.access.tokens") != "true"
        or value.get("attributes", {}).get("access.token.signed.response.alg") != "EdDSA"
    ):
        raise RuntimeError("enrolled DPoP client contract differs")
    return str(uuid.UUID(value["id"]))


def enroll():
    global PHASE
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Identity"
    ):
        raise RuntimeError("requires privileged retained Identity host")
    operator = DATA / "configuration/identity-operator"
    password_path = operator / "admin-password"
    info = password_path.lstat()
    if (
        password_path.is_symlink()
        or not password_path.is_file()
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != 0o400
    ):
        raise RuntimeError("technical administrator custody differs")
    context = ssl.create_default_context(cafile="/etc/kedgeflow-provider/keycloak/ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    def request(path, *, method="GET", body=None, bearer=None, form=None):
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
                raw = response.read((1 << 20) + 1)
                if len(raw) > 1 << 20:
                    raise RuntimeError("identity administration response exceeded bound")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError:
            # Do not emit response body/headers: token and credential errors can be sensitive.
            raise RuntimeError("closed identity administration request refused") from None

    issuer_path = "/realms/" + REALM
    before = request(issuer_path + "/protocol/openid-connect/certs")
    public_keys(before)
    PHASE = "protected_administrator_login"
    admin = request(
        "/realms/master/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "cura-bootstrap-operator",
            "password": password_path.read_text().strip(),
        },
    )["access_token"]
    if not isinstance(admin, str) or not 40 <= len(admin) <= 32768:
        raise RuntimeError("technical administrator token invalid")
    base = "/admin/realms/" + REALM
    PHASE = "enrolled_client_contract"
    clients = request(base + "/clients?clientId=" + CLIENT, bearer=admin)
    if not isinstance(clients, list) or len(clients) != 1:
        raise RuntimeError("ambiguous enrolled pilot client")
    client_id = enrolled_client(clients[0])
    user = request(base + "/clients/" + client_id + "/service-account-user", bearer=admin)
    if (
        user.get("id") != "d0b36f01-1188-4f01-907a-000000000001"
        or user.get("username") != "service-account-kf-pilot-agent"
    ):
        raise RuntimeError("actual service-account subject differs from registered pilot")
    PHASE = "closed_scope_definitions"
    definitions = request(base + "/client-scopes", bearer=admin)
    for name in sorted(SCOPES):
        matches = [s for s in definitions if s.get("name") == name]
        if not matches:
            request(
                base + "/client-scopes",
                method="POST",
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
            or matches[0].get("attributes", {}).get("include.in.token.scope") != "true"
        ):
            raise RuntimeError("existing named scope contract differs; never repurpose")
    definitions = request(base + "/client-scopes", bearer=admin)
    expected = {s["name"]: str(uuid.UUID(s["id"])) for s in definitions if s.get("name") in SCOPES}
    if set(expected) != SCOPES:
        raise RuntimeError("incomplete pilot scope inventory")
    PHASE = "bounded_client_scope_binding"
    path = base + "/clients/" + client_id + "/default-client-scopes"
    current = request(path, bearer=admin)
    for scope in current:
        if scope["name"] not in SCOPES:
            request(path + "/" + str(uuid.UUID(scope["id"])), method="DELETE", bearer=admin)
    current = {s["name"] for s in request(path, bearer=admin)}
    for name, scope_id in expected.items():
        if name not in current:
            request(path + "/" + scope_id, method="PUT", body={}, bearer=admin)
    observed = request(path, bearer=admin)
    if len(observed) != len(SCOPES) or {s["name"] for s in observed} != SCOPES:
        raise RuntimeError("actual default scopes differ")
    enrolled_client(request(base + "/clients/" + client_id, bearer=admin))
    if request(base + "/clients/" + client_id + "/optional-client-scopes", bearer=admin):
        raise RuntimeError("unexpected optional scope permits broader issuance")
    after = request(issuer_path + "/protocol/openid-connect/certs")
    if public_keys(before) != public_keys(after):
        raise RuntimeError("issuer keys changed during scope enrollment; review new public pins")
    record = {
        "format": "kedgeflow-cura-identity-scope-enrollment-v1",
        "status": "closed_sql_scopes_enrolled",
        "client_id": CLIENT,
        "scopes": sorted(SCOPES),
        "subject": {"iss": ORIGIN + issuer_path, "sub": user["id"]},
        "issuer_public_key_ids": sorted(k["kid"] for k in after["keys"]),
        "issuer_public_keys_unchanged": True,
        "dpop_required": True,
        "browser_and_password_client_flows_disabled": True,
        "client_secret_or_keys_rotated": False,
        "tokens_or_passwords_returned": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }
    path = operator / "sql-scope-enrollment.json"
    raw = json.dumps(record, sort_keys=True) + "\n"
    if path.exists():
        info = path.lstat()
        if (
            path.is_symlink()
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o7777 != 0o600
            or path.read_text() != raw
        ):
            raise RuntimeError("retained client scope enrollment differs")
    else:
        with path.open("x") as stream:
            stream.write(raw)
        path.chmod(0o600)
    return record


if __name__ == "__main__":
    try:
        print(json.dumps(enroll(), indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
