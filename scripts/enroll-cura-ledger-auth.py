#!/usr/bin/env python3
"""Enroll individual namespace-scoped etcd principals from the protected Services host.

Passwords and bearer tokens stay on this host. No protocol key/value is written.
Existing overbroad roles, unexpected principals or changed enrollment refuse;
this does not reconcile an existing authority namespace or enroll a restore floor.
"""

import base64
import http.client
import json
import os
import secrets
import ssl
import subprocess
import time
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
DOMAIN = "cura.kedgeflow.internal"
NAMESPACE = "/kedgeflow/cura"
ROLES = (
    "gateway",
    "admission",
    "issuer",
    "broker",
    "recovery",
    "governance",
    "operator",
    "collector",
)
ETCDCTL = "/opt/kedgeflow/runtime/etcd/etcdctl"
PHASE = "preconditions"
LAST_ROUTE = "none"
LAST_STATUS = 0
LAST_CODE = 0


def encode(value):
    return base64.b64encode(value.encode()).decode()


def permissions(read_only=False):
    return [
        {
            "permType": "READ" if read_only else "READWRITE",
            "key": encode(NAMESPACE + "/"),
            "range_end": encode(NAMESPACE + "0"),
        }
    ]


def normalize(perms):
    result = []
    for p in perms:
        kind = p.get("permType", "READ")
        if kind in (0, 1, 2):
            kind = ["READ", "WRITE", "READWRITE"][kind]
        if kind not in {"READ", "WRITE", "READWRITE"} or set(p) - {"permType", "key", "range_end"}:
            raise RuntimeError("unknown ledger role permission")
        result.append((kind, p.get("key", ""), p.get("range_end", "")))
    return sorted(result)


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("ledger administration operation failed")
    return result


def protected_file(path, create=None):
    if not path.exists() and create is not None:
        with path.open("x") as stream:
            stream.write(create)
        path.chmod(0o400)
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_mode & 0o7777 != 0o400
    ):
        raise RuntimeError("ledger operator record custody differs")
    return path.read_text()


class API:
    def __init__(self, host):
        self.host = host
        self.context = ssl.create_default_context(cafile="/etc/kedgeflow/operator/ca.pem")
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(
            "/etc/kedgeflow/operator/identity.pem", "/etc/kedgeflow/operator/identity.key"
        )

    def call(self, route, body, token=None, *, check=True):
        global LAST_ROUTE, LAST_STATUS, LAST_CODE
        LAST_ROUTE = route
        connection = http.client.HTTPSConnection(
            self.host + "." + DOMAIN, 2379, context=self.context, timeout=8
        )
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = token
        try:
            connection.request("POST", "/v3/" + route, json.dumps(body), headers)
            response = connection.getresponse()
            raw = response.read((1 << 20) + 1)
            if len(raw) > 1 << 20:
                raise RuntimeError("ledger administration response exceeded bound")
            result = json.loads(raw)
            LAST_STATUS = response.status
            LAST_CODE = result.get("code", 0) if type(result.get("code", 0)) is int else -1
            if check and (response.status != 200 or "error" in result or "code" in result):
                raise RuntimeError("ledger administration request refused")
            return response.status, result
        finally:
            connection.close()

    def auth(self, username, password):
        result = self.call("auth/authenticate", {"name": username, "password": password})[1]
        token = result.get("token")
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise RuntimeError("ledger authentication response invalid")
        return token


def cli(endpoints, *args):
    return json.loads(
        run(
            [
                ETCDCTL,
                "--endpoints="
                + ",".join("https://" + h + "." + DOMAIN + ":2379" for h in endpoints),
                "--cacert=/etc/kedgeflow/etcd-admin/ca.pem",
                "--cert=/etc/kedgeflow/etcd-admin/identity.pem",
                "--key=/etc/kedgeflow/etcd-admin/identity.key",
                "--dial-timeout=5s",
                "--command-timeout=15s",
                "--write-out=json",
                *args,
            ]
        ).stdout
    )


def auth_enabled(response):
    # Protobuf JSON omits false. Require a complete AuthStatusResponse before
    # applying that default, never an empty/error/ambiguous response.
    if (
        not isinstance(response, dict)
        or not isinstance(response.get("header"), dict)
        or type(response.get("authRevision")) is not int
        or response["authRevision"] < 0
        or set(response) - {"header", "authRevision", "enabled"}
        or type(response.get("enabled", False)) is not bool
    ):
        raise RuntimeError("ambiguous authentication status")
    return response.get("enabled", False)


def provision(root, domain, hosts):
    global PHASE
    PHASE = domain + "_readiness"
    api = API(hosts[0])
    for _ in range(30):
        try:
            health = cli(hosts, "endpoint", "health")
            status = cli(hosts, "endpoint", "status")
            if len(health) != len(hosts) or not all(x["health"] for x in health):
                raise RuntimeError("incomplete ledger endpoint health")
            break
        except (OSError, ValueError, RuntimeError):
            time.sleep(1)
    else:
        raise RuntimeError("ledger readiness deadline")
    member = cli([hosts[0]], "member", "list")
    expected_peers = {"https://" + h + "." + DOMAIN + ":2380" for h in hosts}
    actual_peers = {u for m in member["members"] for u in m.get("peerURLs", [])}
    if (
        len(member["members"]) != len(hosts)
        or actual_peers != expected_peers
        or any(m.get("isLearner") for m in member["members"])
    ):
        raise RuntimeError("ledger membership differs")
    enabled = auth_enabled(cli([hosts[0]], "auth", "status"))
    spec = {
        "format": "kedgeflow-cura-etcd-rbac-v1",
        "domain": domain,
        "hosts": hosts,
        "namespace": NAMESPACE,
        "principals": ["cura-" + r for r in ROLES] + ["cura-observer"],
        "token_type": "simple",
        "token_ttl_seconds": 300,
    }
    record = root / (domain + "-enrollment.json")
    existed = record.exists()
    if not existed and enabled:
        raise RuntimeError(
            "authentication was already enabled without retained enrollment; never reconcile"
        )
    stored = protected_file(record, json.dumps(spec, sort_keys=True) + "\n")
    if json.loads(stored) != spec:
        raise RuntimeError("retained ledger enrollment differs")
    root_password = protected_file(root / (domain + "-root.password"), secrets.token_hex(32))
    token = api.auth("root", root_password) if enabled else None
    PHASE = domain + "_principals"
    user_names = set(api.call("auth/user/list", {}, token)[1].get("users", []))
    role_names = set(api.call("auth/role/list", {}, token)[1].get("roles", []))
    expected_names = {"root", *spec["principals"]}
    if not user_names <= expected_names or not role_names <= expected_names:
        raise RuntimeError("unexpected ledger principals; never remove or repurpose")
    for name in ["root", *spec["principals"]]:
        password = (
            root_password
            if name == "root"
            else protected_file(root / (domain + "-" + name + ".password"), secrets.token_hex(32))
        )
        if name not in user_names:
            if enabled:
                raise RuntimeError("enrolled principal missing; explicit repair required")
            api.call("auth/user/add", {"name": name, "password": password}, token)
        if name not in role_names:
            if enabled:
                raise RuntimeError("enrolled role missing; explicit repair required")
            api.call("auth/role/add", {"name": name}, token)
        wanted = (
            [{"permType": "READWRITE", "key": "", "range_end": "AA=="}]
            if name == "root"
            else permissions(name == "cura-observer")
        )
        actual = api.call("auth/role/get", {"role": name}, token)[1].get("perm", [])
        if not actual and wanted and not enabled and name != "root":
            for permission in wanted:
                api.call("auth/role/grant", {"name": name, "perm": permission}, token)
        elif normalize(actual) != normalize(wanted):
            raise RuntimeError("existing ledger permissions differ; never widen")
        actual_roles = api.call("auth/user/get", {"name": name}, token)[1].get("roles", [])
        if not actual_roles and not enabled:
            api.call("auth/user/grant", {"user": name, "role": name}, token)
        elif actual_roles != [name]:
            raise RuntimeError("existing ledger role membership differs")
    if not enabled:
        api.call("auth/enable", {})
    PHASE = domain + "_authentication_and_scope_checks"
    token = api.auth("root", root_password)
    # No tenant record is created: this is an auth/RBAC gate before native restore enrollment.
    probes = {
        "unauthenticated_read_denied": api.call(
            "kv/range", {"key": encode(NAMESPACE + "/preflight")}, check=False
        )[0]
        != 200
    }
    for name in spec["principals"]:
        password = protected_file(root / (domain + "-" + name + ".password"))
        ordinary = api.auth(name, password)
        wanted = permissions(name == "cura-observer")
        if api.call("auth/user/get", {"name": name}, ordinary)[1].get("roles") != [name]:
            raise RuntimeError("actual principal membership differs")
        if normalize(
            api.call("auth/role/get", {"role": name}, ordinary)[1].get("perm", [])
        ) != normalize(wanted):
            raise RuntimeError("actual effective permission differs")
        api.call("kv/range", {"key": encode(NAMESPACE + "/preflight")}, ordinary)
        for label, route, body in [
            ("outside_read", "kv/range", {"key": encode("/outside/preflight")}),
            (
                "outside_write",
                "kv/put",
                {"key": encode("/outside/preflight"), "value": encode("denied")},
            ),
            ("root_metadata", "auth/user/get", {"name": "root"}),
        ]:
            code, result = api.call(route, body, ordinary, check=False)
            if code == 200 or result.get("code") != 7:
                raise RuntimeError("ledger scoped principal bypass was not permission denied")
        probes[name + ":outside_and_root_denied"] = True
        if name == "cura-observer":
            code, result = api.call(
                "kv/put",
                {"key": encode(NAMESPACE + "/preflight"), "value": encode("denied")},
                ordinary,
                check=False,
            )
            if code == 200 or result.get("code") != 7:
                raise RuntimeError("read-only observer wrote an authority key")
            probes["observer_write_denied"] = True
    if not all(probes.values()) or cli([hosts[0]], "auth", "status").get("enabled") is not True:
        raise RuntimeError("ledger authentication check failed")
    # Assert failed write probes created no record, without disclosing any state.
    outside = api.call("kv/range", {"key": encode("/outside/preflight")}, token)[1]
    inside = api.call("kv/range", {"key": encode(NAMESPACE + "/preflight")}, token)[1]
    if outside.get("kvs") or inside.get("kvs"):
        raise RuntimeError("preflight key exists; preserve it for investigation")
    cluster_ids = {x["Status"]["header"]["cluster_id"] for x in status}
    if len(cluster_ids) != 1:
        raise RuntimeError("endpoint cluster IDs differ")
    return {
        "domain": domain,
        "members": len(hosts),
        "cluster_id": str(next(iter(cluster_ids))),
        "authentication_enabled": True,
        "individual_principals": len(spec["principals"]),
        "namespace": NAMESPACE,
        "token_type": "simple",
        "token_ttl_seconds": 300,
        "scope_refusals": probes,
        "protocol_records_created": False,
    }


def enroll():
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Services"
    ):
        raise RuntimeError("requires privileged retained Services host")
    root = DATA / "operations/ledger-admin"
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != 0 or root.stat().st_mode & 0o7777 != 0o700:
        raise RuntimeError("ledger administrator custody differs")
    result = [
        provision(root, "primary", ["ledgera", "ledgerb", "ledgerc"]),
        provision(root, "witness", ["witness"]),
    ]
    return {
        "format": "kedgeflow-cura-ledger-auth-observation-v1",
        "status": "authenticated_topologies_enrolled",
        "topologies": result,
        "passwords_or_tokens_returned": False,
        "native_namespace_and_floor_enrollment": "PENDING",
        "independent_custody": "BLOCKED_EXTERNAL_INPUT",
        "per_key_service_qualification": "PENDING",
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(enroll(), indent=2))
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "phase": PHASE,
                    "error_class": type(error).__name__,
                    "last_api_route": LAST_ROUTE,
                    "last_http_status": LAST_STATUS,
                    "last_rpc_code": LAST_CODE,
                    "failure_category": {
                        "existing ledger permissions differ; never widen": "permission_mismatch",
                        "existing ledger role membership differs": "membership_mismatch",
                        "unexpected ledger principals; never remove or repurpose": (
                            "unexpected_principals"
                        ),
                        "ledger administration request refused": "api_refused",
                        "unknown ledger role permission": "unknown_permission_shape",
                    }.get(str(error), "other_fixed_failure"),
                }
            )
        )
        raise SystemExit(1) from None
