#!/usr/bin/env python3
"""Add a function-only reader of the one enrolled Cura reservation row.

The existing write migration, executor and reader roles remain unchanged. This
explicit additive deployment records intent before DDL and never retries an
ambiguous installation by dropping/replacing a role/function. No evidence API or
resource action starts here; only public proof-key pins and bounded checks leave.
"""

import argparse
import base64
import hashlib
import json
import os
import pwd
import re
import runpy
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DATA = Path("/var/lib/kedgeflow/pilot")
BASE = Path("/usr/local/sbin/kf-enroll-cura-postgres.py")
PHASE = "preconditions"


def function_body(incarnation):
    if not re.fullmatch(r"cura-reservation-[a-f0-9]{32}", incarnation):
        raise ValueError("exact enrolled reservation incarnation required")
    return (
        "SELECT jsonb_build_object('tenant',tenant,'conflict_domain',conflict_domain,"
        "'resource_id',resource_id,'incarnation',incarnation,'version',version::text,"
        "'last_fence',last_fence::text,'reservation',reservation,'active',active) "
        "FROM kf_reservation.resource WHERE tenant='cura-pilot' AND resource_id='slot-a' "
        f"AND incarnation='{incarnation}';"
    )


def ddl(incarnation):
    return (
        "BEGIN; CREATE ROLE kf_observer LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
        "NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4; "
        "CREATE FUNCTION kf_reservation.observe_cura() RETURNS jsonb "
        "LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp "
        "AS $cura_observer$" + function_body(incarnation) + "$cura_observer$; "
        "REVOKE ALL ON FUNCTION kf_reservation.observe_cura() FROM PUBLIC; "
        "GRANT CONNECT ON DATABASE kedgeflow TO kf_observer; "
        "GRANT USAGE ON SCHEMA kf_reservation TO kf_observer; "
        "GRANT EXECUTE ON FUNCTION kf_reservation.observe_cura() TO kf_observer; COMMIT;"
    )


def observation_check(value, incarnation):
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "tenant",
            "conflict_domain",
            "resource_id",
            "incarnation",
            "version",
            "last_fence",
            "reservation",
            "active",
        }
        or value["tenant"] != "cura-pilot"
        or value["conflict_domain"] != "cura-sql-pilot:reservations"
        or value["resource_id"] != "slot-a"
        or value["incarnation"] != incarnation
        or not isinstance(value["version"], str)
        or not re.fullmatch(r"[1-9][0-9]{0,15}", value["version"])
        or int(value["version"]) > 9007199254740991
        or not isinstance(value["last_fence"], str)
        or not re.fullmatch(r"0|[1-9][0-9]{0,15}", value["last_fence"])
        or int(value["last_fence"]) > 9007199254740991
        or type(value["active"]) is not bool
        or not isinstance(value["reservation"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}", value["reservation"])
    ):
        raise RuntimeError("read-only observation does not match the registered resource")
    return value


def proof_key(path, user):
    if not path.exists() and not path.is_symlink():
        with path.open("xb") as stream:
            stream.write(base64.b64encode(os.urandom(32)))
        os.chown(path, user.pw_uid, user.pw_gid)
        path.chmod(0o400)
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_nlink != 1
        or info.st_uid != user.pw_uid
        or info.st_gid != user.pw_gid
        or info.st_mode & 0o7777 != 0o400
    ):
        raise RuntimeError("observer proof key custody differs")
    raw = base64.b64decode(path.read_bytes(), validate=True)
    if len(raw) != 32:
        raise RuntimeError("observer proof key length differs")
    public = (
        Ed25519PrivateKey.from_private_bytes(raw)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return base64.b64encode(public).decode()


def enroll(base_sha256):
    global PHASE
    if (
        os.geteuid() != 0
        or not DATA.is_mount()
        or json.loads((DATA / ".host-enrollment.json").read_text())["host"] != "Sql"
    ):
        raise RuntimeError("requires privileged retained Sql host")
    info = BASE.lstat()
    if (
        not re.fullmatch(r"[a-f0-9]{64}", base_sha256)
        or BASE.is_symlink()
        or not BASE.is_file()
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != 0o600
        or hashlib.sha256(BASE.read_bytes()).hexdigest() != base_sha256
    ):
        raise RuntimeError("base SQL enrollment source pin or custody differs")
    base = runpy.run_path(str(BASE))
    sql, run = base["sql"], base["run"]
    original = base["private_json"](DATA / "configuration/postgres-operator/enrollment.json")
    incarnation = original["incarnation"]
    if original["tenant"] != "cura-pilot" or original["resource_id"] != "slot-a":
        raise RuntimeError("registered Sql resource differs")
    user, db_user = pwd.getpwnam("kf-observer"), pwd.getpwnam("kf-postgres")
    if not user.pw_uid or user.pw_uid in {db_user.pw_uid, pwd.getpwnam("kf-sql-target").pw_uid}:
        raise RuntimeError("distinct non-root observer identity required")
    source = DATA / "configuration/sql-observer"
    target = Path("/etc/kedgeflow/sql-observer")
    if (
        not source.is_dir()
        or source.is_symlink()
        or source.stat().st_uid != 0
        or source.stat().st_gid != user.pw_gid
        or source.stat().st_mode & 0o7777 != 0o750
        or (source.stat().st_dev, source.stat().st_ino)
        != (target.stat().st_dev, target.stat().st_ino)
    ):
        raise RuntimeError("observer host-local PKI must be enrolled first")
    body, statement = function_body(incarnation), ddl(incarnation)
    pending = DATA / "configuration/postgres-operator/observer-enrollment.json"
    expected = {
        "format": "kedgeflow-cura-sql-observer-enrollment-v1",
        "incarnation": incarnation,
        "base_sql_enrollment": original,
        "ddl_sha256": hashlib.sha256(statement.encode()).hexdigest(),
    }
    before = base["snapshot"]()
    base["audit_roles"]()
    first = not pending.exists()
    PHASE = "read_only_role_installation"
    if first:
        if (
            sql(
                "SELECT to_regprocedure('kf_reservation.observe_cura()') IS NULL AND NOT EXISTS "
                "(SELECT FROM pg_roles WHERE rolname='kf_observer');"
            ).stdout.strip()
            != "t"
        ):
            raise RuntimeError("observer function or role already exists without enrollment")
        base["write_once"](pending, json.dumps(expected, sort_keys=True) + "\n")
        sql(statement)
    elif base["private_json"](pending) != expected:
        raise RuntimeError("observer enrollment differs; never replace")
    # A pending DDL failure has no automatic retry/drop/replace path.
    retained = sql(
        "SELECT prosrc FROM pg_proc WHERE oid=to_regprocedure('kf_reservation.observe_cura()');"
    ).stdout.strip()
    if retained != body:
        raise RuntimeError(
            "installed observer function differs or is absent; preserve enrollment for review"
        )
    custody = sql(
        "SELECT p.prosecdef AND p.provolatile='s' AND p.pronargs=0 "
        "AND p.prorettype='jsonb'::regtype AND l.lanname='sql' "
        "AND p.proowner=(SELECT oid FROM pg_roles WHERE rolname='kf-postgres') "
        "AND array_length(p.proconfig,1)=1 AND p.proconfig[1] IN "
        "('search_path=pg_catalog, pg_temp','search_path=pg_catalog,pg_temp') "
        "AND NOT has_function_privilege('kf_reader',p.oid,'EXECUTE') "
        "FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang "
        "WHERE p.oid=to_regprocedure('kf_reservation.observe_cura()');"
    ).stdout.strip()
    if custody != "t":
        raise RuntimeError("observer function ownership or execution context differs")
    PHASE = "exact_read_only_peer_enrollment"
    data = DATA / "postgresql"
    old_hba, old_ident = base["hba"](), base["ident"]()
    new_hba = old_hba.replace(
        "local all all reject\n",
        "local kedgeflow kf_observer peer map=kf_observer\nlocal all all reject\n",
    )
    new_ident = old_ident + "kf_observer kf-observer kf_observer\n"
    for name, old, new in [
        ("pg_hba.conf", old_hba, new_hba),
        ("pg_ident.conf", old_ident, new_ident),
    ]:
        path = data / name
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_uid != db_user.pw_uid
            or info.st_nlink != 1
            or info.st_mode & 0o7777 != 0o600
            or path.read_text() not in {old, new}
        ):
            raise RuntimeError("database authentication profile differs; never reconcile")
        if path.read_text() == old:
            with path.open("w") as stream:
                stream.write(new)
                stream.flush()
                os.fsync(stream.fileno())
    run(["usermod", "-a", "-G", "kf-postgres", "kf-observer"])
    sql("SELECT pg_reload_conf();")
    for _ in range(20):
        probe = sql(
            "SELECT kf_reservation.observe_cura();", "kf-observer", "kf_observer", check=False
        )
        if not probe.returncode:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError("observer peer mapping startup deadline")
    observed = observation_check(json.loads(probe.stdout), incarnation)
    good = sql(
        "SELECT NOT (rolsuper OR rolinherit OR rolcreaterole OR rolcreatedb "
        "OR rolreplication OR rolbypassrls) "
        "AND rolcanlogin AND NOT EXISTS (SELECT FROM pg_auth_members WHERE member=oid) "
        "AND NOT has_database_privilege('kf_observer','kedgeflow','CREATE') "
        "AND NOT has_schema_privilege('kf_observer','kf_reservation','CREATE') "
        "AND has_function_privilege('kf_observer','kf_reservation.observe_cura()','EXECUTE') "
        "AND NOT has_function_privilege('kf_observer','kf_reservation.observe_cura()',"
        "'EXECUTE WITH GRANT OPTION') "
        "AND NOT has_function_privilege('kf_observer','kf_reservation.apply(jsonb)','EXECUTE') "
        "AND NOT has_function_privilege('kf_observer','kf_reservation.lookup(text,text)',"
        "'EXECUTE') "
        "AND NOT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='kf_reservation' AND c.relkind='r' AND "
        "(has_table_privilege('kf_observer',c.oid,"
        "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') "
        "OR has_any_column_privilege('kf_observer',c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) "
        "FROM pg_roles WHERE rolname='kf_observer';"
    ).stdout.strip()
    if good != "t":
        raise RuntimeError("function-only observer privilege audit refused")
    PHASE = "read_only_bypass_and_key_custody_checks"
    negatives = {}
    for label, statement, user_name, role in [
        (
            "direct_table_read",
            "SELECT * FROM kf_reservation.resource;",
            "kf-observer",
            "kf_observer",
        ),
        (
            "direct_table_write",
            "UPDATE kf_reservation.resource SET reservation='bypass';",
            "kf-observer",
            "kf_observer",
        ),
        ("owner_impersonation", "SELECT current_user;", "kf-observer", "kf-postgres"),
        (
            "agent_observer_login",
            "SELECT kf_reservation.observe_cura();",
            "kf-agent",
            "kf_observer",
        ),
        (
            "executor_observer_function",
            "SELECT kf_reservation.observe_cura();",
            "kf-sql-target",
            "kf_executor",
        ),
    ]:
        negatives[label] = sql(statement, user_name, role, check=False).returncode != 0
    if not all(negatives.values()) or base["snapshot"]() != before:
        raise RuntimeError("observer bypass not refused or resource/attempt state changed")
    base["audit_roles"]()
    pins_path = DATA / "configuration/postgres-operator/observer-public-pins.json"
    if pins_path.exists() and any(
        not (source / (purpose + ".seed")).exists() for purpose in ["evidence", "manifest"]
    ):
        raise RuntimeError("enrolled observer proof key missing; never regenerate implicitly")
    public_keys = {
        purpose: proof_key(source / (purpose + ".seed"), user)
        for purpose in ["evidence", "manifest"]
    }
    # Root-owned enrollment pins detect implicit service-key replacement on rerun.
    base["write_once"](
        DATA / "configuration/postgres-operator/observer-public-pins.json",
        json.dumps(public_keys, sort_keys=True) + "\n",
    )
    for purpose in public_keys:
        if (
            run(
                [
                    "runuser",
                    "-u",
                    "kf-agent",
                    "--",
                    "test",
                    "-r",
                    str(target / (purpose + ".seed")),
                ],
                check=False,
            ).returncode
            == 0
        ):
            raise RuntimeError("agent can read observer proof key")
    return {
        "format": "kedgeflow-cura-sql-observer-enrollment-v1",
        "status": "function_only_observer_enrolled",
        "observer_uid": user.pw_uid,
        "resource": {"id": "slot-a", "incarnation": incarnation},
        "observed_version": observed["version"],
        "observed_fence": observed["last_fence"],
        "resource_rows": len(json.loads(before)["resources"] or []),
        "attempt_rows": len(json.loads(before)["attempts"] or []),
        "function_only_role_audit_passed": True,
        "resource_and_attempt_state_unchanged": True,
        "bypass_refusals": negatives,
        "public_keys_base64": public_keys,
        "private_keys_exported": False,
        "evidence_api_started_by_this_helper": False,
        "evidence_objects_issued_by_this_helper": 0,
        "dispatches_issued_by_this_helper": 0,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-source-sha256", required=True)
    parser.add_argument("--operator-bootstrap", action="store_true")
    args = parser.parse_args()
    if not args.operator_bootstrap:
        parser.error("explicit additive observer enrollment required")
    try:
        print(json.dumps(enroll(args.base_source_sha256), indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
