#!/usr/bin/env python3
"""Enroll the operator-managed Cura reservation database without dispatching an action.

Requires the already enrolled Sql EBS mount. Refuses replacement or ambiguous
partial initialization. Retains data across restarts; emits booleans/public pins,
never SQL data, credentials, logs, or an independent acceptance decision.
"""

import argparse
import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path

DATA = Path("/var/lib/kedgeflow/pilot")
PG = Path("/opt/kedgeflow/runtime/postgres/bin")
SOCKET = Path("/run/kedgeflow-postgres")
UNIT = "kedgeflow-postgres.service"
MIGRATION_SHA256 = "e107b6637432216b2f6f3a2620c15a53547080af26625f6e51c3d27db5999b9e"
PHASE = "preconditions"


def run(argv, *, input=None, check=True):
    result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=90)
    if check and result.returncode:
        # Never export SQL/provider errors: they can contain protected material.
        raise RuntimeError("operator database command failed")
    return result


def private_json(path):
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != 0o600
    ):
        raise RuntimeError("unprotected enrollment record")
    return json.loads(path.read_text())


def write_once(path, contents, owner="root", mode=0o600):
    user = pwd.getpwnam(owner)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_nlink != 1
            or info.st_uid != user.pw_uid
            or info.st_mode & 0o7777 != mode
            or path.read_text() != contents
        ):
            raise RuntimeError("existing database configuration differs")
        return
    with path.open("x") as stream:
        stream.write(contents)
    os.chown(path, user.pw_uid, user.pw_gid)
    path.chmod(mode)


def registration(manifest, incarnation):
    if (
        manifest.get("format") != "kedgeflow-cura-new-storage-v1"
        or manifest.get("host") != "Sql"
        or not re.fullmatch(r"i-[0-9a-f]{17}", manifest.get("instance_id", ""))
        or not re.fullmatch(r"cura-reservation-[0-9a-f]{32}", incarnation)
    ):
        raise ValueError("exact retained Sql host and immutable incarnation required")
    return {
        "format": "kedgeflow-cura-postgres-enrollment-v1",
        "instance_id": manifest["instance_id"],
        "filesystem_uuid": manifest["filesystem_uuid"],
        "migration_sha256": MIGRATION_SHA256,
        "database": "kedgeflow",
        "tenant": "cura-pilot",
        "conflict_domain": "cura-sql-pilot:reservations",
        "resource_id": "slot-a",
        "incarnation": incarnation,
        "action": "postgres.reservation.set.v1",
    }


def hba():
    return (
        "local all kf-postgres peer\n"
        "local kedgeflow kf_executor,kf_reader peer map=kf_target\n"
        "local all all reject\n"
        "host all all 0.0.0.0/0 reject\n"
        "host all all ::/0 reject\n"
    )


def ident():
    return "kf_target kf-sql-target kf_executor\nkf_target kf-sql-target kf_reader\n"


def unit():
    return f"""[Unit]
Description=KedgeFlow Cura persistent reservation PostgreSQL
RequiresMountsFor={DATA}
After=local-fs.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=exec
User=kf-postgres
Group=kf-postgres
ExecStart={PG}/postgres -D {DATA}/postgresql
ExecReload=/bin/kill -HUP $MAINPID
RuntimeDirectory=kedgeflow-postgres
RuntimeDirectoryMode=0750
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths={DATA}/postgresql {SOCKET}
IPAddressDeny=any
Restart=on-failure
RestartSec=5s
TimeoutStopSec=60s
KillSignal=SIGINT
KillMode=mixed
TasksMax=128
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
"""


def sql(statement, user="kf-postgres", role="kf-postgres", *, check=True, database="kedgeflow"):
    return run(
        [
            "runuser",
            "-u",
            user,
            "--",
            str(PG / "psql"),
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-h",
            str(SOCKET),
            "-p",
            "5432",
            "-U",
            role,
            "-d",
            database,
        ],
        input=statement,
        check=check,
    )


def snapshot():
    # Compare retained state locally; no data leaves this host.
    return sql(
        "SELECT json_build_object('resources',(SELECT json_agg(r ORDER BY tenant,resource_id) "
        "FROM kf_reservation.resource r),'attempts',(SELECT json_agg(a ORDER BY tenant,attempt_id) "
        "FROM kf_reservation.attempt a));"
    ).stdout


def audit_roles():
    for role, own, other in [
        ("kf_executor", "kf_reservation.apply(jsonb)", "kf_reservation.lookup(text,text)"),
        ("kf_reader", "kf_reservation.lookup(text,text)", "kf_reservation.apply(jsonb)"),
    ]:
        good = sql(
            "SELECT NOT (rolsuper OR rolinherit OR rolcreaterole OR rolcreatedb OR "
            "rolreplication OR rolbypassrls) AND rolcanlogin "
            f"AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=oid) "
            f"AND NOT has_database_privilege('{role}','kedgeflow','CREATE') "
            f"AND NOT has_schema_privilege('{role}','kf_reservation','CREATE') "
            f"AND has_schema_privilege('{role}','kf_reservation','USAGE') "
            f"AND has_function_privilege('{role}','{own}','EXECUTE') "
            f"AND NOT has_function_privilege('{role}','{other}','EXECUTE') "
            f"AND NOT has_function_privilege('{role}','{own}','EXECUTE WITH GRANT OPTION') "
            "AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='kf_reservation' AND c.relkind='r' AND "
            f"(has_table_privilege('{role}',c.oid,"
            "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') "
            f"OR has_any_column_privilege('{role}',c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) "
            f"FROM pg_roles WHERE rolname='{role}';"
        ).stdout.strip()
        if good != "t":
            raise RuntimeError("database privilege audit refused")
        if sql("SELECT current_user;", "kf-sql-target", role).stdout.strip() != role:
            raise RuntimeError("target peer mapping refused")


def enroll(migration, incarnation):
    global PHASE
    if os.geteuid() != 0 or sys.platform != "linux" or not DATA.is_mount():
        raise RuntimeError("requires privileged enrolled Linux Sql host")
    manifest = private_json(DATA / ".host-enrollment.json")
    expected = registration(manifest, incarnation)
    if hashlib.sha256(migration.read_bytes()).hexdigest() != MIGRATION_SHA256:
        raise ValueError("reservation migration pin differs")
    postgres, target = pwd.getpwnam("kf-postgres"), pwd.getpwnam("kf-sql-target")
    if not postgres.pw_uid or not target.pw_uid or postgres.pw_uid == target.pw_uid:
        raise RuntimeError("distinct non-root database and target identities required")
    if run([str(PG / "postgres"), "--version"]).stdout.strip() != "postgres (PostgreSQL) 18.3":
        raise RuntimeError("PostgreSQL version differs")
    root = DATA / "configuration/postgres-operator"
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != 0 or root.stat().st_mode & 0o7777 != 0o700:
        raise RuntimeError("database operator custody differs")
    marker, pending = root / "enrollment.json", root / "initialization-pending.json"
    db = DATA / "postgresql"
    if (
        db.is_symlink()
        or db.stat().st_uid != postgres.pw_uid
        or db.stat().st_mode & 0o7777 != 0o700
    ):
        raise RuntimeError("database directory custody differs")
    first = not marker.exists()
    if first:
        if pending.exists() or any(db.iterdir()):
            raise RuntimeError(
                "ambiguous partial database initialization; never reset or replay DDL"
            )
        write_once(pending, json.dumps(expected, sort_keys=True) + "\n")
        PHASE = "initialize_new_database"
        run(
            [
                "runuser",
                "-u",
                "kf-postgres",
                "--",
                str(PG / "initdb"),
                "-D",
                str(db),
                "-A",
                "reject",
                "--no-locale",
                "-E",
                "UTF8",
                "--data-checksums",
            ]
        )
    elif private_json(marker) != expected or pending.exists():
        raise RuntimeError("retained database enrollment differs or remains incomplete")
    PHASE = "configuration"
    # initdb owns these two files. On first creation only, replace its reject-only defaults.
    for name, contents in [("pg_hba.conf", hba()), ("pg_ident.conf", ident())]:
        path = db / name
        if first:
            if path.is_symlink() or path.stat().st_uid != postgres.pw_uid:
                raise RuntimeError("unexpected initialized authentication file")
            path.write_text(contents)
            path.chmod(0o600)
        write_once(path, contents, "kf-postgres")
    if first:
        initialize_auto_conf(db)
    else:
        write_once(db / "postgresql.auto.conf", server_configuration(), "kf-postgres")
    run(["usermod", "-a", "-G", "kf-postgres", "kf-sql-target"])
    write_once(Path("/etc/systemd/system") / UNIT, unit(), mode=0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "start", UNIT])
    # A successful local connection waits for the actual server, not only its process.
    import time

    for _ in range(30):
        if sql("SELECT 1;", database="postgres", check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("database startup deadline")
    if first:
        PHASE = "enroll_reservation_schema"
        sql("CREATE DATABASE kedgeflow;", database="postgres")
        sql(migration.read_text())
        sql(
            "BEGIN; REVOKE ALL ON DATABASE kedgeflow FROM PUBLIC; "
            "REVOKE ALL ON SCHEMA public FROM PUBLIC; "
            "CREATE ROLE kf_executor LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS; "
            "CREATE ROLE kf_reader LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS; "
            "GRANT CONNECT ON DATABASE kedgeflow TO kf_executor,kf_reader; "
            "GRANT USAGE ON SCHEMA kf_reservation TO kf_executor,kf_reader; "
            "GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO kf_executor; "
            "GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO kf_reader; "
            "INSERT INTO kf_reservation.resource VALUES "
            f"('cura-pilot','cura-sql-pilot:reservations','slot-a','{incarnation}',"
            "1,0,'available',true); "
            "COMMIT;"
        )
        audit_roles()
        write_once(marker, json.dumps(expected, sort_keys=True) + "\n")
        pending.unlink()
    PHASE = "restart_and_bypass_checks"
    audit_roles()
    before = snapshot()
    run(["systemctl", "restart", UNIT])
    for _ in range(30):
        if sql("SELECT 1;", database="postgres", check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("database restart deadline")
    if snapshot() != before:
        raise RuntimeError("retained resource or attempt state changed across restart")
    audit_roles()
    negatives = {}
    for user in ["kf-agent", "kf-recovery", "kf-gateway"]:
        for role in ["kf_executor", "kf_reader", "kf-postgres"]:
            negatives[user + ":" + role] = (
                sql("SELECT current_user;", user, role, check=False).returncode != 0
            )
    for role, statement in [
        ("kf_executor", "UPDATE kf_reservation.resource SET reservation='bypass';"),
        ("kf_reader", "SELECT * FROM kf_reservation.attempt;"),
        ("kf_executor", 'SET ROLE "kf-postgres";'),
    ]:
        negatives[role + ":" + statement.split()[0]] = (
            sql(statement, "kf-sql-target", role, check=False).returncode != 0
        )
    negatives["agent_database_files"] = (
        run(
            ["runuser", "-u", "kf-agent", "--", "test", "-r", str(db / "PG_VERSION")], check=False
        ).returncode
        != 0
    )
    if not all(negatives.values()):
        raise RuntimeError("deployed database bypass was not refused")
    settings = json.loads(
        sql(
            "SELECT json_build_object('version',current_setting('server_version'),"
            "'listen',current_setting('listen_addresses'),'fsync',current_setting('fsync'),"
            "'full_page_writes',current_setting('full_page_writes'),"
            "'synchronous_commit',current_setting('synchronous_commit'),"
            "'data_checksums',current_setting('data_checksums'));"
        ).stdout
    )
    if settings != {
        "version": "18.3",
        "listen": "",
        "fsync": "on",
        "full_page_writes": "on",
        "synchronous_commit": "on",
        "data_checksums": "on",
    }:
        raise RuntimeError("database durability or network settings differ")
    run(["systemctl", "enable", UNIT])
    return {
        "format": "kedgeflow-cura-postgres-observation-v1",
        "status": "persistent_database_enrolled",
        "registration": expected,
        "database_uid": postgres.pw_uid,
        "target_uid": target.pw_uid,
        "settings": settings,
        "exact_target_peer_maps_passed": True,
        "function_only_role_audit_passed": True,
        "restart_preserved_resource_and_attempt_state": True,
        "bypass_refusals": negatives,
        "database_unit_enabled": True,
        "dispatches_issued": 0,
        "target_listener_started": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


def initialize_auto_conf(db):
    # PostgreSQL creates this file during initdb; only that fresh file may be replaced.
    path = db / "postgresql.auto.conf"
    if path.is_symlink() or path.stat().st_uid != pwd.getpwnam("kf-postgres").pw_uid:
        raise RuntimeError("unexpected initialized server configuration")
    path.unlink()
    write_once(path, server_configuration(), "kf-postgres")


def server_configuration():
    return (
        "listen_addresses = ''\nport = 5432\n"
        f"unix_socket_directories = '{SOCKET}'\nunix_socket_permissions = 0770\n"
        "fsync = on\nfull_page_writes = on\nsynchronous_commit = on\n"
        "log_statement = 'none'\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--migration", type=Path, required=True)
    parser.add_argument("--incarnation", required=True)
    parser.add_argument("--operator-bootstrap", action="store_true")
    args = parser.parse_args()
    if not args.operator_bootstrap:
        parser.error("explicit operator bootstrap required")
    try:
        print(json.dumps(enroll(args.migration, args.incarnation), indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
