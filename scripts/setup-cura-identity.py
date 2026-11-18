#!/usr/bin/env python3
"""Operator bootstrap of persistent Keycloak/PostgreSQL and SPIRE on the Cura Identity host.

Creates real provider service credentials locally, never owner acceptance keys or
signatures. Prints public provider metadata and booleans only. Requires retained
host storage enrollment; startup never initializes replacement authority.
"""

import argparse
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import secrets
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DATA = Path("/var/lib/kedgeflow/pilot")
PROVIDER = Path("/etc/kedgeflow-provider")
POSTGRES = "/opt/kedgeflow/runtime/postgres/bin/"
KEYCLOAK = Path("/opt/kedgeflow/runtime/keycloak")
SPIRE_BIN = "/opt/kedgeflow/runtime/spire/bin/spire-server"
DOMAIN = "identity.cura.kedgeflow.internal"
ISSUER = "https://" + DOMAIN + ":8443/realms/kedgeflow-pilot"
CURRENT_PHASE = "preconditions"


def checkpoint(name):
    global CURRENT_PHASE
    CURRENT_PHASE = name


def run(argv, *, input=None, env=None, check=True):
    result = subprocess.run(argv, input=input, env=env, capture_output=True, text=True, timeout=120)
    if check and result.returncode:
        # Raw provider/SQL errors may contain credentials: keep diagnostics local.
        logs = DATA / "configuration/identity-operator"
        if logs.is_dir():
            path = logs / "last-private-command-error.log"
            path.write_text(result.stderr)
            path.chmod(0o600)
        raise RuntimeError("provider command failed; protected local diagnostic retained")
    return result


def owned_write(path, raw, owner="root", mode=0o400):
    """Create private material once; never replace an existing secret on rerun."""
    if path.exists():
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_uid != pwd.getpwnam(owner).pw_uid
            or (info.st_mode & 0o7777) != mode
            or info.st_nlink != 1
        ):
            raise RuntimeError("unsafe existing provider file")
        return
    with path.open("xb") as output:
        output.write(raw if isinstance(raw, bytes) else raw.encode())
    user = pwd.getpwnam(owner)
    os.chown(path, user.pw_uid, user.pw_gid)
    path.chmod(mode)


def bind_configuration(name, user):
    source, target = DATA / "configuration" / name, PROVIDER / name
    group = grp.getgrnam(user).gr_gid
    if not source.exists():
        source.mkdir(mode=0o750)
        os.chown(source, 0, group)
    if source.is_symlink() or source.stat().st_uid != 0 or source.stat().st_gid != group:
        raise RuntimeError("provider configuration custody mismatch")
    if source.stat().st_mode & 0o022:
        raise RuntimeError("provider configuration directory was writable by other principals")
    source.chmod(0o750)
    if not target.exists():
        target.mkdir(mode=0o750)
        os.chown(target, 0, group)
        target.chmod(0o750)
    if not target.is_mount():
        if any(target.iterdir()):
            raise RuntimeError("refusing to shadow existing configuration")
        run(["mount", "--bind", str(source), str(target)])
        run(["mount", "-o", "remount,bind,ro", str(target)])
    declaration = (
        f"{source} {target} none bind,ro,nofail,"
        "x-systemd.requires-mounts-for=/var/lib/kedgeflow/pilot 0 0"
    )
    fstab = Path("/etc/fstab")
    contents = fstab.read_text()
    rows = [r for r in contents.splitlines() if len(r.split()) > 1 and r.split()[1] == str(target)]
    if rows and rows != [declaration]:
        raise RuntimeError("provider mount declaration differs")
    if not rows:
        with fstab.open("a") as output:
            output.write(declaration + "\n")
    return source


def service(name, contents):
    path = Path("/etc/systemd/system") / name
    if path.exists() and path.read_text() != contents:
        raise RuntimeError("existing provider unit differs; explicit upgrade required")
    owned_write(path, contents, mode=0o644)


HARDENING = """NoNewPrivileges=yes
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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
IPAddressAllow=10.87.0.0/16
UMask=0077
Restart=on-failure
RestartSec=5s
TimeoutStopSec=60s
KillMode=control-group
LimitNOFILE=4096
"""


def setup(realm_template):
    if os.geteuid() != 0 or sys.platform != "linux" or not DATA.is_mount():
        raise RuntimeError("requires root on the retained Cura Identity data mount")
    enrollment = json.loads((DATA / ".host-enrollment.json").read_text())
    if enrollment["host"] != "Identity":
        raise RuntimeError("wrong enrolled host")
    operator = DATA / "configuration/identity-operator"
    operator.mkdir(mode=0o700, exist_ok=True)
    PROVIDER.mkdir(mode=0o755, exist_ok=True)
    if PROVIDER.is_symlink() or PROVIDER.stat().st_uid != 0:
        raise RuntimeError("provider ancestor must be root owned")
    PROVIDER.chmod(0o711)
    kc = bind_configuration("keycloak", "kf-keycloak")
    spire = bind_configuration("spire-server", "kf-spire-server")
    checkpoint("local_transport_and_secrets")
    for filename in ("db-password", "admin-password", "agent-client-secret"):
        owned_write(operator / filename, secrets.token_hex(32))
    # Transport authority is operator-managed pilot PKI, not an acceptance owner.
    if not (operator / "transport-ca.key").exists():
        ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Cura operator identity transport")]
        )
        now = datetime.now(timezone.utc)
        ca = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        owned_write(
            operator / "transport-ca.key",
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        owned_write(
            operator / "transport-ca.pem", ca.public_bytes(serialization.Encoding.PEM), mode=0o444
        )
    if not (kc / "tls.key").exists():
        ca_key = serialization.load_pem_private_key(
            (operator / "transport-ca.key").read_bytes(), None
        )
        ca = x509.load_pem_x509_certificate((operator / "transport-ca.pem").read_bytes())
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenKedge Cura pilot")])
            )
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(DOMAIN),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        owned_write(
            kc / "tls.key",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            "kf-keycloak",
        )
        owned_write(
            kc / "tls.pem", certificate.public_bytes(serialization.Encoding.PEM), mode=0o444
        )
    owned_write(kc / "ca.pem", (operator / "transport-ca.pem").read_bytes(), mode=0o444)
    pgdata = DATA / "identity-db"
    checkpoint("persistent_database_initialization")
    if not (pgdata / "PG_VERSION").exists():
        if any(pgdata.iterdir()):
            raise RuntimeError("refusing to initialize nonempty provider database")
        run(
            [
                "runuser",
                "-u",
                "kf-identity-db",
                "--",
                POSTGRES + "initdb",
                "-D",
                str(pgdata),
                "--username=kf-identity-db",
                "--auth-local=peer",
                "--auth-host=scram-sha-256",
                "--encoding=UTF8",
                "--locale=C",
            ]
        )
        with (pgdata / "postgresql.conf").open("a") as output:
            output.write(
                "\nlisten_addresses='127.0.0.1'\nport=5433\n"
                "unix_socket_directories='/run/kedgeflow-identity-db'\n"
                "unix_socket_permissions=0700\nshared_buffers=64MB\nmax_connections=32\n"
                "log_statement='none'\npassword_encryption='scram-sha-256'\n"
            )
        hba = pgdata / "pg_hba.conf"
        hba.write_text(
            "local all kf-identity-db peer\nhost keycloak keycloak 127.0.0.1/32 scram-sha-256\n"
            "local all all reject\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n"
        )
        os.chown(hba, pwd.getpwnam("kf-identity-db").pw_uid, pwd.getpwnam("kf-identity-db").pw_gid)
        hba.chmod(0o600)
    if (pgdata / "PG_VERSION").read_text().strip() != "18":
        raise RuntimeError("unexpected retained PostgreSQL major version")
    service(
        "kedgeflow-identity-db.service",
        f"""[Unit]
Description=Cura persistent Keycloak PostgreSQL database
RequiresMountsFor={DATA}
ConditionPathIsMountPoint={DATA}
ConditionPathExists={pgdata}/PG_VERSION
[Service]
Type=exec
User=kf-identity-db
Group=kf-identity-db
RuntimeDirectory=kedgeflow-identity-db
RuntimeDirectoryMode=0700
ExecStart={POSTGRES}postgres -D {pgdata}
ReadWritePaths={pgdata} /run/kedgeflow-identity-db
MemoryMax=768M
{HARDENING}[Install]
WantedBy=multi-user.target
""",
    )
    run(["systemctl", "daemon-reload"])
    checkpoint("persistent_database_startup")
    run(["systemctl", "start", "kedgeflow-identity-db.service"])
    psql = [
        "runuser",
        "-u",
        "kf-identity-db",
        "--",
        POSTGRES + "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        "/run/kedgeflow-identity-db",
        "-p",
        "5433",
        "-d",
        "postgres",
        "-At",
    ]
    for _ in range(30):
        if run(psql, input="SELECT 1;", check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("provider database startup deadline")
    if run(psql, input="SELECT 1 FROM pg_roles WHERE rolname='keycloak';").stdout.strip() != "1":
        password = (operator / "db-password").read_text().strip()
        if not len(password) == 64 or any(c not in "0123456789abcdef" for c in password):
            raise RuntimeError("unexpected protected database secret format")
        run(
            psql,
            input="CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '"
            + password
            + "';\nCREATE DATABASE keycloak OWNER keycloak;\n",
        )
    checkpoint("persistent_keycloak_configuration")
    kcdata = DATA / "keycloak"
    public_data = KEYCLOAK / "data"
    if not public_data.is_symlink():
        if public_data.exists():
            if set(p.name for p in public_data.iterdir()) - {"README.md"}:
                raise RuntimeError("unexpected preexisting Keycloak image data")
            public_data.rename(KEYCLOAK / "data.image-default")
        public_data.symlink_to(kcdata, target_is_directory=True)
    elif public_data.resolve() != kcdata:
        raise RuntimeError("Keycloak data link differs from enrolled retained storage")
    imports = kcdata / "import"
    if not imports.exists():
        imports.mkdir(mode=0o700)
        user = pwd.getpwnam("kf-keycloak")
        os.chown(imports, user.pw_uid, user.pw_gid)
    realm = json.loads(realm_template.read_text())
    if realm["realm"] != "kedgeflow-pilot" or realm["clients"][0]["clientId"] != "kf-pilot-agent":
        raise RuntimeError("closed reference realm required")
    realm["clients"][0]["secret"] = (operator / "agent-client-secret").read_text().strip()
    owned_write(imports / "kedgeflow-pilot-realm.json", json.dumps(realm), "kf-keycloak")
    owned_write(
        kc / "keycloak.conf",
        f"""db=postgres
db-url=jdbc:postgresql://127.0.0.1:5433/keycloak
db-username=keycloak
db-pool-initial-size=1
db-pool-min-size=1
db-pool-max-size=10
hostname=https://{DOMAIN}:8443
hostname-strict=true
https-port=8443
http-enabled=false
https-certificate-file={PROVIDER}/keycloak/tls.pem
https-certificate-key-file={PROVIDER}/keycloak/tls.key
cache=local
""",
        mode=0o444,
    )
    launcher = Path("/usr/local/libexec/kedgeflow-keycloak-launch.py")
    launcher.parent.mkdir(mode=0o755, exist_ok=True)
    if launcher.parent.is_symlink() or launcher.parent.stat().st_uid != 0:
        raise RuntimeError("public executable ancestor must be root owned")
    launcher.parent.chmod(0o755)
    owned_write(
        launcher,
        """#!/usr/bin/python3
import os
from pathlib import Path
credentials=Path(os.environ['CREDENTIALS_DIRECTORY'])
environment=dict(os.environ)
environment['KC_DB_PASSWORD']=(credentials/'db-password').read_text().strip()
environment['KC_BOOTSTRAP_ADMIN_USERNAME']='cura-bootstrap-operator'
environment['KC_BOOTSTRAP_ADMIN_PASSWORD']=(credentials/'admin-password').read_text().strip()
environment['JAVA_OPTS_APPEND']=('-Xms128m -Xmx768m -XX:MaxMetaspaceSize=384m '
                                 '-XX:ReservedCodeCacheSize=96m')
os.execve('/opt/kedgeflow/runtime/keycloak/bin/kc.sh',['kc.sh','--config-file=/etc/kedgeflow-provider/keycloak/keycloak.conf','start','--optimized','--import-realm'],environment)
""",
        mode=0o755,
    )
    service(
        "kedgeflow-keycloak.service",
        f"""[Unit]
Description=Cura persistent Keycloak identity provider
Requires=kedgeflow-identity-db.service
After=kedgeflow-identity-db.service network-online.target
RequiresMountsFor={DATA} {PROVIDER}/keycloak
ConditionPathIsMountPoint={DATA}
[Service]
Type=exec
User=kf-keycloak
Group=kf-keycloak
LoadCredential=db-password:{operator}/db-password
LoadCredential=admin-password:{operator}/admin-password
ExecStart=/usr/bin/python3 {launcher}
ReadWritePaths={kcdata}
MemoryMax=1600M
TasksMax=256
{HARDENING}[Install]
WantedBy=multi-user.target
""",
    )
    owned_write(
        spire / "server.conf",
        f"""server {{
 trust_domain = "cura.kedgeflow.internal"
 bind_address = "0.0.0.0"
 bind_port = 8081
 socket_path = "/run/kedgeflow-spire-server/server.sock"
 data_dir = "{DATA}/spire-server"
 log_level = "WARN"
 jwt_key_type = "ec-p256"
 default_jwt_svid_ttl = "5m"
 default_x509_svid_ttl = "10m"
 ca_subject {{ common_name = "Cura operator SPIRE pilot" }}
}}
plugins {{
 DataStore "sql" {{ plugin_data {{ database_type = "sqlite3"
  connection_string = "{DATA}/spire-server/datastore.sqlite3" }} }}
 NodeAttestor "join_token" {{ plugin_data {{}} }}
 KeyManager "disk" {{ plugin_data {{ keys_path = "{DATA}/spire-server/keys.json" }} }}
}}
""",
        mode=0o444,
    )
    service(
        "kedgeflow-spire-server.service",
        f"""[Unit]
Description=Cura persistent SPIRE server
After=network-online.target
RequiresMountsFor={DATA} {PROVIDER}/spire-server
ConditionPathIsMountPoint={DATA}
[Service]
Type=exec
User=kf-spire-server
Group=kf-spire-server
RuntimeDirectory=kedgeflow-spire-server
RuntimeDirectoryMode=0700
ExecStart={SPIRE_BIN} run -config {PROVIDER}/spire-server/server.conf
ReadWritePaths={DATA}/spire-server /run/kedgeflow-spire-server
MemoryMax=512M
TasksMax=128
{HARDENING}[Install]
WantedBy=multi-user.target
""",
    )
    run(["systemctl", "daemon-reload"])
    checkpoint("provider_process_startup")
    run(["systemctl", "start", "kedgeflow-keycloak.service", "kedgeflow-spire-server.service"])
    context = ssl.create_default_context(cafile=str(kc / "ca.pem"))
    checkpoint("keycloak_tls_and_realm_readiness")
    for _ in range(90):
        try:
            with urllib.request.urlopen(
                ISSUER + "/.well-known/openid-configuration", context=context, timeout=3
            ) as response:
                metadata = json.load(response)
            if metadata["issuer"] != ISSUER:
                raise RuntimeError("unexpected actual provider issuer")
            break
        except (OSError, ValueError):
            time.sleep(1)
    else:
        raise RuntimeError("Keycloak TLS/realm startup deadline")
    for _ in range(30):
        if Path("/run/kedgeflow-spire-server/server.sock").is_socket():
            break
        time.sleep(1)
    else:
        raise RuntimeError("SPIRE server socket deadline")
    with urllib.request.urlopen(metadata["jwks_uri"], context=context, timeout=5) as response:
        jwks = json.load(response)
    (operator / "openid-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (operator / "jwks-public.json").write_text(json.dumps(jwks, indent=2) + "\n")
    return {
        "format": "kedgeflow-cura-identity-bootstrap-v1",
        "status": "persistent_providers_started",
        "issuer": ISSUER,
        "jwks_key_ids": [k["kid"] for k in jwks["keys"]],
        "public_tls_ca_sha256": hashlib.sha256((kc / "ca.pem").read_bytes()).hexdigest(),
        "database": "PostgreSQL 18.3; local peer administration; SCRAM application login",
        "provider_service_uids": {
            u: pwd.getpwnam(u).pw_uid for u in ["kf-identity-db", "kf-keycloak", "kf-spire-server"]
        },
        "secrets_generated_on_host_only": True,
        "provider_units_enabled": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "execution_authority": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--realm-template", type=Path, required=True)
    parser.add_argument("--operator-bootstrap", action="store_true")
    args = parser.parse_args()
    if not args.operator_bootstrap:
        parser.error("explicit operator bootstrap required")
    try:
        print(json.dumps(setup(args.realm_template), indent=2))
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "phase": CURRENT_PHASE,
                    "error_class": type(error).__name__,
                    "private_diagnostic": "inspect units locally; never export credential values",
                }
            )
        )
        raise SystemExit(1) from None
