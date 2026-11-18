#!/usr/bin/env python3
"""Operator service PKI for the bounded Cura pilot; private keys never leave their host.

Prepare fixed role CSRs on each enrolled host, sign public CSRs on Services, and
install public chains back on the original hosts. This CA is operator-managed
transport authority, never independent acceptance authority. No service starts.
"""

import argparse
import hashlib
import json
import os
import pwd
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DATA = Path("/var/lib/kedgeflow/pilot")
DOMAIN = "cura.kedgeflow.internal"
PROFILES = {
    "Services": {
        r: "kf-" + r
        for r in ["gateway", "admission", "issuer", "broker", "recovery", "governance", "operator"]
    }
    | {"etcd-admin": "root"},
    "Sql": {"sql-target": "kf-sql-target"},
    "LedgerA": {"etcd": "kf-etcd"},
    "LedgerB": {"etcd": "kf-etcd"},
    "LedgerC": {"etcd": "kf-etcd"},
    "Witness": {"witness-etcd": "kf-witness"},
    "Audit": {"collector": "kf-collector"},
}


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("service PKI custody operation failed")
    return result


def write_once(path, raw, owner="root", mode=0o444):
    raw = raw.encode() if isinstance(raw, str) else raw
    user = pwd.getpwnam(owner)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or info.st_nlink != 1
            or info.st_uid != user.pw_uid
            or info.st_mode & 0o7777 != mode
            or path.read_bytes() != raw
        ):
            raise RuntimeError("existing transport material differs; explicit rotation required")
        return
    with path.open("xb") as stream:
        stream.write(raw)
    os.chown(path, user.pw_uid, user.pw_gid)
    path.chmod(mode)


def subject(role):
    # etcd native JSON gateway clients MUST have no Common Name. Only the
    # separately protected CLI administrator receives the reserved root CN.
    attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenKedge Cura operator pilot")]
    if role == "etcd-admin":
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, "root"))
    return x509.Name(attrs)


def sans(host, role):
    uri = "spiffe://" + DOMAIN + "/" + role
    if role in {"etcd", "witness-etcd"}:
        uri += "/" + host.lower()
    return x509.SubjectAlternativeName(
        [x509.DNSName(host.lower() + "." + DOMAIN), x509.UniformResourceIdentifier(uri)]
    )


def check_csr(raw, host, role):
    if host not in PROFILES or role not in PROFILES[host] or len(raw) > 8192:
        raise ValueError("unregistered host or service CSR")
    csr = x509.load_pem_x509_csr(raw.encode())
    key = csr.public_key()
    if (
        not csr.is_signature_valid
        or csr.subject != subject(role)
        or not isinstance(key, ec.EllipticCurvePublicKey)
        or not isinstance(key.curve, ec.SECP256R1)
        or len(csr.extensions) != 1
        or csr.extensions[0].value != sans(host, role)
        or csr.extensions[0].critical
    ):
        raise ValueError("CSR key, identity, or extensions differ from registered profile")
    return csr


def host_check(host):
    if os.geteuid() != 0 or not DATA.is_mount():
        raise RuntimeError("requires privileged retained Cura service host")
    marker = DATA / ".host-enrollment.json"
    if marker.is_symlink() or marker.stat().st_uid != 0 or marker.stat().st_mode & 0o7777 != 0o600:
        raise RuntimeError("host enrollment custody differs")
    state = json.loads(marker.read_text())
    if host not in PROFILES or state["host"] != host:
        raise RuntimeError("wrong enrolled service host")


def directory(host, role):
    user = pwd.getpwnam(PROFILES[host][role])
    source = DATA / "configuration" / role
    ancestor = Path("/etc/kedgeflow")
    ancestor.mkdir(mode=0o755, exist_ok=True)
    if ancestor.is_symlink() or ancestor.stat().st_uid != 0 or ancestor.stat().st_mode & 0o022:
        raise RuntimeError("unprotected service configuration ancestor")
    ancestor.chmod(0o755)
    target = ancestor / role
    for path in [source, target]:
        if not path.exists():
            path.mkdir(mode=0o750)
            os.chown(path, 0, user.pw_gid)
            path.chmod(0o750)
        info = path.lstat()
        if (
            path.is_symlink()
            or not path.is_dir()
            or info.st_uid != 0
            or info.st_gid != user.pw_gid
            or info.st_mode & 0o7777 != 0o750
        ):
            raise RuntimeError("service configuration directory custody differs")
    mounted = (
        subprocess.run(
            ["findmnt", "--noheadings", "--mountpoint", str(target)],
            capture_output=True,
            text=True,
            timeout=10,
        ).returncode
        == 0
    )
    if mounted:
        if (source.stat().st_dev, source.stat().st_ino) != (
            target.stat().st_dev,
            target.stat().st_ino,
        ):
            raise RuntimeError("configuration bind source differs")
        options = json.loads(run(["findmnt", "--json", "--mountpoint", str(target)]).stdout)[
            "filesystems"
        ][0]["options"]
        if "ro" not in options.split(","):
            raise RuntimeError("configuration projection is writable")
    else:
        if any(target.iterdir()):
            raise RuntimeError("refusing to shadow existing service configuration")
        run(["mount", "--bind", str(source), str(target)])
        run(["mount", "-o", "remount,bind,ro", str(target)])
    row = f"{source} {target} none bind,ro,nofail,x-systemd.requires-mounts-for={DATA} 0 0"
    fstab = Path("/etc/fstab")
    existing = [
        r
        for r in fstab.read_text().splitlines()
        if len(r.split()) > 1 and r.split()[1] == str(target)
    ]
    if existing and existing != [row]:
        raise RuntimeError("existing configuration mount declaration differs")
    if not existing:
        with fstab.open("a") as stream:
            stream.write(row + "\n")
    return source


def prepare(host):
    host_check(host)
    requests = {}
    for role, user in PROFILES[host].items():
        source = directory(host, role)
        key_path, request_path = source / "identity.key", source / "identity.csr"
        if key_path.exists():
            info = key_path.lstat()
            if (
                key_path.is_symlink()
                or info.st_uid != pwd.getpwnam(user).pw_uid
                or info.st_nlink != 1
                or info.st_mode & 0o7777 != 0o400
            ):
                raise RuntimeError("transport private key custody differs")
            key = serialization.load_pem_private_key(key_path.read_bytes(), None)
        else:
            if any(source.iterdir()):
                raise RuntimeError("ambiguous service key initialization; never reset")
            key = ec.generate_private_key(ec.SECP256R1())
            write_once(
                key_path,
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                user,
                0o400,
            )
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise RuntimeError("transport key algorithm differs")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject(role))
            .add_extension(sans(host, role), critical=False)
            .sign(key, hashes.SHA256())
        )
        # ECDSA CSR signatures vary on re-signing. Retain the initial public request.
        if not request_path.exists():
            write_once(request_path, csr.public_bytes(serialization.Encoding.PEM))
        retained = check_csr(request_path.read_text(), host, role)
        if retained.public_key().public_numbers() != key.public_key().public_numbers():
            raise RuntimeError("retained CSR and private key differ")
        requests[role] = request_path.read_text()
    run(["systemctl", "daemon-reload"])
    return {
        "format": "kedgeflow-cura-service-csrs-v1",
        "host": host,
        "requests": requests,
        "private_keys_exported": False,
        "services_started": False,
    }


def deadline(value, now):
    result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if not now + timedelta(minutes=15) < result <= now + timedelta(hours=48):
        raise ValueError("transport lifetime must fit the bounded approved pilot window")
    return result


def certificate_expiry(cert):
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    # Ubuntu's pinned cryptography package returns a naive UTC datetime.
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def sign(requests, until):
    host_check("Services")
    now = datetime.now(timezone.utc)
    expires = deadline(until, now)
    root = DATA / "pki"
    if root.is_symlink() or root.stat().st_uid != 0 or root.stat().st_mode & 0o7777 != 0o700:
        raise RuntimeError("operator transport CA custody differs")
    key_path, cert_path = root / "service-ca.key", root / "service-ca.pem"
    if not key_path.exists():
        if cert_path.exists():
            raise RuntimeError("missing retained operator CA key; never replace")
        key = ec.generate_private_key(ec.SECP256R1())
        ca_subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Cura operator service transport")]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(expires + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        write_once(
            key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            mode=0o400,
        )
        write_once(cert_path, certificate.public_bytes(serialization.Encoding.PEM))
    info = key_path.lstat()
    if (
        key_path.is_symlink()
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != 0o400
    ):
        raise RuntimeError("unprotected operator transport CA key")
    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    ca = x509.load_pem_x509_certificate(cert_path.read_bytes())
    if (
        ca.public_key().public_numbers() != key.public_key().public_numbers()
        or certificate_expiry(ca) <= expires
    ):
        raise RuntimeError("CA key or bounded lifetime differs")
    signed = {}
    for host, entry in requests.items():
        if (
            host not in PROFILES
            or entry.get("host") != host
            or entry.get("format") != "kedgeflow-cura-service-csrs-v1"
            or set(entry["requests"]) != set(PROFILES[host])
        ):
            raise ValueError("closed host CSR inventory required")
        signed[host] = {}
        for role, raw in entry["requests"].items():
            csr = check_csr(raw, host, role)
            path = root / (host + "-" + role + ".pem")
            if not path.exists():
                usages = [ExtendedKeyUsageOID.CLIENT_AUTH]
                if role != "etcd-admin":
                    usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
                certificate = (
                    x509.CertificateBuilder()
                    .subject_name(csr.subject)
                    .issuer_name(ca.subject)
                    .public_key(csr.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=5))
                    .not_valid_after(expires)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(sans(host, role), critical=False)
                    .add_extension(x509.ExtendedKeyUsage(usages), critical=False)
                    .add_extension(
                        x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                        critical=True,
                    )
                    .sign(key, hashes.SHA256())
                )
                write_once(path, certificate.public_bytes(serialization.Encoding.PEM))
            certificate = x509.load_pem_x509_certificate(path.read_bytes())
            if (
                certificate.public_key().public_numbers() != csr.public_key().public_numbers()
                or certificate_expiry(certificate) != expires
            ):
                raise RuntimeError(
                    "existing signed certificate differs; explicit rotation required"
                )
            signed[host][role] = path.read_text()
    return {
        "format": "kedgeflow-cura-service-certificates-v1",
        "ca_pem": cert_path.read_text(),
        "ca_sha256": hashlib.sha256(cert_path.read_bytes()).hexdigest(),
        "certificates": signed,
        "expires_utc": until,
        "independent_custody": "BLOCKED_EXTERNAL_INPUT",
    }


def install(host, document):
    host_check(host)
    if document.get("format") != "kedgeflow-cura-service-certificates-v1" or set(
        document["certificates"].get(host, {})
    ) != set(PROFILES[host]):
        raise ValueError("closed signed service certificate inventory required")
    ca_raw = document["ca_pem"].encode()
    if hashlib.sha256(ca_raw).hexdigest() != document["ca_sha256"]:
        raise ValueError("public transport CA pin differs")
    ca = x509.load_pem_x509_certificate(ca_raw)
    installed = {}
    for role, raw in document["certificates"][host].items():
        source = directory(host, role)
        csr = check_csr((source / "identity.csr").read_text(), host, role)
        cert = x509.load_pem_x509_certificate(raw.encode())
        cert.verify_directly_issued_by(ca)
        if (
            cert.public_key().public_numbers() != csr.public_key().public_numbers()
            or cert.subject != csr.subject
            or cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            != sans(host, role)
            or certificate_expiry(cert) <= datetime.now(timezone.utc)
        ):
            raise ValueError("certificate does not bind the original registered host key")
        write_once(source / "identity.pem", raw)
        write_once(source / "ca.pem", ca_raw)
        installed[role] = {
            "uid": pwd.getpwnam(PROFILES[host][role]).pw_uid,
            "certificate_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }
    return {
        "format": "kedgeflow-cura-service-pki-installed-v1",
        "host": host,
        "ca_sha256": document["ca_sha256"],
        "roles": installed,
        "private_keys_exported": False,
        "services_started": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=["prepare", "sign", "install"], required=True)
    parser.add_argument("--host", choices=PROFILES)
    parser.add_argument("--document", type=Path)
    parser.add_argument("--until")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            result = prepare(args.host)
        elif args.action == "sign":
            result = sign(json.loads(args.document.read_text()), args.until)
        else:
            result = install(args.host, json.loads(args.document.read_text()))
        print(json.dumps(result, indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__}))
        raise SystemExit(1) from None
