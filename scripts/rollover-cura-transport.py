#!/usr/bin/env python3
"""Explicit pre-application transport rollover after an approved offline window.

Prepare public CSRs from retained host keys, sign under a new protected CA
generation on Services, install only public material while services are stopped.
Archive old public chains, preserve private keys and all protocol/provider state.
SPIRE trust recovery is separate: this tool never changes its keys/registrations.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import pwd
import re
import runpy
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DATA = Path("/var/lib/kedgeflow/pilot")
BASE = Path("/usr/local/sbin/kf-enroll-cura-service-pki.py")
PHASE = "preconditions"


def run(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    if check and result.returncode:
        raise RuntimeError("transport rollover operation failed")
    return result


def safe_file(path, owner, mode):
    info = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != pwd.getpwnam(owner).pw_uid
        or info.st_nlink != 1
        or info.st_mode & 0o7777 != mode
        or info.st_size > 1 << 20
    ):
        raise RuntimeError("transport file custody differs")
    return path.read_bytes()


def directory(path):
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
        path.chmod(0o700)
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o7777 != 0o700:
        raise RuntimeError("transport generation directory custody differs")


def write_once(path, raw, mode=0o400):
    raw = raw.encode() if isinstance(raw, str) else raw
    if path.exists() or path.is_symlink():
        if safe_file(path, "root", mode) != raw:
            raise RuntimeError("existing rollover generation differs; never replace")
        return
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def load_base(expected, host, generation):
    if not re.fullmatch(r"[a-z0-9-]{1,40}", generation):
        raise ValueError("closed explicit rollover generation required")
    if os.geteuid() != 0 or not DATA.is_mount():
        raise RuntimeError("requires privileged retained service host")
    if json.loads(safe_file(DATA / ".host-enrollment.json", "root", 0o600))["host"] != host:
        raise RuntimeError("wrong enrolled rollover host")
    if (
        not re.fullmatch(r"[a-f0-9]{64}", expected)
        or hashlib.sha256(safe_file(BASE, "root", 0o600)).hexdigest() != expected
    ):
        raise RuntimeError("transport enrollment source pin differs")
    return runpy.run_path(str(BASE))


def profiles(base, host):
    return {"keycloak": "kf-keycloak"} if host == "Identity" else base["PROFILES"][host]


def paths(host, role):
    root = DATA / "configuration" / role
    if host == "Identity" and role == "keycloak":
        return root / "tls.key", root / "tls.pem", root / "ca.pem"
    return root / "identity.key", root / "identity.pem", root / "ca.pem"


def san(base, host, role):
    if host == "Identity" and role == "keycloak":
        return x509.SubjectAlternativeName(
            [
                x509.DNSName("identity.cura.kedgeflow.internal"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]
        )
    return base["sans"](host, role)


def verify_csr(base, raw, host, role):
    if role not in profiles(base, host) or len(raw) > 8192:
        raise ValueError("unregistered transport rollover profile")
    csr = x509.load_pem_x509_csr(raw.encode())
    public = csr.public_key()
    if (
        not csr.is_signature_valid
        or csr.subject != base["subject"](role)
        or not isinstance(public, ec.EllipticCurvePublicKey)
        or not isinstance(public.curve, ec.SECP256R1)
        or len(csr.extensions) != 1
        or csr.extensions[0].value != san(base, host, role)
        or csr.extensions[0].critical
    ):
        raise ValueError("rollover CSR does not bind the exact original role")
    return csr


def private_key(host, role, user):
    key_path, cert_path, _ = paths(host, role)
    key = serialization.load_pem_private_key(safe_file(key_path, user, 0o400), None)
    current = x509.load_pem_x509_certificate(safe_file(cert_path, "root", 0o444))
    if (
        not isinstance(key, ec.EllipticCurvePrivateKey)
        or not isinstance(key.curve, ec.SECP256R1)
        or key.public_key().public_numbers() != current.public_key().public_numbers()
    ):
        raise RuntimeError("retained key and certificate differ; never regenerate")
    return key


def prepare(base, host, generation, old_ca):
    global PHASE
    PHASE = "prepare_public_requests"
    if not re.fullmatch(r"[a-f0-9]{64}", old_ca):
        raise ValueError("previous trusted CA fingerprint required")
    root = DATA / "configuration/transport-rollover" / generation
    directory(root)
    retained = root / "requests.json"
    if retained.exists():
        document = json.loads(safe_file(retained, "root", 0o400))
        for role, user in profiles(base, host).items():
            key = private_key(host, role, user)
            csr = verify_csr(base, document["requests"][role]["csr"], host, role)
            if key.public_key().public_numbers() != csr.public_key().public_numbers():
                raise RuntimeError("retained rollover key changed")
        return document
    requests = {}
    for role, user in profiles(base, host).items():
        key = private_key(host, role, user)
        _, certificate, ca = paths(host, role)
        old_pem = safe_file(ca, "root", 0o444)
        if hashlib.sha256(old_pem).hexdigest() != old_ca:
            raise RuntimeError("previous transport trust pin differs")
        raw = safe_file(certificate, "root", 0o444)
        write_once(root / (role + "-previous.pem"), raw)
        write_once(root / (role + "-previous-ca.pem"), old_pem)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(base["subject"](role))
            .add_extension(san(base, host, role), critical=False)
            .sign(key, hashes.SHA256())
        )
        requests[role] = {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "previous_certificate_sha256": hashlib.sha256(raw).hexdigest(),
            "previous_ca_sha256": old_ca,
        }
    document = {
        "format": "kedgeflow-cura-transport-rollover-requests-v1",
        "host": host,
        "generation": generation,
        "requests": requests,
        "private_keys_exported": False,
    }
    write_once(retained, json.dumps(document, sort_keys=True) + "\n")
    return document


def sign(base, generation, requests, until):
    global PHASE
    PHASE = "new_protected_ca_generation"
    now = datetime.now(timezone.utc)
    end = base["deadline"](until, now)
    root = DATA / "pki/rollover" / generation
    directory(root)
    required = {*base["PROFILES"], "Identity"}
    if set(requests) != required:
        raise ValueError("complete registered host inventory required")
    for host, document in requests.items():
        if (
            document.get("format") != "kedgeflow-cura-transport-rollover-requests-v1"
            or document.get("host") != host
            or document.get("generation") != generation
            or set(document["requests"]) != set(profiles(base, host))
        ):
            raise ValueError("closed rollover request inventory required")
        for role, record in document["requests"].items():
            verify_csr(base, record["csr"], host, role)
    intent = {
        "generation": generation,
        "until": until,
        "request_sha256": hashlib.sha256(json.dumps(requests, sort_keys=True).encode()).hexdigest(),
    }
    write_once(root / "intent.json", json.dumps(intent, sort_keys=True) + "\n")
    key_file, ca_file = root / "ca.key", root / "ca.pem"
    if not key_file.exists():
        if ca_file.exists():
            raise RuntimeError("generation CA key missing; never replace")
        key = ec.generate_private_key(ec.SECP256R1())
        write_once(
            key_file,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
    key = serialization.load_pem_private_key(safe_file(key_file, "root", 0o400), None)
    if not ca_file.exists():
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Cura transport " + generation)]
        )
        ca = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(end + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        write_once(ca_file, ca.public_bytes(serialization.Encoding.PEM), 0o444)
    ca = x509.load_pem_x509_certificate(safe_file(ca_file, "root", 0o444))
    if ca.public_key().public_numbers() != key.public_key().public_numbers() or base[
        "certificate_expiry"
    ](ca) != end + timedelta(hours=1):
        raise RuntimeError("CA generation key or lifetime differs")
    certificates = {}
    for host, document in requests.items():
        certificates[host] = {}
        for role, record in document["requests"].items():
            csr = verify_csr(base, record["csr"], host, role)
            path = root / (host + "-" + role + ".pem")
            if not path.exists():
                usages = (
                    [ExtendedKeyUsageOID.SERVER_AUTH]
                    if role == "keycloak"
                    else [ExtendedKeyUsageOID.CLIENT_AUTH]
                )
                if role not in {"keycloak", "etcd-admin"}:
                    usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
                leaf = (
                    x509.CertificateBuilder()
                    .subject_name(csr.subject)
                    .issuer_name(ca.subject)
                    .public_key(csr.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=5))
                    .not_valid_after(end)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(san(base, host, role), critical=False)
                    .add_extension(x509.ExtendedKeyUsage(usages), critical=False)
                    .add_extension(
                        x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                        critical=True,
                    )
                    .sign(key, hashes.SHA256())
                )
                write_once(path, leaf.public_bytes(serialization.Encoding.PEM), 0o444)
            leaf = x509.load_pem_x509_certificate(safe_file(path, "root", 0o444))
            if (
                leaf.public_key().public_numbers() != csr.public_key().public_numbers()
                or base["certificate_expiry"](leaf) != end
            ):
                raise RuntimeError("issued leaf differs from retained generation")
            certificates[host][role] = path.read_text()
    document = {
        "format": "kedgeflow-cura-transport-rollover-certificates-v1",
        "generation": generation,
        "until": until,
        "ca_pem": ca_file.read_text(),
        "ca_sha256": hashlib.sha256(ca_file.read_bytes()).hexdigest(),
        "certificates": certificates,
    }
    write_once(root / "issued-public.json", json.dumps(document, sort_keys=True) + "\n")
    return {
        "status": "public_certificate_generation_prepared",
        "generation": generation,
        "ca_sha256": document["ca_sha256"],
        "certificates": sum(len(v) for v in certificates.values()),
        "private_keys_exported": False,
        "old_ca_keys_removed": False,
    }


def export(host, generation):
    root = DATA / "pki/rollover" / generation
    d = json.loads(safe_file(root / "issued-public.json", "root", 0o400))
    return {**d, "certificates": {host: d["certificates"][host]}}


def replace_public(path, raw):
    # Called only with bound public certificates and stopped users. Existing
    # entries remain regular root-owned files; private keys are never replaced.
    safe_file(path, "root", 0o444)
    temporary = path.with_name(path.name + ".rollover-new")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o444)
    temporary.replace(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install(base, host, generation, document):
    global PHASE
    PHASE = "validate_generation_before_stop"
    root = DATA / "configuration/transport-rollover" / generation
    requests = json.loads(safe_file(root / "requests.json", "root", 0o400))
    if (
        document.get("format") != "kedgeflow-cura-transport-rollover-certificates-v1"
        or document.get("generation") != generation
        or set(document["certificates"].get(host, {})) != set(profiles(base, host))
    ):
        raise ValueError("signed rollover inventory differs")
    ca_raw = document["ca_pem"].encode()
    if hashlib.sha256(ca_raw).hexdigest() != document["ca_sha256"]:
        raise ValueError("new transport CA pin differs")
    ca = x509.load_pem_x509_certificate(ca_raw)
    end = base["deadline"](document["until"], datetime.now(timezone.utc))
    for role, user in profiles(base, host).items():
        leaf = x509.load_pem_x509_certificate(document["certificates"][host][role].encode())
        leaf.verify_directly_issued_by(ca)
        key = private_key(host, role, user)
        csr = verify_csr(base, requests["requests"][role]["csr"], host, role)
        if (
            leaf.public_key().public_numbers() != key.public_key().public_numbers()
            or leaf.public_key().public_numbers() != csr.public_key().public_numbers()
            or leaf.subject != csr.subject
            or leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            != san(base, host, role)
            or base["certificate_expiry"](leaf) != end
        ):
            raise ValueError("rollover leaf changed role, key or lifetime")
    for app in [
        "gateway",
        "admission",
        "issuer",
        "broker",
        "recovery",
        "governance",
        "sql-target",
        "collector",
    ]:
        if (
            run(
                ["systemctl", "is-active", "--quiet", "kedgeflow-" + app + ".service"], False
            ).returncode
            == 0
        ):
            raise RuntimeError("live application authority forbids pre-application rollover")
    units = {
        "Services": [
            "kedgeflow-ledger-publish.timer",
            "kedgeflow-ledger-publish.service",
            "kedgeflow-ledger-issue.service",
        ],
        "Identity": ["kedgeflow-keycloak.service"],
        "LedgerA": ["kedgeflow-etcd.service"],
        "LedgerB": ["kedgeflow-etcd.service"],
        "LedgerC": ["kedgeflow-etcd.service"],
        "Witness": ["kedgeflow-witness-etcd.service"],
    }.get(host, [])
    PHASE = "stop_transport_consumers"
    for unit in units:
        run(["systemctl", "stop", unit])
    PHASE = "install_public_chains_only"
    for role in profiles(base, host):
        _, leaf_path, ca_path = paths(host, role)
        old = requests["requests"][role]
        for path, new, expected_old in [
            (ca_path, ca_raw, old["previous_ca_sha256"]),
            (
                leaf_path,
                document["certificates"][host][role].encode(),
                old["previous_certificate_sha256"],
            ),
        ]:
            current = safe_file(path, "root", 0o444)
            if current == new:
                continue
            if hashlib.sha256(current).hexdigest() != expected_old:
                raise RuntimeError("transport material changed outside the declared generation")
            replace_public(path, new)
    report = {
        "format": "kedgeflow-cura-transport-rollover-installed-v1",
        "host": host,
        "generation": generation,
        "ca_sha256": document["ca_sha256"],
        "until": document["until"],
        "certificates": len(profiles(base, host)),
        "host_private_keys_preserved": True,
        "old_public_chains_archived": True,
        "consumers_started": False,
        "spire_keys_or_registrations_changed": False,
        "owner_acceptance": "BLOCKED_EXTERNAL_INPUT",
    }
    write_once(root / "installed.json", json.dumps(report, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=["prepare", "sign", "export", "install"], required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--base-source-sha256", required=True)
    parser.add_argument("--previous-ca-sha256")
    parser.add_argument("--document", type=Path)
    parser.add_argument("--until")
    args = parser.parse_args()
    try:
        base = load_base(args.base_source_sha256, args.host, args.generation)
        if args.action in {"sign", "export"} and args.host != "Services":
            raise RuntimeError("transport CA generation stays on Services")
        if args.action == "prepare":
            result = prepare(base, args.host, args.generation, args.previous_ca_sha256)
        elif args.action == "sign":
            result = sign(base, args.generation, json.loads(args.document.read_text()), args.until)
        elif args.action == "export":
            result = export(json.loads(args.document.read_text())["export_host"], args.generation)
        else:
            result = install(
                base, args.host, args.generation, json.loads(args.document.read_text())
            )
        print(json.dumps(result, indent=2))
    except Exception as error:
        print(json.dumps({"status": "failed", "phase": PHASE, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
