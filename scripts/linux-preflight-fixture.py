"""Generated local material for the disposable Linux package preflight only."""

import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(kind, value):
    prefix = f"KedgeFlow/KF-JSON-0.2/{kind}\0".encode()
    return hashlib.sha256(prefix + canonical(value)).hexdigest()


def public(seed):
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(value):
    return base64.b64encode(value).decode()


def url64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def key_usage(ca):
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def generate(stage, users):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable Linux package CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(key_usage(True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    configs = {}

    def material(role):
        directory = stage / "etc/kedgeflow" / role
        uid, gid = users[role]

        def write(name, value):
            path = directory / name
            path.write_bytes(value.encode() if isinstance(value, str) else value)
            os.chown(path, uid, gid)
            path.chmod(0o400)
            return str(path)

        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable " + role)])
            )
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(key_usage(False), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.UniformResourceIdentifier(f"spiffe://example.org/{role}"),
                    ]
                ),
                False,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert = write("service.pem", certificate.public_bytes(serialization.Encoding.PEM))
        private = write(
            "service.key",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        roots = write("ca.pem", ca.public_bytes(serialization.Encoding.PEM))
        token = write("ledger-token", secrets.token_urlsafe(32))
        witness = {
            "endpoint": "https://localhost:9001",
            "prefix": "/witness",
            "ca": roots,
            "certificate": cert,
            "private_key": private,
            "token_file": token,
        }
        return write, cert, private, roots, token, witness

    for role in ("gateway", "control", "broker", "sql-target"):
        write, cert, private, roots, token, witness = material(role)
        template = {
            "gateway": "gateway-postgres",
            "control": "control",
            "broker": "broker-refresh",
            "sql-target": "postgres-target",
        }[role]
        config = json.loads((ROOT / f"config/{template}.example.json").read_text())
        config.update(certificate=cert, private_key=private, workload_ca=roots)
        if role != "sql-target":
            config.update(etcd_ca=roots, etcd_token_file=token, restore_gate=witness)
        if role in ("control", "broker"):
            config.update(etcd_certificate=cert, etcd_private_key=private)
        if role in ("gateway", "control"):
            subject = {"iss": config["oidc_issuer"], "sub": "disposable-linux-preflight"}
            if role == "control":
                subject = config["subjects"][0]
            config["shared_auth"] = {
                "capacity": 16,
                "registrations": [
                    {
                        "subject": subject,
                        "workload_id": config.get(
                            "workload_id", "spiffe://example.org/agents/planner"
                        ),
                        "allowed_scopes": [config.get("action_scope", "reservation:request")],
                    }
                ],
            }
        if role == "gateway":
            config.update(
                grant_public_key_base64=b64(public(5)),
                oidc_public_key_base64=b64(public(7)),
                broker_ca=roots,
                target_ca=roots,
                actor_token_file=write("actor.jwt", "disposable-non-token-assertion"),
            )
            config["tools"][0]["action"]["digest"] = "a" * 64
            config["postgres_adapter"]["registration"]["action"]["digest"] = "a" * 64
            config["postgres_adapter"]["target_keys"] = {"target": b64(public(11))}
            config["enforcement"].update(
                control_ca=roots,
                installation_keys={"installation": b64(public(12))},
                acknowledgement_key_file=write("ack-seed", b64(bytes([9]) * 32)),
            )
        elif role == "control":
            config.update(
                admission_signing_key_file=write("admission-seed", b64(bytes([6]) * 32)),
                issuer_signing_key_file=write("issuer-seed", b64(bytes([5]) * 32)),
            )
        elif role == "broker":
            config.update(
                grant_keys={"grant": b64(public(5))},
                target_key_id="target",
                target_signing_key_file=write("target-seed", b64(bytes([11]) * 32)),
                target_verification_keys={"target": b64(public(11))},
                installed_trust_digest="a" * 64,
            )
            config["registration"]["tool"]["action"]["digest"] = "a" * 64
            snapshot = json.loads((ROOT / "config/exchange-identities.example.json").read_text())
            milliseconds = int(time.time() * 1000)
            snapshot.update(not_before=milliseconds - 60000, expires_at=milliseconds + 240000)
            snapshot["registrations"][0]["subject"]["sub"] = "disposable-linux-preflight"
            for entry in snapshot["subject_keys"] + snapshot["actor_keys"]:
                entry.update(not_before=milliseconds - 60000, expires_at=milliseconds + 240000)
            snapshot["subject_keys"][0].update(kid="subject", public_key=url64(public(3)))
            actor = ec.generate_private_key(ec.SECP256R1()).public_key()
            snapshot["actor_keys"][0].update(
                kid="actor",
                public_key=url64(
                    actor.public_bytes(
                        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                    )
                ),
            )
            realm = {key: snapshot[key] for key in ("issuer", "subject_audience", "actor_audience")}
            head = {
                "profile": "KF-IDENTITY-REFRESH-0.1-draft",
                "kind": "head",
                "authority_id": "disposable-refresh",
                "realm_digest": digest("identity-realm", realm),
                "epoch": 1,
                "snapshot_digest": digest("identity-snapshot", snapshot),
            }
            record = {**head, "kind": "snapshot", "snapshot": snapshot, "key_id": "refresh"}
            signer = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([15]) * 32)
            record["signature"] = url64(
                signer.sign(b"KF-IDENTITY-REFRESH-0.1-draft\0" + canonical(record))
            )
            config["identity_refresh"] = {
                "authority_id": "disposable-refresh",
                "issuer": snapshot["issuer"],
                "authority_keys": {"refresh": b64(public(15))},
                "signed_snapshot_file": write("signed.json", json.dumps(record)),
                "head_file": write("head.json", json.dumps(head)),
                "minimum_epoch_file": write("floor", "1"),
            }
        else:
            config.update(
                grant_keys={"grant": b64(public(5))},
                target_keys={"target": b64(public(11))},
                query_token_file=write("query-token", secrets.token_urlsafe(32)),
            )
            config["registration"]["action"]["digest"] = "a" * 64
        path = write("config.json", json.dumps(config))
        configs[role] = (Path(path), config)
    materials = {}
    for role in ("recovery", "collector", "governance", "operator"):
        write, cert, private, roots, token, witness = material(role)
        materials[role] = (write, cert, private, roots, token, witness)
        if role == "recovery":
            config = json.loads((ROOT / "config/recovery.example.json").read_text())
            config.update(
                etcd_ca=roots,
                etcd_certificate=cert,
                etcd_private_key=private,
                etcd_token_file=token,
                restore_gate=witness,
                query_ca=roots,
                query_certificate=cert,
                query_private_key=private,
                query_token_file=write("query-token", secrets.token_urlsafe(32)),
                grant_keys={"grant": b64(public(5))},
                receipt_key_id="outcome",
                receipt_signing_key_file=write("receipt-seed", b64(bytes([14]) * 32)),
            )
            name = "recovery.json"
        elif role == "collector":
            config = json.loads((ROOT / "config/outcomes.example.json").read_text())
            config.update(
                certificate=cert,
                private_key=private,
                workload_ca=roots,
                etcd_ca=roots,
                etcd_certificate=cert,
                etcd_private_key=private,
                etcd_token_file=token,
                restore_gate=witness,
                oidc_public_key_base64=b64(public(7)),
                grant_keys={"grant": b64(public(5))},
                outcome_keys={"outcome": b64(public(14))},
                acknowledgement_signing_key_file=write("ack-seed", b64(bytes([15]) * 32)),
            )
            config["reporter_subject"]["sub"] = "disposable-linux-reporter"
            config["shared_auth"] = {
                "capacity": 16,
                "registrations": [
                    {
                        "subject": config["reporter_subject"],
                        "workload_id": config["source_id"],
                        "allowed_scopes": [config["report_scope"]],
                    }
                ],
            }
            name = "config.json"
        elif role == "governance":
            config = json.loads((ROOT / "config/governance.example.json").read_text())
            control = config["control"]
            control.update(
                certificate=cert,
                private_key=private,
                workload_ca=roots,
                etcd_ca=roots,
                etcd_certificate=cert,
                etcd_private_key=private,
                etcd_token_file=token,
                restore_gate=witness,
                admission_signing_key_file="",
                issuer_signing_key_file="",
            )
            control["shared_auth"] = {
                "capacity": 16,
                "registrations": [
                    {
                        "subject": control["subjects"][0],
                        "workload_id": control["workload_id"],
                        "allowed_scopes": ["kf.control"],
                    }
                ],
            }
            name = "config.json"
        else:
            config = {
                "etcd_endpoint": "https://localhost:9000",
                "etcd_prefix": "/authority",
                "etcd_ca": roots,
                "etcd_certificate": cert,
                "etcd_private_key": private,
                "etcd_token_file": token,
                "restore_gate": witness,
            }
            name = "config.json"
        configs[role] = (Path(write(name, json.dumps(config))), config)
    write, cert, private, roots, _, _ = materials["recovery"]
    config = json.loads((ROOT / "config/supervision.example.json").read_text())
    config["recovery"] = configs["recovery"][1]
    collector = configs["collector"][1]
    config["delivery"].update(
        collector_ca=roots,
        certificate=cert,
        private_key=private,
        token_file=write("reporter.jwt", "disposable-not-a-token"),
        dpop_signing_key_file=write("proof-seed", b64(bytes([8]) * 32)),
        tenant=collector["tenant"],
        conflict_domain=collector["conflict_domain"],
        reporter_subject=collector["reporter_subject"],
        outcome_keys=collector["outcome_keys"],
        acknowledgement_keys={collector["acknowledgement_key_id"]: b64(public(15))},
    )
    configs["supervisor"] = (Path(write("config.json", json.dumps(config))), config)
    return configs
