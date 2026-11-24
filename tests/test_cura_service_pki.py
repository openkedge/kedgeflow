"""Service CSRs cannot request another role, a broader identity, or a long lifetime."""

import runpy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/enroll-cura-service-pki.py"))


def csr(host="Services", role="gateway", *, subject=None, san=None, extra=False):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject if subject is not None else SCRIPT["subject"](role))
        .add_extension(san if san is not None else SCRIPT["sans"](host, role), critical=False)
    )
    if extra:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def test_csr_refuses_another_workload_or_host_and_ca_escalation():
    raw = csr()
    SCRIPT["check_csr"](raw, "Services", "gateway")
    for host, role in [("Sql", "sql-target"), ("Services", "broker"), ("Agent", "gateway")]:
        with pytest.raises(ValueError):
            SCRIPT["check_csr"](raw, host, role)
    for bad in [
        csr(extra=True),
        csr(
            san=x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("spiffe://cura.kedgeflow.internal/agent")]
            )
        ),
        csr(subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "root")])),
    ]:
        with pytest.raises(ValueError):
            SCRIPT["check_csr"](bad, "Services", "gateway")


def test_only_separate_root_cli_administrator_has_common_name():
    for roles in SCRIPT["PROFILES"].values():
        for role in roles:
            values = SCRIPT["subject"](role).get_attributes_for_oid(NameOID.COMMON_NAME)
            assert [v.value for v in values] == (["root"] if role == "etcd-admin" else [])


def test_transport_lifetime_is_bounded_and_rejects_expired_inputs():
    now = datetime(2026, 11, 18, tzinfo=timezone.utc)
    assert SCRIPT["deadline"]("2026-11-18T23:16:43Z", now) > now
    for delta in [timedelta(0), timedelta(minutes=15), timedelta(hours=49)]:
        value = (now + delta).strftime("%Y-%m-%dT%H:%M:%SZ")
        with pytest.raises(ValueError):
            SCRIPT["deadline"](value, now)
