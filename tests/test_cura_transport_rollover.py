"""Transport recovery cannot widen a role or replace a private-key file."""

import os
import pwd
import runpy
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).parents[1]
SCRIPT = runpy.run_path(str(ROOT / "scripts/rollover-cura-transport.py"))
BASE = runpy.run_path(str(ROOT / "scripts/enroll-cura-service-pki.py"))


def csr(host, role, *, extra=False, wrong_san=False):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(BASE["subject"](role))
    san = (
        x509.SubjectAlternativeName([x509.DNSName("unregistered.invalid")])
        if wrong_san
        else SCRIPT["san"](BASE, host, role)
    )
    builder = builder.add_extension(san, False)
    if extra:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def test_keycloak_rollover_is_exactly_its_existing_server_names():
    SCRIPT["verify_csr"](BASE, csr("Identity", "keycloak"), "Identity", "keycloak")
    for bad in [
        csr("Identity", "keycloak", extra=True),
        csr("Identity", "keycloak", wrong_san=True),
    ]:
        with pytest.raises(ValueError):
            SCRIPT["verify_csr"](BASE, bad, "Identity", "keycloak")
    with pytest.raises(ValueError):
        SCRIPT["verify_csr"](BASE, csr("Services", "gateway"), "Sql", "sql-target")


def test_rollover_cannot_add_ca_authority_to_an_ordinary_role():
    with pytest.raises(ValueError):
        SCRIPT["verify_csr"](BASE, csr("Services", "gateway", extra=True), "Services", "gateway")


def test_atomic_public_replacement_refuses_private_keys_and_links(tmp_path, monkeypatch):
    account = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(SCRIPT["safe_file"].__globals__["pwd"], "getpwnam", lambda _: account)
    private = tmp_path / "identity.key"
    private.write_bytes(b"fixture-private-key")
    private.chmod(0o400)
    with pytest.raises(RuntimeError, match="custody differs"):
        SCRIPT["replace_public"](private, b"must-not-replace")
    assert private.read_bytes() == b"fixture-private-key"
    public = tmp_path / "identity.pem"
    public.write_bytes(b"old-public-certificate")
    public.chmod(0o444)
    link = tmp_path / "linked.pem"
    link.symlink_to(public)
    with pytest.raises(RuntimeError):
        SCRIPT["replace_public"](link, b"new-public-certificate")
    SCRIPT["replace_public"](public, b"new-public-certificate")
    assert public.read_bytes() == b"new-public-certificate"
    assert public.stat().st_mode & 0o7777 == 0o444
    assert private.read_bytes() == b"fixture-private-key"
