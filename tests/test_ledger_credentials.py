"""Credential sink refusal mechanics; actual UID/capability behavior needs Linux qualification."""

import json
import os
import runpy
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SINK = runpy.run_path(str(ROOT / "deploy/linux/credentials/publish.py"))


def permission():
    return {"permission": "READWRITE", "key": "/authority/", "range_end": "/authority0"}


def test_policy_digest_matches_protocol_domain_and_canonical_order():
    permissions = [permission()]
    reference = runpy.run_path(str(ROOT / "scripts/linux-sql-workflow.py"))
    assert SINK["permissions_digest"](permissions, "/authority") == reference["digest"](
        "ledger-credential-permissions", permissions
    )


@pytest.mark.parametrize("raw", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":1.5}'])
def test_sink_refuses_ambiguous_json(raw):
    with pytest.raises(ValueError):
        SINK["decode"](raw)


@pytest.mark.parametrize("path", ["relative", "/a/../b", "/a/./b", "/a//b", "/"])
def test_sink_refuses_noncanonical_paths(path):
    with pytest.raises(ValueError):
        SINK["absolute"](path)


def test_sink_reads_are_bounded_private_stable_and_reject_links(tmp_path):
    secret = tmp_path / "secret"
    secret.write_bytes(b"opaque-secret")
    secret.chmod(0o400)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:

        def read(bound=64):
            return SINK["read_file"](fd, "secret", os.getuid(), os.getgid(), 0o400, bound)

        assert read() == b"opaque-secret"
        with pytest.raises(ValueError):
            read(2)
        secret.chmod(0o440)
        with pytest.raises(ValueError):
            read()
        secret.chmod(0o400)
        os.link(secret, tmp_path / "alias")
        with pytest.raises(ValueError):
            read()
        secret.unlink()
        secret.symlink_to(tmp_path / "alias")
        with pytest.raises(OSError):
            read()
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "variant", ["stale", "future", "extra", "duplicate", "permissions", "token", "path"]
)
def test_batch_validation_finishes_before_any_files_are_prepared(tmp_path, variant):
    destination = {
        "name": "control-primary",
        "username": "ordinary",
        "scope_prefix": "/authority",
        "permissions": [permission()],
        "role": "control",
        "filename": "primary.token",
    }
    credential = {
        "name": destination["name"],
        "username": destination["username"],
        "scope_prefix": "/authority",
        "permissions_digest": SINK["permissions_digest"]([permission()], "/authority"),
        "token": "opaque-token",
    }
    config = {
        "destinations": [destination],
        "publisher": "kf-credentials",
        "credential_root": str(tmp_path),
    }
    batch = {
        "profile": SINK["PROFILE"],
        "created_at": int(time.time() * 1000),
        "credentials": [credential],
    }
    if variant == "stale":
        batch["created_at"] -= 11000
    elif variant == "future":
        batch["created_at"] += 2000
    elif variant == "extra":
        batch["credentials"].append(dict(credential, name="unconfigured"))
    elif variant == "duplicate":
        batch["credentials"].append(credential)
        config["destinations"].append(destination)
    elif variant == "permissions":
        credential["permissions_digest"] = "0" * 64
    elif variant == "token":
        credential["token"] = "token\nheader"
    else:
        destination["filename"] = "../signing-key"
    with ExitStack() as stack, pytest.raises((ValueError, KeyError)):
        SINK["plan"](stack, config, batch)
    assert list(tmp_path.iterdir()) == []


def test_example_policies_and_targets_are_consistent():
    issuer = json.loads((ROOT / "deploy/linux/credentials/issuer.example.json").read_bytes())
    mapping = json.loads((ROOT / "deploy/linux/credentials/mapping.example.json").read_bytes())
    assert issuer["profile"] == mapping["profile"] == SINK["PROFILE"]
    for source, target in zip(issuer["issuers"], mapping["destinations"], strict=True):
        assert all(
            source[k] == target[k] for k in ("name", "username", "scope_prefix", "permissions")
        )


def test_destructive_qualification_requires_disposable_opt_in():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/qualify-ledger-credentials.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2 and "requires explicit --ephemeral-host" in result.stderr
