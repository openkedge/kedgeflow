"""The Agent's own request keys remain stable and widened/link custody refuses."""

import os
import pwd
import runpy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/prepare-cura-agent-identity.py"))
USER = pwd.getpwuid(os.getuid())


def test_agent_key_creation_is_private_and_rerun_keeps_the_same_public_key(tmp_path):
    path = tmp_path / "request.seed"
    first = SCRIPT["key"](path, USER)
    before = path.read_bytes()
    second = SCRIPT["key"](path, USER)
    assert before == path.read_bytes()
    assert path.stat().st_mode & 0o7777 == 0o400
    assert first.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == second.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    path.chmod(0o600)
    with pytest.raises(RuntimeError, match="custody differs"):
        SCRIPT["key"](path, USER)
    assert path.stat().st_mode & 0o7777 == 0o600


def test_agent_key_loader_refuses_symlinks_and_hardlinks(tmp_path):
    source, link = tmp_path / "source", tmp_path / "link"
    SCRIPT["key"](source, USER)
    link.symlink_to(source)
    with pytest.raises(RuntimeError, match="custody differs"):
        SCRIPT["key"](link, USER)
    link.unlink()
    os.link(source, link)
    with pytest.raises(RuntimeError, match="custody differs"):
        SCRIPT["key"](link, USER)
