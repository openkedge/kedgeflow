"""Public continuity checks reject empty or accidentally private provider key sets."""

import runpy
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/probe-cura-provider-restart.py"))


def test_public_continuity_comparison_is_order_independent_and_rejects_private_fields():
    public = [{"kid": "one", "kty": "EC", "x": "fixture-public"}, {"kid": "two", "kty": "RSA"}]
    assert SCRIPT["public_key_set"]({"keys": public}) == SCRIPT["public_key_set"](
        {"keys": list(reversed(public))}
    )
    for secret in ["d", "p", "q", "dp", "dq", "qi", "k"]:
        with pytest.raises(ValueError, match="private fields"):
            SCRIPT["public_key_set"]({"keys": [{**public[0], secret: "fixture-private"}]})


def test_missing_or_empty_provider_key_set_cannot_pass_continuity():
    for bundle in [{}, {"keys": []}, {"keys": "not-a-key-list"}]:
        with pytest.raises(ValueError, match="key set missing"):
            SCRIPT["public_key_set"](bundle)
