"""Test conformance of normative machine-readable contracts and test fixtures."""

import sys
from pathlib import Path

# Ensure spec directory is importable
spec_dir = Path(__file__).resolve().parent.parent / "spec"
if str(spec_dir) not in sys.path:
    sys.path.insert(0, str(spec_dir))


def test_machine_readable_fixtures():
    """Check all fixture schemas, signatures and declared semantic bindings."""
    from validate import validate_all

    fixtures, keys = validate_all()
    assert len(fixtures) == 13
    assert len(keys) == 9
