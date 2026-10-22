"""Required-suite inventory keeps binary identity and test output boundaries."""

import runpy
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[1] / "scripts/conformance.py"))


def test_split_rust_logs_preserve_same_named_cases_and_zero_test_targets():
    manifest = """    Running unittests src/lib.rs (target/lib)
same_name: test
    Running tests/governance.rs (target/governance)
same_name: test
family_saga_case: test
    Running unittests src/bin/empty.rs (target/empty)
0 tests, 0 benchmarks
"""
    primary = """    Running unittests src/lib.rs (target/lib)
test same_name ... ok
    Running tests/governance.rs (target/governance)
test same_name ... actual fixture stdout
ok
    Running unittests src/bin/empty.rs (target/empty)
running 0 tests
"""
    saga = """    Running tests/governance.rs (target/governance)
test family_saga_case ... actual fixture stdout
ok
"""
    expected = SCRIPT["rust_cases"](manifest, True)
    actual = SCRIPT["rust_cases"](primary, False) + SCRIPT["rust_cases"](saga, False)
    assert len(expected) == len(set(expected)) == len(actual) == 3
    assert set(expected) == set(actual)
    assert len(SCRIPT["rust_targets"](manifest)) == 3
    assert set(SCRIPT["rust_targets"](manifest)) == set(
        SCRIPT["rust_targets"](primary) + SCRIPT["rust_targets"](saga)
    )
    assert set(expected) != set(actual[:-1])  # Omitted required batch.
    assert len(actual + [actual[-1]]) != len(set(actual + [actual[-1]]))


def test_unattributed_rust_case_cannot_count_toward_required_population():
    with pytest.raises(ValueError, match="without target identity"):
        SCRIPT["rust_cases"]("test invented_case ... ok", False)
