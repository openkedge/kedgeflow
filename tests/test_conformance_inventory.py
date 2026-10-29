"""Required-suite inventory keeps binary identity and test output boundaries."""

import json
import re
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


def owned_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("KF_KUBE_TEST_CONTEXT", "kind-kf8-tests")
    monkeypatch.setenv("KF_KUBE_TEST_KUBECTL", str(tmp_path / "kubectl"))
    monkeypatch.setenv("KF_KUBE_TEST_KUBECONFIG", str(tmp_path / "kubeconfig"))


def test_kube_bootstrap_uses_fresh_owned_namespace_and_private_credentials(monkeypatch, tmp_path):
    owned_environment(monkeypatch, tmp_path)
    stale = tmp_path / "expired-bootstrap"
    monkeypatch.setenv("KF_KUBE_FIXTURE", str(stale))
    private = tmp_path / "private" / "fixture"
    first = SCRIPT["kube_bootstrap_command"](private)
    second = SCRIPT["kube_bootstrap_command"](private)
    assert first[first.index("--output") + 1] == str(private)
    assert str(stale) not in first
    assert first[first.index("--context") + 1] == "kind-kf8-tests"
    assert first[first.index("--cluster") + 1] == "kf8-tests"
    namespace = first[first.index("--namespace") + 1]
    assert re.fullmatch(r"kf-drain-[a-f0-9]{16}", namespace)
    assert namespace != second[second.index("--namespace") + 1]
    assert not private.exists()  # Issuance happens when the recorded command runs.


@pytest.mark.parametrize("context", ["", "kind-production", "production", "kind-kf8_shared"])
def test_kube_bootstrap_refuses_implicit_or_unowned_context(monkeypatch, tmp_path, context):
    owned_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("KF_KUBE_TEST_CONTEXT", context)
    with pytest.raises(ValueError, match="task-owned"):
        SCRIPT["kube_bootstrap_command"](tmp_path / "private")


@pytest.mark.parametrize("missing", ["KF_KUBE_TEST_KUBECTL", "KF_KUBE_TEST_KUBECONFIG"])
def test_kube_bootstrap_never_falls_back_to_default_tools_or_config(monkeypatch, tmp_path, missing):
    owned_environment(monkeypatch, tmp_path)
    monkeypatch.delenv(missing)
    with pytest.raises(ValueError, match="explicit kubectl and kubeconfig"):
        SCRIPT["kube_bootstrap_command"](tmp_path / "private")


def test_kube_bootstrap_cleanup_refuses_foreign_scope_before_any_command(monkeypatch, tmp_path):
    owned_environment(monkeypatch, tmp_path)
    fixture = tmp_path / "private"
    fixture.mkdir()
    (fixture / "fixture-public.json").write_text(json.dumps({
        "cluster": "kf8-another", "namespace": "kf-drain-0123456789abcdef",
    }))
    with pytest.raises(ValueError, match="cleanup context/namespace mismatch"):
        SCRIPT["cleanup_bootstrap"](fixture, tmp_path / "public")
    assert not (tmp_path / "public").exists()
