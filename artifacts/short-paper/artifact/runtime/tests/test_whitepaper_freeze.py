"""The freeze check must reject altered contracts and incomplete paper bundles."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
CHECKER = REPOSITORY / "scripts/verify-whitepaper.py"


@pytest.fixture
def frozen_repo(tmp_path: Path) -> Path:
    bundle = "docs/whitepaper/v0.9"
    shutil.copytree(REPOSITORY / bundle, tmp_path / bundle)
    manifest = json.loads((tmp_path / bundle / "FREEZE.json").read_text())
    for entry in manifest["contracts"]:
        relative = entry["implementation_path"]
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY / relative, target)
    return tmp_path


def run_check(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_original_bundle_passes(frozen_repo: Path) -> None:
    result = run_check(frozen_repo)
    assert result.returncode == 0, result.stderr
    assert "58 files and 24 contract pins match" in result.stdout


@pytest.mark.parametrize("relative", [
    "spec/kedgeflow.schema.json",
    "spec/GRANT_REFERENCE_PROFILE.md",
    "fixtures/grant.json",
    "docs/whitepaper/v0.9/whitepaper/06-implementation.tex",
])
def test_changed_bytes_fail(frozen_repo: Path, relative: str) -> None:
    with (frozen_repo / relative).open("ab") as stream:
        stream.write(b"\n")
    result = run_check(frozen_repo)
    assert result.returncode == 1
    assert "SHA-256 mismatch" in result.stderr


def test_missing_contract_fails(frozen_repo: Path) -> None:
    (frozen_repo / "fixtures/grant.json").unlink()
    result = run_check(frozen_repo)
    assert result.returncode == 1
    assert "missing file: fixtures/grant.json" in result.stderr


def test_removed_pin_fails(frozen_repo: Path) -> None:
    path = frozen_repo / "docs/whitepaper/v0.9/FREEZE.json"
    manifest = json.loads(path.read_text())
    manifest["contracts"].pop()
    path.write_text(json.dumps(manifest))
    result = run_check(frozen_repo)
    assert result.returncode == 1
    assert "contract inventory differs" in result.stderr


def test_unlisted_frozen_file_fails(frozen_repo: Path) -> None:
    (frozen_repo / "docs/whitepaper/v0.9/unlisted.txt").write_text("unexpected")
    result = run_check(frozen_repo)
    assert result.returncode == 1
    assert "frozen package inventory differs" in result.stderr
