"""Vendoring cannot remove packages from advisory scope or hide source drift."""

import json
import runpy
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
AUDIT = runpy.run_path(str(ROOT / "scripts/audit-dependencies.py"))


def copy_source(tmp_path):
    shutil.copytree(ROOT / "vendor", tmp_path / "vendor")
    shutil.copyfile(ROOT / "Cargo.toml", tmp_path / "Cargo.toml")
    return tmp_path


def test_vendored_source_stays_in_the_public_advisory_inventory():
    AUDIT["verify_vendor"](ROOT)
    assert {
        "package": {"ecosystem": "crates.io", "name": "cedar-policy-core"},
        "version": "4.7.1",
    } in AUDIT["queries"]()
    assert all(q["package"]["name"] != "chrono" for q in AUDIT["queries"]())
    triage = json.loads((ROOT / "config/dependency-advisory-triage.json").read_text())
    assert not any(e["package"]["name"] == "chrono" for e in triage["entries"])


@pytest.mark.parametrize("change", ["content", "omission", "extra", "symlink", "provenance"])
def test_vendored_source_drift_is_refused(tmp_path, change):
    root = copy_source(tmp_path)
    package = root / "vendor/cedar-policy-core-4.7.1"
    target = package / "src/extensions/datetime.rs"
    if change == "content":
        target.write_text(target.read_text() + "\n// unreviewed\n")
    elif change == "omission":
        target.unlink()
    elif change == "extra":
        (package / "extra.rs").write_text("unreviewed")
    elif change == "symlink":
        target.unlink()
        target.symlink_to(package / "src/lib.rs")
    else:
        (root / "vendor/provenance.json").write_text("{}")
    with pytest.raises(ValueError):
        AUDIT["verify_vendor"](root)


def test_other_cargo_patches_require_explicit_audit_coverage(tmp_path):
    root = copy_source(tmp_path)
    config = root / "Cargo.toml"
    config.write_text(
        config.read_text().replace(
            "[patch.crates-io]", '[patch.crates-io]\nother = { path = "elsewhere" }'
        )
    )
    with pytest.raises(ValueError, match="patch inventory"):
        AUDIT["verify_vendor"](root)
