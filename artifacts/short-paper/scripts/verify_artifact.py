#!/usr/bin/env python3
"""Verify the published snapshot and retained evidence without running experiments."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


source = json.loads((R / "artifact/source-manifest.json").read_text())
for name, expected in source["sha256"].items():
    assert digest(R / "artifact/runtime" / name) == expected, name
for name in ["paper_safety.rs", "paper_adversarial.rs"]:
    assert (R / "tests" / name).read_bytes() == (
        R / "artifact/runtime/crates/kedgeflow/tests" / name
    ).read_bytes(), name
for folder, expected_tests in [("baseline-20261008", 57), ("final", 58)]:
    summary = json.loads((R / "results" / folder / "summary.json").read_text())
    raw = R / "results" / folder / "rust-tests.log"
    assert digest(raw) == summary["raw_log_sha256"], folder
    assert summary["source_commit"] == source["source_commit"]
    assert summary["passed"] == expected_tests and summary["returncode"] == 0
    assert summary["failed"] == summary["ignored"] == 0 and not summary["skipped"]
    assert digest(R / "tests/paper_safety.rs") == summary["paper_tests_sha256"]
    totals = [
        tuple(map(int, x))
        for x in re.findall(
            r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", raw.read_text()
        )
    ]
    assert sum(x[0] for x in totals) == expected_tests and all(x[1:] == (0, 0) for x in totals)
final = json.loads((R / "results/final/summary.json").read_text())
assert digest(R / "tests/paper_adversarial.rs") == final["adversarial_tests_sha256"]
raw = (R / "results/final/rust-tests.log").read_text()
rows = [
    json.loads(line.split("ADVERSARIAL_RESULT ", 1)[1])
    for line in raw.splitlines()
    if line.startswith("ADVERSARIAL_RESULT ")
]
assert rows == final["adversarial_experiments"] and len(rows) == 12
assert all(row["actual_result"] == "passed" for row in rows)
matrices = [row for row in final["experiments"] if row["experiment"] == "claim_matrix"]
assert {
    k: sum(row[k] for row in matrices)
    for k in ["attempts", "claims", "refused", "transport_errors"]
} == {"attempts": 6560, "claims": 82, "refused": 6478, "transport_errors": 0}
git_check = False
repo = R.parents[1]
if (repo / ".git").exists():
    for name, expected in source["sha256"].items():
        data = subprocess.check_output(
            ["git", "-C", str(repo), "show", source["source_commit"] + ":" + name]
        )
        assert hashlib.sha256(data).hexdigest() == expected, name
    git_check = True
print(
    json.dumps(
        {
            "status": "passed",
            "original_files": len(source["sha256"]),
            "pinned_git_objects_checked": git_check,
            "tests": 58,
            "adversarial_scenarios": 12,
        },
        indent=2,
    )
)
