#!/usr/bin/env python3
"""Required local software checks, immutable evidence, explicit open release gates."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPEN_GATES = {
    "M0": "minimum Rust execution and independent paper reproduction",
    "M1": "protocol owner/reviewer decisions and accepted versions",
    "M2-M6": "approved providers, all-service custody/rotation, deployed pilot/writer/restore/"
    "retention/budgets/owner acceptance",
    "M7": "protected browser panel, enrollment/attestation, physical authenticator, "
    "frozen HitlWitness carriage, SDK lease workflow and "
    "approved membership lifecycle",
    "M8": "native reservation/grant/claim binding, A2A peers, durable saga/compensation "
    "and actual Kubernetes drain",
    "M9": "independent controller wire exchange, second runtime/target, intermediaries, "
    "reproduction and release decision",
}


def source_hashes() -> dict[str, str]:
    names = (
        subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
        )
        .decode()
        .split("\0")
    )
    return {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in sorted(set(names))
        if name and not name.startswith(("results/", "artifacts/")) and (ROOT / name).is_file()
    }


def run(bindir: Path, output: Path) -> int:
    output.mkdir(parents=True, exist_ok=False)
    before = source_hashes()
    commands = [
        ("format", ["cargo", "fmt", "--all", "--", "--check"]),
        (
            "clippy",
            [
                "cargo",
                "clippy",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("ruff", [sys.executable, "-m", "ruff", "check", "."]),
        ("mypy", [sys.executable, "-m", "mypy", "src"]),
        ("python", [sys.executable, "-m", "pytest", "-q"]),
        ("whitepaper", [sys.executable, "scripts/verify-whitepaper.py"]),
        (
            "schema",
            [
                sys.executable,
                "-m",
                "jsonschema",
                "--instance",
                "fixtures/grant.json",
                "spec/kedgeflow.schema.json",
            ],
        ),
        ("node-vectors", ["node", "tests/sdk/agent-vectors.mjs"]),
        (
            "required-runtime",
            [
                sys.executable,
                "scripts/test-postgres.py",
                "--bindir",
                str(bindir),
                "--peer",
                "--recovery-rehearsal",
                "--command",
                "scripts/start-etcd.sh",
                "--",
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--",
                "--nocapture",
                "--test-threads=1",
            ],
        ),
    ]
    summary = {
        "profile": "KF-SOFTWARE-CONFORMANCE-0.1-draft",
        "baseline_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "tested_working_tree": True,
        "status": "running",
        "source_sha256": before,
        "commands": [],
        "open_gates": OPEN_GATES,
        "linux_account_fixture": "unobserved_by_this_runner; separate CI artifact required",
    }
    for name, command in commands:
        path = output / (name + ".log")
        start = time.monotonic()
        print(f"Running {name}", flush=True)
        with path.open("w") as log:
            try:
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    env={**os.environ, "KF_REQUIRE_SDK": "1"},
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=1200,
                )
                exit_code = result.returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                log.write(f"required command failed: {type(error).__name__}\n")
                exit_code = 1
        # Normalize local paths before pinning the new record, never old records.
        text = path.read_text().replace(str(ROOT), "$WORKSPACE")
        for variable, marker in (("CARGO_TARGET_DIR", "$TARGET"), ("CARGO_HOME", "$CARGO_HOME")):
            if os.environ.get(variable):
                text = text.replace(os.environ[variable], marker)
        path.write_text(
            "\n".join(line.rstrip() for line in text.rstrip().splitlines())
            + ("\n" if text.strip() else "")
        )
        summary["commands"].append(
            {
                "name": name,
                "argv": command,
                "exit_code": exit_code,
                "elapsed_seconds": time.monotonic() - start,
                "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
        if exit_code:
            summary["status"] = "failed_software_checks"
            break
    else:
        text = (output / "required-runtime.log").read_text()
        populations = re.findall(
            r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", text
        )
        counts = tuple(sum(int(values[n]) for values in populations) for n in range(3))
        if not populations or counts[1:] != (0, 0) or re.search(r"\bSKIP\b", text):
            summary["status"] = "failed_required_population"
        else:
            summary["rust_tests"] = {
                "passed": counts[0],
                "failed": counts[1],
                "ignored": counts[2],
                "binaries": len(populations),
            }
            summary["postgres"] = json.loads(text[text.rfind("\n{") + 1 :])
            summary["status"] = "passed_software_checks"
    if before != source_hashes():
        summary["status"] = "failed_source_changed_during_run"
    summary["tools"] = {"python": sys.version}
    for name, command in (
        ("rust", ["rustc", "--version"]),
        ("node", ["node", "--version"]),
        ("postgres", [str(bindir / "postgres"), "--version"]),
    ):
        summary["tools"][name] = subprocess.check_output(command, text=True).strip()
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(summary["status"], flush=True)
    return 0 if summary["status"] == "passed_software_checks" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.bindir.resolve(), args.output.resolve()))
