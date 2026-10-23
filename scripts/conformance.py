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
    "frozen HitlWitness carriage and "
    "approved membership lifecycle",
    "M8": "wider dynamic delegation deployment acceptance, "
    "independent A2A authority-peer acceptance, "
    "wider multi-contract crash/failure and owner-command deployment qualification, "
    "physical inverse SQL restore/cutover "
    "and wider crash acceptance, "
    "independent saga acceptance and wider Kubernetes drain process/failure/physical acceptance",
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


def rust_cases(text: str, listing: bool) -> list[tuple[str, str]]:
    """Keep target identity: different binaries can have identically named tests."""
    cases = []
    target = None
    for line in text.splitlines():
        header = re.match(r"\s*Running (.+?) \(", line)
        if header:
            target = header[1]
        case = re.match(r"(\S+): test$" if listing else r"test (\S+) \.\.\.", line)
        if case:
            if target is None:
                raise ValueError("Rust case without target identity")
            cases.append((target, case[1]))
    return cases


def rust_targets(text: str) -> list[str]:
    return re.findall(r"^\s*Running (.+?) \(", text, re.MULTILINE)


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
        ("node-lease-vectors", ["node", "tests/sdk/lease-vectors.mjs"]),
        ("node-family-saga-vectors", ["node", "tests/sdk/family-saga-vectors.mjs"]),
        (
            "rust-manifest",
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--",
                "--list",
            ],
        ),
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
                "--skip",
                "family_saga",
            ],
        ),
        (
            "required-family-saga",
            [
                sys.executable,
                "scripts/test-postgres.py",
                "--bindir",
                str(bindir),
                "--peer",
                "--command",
                "scripts/start-etcd.sh",
                "--",
                "cargo",
                "test",
                "--locked",
                "--offline",
                "-p",
                "kedgeflow",
                "--test",
                "governance",
                "family_saga",
                "--",
                "--nocapture",
                "--test-threads=1",
                "--skip",
                "kube_drain_real_",
            ],
        ),
    ]
    commands.extend([
        (
            "required-kube-rbac",
            [sys.executable, "scripts/kube-drain-rbac.py",
             os.environ.get("KF_KUBE_FIXTURE", "__missing_owned_kube_fixture__"),
             "--output", str(output / "kube-rbac.json")],
        ),
        (
            "required-kube-drain",
            [sys.executable, "scripts/test-postgres.py", "--bindir", str(bindir),
             "--peer", "--command", "scripts/start-etcd.sh", "--", "cargo", "test",
             "--locked", "--offline", "-p", "kedgeflow", "--test", "governance",
             "kube_drain_real_", "--", "--nocapture", "--test-threads=1"],
        ),
    ])
    for name, bundle, trust in (
        ("completed", "family-saga-two-sql/aggregate.json", "family-saga-two-sql/audit-trust.json"),
        (
            "unknown",
            "family-saga-two-sql/unknown-aggregate.json",
            "family-saga-two-sql/audit-trust.json",
        ),
        (
            "sdk",
            "family-saga-sdk-two-sql/aggregate.json",
            "family-saga-sdk-two-sql/audit-trust.json",
        ),
        (
            "failed",
            "family-saga-sql-failure/aggregate.json",
            "family-saga-sql-failure/audit-trust.json",
        ),
        ("drain", "kube-drain-completed/aggregate.json", "kube-drain-completed/audit-trust.json"),
        ("drain-no-effect", "kube-drain-no-effect/aggregate.json",
         "kube-drain-no-effect/audit-trust.json"),
    ):
        commands.append(
            (
                f"artifact-verify-{name}",
                [
                    "cargo",
                    "run",
                    "--locked",
                    "--offline",
                    "-p",
                    "kedgeflow",
                    "--bin",
                    "kf-family-saga",
                    "--",
                    "verify",
                    "--bundle",
                    str(output / "native-artifacts" / bundle),
                    "--trust",
                    str(output / "native-artifacts" / trust),
                ],
            )
        )
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
                    env={
                        **os.environ,
                        "KF_REQUIRE_SDK": "1",
                        "KF_CONFORMANCE_ARTIFACTS": str(output / "native-artifacts"),
                    },
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
        if name == "required-kube-rbac":
            fixture = Path(os.environ["KF_KUBE_FIXTURE"])
            for public in ["fixture-public.json", "contract.json"]:
                (output / ("kube-" + public)).write_bytes((fixture / public).read_bytes())
    else:
        primary = (output / "required-runtime.log").read_text()
        saga = (output / "required-family-saga.log").read_text()
        drain = (output / "required-kube-drain.log").read_text()
        text = primary + "\n" + saga + "\n" + drain
        listing = (output / "rust-manifest.log").read_text()
        manifest = rust_cases(listing, True)
        executed = rust_cases(primary, False) + rust_cases(saga, False) + rust_cases(drain, False)
        targets = rust_targets(listing)
        target_runs = rust_targets(primary) + rust_targets(saga) + rust_targets(drain)
        populations = re.findall(
            r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", text
        )
        counts = tuple(sum(int(values[n]) for values in populations) for n in range(3))
        if (
            not populations
            or counts[1:] != (0, 0)
            or re.search(r"\bSKIP\b", text)
            or not manifest
            or len(set(manifest)) != len(manifest)
            or len(set(executed)) != len(executed)
            or set(manifest) != set(executed)
            or counts[0] != len(manifest)
            or len(set(targets)) != len(targets)
            or set(targets) != set(target_runs)
            or len(populations) != len(target_runs)
        ):
            summary["status"] = "failed_required_population"
        else:
            summary["rust_tests"] = {
                "passed": counts[0],
                "failed": counts[1],
                "ignored": counts[2],
                "binaries": len(targets),
                "binary_executions": len(populations),
                "manifest_cases": len(manifest),
                "manifest_sha256": hashlib.sha256(
                    json.dumps(sorted(manifest), separators=(",", ":")).encode()
                ).hexdigest(),
            }
            summary["postgres"] = json.loads(primary[primary.rfind("\n{") + 1 :])
            summary["family_saga_postgres"] = json.loads(saga[saga.rfind("\n{") + 1 :])
            summary["kube_drain_postgres"] = json.loads(drain[drain.rfind("\n{") + 1 :])
            summary["status"] = "passed_software_checks"
            required_artifacts = [
                "family-saga-two-sql/aggregate.json",
                "family-saga-two-sql/audit-trust.json",
                "family-saga-two-sql/verification.json",
                "family-saga-two-sql/target-rows.json",
                "family-saga-two-sql/unknown-aggregate.json",
                "family-saga-two-sql/unknown-verification.json",
                "family-saga-sdk-two-sql/aggregate.json",
                "family-saga-sdk-two-sql/audit-trust.json",
                "family-saga-sdk-two-sql/verification.json",
                "family-saga-sdk-two-sql/wire.json",
                "family-saga-sdk-two-sql/target-rows.json",
                "family-saga-sql-failure/aggregate.json",
                "family-saga-sql-failure/audit-trust.json",
                "family-saga-sql-failure/verification.json",
                "family-saga-sql-failure/target-rows.json",
                "kube-drain-completed/aggregate.json",
                "kube-drain-completed/audit-trust.json",
                "kube-drain-completed/verification.json",
                "kube-drain-completed/controller-state.json",
                "kube-drain-no-effect/aggregate.json",
                "kube-drain-no-effect/audit-trust.json",
                "kube-drain-no-effect/verification.json",
            ]
            artifacts = output / "native-artifacts"
            summary["runtime_artifacts_sha256"] = {
                name: hashlib.sha256((artifacts / name).read_bytes()).hexdigest()
                for name in required_artifacts
                if (artifacts / name).is_file()
            }
            if len(summary["runtime_artifacts_sha256"]) != len(required_artifacts):
                summary["status"] = "failed_required_artifacts"
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
