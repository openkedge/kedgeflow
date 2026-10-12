#!/usr/bin/env python3
"""Run pinned Rust runtime with required real etcd and SDK; retain evidence."""

import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "artifact/runtime"
RESULTS = ROOT / "results/final"
RESULTS.mkdir(parents=True, exist_ok=True)
for name in ["paper_safety.rs", "paper_adversarial.rs"]:
    shutil.copy2(ROOT / "tests" / name, RUNTIME / "crates/kedgeflow/tests" / name)
env = os.environ.copy()
cargo = shutil.which("cargo")
if not cargo:
    candidate = Path.home() / ".rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo"
    if candidate.exists():
        cargo = str(candidate)
        env["PATH"] = str(candidate.parent) + os.pathsep + env["PATH"]
if not cargo:
    raise SystemExit("cargo is required")
if not (RUNTIME / "tests/sdk/node_modules/@modelcontextprotocol/client/package.json").exists():
    subprocess.run(
        [
            "npm",
            "ci",
            "--prefix",
            str(RUNTIME / "tests/sdk"),
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
        env=env,
        check=True,
    )
etcd = ROOT / "artifact/etcd"
if not etcd.exists():
    subprocess.run(
        ["go", "build", "-o", str(etcd), "./etcd.go"], cwd=ROOT / "tests", env=env, check=True
    )
with tempfile.TemporaryDirectory(prefix="kf-paper-") as tmp:
    endpoint_file = Path(tmp) / "endpoints.json"
    with (RESULTS / "etcd.log").open("w") as cluster_log:
        cluster = subprocess.Popen(
            [str(etcd), str(endpoint_file)], stdout=cluster_log, stderr=subprocess.STDOUT, env=env
        )
        try:
            deadline = time.monotonic() + 35
            while not endpoint_file.exists():
                if cluster.poll() is not None:
                    raise RuntimeError("etcd startup failed; see results/final/etcd.log")
                if time.monotonic() > deadline:
                    raise RuntimeError("etcd readiness timeout")
                time.sleep(0.1)
            endpoints = json.loads(endpoint_file.read_text())
            env.update(
                ETCD_ENDPOINT=endpoints[0],
                ETCD_ENDPOINTS=",".join(endpoints),
                KF_REQUIRE_ETCD="1",
                KF_REQUIRE_SDK="1",
            )
            command = [
                cargo,
                "test",
                "--offline",
                "--locked",
                "--workspace",
                "--all-targets",
                "--",
                "--nocapture",
            ]
            started = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with (RESULTS / "rust-tests.log").open("w") as log:
                result = subprocess.run(
                    command, cwd=RUNTIME, env=env, stdout=log, stderr=subprocess.STDOUT
                )
            raw = (RESULTS / "rust-tests.log").read_text()
            rows = [
                json.loads(line.split("PAPER_RESULT ", 1)[1])
                for line in raw.splitlines()
                if "PAPER_RESULT " in line
            ]
            totals = [
                tuple(map(int, m))
                for m in re.findall(
                    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", raw
                )
            ]
            summary = {
                "started_utc": started,
                "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source_commit": json.loads((ROOT / "artifact/source-manifest.json").read_text())[
                    "source_commit"
                ],
                "environment": {
                    "os": platform.platform(),
                    "machine": platform.machine(),
                    "logical_cpus": os.cpu_count(),
                    "rust": subprocess.check_output(
                        [str(Path(cargo).with_name("rustc")), "--version"], text=True
                    ).strip(),
                    "node": subprocess.check_output(
                        ["node", "--version"], env=env, text=True
                    ).strip(),
                    "etcd": "3.6.5",
                    "members": 3,
                    "topology": "single-host-loopback",
                },
                "command": command,
                "required_etcd": True,
                "required_sdk": True,
                "returncode": result.returncode,
                "passed": sum(t[0] for t in totals),
                "failed": sum(t[1] for t in totals),
                "ignored": sum(t[2] for t in totals),
                "skipped": bool(re.search(r"\bSKIP\b", raw)),
                "experiments": rows,
                "adversarial_experiments": [
                    json.loads(line.split("ADVERSARIAL_RESULT ", 1)[1])
                    for line in raw.splitlines()
                    if "ADVERSARIAL_RESULT " in line
                ],
                "adversarial_tests_sha256": hashlib.sha256(
                    (ROOT / "tests/paper_adversarial.rs").read_bytes()
                ).hexdigest(),
                "paper_tests_sha256": hashlib.sha256(
                    (ROOT / "tests/paper_safety.rs").read_bytes()
                ).hexdigest(),
                "raw_log_sha256": hashlib.sha256(
                    (RESULTS / "rust-tests.log").read_bytes()
                ).hexdigest(),
            }
            (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(
                json.dumps(
                    {
                        k: summary[k]
                        for k in ["returncode", "passed", "failed", "ignored", "skipped"]
                    },
                    indent=2,
                )
            )
            if (
                result.returncode
                or summary["skipped"]
                or summary["passed"] != 58
                or summary["failed"]
                or summary["ignored"]
                or len(rows) != 10
                or len(summary["adversarial_experiments"]) != 12
            ):
                raise SystemExit("tests incomplete or failed")
        finally:
            cluster.terminate()
            try:
                cluster.wait(timeout=15)
            except subprocess.TimeoutExpired:
                cluster.kill()
                cluster.wait()
