#!/usr/bin/env python3
"""Run every required real-cluster case in its own owned Kubernetes fixture.

The caller supplies explicit private kubeconfig/context/tool paths and wraps this
driver in the required real PostgreSQL/etcd harness. No default context is used.
"""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(selected: str | None = None) -> int:
    env = dict(os.environ)
    kubectl = Path(env["KF_KUBE_TEST_KUBECTL"]).resolve()
    kubeconfig = Path(env["KF_KUBE_TEST_KUBECONFIG"]).resolve()
    context = env["KF_KUBE_TEST_CONTEXT"]
    base = Path(env["KF_KUBE_FIXTURE"]).resolve()
    fixture_info = json.loads((base / "fixture-public.json").read_text())
    cluster = fixture_info["cluster"]
    if not re.fullmatch(r"kf8-[a-z0-9-]+", cluster) or context != "kind-" + cluster:
        raise ValueError("explicit task-owned cluster/context required")
    common = ["--kubectl", str(kubectl), "--kubeconfig", str(kubeconfig), "--context", context]
    env["KF_KUBE_TEST_PYTHON"] = sys.executable
    listing = subprocess.run(
        ["cargo", "test", "--locked", "--offline", "-p", "kedgeflow", "--test", "governance",
         "kube_drain_real_", "--", "--list"],
        cwd=ROOT, env=env, text=True, capture_output=True, check=True,
    )
    cases = re.findall(r"^(\S+): test$", listing.stdout, re.MULTILINE)
    if selected is not None:
        cases = [case for case in cases if selected in case]
    if (
        not cases or len(cases) != len(set(cases))
        or any("kube_drain_real_" not in c for c in cases)
    ):
        raise ValueError("required Kubernetes case manifest is absent or ambiguous")
    # The bootstrap fixture was used for explicit RBAC qualification. Remove its
    # owned pods before introducing any other workload on the target node.
    present = subprocess.run(
        [str(kubectl), "--kubeconfig", str(kubeconfig), "--context", context,
         "--request-timeout=10s", "get", "namespace", fixture_info["namespace"],
         "--ignore-not-found", "-o", "json"],
        cwd=ROOT, text=True, capture_output=True, check=True,
    )
    if present.stdout.strip():
        subprocess.run([sys.executable, "scripts/kube-drain-owned.py", "cleanup",
                        "--fixture", str(base), *common], cwd=ROOT, check=True)
    public = Path(env["KF_CONFORMANCE_ARTIFACTS"]) / "kube-drain-fixtures"
    public.mkdir(parents=True, exist_ok=False)
    records = []
    with tempfile.TemporaryDirectory(prefix="kf-kube-cases-") as temporary:
        for case in cases:
            identity = hashlib.sha256(case.encode()).hexdigest()[:16]
            fixture = Path(temporary) / identity
            # Namespace identities are fresh on every complete attempt.
            namespace = "kf-drain-" + os.urandom(8).hex()
            subprocess.run(
                [sys.executable, "scripts/kube-drain-fixture.py", *common,
                 "--cluster", cluster, "--namespace", namespace, "--output", str(fixture)],
                cwd=ROOT, check=True,
            )
            case_out = public / identity
            case_out.mkdir()
            for name in ["contract.json", "fixture-public.json"]:
                (case_out / name).write_bytes((fixture / name).read_bytes())
            process = None
            try:
                subprocess.run(
                    [sys.executable, "scripts/kube-drain-rbac.py", str(fixture),
                     "--output", str(case_out / "rbac.json")], cwd=ROOT, check=True,
                )
                process = subprocess.Popen(
                    ["cargo", "test", "--locked", "--offline", "-p", "kedgeflow",
                     "--test", "governance", case, "--", "--exact", "--nocapture",
                     "--test-threads=1"],
                    cwd=ROOT, env={**env, "KF_KUBE_FIXTURE": str(fixture)}, start_new_session=True,
                )
                code = process.wait(timeout=300)
                records.append({
                    "case": case, "public_directory": identity, "exit_code": code,
                    "public_sha256": {
                        name: hashlib.sha256((case_out / name).read_bytes()).hexdigest()
                        for name in ["contract.json", "fixture-public.json", "rbac.json"]
                    },
                })
                if code:
                    return code
            finally:
                if process is not None:
                    # Includes shipping controller descendants if a test aborts.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                subprocess.run(
                    [sys.executable, "scripts/kube-drain-owned.py", "cleanup",
                     "--fixture", str(fixture), *common], cwd=ROOT, check=True,
                )
                (public / "index.json").write_text(json.dumps({
                    "profile": "KF-KUBE-DRAIN-QUALIFICATION-0.1-draft",
                    "required_cases": cases, "executed": records,
                    "focused_filter": selected,
                    "status": "passed" if len(records) == len(cases)
                    and all(r["exit_code"] == 0 for r in records) else "incomplete",
                }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--filter", help="focused diagnostics only; full conformance forbids filtering"
    )
    raise SystemExit(run(parser.parse_args().filter))
