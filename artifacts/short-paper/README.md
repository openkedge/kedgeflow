# KedgeFlow short-paper research artifact

This directory publishes the code and retained results for **KedgeFlow: A Programmable Control Plane for Enterprise AI Agents**. It contains the evaluated Rust snapshot, both added paper tests, synthetic fixtures, Cargo/npm/Go lockfiles, the three-member etcd launcher, reproduction scripts, raw logs, and machine-readable result manifests. It is a bounded research artifact, not a production deployment.

## Source and evidence

The runtime is pinned to upstream commit `21d5efe7f543e7396604ba246437b2c4b756b4ff` (crate `0.9.0-alpha.1`). `artifact/source-manifest.json` records SHA-256 hashes for all 77 original files. Those files are unchanged. `paper_safety.rs` and `paper_adversarial.rs` are added paper tests; identical copies live under `tests/` and the snapshot's Rust test directory.

The retained final run finished on 8 October 2026 at 23:06 UTC: 58 tests passed, none failed/ignored/skipped. The direct-ledger matrix contains 6,560 attempts, 82 claims across 82 roots, 6,478 refusals and no transport errors. One adversarial Rust test exercises 12 deterministic scenarios. Logs and summaries are under `results/final/`; the earlier 57-test run is under `results/baseline-20261008/`. Publishing this artifact does not rerun or extend the experiments.

Trust inputs and target credentials are synthetic. The experiments use three etcd members on one host and a fenced mock target. Prompt-injection redirection is assumed by scripted fixtures; this is not an LLM attack-success study. Physical exactly-once execution, production complete mediation, distributed reservations, native crash recovery and independent interoperability are untested.

## Verify retained files

From this directory:

```sh
python3 scripts/verify_artifact.py
```

This checks the immutable snapshot, the two added test copies, raw-log hashes, retained suite totals and scenario records. In a full Git clone it also compares the snapshot with the pinned upstream Git objects.

## Reproduce

Requirements: Rust >=1.88, Node >=20 and npm, Go compatible with `tests/go.mod`, and Python >=3.9. The test harness needs permission to bind loopback listeners; all accounts, credentials, requests and targets are synthetic.

```sh
cd artifact/runtime
cargo fetch --locked
npm ci --prefix tests/sdk --ignore-scripts --no-audit --no-fund
cd ../..
python3 scripts/run_tests.py
python3 scripts/record_results.py
```

The runner builds the pinned Go etcd launcher, starts three disposable loopback members, requires real etcd and the pinned SDK, executes Cargo offline with lockfiles, retains the new run under `results/final/`, and shuts down the cluster. Reproduction replaces local final logs; this Git commit retains the original published evidence. Node/Rust/Go dependencies are fetched by the explicit commands above or the initial launcher build.

The snapshot's Apache-2.0 license is retained in `LICENSE` and `artifact/runtime/LICENSE`.
