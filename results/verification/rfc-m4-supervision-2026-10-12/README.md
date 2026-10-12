# M4c3 owned incidents and automatic delivery — 12 October 2026

Based on `0fdfccb` plus the 144 final source hashes in
[summary.json](summary.json). [RFC 0017](../../../docs/rfcs/0017-outcome-supervision.md)
and the [operator guide](../../../docs/OUTCOME_SUPERVISION.md) define the bounded
draft. Earlier evidence and frozen wire records are unchanged.

| Check | Result |
| --- | --- |
| Required Rust workspace/native suite | 173 passed across 31 binaries; zero failures, ignored cases or skips |
| New supervision tests | 15 native etcd/collector/worker cases |
| Shipping supervisor | Actual SIGKILL after accepted report, exact-ack restart, and continuous later-commit polling |
| Clippy / formatting / whitespace | Pass; warnings denied |
| Node vectors | Pass |
| Frozen white paper | 58 files and 24 pins unchanged |
| Frozen signed fixtures | 13 envelopes and declared bindings pass |

Tests retain the original unknown journal time, fixed owner and deadline through
recreated/concurrent workers. Changed owner/duration and regressed time refuse.
Commit resolves the incident without refunding consumption. A paused escalation
CAS loses against a retained commit and cannot overwrite it. More than 64 receipt
records refuse full delivery export while the verified current head still permits
the original deadline to escalate.

Ordered receipt budgets preserve predecessor acceptance. Collector outage,
acceptance with lost/invalid replies, failed local progress persistence and
supervisor termination resume through exact authenticated lookup. Corrupt local
progress never skips signature verification. Actual worker signing material and
registered domain are checked before work. A quarantined restore marker refuses
before query or report network access.

The full named results are in [rust-tests.log](rust-tests.log). Each harness uses
a unique namespace in three real same-host etcd members, software mTLS identities,
a native collector and correlated software target queries. Middleware faults occur
at declared acceptance/CAS boundaries. No real enterprise target, physical failure,
external page/ticket, human acknowledgement, production custody or independent
protocol peer is claimed. Restore-marker refusal is tested separately from a
complete managed witness deployment.

Incidents are unsigned protected operator records. Delivery progress records
verified collector acceptance; it does not prove target commit or independent
custody. Full export is bounded to 64 receipts/16 MiB; pagination, hard scheduling
SLOs, token/SVID rotation, ownership transfer and production routing remain open.

## Reproduction

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
PYTHONPATH=src python scripts/verify-whitepaper.py
PYTHONPATH=src python spec/validate.py
```

Executed on Darwin ARM64, Rust 1.98.0, Node 25.2.1 and etcd 3.6.5.
Archive/tool pins and scope are retained in the summary. Declared minimum Rust
1.88 and Node 20 runtimes remain execution-unqualified.
