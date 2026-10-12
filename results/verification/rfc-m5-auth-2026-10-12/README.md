# M5a shared authentication prerequisite — 12 October 2026

Based on `91442da` and 150 final source hashes in
[summary.json](summary.json). Implements the bounded internal contract in
[RFC 0018](../../../docs/rfcs/0018-shared-authentication.md); see the
[operator guide](../../../docs/SHARED_AUTHENTICATION.md).

| Check | Result |
| --- | --- |
| Required Rust workspace/native suite | 183 passed across 31 binaries; zero failures, ignored cases or skips |
| New authentication cases | Eight registration/store cases plus native admission and collector cases |
| Clippy / formatting / whitespace | Pass; warnings denied |
| Node vectors | Pass |
| Frozen white paper | 58 files and 24 pins unchanged |
| Frozen fixtures | 13 signed envelopes and declared bindings pass |

Two independently constructed authenticators race one proof against real etcd;
one accepts and a recreated verifier refuses replay. Wrong workload, subject,
scope and invalid signature refuse before shared state exists. Future-skew proof
retention covers the full window without capacity eviction. Clock regression and
registration drift leave state unchanged. Corrupt state, unreachable store and
restore-required marker refuse with no local acceptance. A fault proxy returns
an error after a successful consumption write; restart still refuses that proof.

The native collector uses verified software mTLS and shipping service routing;
after service recreation at the same URL it rejects the previously accepted proof,
while a fresh proof returns the same signed acknowledgement. Native admission
similarly rejects proof replay before its idempotent operation retry returns the
original certificate. Shipping gateway `--check` validates configured shared
material without contacting unreachable dependencies. Earlier SDK, managed
control, process-kill, restore and supervision cases remain required.

This is an optional reference-store prerequisite, not accepted enterprise identity
integration. Tokens/certificates and identities are generated software fixtures;
all etcd members remain same-host loopback. Real AS/SVID provisioning, rotation,
revocation, key custody, production RBAC/clock/egress, raw-writer exclusion,
combined managed witness deployment and independent custody are unqualified.
Registration migration and replay reset have no override contract. Shared state
assumes retained store survival unless the independent restore gate is deployed.
Single-record CAS rewriting has bounded capacity, with no measured throughput SLO.

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
Pins and test names are in the summary; normalized full output is in
[rust-tests.log](rust-tests.log). Minimum Rust 1.88 and Node 20 remain
execution-unqualified.
