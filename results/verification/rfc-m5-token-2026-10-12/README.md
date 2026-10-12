# M5c2 native broker/reference credential — 12 October 2026

Bounded [RFC 0021](../../../docs/rfcs/0021-broker-token-http.md) verification,
based on `32fd291` plus tested working-tree broker sources. The
[guide](../../../docs/BROKER_TOKEN_SERVICE.md) defines integration and limits.
[Summary](summary.json) pins tested sources and tooling. Unrelated concurrently
staged short-paper script changes are excluded from this milestone and its commit.

## Reproduction

Darwin ARM64; Rust 1.98.0; Node 25.2.1; etcd 3.6.5, three same-host loopback
members. Rust 1.88 / Node 20 execution remains unqualified. Existing restore tests
spawn separate one-member witnesses on the same host; physical failure-domain
independence remains unqualified. The summary retains the etcd archive digest.

```sh
PATH=/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH
CARGO_HOME=/private/tmp/kedgeflow-cargo
CARGO_TARGET_DIR=/private/tmp/kedgeflow-paper-target
ETCD_BINARY=/private/tmp/kedgeflow-etcd-3.6.5/etcd
export PATH CARGO_HOME CARGO_TARGET_DIR ETCD_BINARY
KF_REQUIRE_SDK=1 scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture --test-threads=1
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
PYTHONPATH=src:/private/tmp/kedgeflow-review-20261010-deps \
  .venv/bin/python scripts/verify-whitepaper.py
PYTHONPATH=src:/private/tmp/kedgeflow-review-20261010-deps \
  .venv/bin/python spec/validate.py
git diff --check
```

## Evidence

The 13 new broker cases use real verified mTLS and generated subject/JWT-SVID and
target keys, native etcd and the shipped token-exchange client. They verify closed
form/malformed encoding refusals, exact gateway/target/grant/attempt/role, unclaimed
refusal, concurrent one mint, service recreation, failed/broader/expired/invalid
mint, mint timeout and dropped client response. Independent target verification
checks actual signed claims and expiry. The actual shipping `kf-broker` binary
performs material-only checks without network authority and refuses another
exchange after forced termination/restart of a successful mint.

A shared software identity fixture retains the previous 13 RFC 0020 cases.
The native binary test caught conflated subject-token and execution-grant audiences;
configuration now supplies independent `delegation_audience`/`gateway_audience`
pins. A prior full run timed out at the existing `BeforeReceipt` crash barrier.
Its worker output had been discarded. That fixture now captures stdout/stderr and
reports early child exit; the barrier and five-second deadline are unchanged.
A further parallel run failed because a restore witness could not allocate its
WAL (`no space left on device`). The final run serializes test cases to limit
fixture storage, while each explicit concurrency race remains concurrent.
The final full run is retained without suppressing failures. A pass does not
establish the cause of the earlier intermittent barrier timeout or production
process-startup reliability.

One initial native launch encountered an automatic permission-review timeout;
the permitted retry started successfully. Project-owned temporary Cargo outputs
were cleared before the full build to avoid the host's limited disk capacity.
Logs remove ANSI sequences and normalize workspace/temp paths. No dependencies
or frozen wire records changed.

## Remaining gates

The minter/token verifier are a named reference profile, not an approved third-party
AS/introspection contract or real target effect. Managed checks are required by
default; native exchange/restart tests explicitly use unmanaged loopback fixtures.
Actual TLS/RBAC/managed-control/witness composition, approved AS/SVID issuance and
revocation, authenticated refresh, independent epoch/signing-key custody,
bypass/isolation, real SQL target enforcement/deduplication/query, owner acceptance
and M7–M9 hardware/delegation/independent interoperability remain open. Native
snapshot refresh is not automatic. Lost/failed mint authority stays consumed;
there is no credential renewal, lookup/redelivery, refund or replacement path.
