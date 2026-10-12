# M5c1 pinned exchange identity verification — 12 October 2026

Bounded [RFC 0020](../../../docs/rfcs/0020-pinned-exchange-identities.md)
verification on Darwin ARM64, based on `8e83aeb` plus the tested working tree.
[Summary and source hashes](summary.json) identify the exact tested sources.
The [integration guide](../../../docs/EXCHANGE_IDENTITIES.md) states the supported
subject/actor profile and trust-refresh boundary.

## Reproduction

Rust 1.98.0, Node 25.2.1, etcd 3.6.5; Rust 1.88 and Node 20 execution remains
unqualified. The authority uses three same-host native loopback etcd members.
Existing restore tests use distinct one-member native witness processes on the
same host; physical failure-domain separation is not established.

```sh
PATH=/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH
CARGO_HOME=/private/tmp/kedgeflow-cargo
CARGO_TARGET_DIR=/private/tmp/kedgeflow-paper-target
ETCD_BINARY=/private/tmp/kedgeflow-etcd-3.6.5/etcd
export PATH CARGO_HOME CARGO_TARGET_DIR ETCD_BINARY
KF_REQUIRE_SDK=1 scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
PYTHONPATH=src:/private/tmp/kedgeflow-review-20261010-deps \
  .venv/bin/python scripts/verify-whitepaper.py
PYTHONPATH=src:/private/tmp/kedgeflow-review-20261010-deps \
  .venv/bin/python spec/validate.py
git diff --check
```

Dependency versions remain locked. `ring` 0.17.14 was already present transitively
and is now an explicit pinned dependency for ES256 verification and software test
signatures. The etcd release archive digest is retained in the summary.

## Evidence and limits

The 13 new cases verify real Ed25519 subject and ES256 actor signatures, exact
admission delegation equality, closed JWT/config objects, wrong key/role/domain,
unsupported algorithms, single audience, validity/snapshot freshness, key overlap
then retirement, workload/token withdrawal, rollback floor, invalid update
preservation and concurrent same-epoch replacement. A real-etcd broker composition
refuses unclaimed/withdrawn identities, then authorizes one concurrent winner on
the original durable undispatched claim; repeat authorization stays refused and
original consumption remains held.

Full logs are retained with ANSI sequences removed and workspace/temp paths
normalized to `$WORKSPACE`/`$TMP`. An initial linker run exhausted host disk before
tests ran. Only this project's temporary Cargo outputs were cleared; the final
required-mode run was then executed afresh. No test failure was suppressed.

Generated software keys are not evidence of approved AS/SPIRE provisioning or
revocation delivery. Snapshot replacement is a trusted library API, not an
authenticated refresh service; stale restore protection requires an independently
retained epoch floor. Expired snapshots fail closed. Replacement affects later
verification and does not revoke existing permits or target credentials. No native
AS endpoint, actual target token mint, credential custody, production RBAC/bypass,
owner acceptance or independent interoperability is qualified. M5c and M6–M9
enterprise gates remain open. Frozen paper/record bytes are unchanged.
