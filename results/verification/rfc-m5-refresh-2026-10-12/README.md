# M5c3 signed identity refresh — 12 October 2026

Bounded [RFC 0022](../../../docs/rfcs/0022-identity-refresh.md) verification on
Darwin ARM64, based on `3c428b9` and the tested working tree. The
[integration guide](../../../docs/IDENTITY_REFRESH.md) specifies source/custody
assumptions. [Summary](summary.json) pins tested sources and tooling. The three
unrelated staged short-paper script changes remain outside this milestone.

## Reproduction

Rust 1.98.0, Node 25.2.1, etcd 3.6.5 (three same-host loopback authority members).
Declared Rust 1.88 / Node 20 execution remains unqualified. Separate native witness
processes share the same host; independent physical failure domains are unqualified.

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

Test cases are serialized to fit native witness WAL allocation within host disk
capacity; explicit concurrency actors still race inside tests. Only this project's
temporary Cargo outputs were cleared before the full build. Dependency versions,
frozen records and previous evidence remain unchanged.

## Evidence

Eleven new generated-key/source tests cover exact signatures/digests/epoch and
independent authority/realm/role checks, renewal without cached trust, changed
heads during verification, remembered rollback even after missing higher
publication, same-epoch split heads, source loss/expiry, withdrawal/retirement,
concurrent replicas/restart with retained floor, and closed duplicate/oversized
records, including exact array-order binding before typed normalization. Two additional native broker cases use real mTLS and native etcd:
shipping live actor-key rotation without process restart, plus material-only
closed-mode/head/role/floor negatives with unreachable authority.

The live test retires the old actor key in a signed higher epoch, refuses its
assertion before permit/mint, refuses a restored old head, then redeems the
original consumed undispatched claim once with the new key for the same registered
workload. Independent reference target verification checks the returned token.
The same process remains alive throughout; subsequent exchange stays refused.

All existing native process crash/restore/recovery/supervisor and official SDK
cases remain part of the required-mode suite. Logs remove ANSI escapes and
normalize workspace/temp paths. Source pins exclude unrelated staged artifact
scripts; the commit includes only the milestone's files.

## Limits

The head/floor sources are ordinary protected-file fixtures, not deployed
rollback-resistant custody. File paths alone do not prove independence. Authority
keys and the startup floor are operator pins; the broker never signs publications
or advances its own head/floor. Higher observed heads are remembered in-process;
external retained head/floor are still required on restart. Changes after the
final head read cannot revoke previously returned identity/permit/target tokens.

Approved publisher administration, power-loss/atomic-storage guarantees, real
AS/SVID provisioning and revocation delivery, cross-replica delivery/clock budgets,
production RBAC/bypass and managed/witness composition, real SQL target effects and
M7–M9 enterprise acceptance remain open. Earlier M5c2 crash-barrier timeout cause
remains unqualified; this run is additional software verification, not production
startup reliability evidence.
