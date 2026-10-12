# M3b operation status and client fault verification — 11 October 2026

This increment follows M3a commit `cc6d7b7` and implements the bounded
[RFC 0009](../../../docs/rfcs/0009-operation-status.md) signed-proposal lookup.
Full M3 deployment qualification and RFC owner acceptance remain open.
[summary.json](summary.json) binds tested source and logs by SHA-256.

| Check | Result |
| --- | --- |
| Locked Rust workspace, all targets | **105 passed**, zero failed/ignored/skipped |
| Required infrastructure | Three real etcd 3.6.5 members; pinned official MCP client 2.3.0 |
| New acceptance cases | One native status authorization/correlation case; three official-client fault cases |
| Live client processes | Ten: five first runs and five separate resumed processes |
| Client negative vectors | Closed status replies, substituted correlation and invalid/null/array digest/attempt fields refuse |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Frozen white paper | 58 file hashes and 24 contract pins unchanged |
| Frozen schema and signed fixtures | 13 envelopes and declared bindings pass |

Logs: [workspace and public wire summaries](rust-tests.log),
[Node vectors](node-vectors.log), [clippy](clippy.log),
[white paper](whitepaper.log), [schema](schema.log).
Trailing whitespace and final blank lines are normalized for repository review.

## Established behavior

The native status service authenticates current mTLS workload, pinned JWT/DPoP,
allowed subject and distinct disclosure scope. It verifies the exact signed
proposal, derives the authority key within its configured tenant/namespace, and
correlates retained issuance, admission and execution records. It performs no
writes, issuance, exchange, dispatch or target query. Status has a bounded deadline
and uses the existing connection/owned-operation limits.

The native test distinguishes absent issuance, unclaimed grants and the original
claimed attempt, including after service recreation. Missing disclosure scope,
wrong token subject, wrong proof URL, substituted signed proposal tenant,
subject, workload, PoP, descriptor or parameters, unknown fields/profile and
unexpected grant headers refuse. Malformed issuance and untrusted retained grant
signatures return authority_unavailable. The resource fence counter stays at one.

Three new official-client cases use live evidence/admission/issuance services:

- A committed issuer reply is consumed and discarded before the adapter can
  save a grant. Proposal-addressed status resolves `unclaimed`.
- The grant-store write throws after successful issuance. The durable proposal
  remains queryable; status resolves `unclaimed` and dispatch never starts.
- A signed evidence-provider reply is consumed and discarded. The saved proposal
  resolves `unissued`; admission/issuance never start and evidence is not recollected.

All three have zero credential exchanges, dispatches and mock effects. The
provider baseline and collection happen once. Subsequent execute/status calls
are query-only. For each, a separate Node process loads the store after the
original execution delegation has expired and the domain has been revoked. A
renewed status-only token resolves the same state/digest. The earlier normal and
lost-execution-response cases still produce one effect and resolve their original
committed attempt after expiry/revocation. Every wire request has a fresh proof
JTI, and query requests carry no grant execution header.

`unissued` is a snapshot of no issuance record in the live namespace. It does
not cancel an in-flight issuer, establish no target effect under a stale restored
namespace, or authorize a retry. A saved operation never silently acquires new
authority or dispatches again.

## Reproduction and limits

The full run used Rust 1.98.0 / macOS ARM64, Node 25.2.1 and etcd 3.6.5. Rust
1.88 and Node 20 minimum-version execution remain unqualified. Use the same
pinned toolchain/dependencies and etcd binary, then:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5/etcd \
  scripts/start-etcd.sh -- cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
python scripts/verify-whitepaper.py
python spec/validate.py
```

The etcd cluster uses three members on one host and loopback. Evidence, credential
exchange, target guard/effect and identity enrollment remain explicit software
fixtures with a trusted fixed test clock. Failed-write injection and ordinary
client restart do not qualify a hard crash, power loss, stale backup, authority
restore or automated crash-owner lock recovery. Generic ID lookup, key/PoP/CTD
history, enterprise identity/RBAC/shared proof replay, real providers and complete
target writer coverage remain open. Historical state does not reconstruct signed
outcome evidence; M4 supplies that contract and recovery worker next.
