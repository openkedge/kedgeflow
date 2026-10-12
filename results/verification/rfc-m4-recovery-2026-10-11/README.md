# M4a query-only recovery and outcome verification — 11 October 2026

This increment follows `c312711` and implements the bounded
[RFC 0010](../../../docs/rfcs/0010-outcome-recovery.md). M4b, full M4 acceptance
and enterprise deployment qualification remain open.
[summary.json](summary.json) binds tested source and logs by SHA-256.

| Check | Result |
| --- | --- |
| Locked Rust workspace, all targets | **113 passed**, zero failed/ignored/skipped |
| Required infrastructure | Three real etcd 3.6.5 members; pinned official MCP client 2.3.0 |
| New recovery acceptance cases | Eight; real-etcd transactions, native TLS and separate worker/verifier processes |
| Concurrent workers | Sixteen; one retained pre-dispatch receipt and zero target queries |
| Dispatch/seal race | Twelve independent attempts; a winning dispatch cannot receive an undispatched seal |
| Killed worker | Actual `kf-recover` process killed during native mTLS query; restart records one receipt without redispatch |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Frozen white paper | 58 file hashes and 24 contract pins unchanged |
| Frozen schema and signed fixtures | 13 envelopes and declared bindings pass |

Logs: [workspace and native recovery summaries](rust-tests.log),
[Node vectors](node-vectors.log), [clippy](clippy.log),
[white paper](whitepaper.log), [schema](schema.log).
Trailing whitespace and final blank lines are normalized for repository review.

## Established behavior

The gateway atomically records the exact signed grant, tool and parameters with
the consumed claim, attempt and recovery index. Claim, dispatch authorization
and terminal changes retain journal entries in the same authority transaction.
Successful terminal adapter replies are retained before the gateway returns.

Recorded attempts are discovered through bounded index pages. The worker
authenticates retained grants independently, defers active dispatch budgets and
uses an exact snapshot comparison to seal only pre-dispatch work. A winning seal
blocks a delayed dispatch. Root/nonce consumption and refusal of replacement
persist after every outcome, including not_dispatched.

After possible sends, pending, missing, no-effect labels, wrong-attempt commit
observations and query errors remain consumed unknown. Distinct observations
produce a six-receipt predecessor chain in the acceptance case. A correlated
commit becomes terminal; subsequent worker instances reuse the retained receipt
without querying. An explicit reconciliation handoff preserves its commit
observation and the earlier pending evidence in a verifiable two-receipt chain.
Late gateway completion cannot overwrite the recovered terminal state.

The native process case uses verified mTLS workload identity and separate fixture
etcd/query credentials. The etcd HTTPS proxy forwards to the actual three-member
cluster. `--check` performs zero queries. A worker is killed while its query is
blocked; no receipt is recorded and dispatch authorization remains. A separate
process queries successfully and records a committed receipt. Another process
reuses it without another query. Two queries occurred: the killed query and the
successful query. The target is a software status service representing an earlier
commit; this case does not exercise an actual target mutation or target crash.

Tampered execution context refuses before query/receipt. Substituted parameters
refuse before claim. The independent offline CLI verifies trusted issuer and
OutcomeService keys, exact lineage bindings, predecessor order and canonical
evidence digests. Removed/reordered predecessors, missing evidence, altered
parameters, wrong source and overlapping signer roles refuse.

The offline result explicitly lists missing signed proposal, manifest/witness,
admission certificate, installed control/key history, independently authenticated
authority journal and target-signed proof. Receipt signatures attest an
OutcomeService report; they do not authenticate a physical target effect.
The frozen effect_digest binding remains the grant's parameters_digest; actual
observations are referenced separately in resolution_evidence.

## Reproduction and limits

The run used Rust 1.98.0 / macOS ARM64, Node 25.2.1 and etcd 3.6.5. Rust 1.88
and Node 20 minimum-version execution remain unqualified. Use the same pinned
toolchain/dependencies and etcd binary, then:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5/etcd \
  scripts/start-etcd.sh -- cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
python scripts/verify-whitepaper.py
python spec/validate.py
```

The etcd cluster uses three members on one host and loopback. The authority
transitions are actual etcd transactions; enrollment, keys, role-token proxy,
query status, providers, broker and target guards remain software fixtures.
Grant timestamps and trusted test clocks simulate retained historical attempts;
the recovery fixtures use the privileged library issuance path. Existing native
live-agent integration remains covered by the required workspace run.

Only the recovery process is hard-killed here. Gateway/target crash points,
power loss, ambiguous receipt persistence and stale-backup restore fencing remain
M4b. External report/ack, complete admission-lineage verification, key rollover,
incident ownership/deadlines and larger retention remain open. No production etcd
RBAC, target writer coverage, no-effect barrier, compensation, automatic retry,
refund, pruning or restore qualification is established. Legacy claims without
recorded execution context are excluded from discovery.
