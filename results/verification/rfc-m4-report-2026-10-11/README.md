# M4b1 retained outcome delivery verification — 11 October 2026

This increment follows `3548798` and implements bounded
[RFC 0011](../../../docs/rfcs/0011-outcome-report-http.md). Full M4 acceptance
and enterprise deployment qualification remain open.
[summary.json](summary.json) binds tested source and logs by SHA-256.

| Check | Result |
| --- | --- |
| Locked Rust workspace, all targets | **118 passed**, zero failed/ignored/skipped |
| Required infrastructure | Three real etcd 3.6.5 members; pinned official MCP client 2.3.0 |
| New acceptance cases | Five; native TLS/DPoP client/collector, actual-etcd writes and CLI material check |
| Concurrent duplicate submissions | Sixteen; one exact immutable signed acknowledgement |
| Lost reply and restart | Discarded committed acknowledgement reply; query/retry/recreated collector reuse original acknowledgement |
| Ordering | Terminal delivery refuses before its unknown predecessor; earlier receipt remains deliverable afterward |
| Authority conservation | Original committed attempt unchanged; consumed nonce and replacement remain refused |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Frozen white paper | 58 file hashes and 24 contract pins unchanged |
| Frozen schema and signed fixtures | 13 envelopes and declared bindings pass |

Logs: [workspace and native delivery summaries](rust-tests.log),
[Node vectors](node-vectors.log), [clippy](clippy.log),
[white paper](whitepaper.log), [schema](schema.log).
Trailing whitespace and final blank lines are normalized for repository review.

## Established behavior

A native TLS 1.3 listener accepts the exact configured endpoint and application/json
POST commands. Verified workload, pinned OAuth/DPoP, approved subject and distinct
report scope authenticate every report and query. The independent OutcomeService
receipt signature and retained issuer grant are verified without requiring current
execution validity. The registered source differs from the executing workload.

The collector compares immutable retained receipt/evidence, consumed root/grant/
nonce, exact execution context and recovery index. It writes an acknowledgement
only. A signature on an unretained receipt cannot establish durable delivery.
The acknowledgement binds exact collector identity/URL, operator namespace tenant,
grant/original attempt/receipt, evidence, source and predecessor. Signing domain
and key are distinct from frozen grant/receipt domains and roles.

The reporting client uses pinned native mTLS and a fresh confirmed DPoP proof for
each call. It verifies the collector acknowledgement signature and every expected
binding before returning success. Sixteen concurrent first reports return one
exact winning signed envelope. A collector with a recreated authentication/service
instance and a fresh client retrieves that same envelope, including original time.

The lost-reply fixture discards the first successful collector response after its
acknowledgement transaction and substitutes HTTP 503. The client reports ambiguity;
lookup and exact retry return the stored acknowledgement. This is committed-reply
loss injection, not a process kill or power-loss test. A missing lookup before
delivery writes nothing and remains a live snapshot, not cancellation authority.

The two-receipt case delivers retained unknown then committed outcomes. Delivering
the latter first returns predecessor_required. After both acknowledgements,
redelivering the older unknown receipt returns its original acknowledgement and
does not regress the committed attempt. Replay consumption and replacement refusal
persist throughout delivery and lookup.

Wrong workload, scope, subject and proof URL refuse; reusing a proof refuses.
Evidence substitution, receipt/source tampering and extra command fields refuse.
A correctly signed but unretained receipt refuses. Wrong collector key, re-signed
wrong receipt correlation and collector URL substitution fail ack verification.
The actual `kf-outcomes --check` process validates protected fixture material with
an unreachable remote endpoint; it performs no remote reads/writes. Unknown config
fields and overlapping issuer/outcome signing roles refuse.

## Reproduction and remaining gates

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

The etcd cluster has three members on one host and loopback. Native mTLS, actual
HTTP clients, cryptographic JWT/DPoP and real etcd transactions are exercised.
Enrollment, keys, query status and access-token issuance remain software fixtures;
trusted clocks simulate expired historical execution. Recovery fixtures use the
privileged library issuance path; existing full native admission/agent workflows
remain covered by the required workspace suite. Temporary package build artifacts
were cleaned after an initial disk-full build; the complete recorded rerun passed.

The frozen grant contains no tenant field. Tenant is a dedicated operator-selected
namespace/key-set assignment, not verified signed proposal tenancy. Mixed-tenant
namespaces are unsupported. M4b2 must add complete admission-lineage reconstruction.
The collector shares the authority ledger and accepts already-retained receipts
only. Separate evidence-store durability/restore, new target-signed report types,
automatic delivery scheduling, key history/rollover, incident ownership/deadlines,
gateway/target hard-crash and stale-backup fencing remain open. Production RBAC,
shared DPoP replay, identity custody and real target writer coverage require M5/M6.
