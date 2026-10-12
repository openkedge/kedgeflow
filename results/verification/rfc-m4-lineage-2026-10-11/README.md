# M4b2 retained signed admission lineage verification — 11 October 2026

Based on `e4a79a0a6abd2758ab1c3aedd0e6ade65267d4d5` plus the working-tree
source hashes in [summary.json](summary.json). This is bounded implementation
qualification of [RFC 0012](../../../docs/rfcs/0012-admission-lineage.md), with
[operator instructions](../../../docs/ADMISSION_LINEAGE.md). It does not close
M4 deployment, historical installation/key custody or target-proof gates.

| Check | Result |
| --- | --- |
| Required workspace/native suite | 125 passed; zero failed, ignored or skipped; etcd and SDK required |
| New acceptance cases | Seven; actual retained admission/issuance and etcd recovery/export, separate offline CLI |
| Historical inspection | Expired grant and changed current policy export/verify under independently pinned historical trust |
| Outcome chain | Unknown prefix and later unknown → committed chain verify; original attempt preserved |
| Authority conservation | Consumed nonce, replacement and further dispatch remain refused |
| Historical semantic checks | Signed-time freshness, approved certificate TTL, pinned Cedar evaluation and issuer constraints/discharges |
| Re-signed negative records | Tenant/subject/workload/delegation/scope, certificate/grant time, parameter constraints and provider result refuse |
| Evidence and policy evaluation | Repaired manifest references reach predicate rejection; repaired policy pin reaches Cedar denial |
| Closed carriage/bounds | Unknown nested fields, duplicate JSON fields, role overlap, malformed/missing journal and multibyte byte limit refuse |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Frozen white paper | 58 files and 24 contract pins unchanged |
| Frozen schema / signed fixtures | 13 envelopes and all declared bindings pass |

Logs: [Rust/native tests](rust-tests.log), [clippy](clippy.log),
[formatting](format.log), [Node vectors](node-vectors.log),
[white paper](whitepaper.log), [schema](schema.log). Trailing whitespace and final
blank lines are normalized for repository review. Prior evidence is unchanged.

The new acceptance fixture uses the actual AdmissionController to sign/retain a
certificate, then the actual GrantAuthority to allocate/sign/retain its grant.
Recorded claim and optional dispatch are persisted in actual etcd. The existing
query-only recovery worker signs not_dispatched or unknown/committed outcomes.
A privileged export reads correlated retained admission/issuance and outcome
records. The actual `kf-verify-lineage` process verifies the expired bundle under
separate public registration without network access or signing material.

Unsigned admission/issuance metadata must match recomputed operation key,
admission/issuance bindings, digests and signed times. The issued canonical grant
and execution parameters must match the outcome bundle. Missing/swapped proposal,
CTD, manifest, witness, certificate, grant, metadata or evidence refuse. Missing
and reversed predecessor receipts refuse. Malformed, duplicate or substituted
journal correlation and missing dispatch authorization refuse.

The signed proposal/CTD tenant is transitively established under pinned trust;
frozen grants still have no tenant field. This does not broaden RFC 0011's dedicated
operator namespace or collector tenant label. Exports are receipt-chain prefixes,
not independently authenticated latest-head snapshots. Original runtime OAuth/
DPoP/mTLS transcript, installed control/revocation/key history, authenticated
journal/fence allocation, tool-name mapping, target-signed proof and complete
writer coverage remain explicit gaps in every successful verifier result.

## Reproduction and remaining gates

Run with Rust 1.98.0, Node 25.2.1 and etcd 3.6.5 on macOS ARM64:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5/etcd \
  scripts/start-etcd.sh -- cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
python scripts/verify-whitepaper.py
python spec/validate.py
```

The etcd topology is three members on one host/loopback. The new fixtures use
software keys, declared identity, approved registration and target observations;
they do not reproduce the original token/TLS/DPoP transcript. The required full
suite continues to test native authenticated admission/issuance, governance,
official agent workflows and retained collector delivery. Rust 1.88 and Node 20
minimum-version execution, multi-host failures, production RBAC/enrollment,
independent protocol peers, real target writer coverage and enterprise custody
remain unqualified. Earlier test-fixture corrections preceded the recorded final
passing run. No frozen contracts or previous verification results were edited.

Next M4b3 adds authenticated installation/key/revocation history. Broader automatic
delivery/incident deadlines, gateway/target kill cases and stale-backup restore
fencing remain open. Historical verification never supplies execution authority.
