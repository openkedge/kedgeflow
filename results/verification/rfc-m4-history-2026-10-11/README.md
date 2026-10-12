# M4b3 governance history verification — 11 October 2026

Based on `b1caeea34173cf9a31f4537dc9671a17cfe04349` plus working-tree source
hashes in [summary.json](summary.json). This qualifies the bounded software
increment in [RFC 0013](../../../docs/rfcs/0013-control-history.md); see
[operator instructions](../../../docs/CONTROL_HISTORY.md). Operation-bound
control/revocation CAS evidence and M4/M5 deployment gates remain open.

| Check | Result |
| --- | --- |
| Required workspace/native suite | 132 passed; zero failed, ignored or skipped; actual etcd and official SDK required |
| New history cases | Seven; native authenticated governance, actual etcd retention/export, separate offline CLI |
| Atomic retention/retry | Four initial events; exact current-record retries and failed installation changes preserve the head |
| Renewal/recreation | Prior acknowledgement retained after refresh; recreated native governance service appends another acknowledgement |
| Historical membership | Approved issuer key change 5 → 16 and policy epoch 7 → 8, second installation; old operation verifies under old keys; unapproved new snapshot refuses |
| Revocations | Grant/root/domain records retained once each; original nonce/attempt retained and claim/dispatch refused |
| Checkpoint | Separate observer key 17 binds namespace, tenant/domain, head/count/capture time and exact lineage digest |
| Negative records | Missing/reordered history, altered checkpoint/digest/time/namespace/lineage/signer; re-signed bad revision/membership/coverage/time/definition and repaired checkpoint refuse |
| Bounds/compatibility | Unknown carriage, duplicate JSON, role confusion, byte/aggregate limits, oversized export head, legacy genesis and corrupt prior head refuse |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Frozen white paper | 58 file hashes and 24 contract pins unchanged |
| Frozen schema / signed fixtures | 13 envelopes and declared bindings pass |

Logs: [Rust/native tests](rust-tests.log), [clippy](clippy.log),
[formatting](format.log), [Node vectors](node-vectors.log),
[white paper](whitepaper.log), [schema](schema.log). Trailing whitespace and final
blank lines are normalized for repository review. Prior evidence is unchanged.

## Established behavior

Every successful native governance mutation writes an immutable sequenced event
and updated history head in the same transaction as its live state change. Existing
publication/installation/ack/revocation comparisons remain. History appends compare
the previous head and exact prior head event and require a new event key. Exact
current-record retries write nothing. A failed installation/clock/conflicting
change leaves the head unchanged; a corrupt head event prevents a new mutation.
Old managed pointers without history genesis cannot synthesize a complete prefix.
An oversized retained head refuses export rather than silently truncating history.

New fixtures bootstrap through native TLS/JWT/DPoP policy/descriptor publication,
installation and workload-authenticated acknowledgement. They use actual library
AdmissionController/GrantAuthority issuance and recorded etcd claim/recovery. The
query-only worker seals undispatched work without a target query. An independently
registered software observer signs the protected export. The actual
`kf-verify-history` process verifies it after grant expiry with separate public
historical registration and no network/signing material.

The issuer-change case creates a new native governance service with an independently
approved epoch-eight/key-sixteen registration, publishes and installs revision two,
and accepts its gateway configuration acknowledgement. Both snapshots are approved
separately by the offline operator. The old operation remains bound to revision-one
key-five membership; removing approval for the new snapshot refuses the complete
history. A second recreated native governance service accepts a later renewal,
preserving both older acknowledgements. These are service recreations on new test
endpoints and gateway configuration assertions, not gateway process kills, automatic
trust discovery or production key rollover.

All three revocation targets are retained once. Reapplying exact records leaves the
head unchanged. Their recorded times are reported relative to issuance, with no
non-revocation assertion. The consumed nonce still points to the original terminal
attempt; claim and dispatch remain refused. A valid older checkpoint stays verifiable
as a prefix and cannot establish the latest head or exclude later revocation.

An observer signature authenticates the retained observation, not etcd consensus,
correct service operation, a distributed clock or an operation's control CAS.
Accepted time is a clock sample before the successful mutation, not its consensus
commit timestamp. Remaining gaps are original authentication transcript, operation-
bound control/revocation sequence and clock trust, authenticated claim/dispatch/fence
allocation, tool-name mapping and target-signed proof with complete writer coverage.
Every successful verification reports operation control state as not attested.

## Reproduction and remaining gates

Rust 1.98.0 / macOS ARM64, Node 25.2.1, etcd 3.6.5:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5/etcd \
  scripts/start-etcd.sh -- cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
python scripts/verify-whitepaper.py
python spec/validate.py
```

The three etcd members run on one host/loopback. Keys, enrollment, access-token
issuance, declared operation identity, observer custody, gateway configuration
assertions and outcome state remain software fixtures. Existing required native
admission/agent/governance/collector workflows continue to pass. Rust 1.88 and Node
20 minimum execution, multi-host failure, production RBAC, observer custody and
clock trust remain unqualified. Initial fixture corrections and strict lint repair
preceded the recorded passing final run. Frozen contracts and prior evidence were
not modified.

Next M4b4 retains actual operation-to-control comparisons. History pagination,
legacy migration, observer deployment/custody, automatic incidents/delivery,
hard-crash/restore fencing, real target coverage and independent protocol peers
remain open. History verification supplies evidence only, never execution authority.
