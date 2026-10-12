# RFC 0016: Write-ahead restore quarantine

- Status: Draft
- Milestone: bounded M4c2
- Baseline: `a12cdab`; RFCs 0006, 0007, 0010 and 0015
- Owners/reviewers: unassigned; authority, resource, security and SRE owners
- Profile: `KF-RESTORE-GATE-0.1-draft` (separate internal storage contract)

## Contract and trust boundary

Every transaction in an enrolled authority namespace checks a local head against
an independently retained witness. A periodic checkpoint is insufficient: it can
miss consumption, issuance or fences written between capture and restore. The
witness therefore reserves each potentially mutating transaction BEFORE local
submission, with no lease expiry, timeout release or automatic reconciliation.

The witness is a separately administered etcd store accessed with pinned HTTPS,
software mTLS enrollment and a separate role token. Its retention, write access
and restore policy are trusted. It MUST survive every restore of the authority
namespace and MUST NOT be restored or recreated from local authority data. A
second prefix or URL alias in the same cluster does not satisfy independence.
The bounded implementation rejects identical origins; deployment approval must
establish distinct clusters, backup domains and credential administration.

All online writers MUST use the gate. Retire older binaries and bypass write
credentials before enrollment. Independently retained deployment configuration
pins the witness origin/prefix and enables `restore_gate` on every service.
Compatibility mode without this field is solely for legacy, unenrolled fixtures.
An enrolled marker blocks current unconfigured clients, but a backup from before
enrollment lacks that marker: its quarantine depends on the required external
configuration. A marker stored inside a backup cannot establish its own trust.

## Closed records and state machine

The [draft schema](../../spec/drafts/restore-gate-v0.1.schema.json) defines:

- `RestoreHead`: profile, local namespace, witness origin plus prefix, random
  enrollment ID, sequence in 0..2^53−1 and a domain-separated SHA-256 digest.
- `WitnessRecord`: exact head and state `ready` or `pending`.

Local key: `<authority-prefix>/restore-gate`. Independent key:
`<witness-prefix>/head`. Both use the existing restricted canonical JSON profile.
Records are bounded to 4096 bytes when read. These records are unsigned; their
trust comes from the authenticated stores and trusted writer implementation.
A digest chain is correlation, not signed evidence or proof of target effects.

For each transaction:

1. Read the local head and linearly read the witness. Require exact bindings,
   head equality and `ready`; absent, corrupt, foreign or pending state refuses.
2. For a potentially mutating transaction, CAS the witness from `ready(H)` to
   `pending(H+1)`. The new digest binds the prior head, original transaction and
   fresh random salt. At most one reservation wins. Contending writers refuse;
   there is no blind retry or implicit successful authority response.
3. Submit an OUTER local CAS on the exact old head. Its successful branch runs
   the original transaction as a nested transaction and stamps the new local
   head atomically. This guards BOTH original branches. A false application
   comparison still consumes a sequence, even if its failure branch only reads.
   A failed outer CAS runs neither application branch and leaves the witness
   pending. Read-only transactions compare the local head without reserving or
   advancing the witness.
4. After a validated local result, CAS the exact pending witness to `ready(H+1)`.
   Only then return the original nested result to the authority caller.

A loss after remote reservation, local commit or local response leaves pending
state and quarantines subsequent calls. A finalization that persisted despite a
lost reply can leave both stores equal and ready; ordinary restart then succeeds,
while retained operation/nonce rules resolve the ambiguous original call. No
transaction timestamp or restored clock is accepted as a freshness substitute.

## Enrollment, restoration and failure handling

`kf-restore --config FILE --enroll-empty` is a privileged bootstrap operation.
It first reserves an ABSENT witness, then atomically requires the entire local
prefix range to be empty and installs sequence zero, then finalizes the witness.
It never migrates existing authority or replaces an existing witness. A failed
bootstrap leaves a reservation pending; do not clear it automatically.
`--status` checks both authenticated stores and writes nothing; nonzero means
quarantine or an unavailable dependency, not authorization to override the gate.

While services are quiesced, a consistent backup containing the exact latest
ready head can resume with the SAME independently pinned enrollment/witness.
A stale snapshot must refuse even when it restores an unclaimed root, absent
nonce, earlier fence counter, older governance history or empty namespace.
Recovery and collector writes also refuse; stale outcomes are not newly attested.

This slice offers NO repair or re-enrollment of pending/stale authority. Preserve
both stores, original consumption and incidents. Resource and SRE owners must
establish target/writer quiescence, recover complete authoritative state and
approve a future repair protocol before resuming. Matching a restored local
record alone cannot resolve an ambiguous reservation. Existing target requests
and credentials are not canceled by the gate; target fencing remains required.

## Compatibility and implementation

Frozen grants, certificates, receipts, fixtures and public MCP operations are
unchanged. Optional closed `restore_gate` configuration is added to gateway,
leaf-control, recovery and collector configs; governance uses its nested control
config. Gateway acknowledgement reads also use the gate. All runtime ledger
transactions flow through `EtcdLedger::txn`; the privileged raw transport is
crate-private and is used only for gate/witness mechanics. Historical offline
verification remains independent of live store freshness.

Library entry points are `RestoreGate::new`, `enroll_empty`, `check` and
`EtcdLedger::with_restore_gate`. The operator CLI has no agent-callable route.
The current unconfigured ledger additionally compares marker absence on writes
and refuses mutating failure branches. Services must not infer live enrollment
from material-only `--check` flags.

## Executable acceptance and open decisions

[Native tests](../../crates/kedgeflow/tests/restore.rs) run a separate witness etcd
process/data directory, mTLS proxies and the shipping `kf-restore` binary. Exercise
empty enrollment, status/restart, stale/empty snapshot restoration, consumed root
and fence preservation, missing/foreign witness, omitted configuration, reservation
and local response loss, finalization response loss, witness outage, concurrency,
restore during the outer CAS and nonempty enrollment refusal. Quarantine must
leave local state unchanged and must never reset the independent witness.

Backups are test-owned prefix copies performed while application work is stopped;
this is not etcd snapshot-tool, host/power failure or production target rehearsal.
The witness is a single-member software cluster on the same host; the authority
fixture has three members. Native admission-chain/governance/crash tests remain
separate; combined managed service kills under witness enrollment, scale and
latency, production RBAC/custody, independent failure domains and owner acceptance
remain unqualified. Global prefix serialization intentionally favors safety over
availability. Pending repair, existing-state migration, cluster failover aliases,
witness rollover, historical exports and independent peers require future RFCs.
M4c3 adds durable incident ownership and bounded automatic outcome delivery.
