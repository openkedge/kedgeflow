# Audited static hierarchy (M8c3)

[RFC 0042](rfcs/0042-hierarchical-history.md) adds fresh-root enrollment under
`KF-HIERARCHICAL-LEAF-0.2-draft` and the separate
`KF-HIERARCHICAL-LINEAGE-0.1-draft` historical bundle. It preserves
[RFC 0041's static signed composites and leaf bindings](HIERARCHICAL_LEAF_AUTHORITY.md),
adds complete bounded history and refines original outcomes without releasing
forward or compensation allowances. Hierarchical 0.1 keeps its unknown/held
behavior; changing configuration cannot upgrade an existing root.

## Protected enrollment

Put the same approved audited `reservation` in control, gateway and recovery
configuration before enrolling a new root. The [example fragment](../config/hierarchical-history.example.json)
contains public demonstration keys, fictional deployment pins and fixed test
validity times. Regenerate approved signed composites and assignments for the
actual deployment; edits to signed fields require resigning and recomputing
ancestry digests. No key or descriptor in the example is deployment acceptance.

```sh
kf-control --config /etc/kedgeflow/control.json --check
kf-control --config /etc/kedgeflow/control.json --enroll-reservation
kf-control --config /etc/kedgeflow/control.json --stop-reservation
kf-recover --config /etc/kedgeflow/recovery.json --check
kf-recover --config /etc/kedgeflow/recovery.json --once
```

Enrollment atomically retains the exact static skeleton, original signed
composites, required-profile markers and genesis event. Raw coordination mutation
ports cannot mutate this root. Native stop is permanent and idempotent. Missing
or mismatched audited recovery configuration cannot bypass required history.
Delegation, admission, leaf issuer, outcome and observer keys have separate roles.

## History, outcomes and limits

An early resource fence retains no hierarchical cost. The issuance transaction
adds exactly one leaf under its protected parent and retains cost, original
signed grant/binding, fence, issuance and history together. Reuse appends nothing.
Claim consumes one original attempt; dispatch compares active lineage. Stop
preserves every allocation. Native receipt retention and budget refinement share
one transaction, even after stop or expiry:

- A correlated signed committed outcome after dispatch becomes `committed`.
- A signed pre-send `not_dispatched` outcome becomes `proven_no_effect` only with
  an atomic absent-dispatch-journal comparison.
- Dispatched uncertainty, timeout, pending/not-found/no-effect wording and failed
  outcomes stay `unknown`. No classification refunds or transfers capacity.

The static graph retains RFC 0041's one fixed executable contract, generation 1,
at most 16 signed composites/assignments and seven composite levels. Snapshots
have at most 256 total allocations and 128 KiB. History has at most 256 events,
256 KiB each, with event 256 reserved for stop. Exhaustion refuses new mutations
and can also prevent later signed receipt refinement. Retain held unknown data;
there is no history pruning, automatic repair, replacement or timer refund.
Every native gate compares the snapshot, head/latest event and original composites.
Missing older events prevent complete export; missing latest/head data also
blocks native authority. Custody, ACLs, restore and clock assumptions remain.

## Complete independent replay

The privileged Rust `export_reserved_lineage` API uses an independently approved
`reserved_lineage::Trust` and observer. It carries the complete history, selected
ordinary admission/outcome lineage, and the original authorization proof for
**every issued leaf**, including unclaimed leaves. Each proof retains admission,
raw signed proposal/descriptor/manifest/witnesses, issuance and, when applicable,
both original lease-authority bindings. Missing retained inputs refuse export.
The observer checkpoint binds that exact proof map as well as history and lineage.
Bundles are bounded to 64 MiB, proofs to 16 MiB and signed records to 1 MiB.

Use an independently approved trust file with `registration`, `namespace`,
`observer_id`, `observer_keys` and `lineage` (the public
[historical lineage trust](../config/lineage-trust.example.json) shape). Approve all
leaf subjects and the shared descriptor/policy/role pins. The protected hierarchy
assignments approve each exact subject/workload pair; the verifier uses that
approved workload when reevaluating the leaf's signed admission inputs. Exported
identity fields cannot expand assignments or approved subject/role sets.

```sh
kf-verify-reserved-lineage --trust approved-hierarchical-trust.json \
  --bundle hierarchical-lineage.json
```

The verifier validates the raw closed schema before set decoding, verifies the
original static signatures/narrowing and each leaf's signed inputs/certificate /
policy/grant/binding, and replays all capacity transitions. Every issued operation
requires exactly one matching proof. Positive original fences must be unique;
issuance may follow earlier fence allocation in a different order. Costs and
composite states cannot change. Correctly re-signed observer checkpoints cannot
make a missing proof, widened parent, refund or inconsistent receipt valid.

The result is historical evidence with `execution_authority: false`. Observer
correctness, ledger consensus/custody, runtime OAuth/DPoP/mTLS transcripts,
control/key/lease lifecycle history, target-signed effects and writer/predicate
coverage remain explicit limits. This software verifier does not independently
establish those deployment properties.

[Required verification](../results/verification/rfc-m8-hierarchical-history-2026-10-14/README.md)
includes native contention, signed semantic substitutions, mixed approved
workloads/reversed fence order, unknown/no refunds, missing/corrupt/exhausted
history, receipt/dispatch/stop races, shipping recovery/audit/operator CLIs and
official SDK normal/lost-reply/query-only restart. Dynamic delegation, full A2A
peers, saga/compensation, actual Kubernetes drain and enterprise acceptance remain
open. M8d is the next planned implementation increment.
