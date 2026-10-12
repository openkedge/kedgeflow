# RFC 0013: Retained governance history and observer checkpoints

- Status: Draft
- Profile: `KF-CONTROL-HISTORY-0.1-draft`
- Milestone: bounded M4b3; operation-bound control snapshots remain M4b4
- Baseline: `b1caeea`; RFCs 0007, 0010, 0012
- Owners/reviewers: unassigned; policy, runtime, resource and security owners

## Problem and scope

Policy and descriptor publications are retained, but installations and gateway
acknowledgements overwrite their latest pointers. Revocations are immutable per
target, without accepted-time history. An offline verifier cannot reconstruct
applied governance changes from the latest snapshot alone.

Append each successful governance mutation to a per-domain, immutable, contiguous
history in the same etcd transaction as its live state change. Export this history
alongside RFC 0012 lineage, with a checkpoint signed by a separately registered
observer. Verify the original control signatures, sequence/hash chain, observer
assertion, installation references, gateway acknowledgements and independently
approved historical admission/issuer key membership.

This increment establishes authenticated retained governance assertions. It does
not prove a historical operation's exact control CAS revision or non-revocation.
Accepted-time ordering is observer-attested ledger data, not an independently
trusted distributed clock. A history prefix cannot prove absence of later events.
No old schema, signing domain or execution freshness rule changes.

## Atomic retention and compatibility

An event contains sequence (starting at one), previous_digest (null at genesis),
kind, accepted_at and exact StoredControl. Its digest uses control-history-event.
The per-domain head records sequence, event digest and accepted_at. Append compares
the prior head and requires the next immutable event key to be absent. All existing
publication/installation/ack/revocation comparisons remain in the same transaction.
Failed mutations write no event; exact current-record retries append nothing.
The accepted_at field samples the authority clock before the successful transaction;
it is not a consensus commit timestamp. Backward accepted times refuse. A successful concurrent mutation can require an
unchanged retry after a head conflict.

Genesis requires no existing managed publication/installation/ack/control-required
or domain revocation pointers. Existing untracked managed domains cannot synthesize
history: export and new history mutations refuse; migration/restore needs a separate
approved contract. Standalone legacy fixture authority is not claimed as managed
history. Retention has no pruning; export is bounded to 64 complete events. Longer
histories refuse export rather than omit a prefix; pagination is later work.

## Checkpoint and trust

A privileged `export_control_history(candidate, operation_key, observer, clock)`
reads a retained history head and all immutable events through that head, then
exports RFC 0012 lineage. The independently registered observer signs a closed
checkpoint: profile/kind/key_id/payload/signature. Payload binds observer_id,
namespace, tenant, conflict_domain, event_count, head_digest, captured_at and the
canonical control-history-lineage digest of the exported lineage. Signing uses
`KedgeFlow:KF-CONTROL-HISTORY-0.1-draft\0` and excludes signature. The observer
asserts its protected ledger observation; this is not an etcd consensus signature.
Read-only observer access, signing-key custody and authorized disclosure are
operator responsibilities. There is no agent-facing listener or automatic signer.

Public verifier trust independently selects the operation's RFC 0012 registration,
approved historical registration/scope/acknowledger snapshots, four administrative
role key sets, observer identity/namespace and observer keys. None is selected by
exported metadata. Administrative, acknowledgement, observer, input, admission,
issuer and outcome signer roles must remain independent. Old/new issuer membership
must exactly match its approved signed installation registration and trust digest.
Rotation is externally approved snapshot enrollment, not automatic key discovery,
key revocation, cross-certification or production rollover.

## Offline verification

1. Enforce closed carriage, 32 MiB aggregate bundle, 4 MiB public trust, 1 MiB per
   signed record, 1–16 approved historical snapshots and 1–64 events. Authenticate checkpoint with approved observer.
   Bind exact RFC 0012 lineage digest, namespace, tenant/domain/count/head/capture.
2. Verify RFC 0012 signed authorization/outcome chain under operation trust.
3. Verify contiguous sequence/predecessors/digests, monotonically nondecreasing
   accepted times bounded by captured_at, each control signature under its role,
   and the exact approved historical registration.
4. Policy publication must bind the approved Cedar definition; descriptor
   publication must bind the independently signed CTD and exact approved scope.
   Installation must bind current verified publication digests/registrations and
   the next expected revision. Enforce policy/ownership monotonicity and reject
   same-epoch conflicts. Gateway acknowledgements must bind the installed record,
   approved signer/component/workload/coverage, accepted-time freshness and refresh
   monotonicity. Revocations bind current tenant/domain and immutable revision-one
   target/reason. No installation is permitted after a domain revocation.
5. Identify installations matching the operation's exact scope, policy, ownership,
   approved admission/issuer trust digest and issuer key set. Require an accepted
   gateway acknowledgement covering the signed admission and issuance times for
   at least one matching installation. This is a historical assertion check,
   not proof that an operation compared that installation in its authority CAS.
6. Return verified event/installation/ack/revocation counts and identities, matching
   installations and known revocation targets/sequence/accepted times. Never return
   a historical execution permission or a non-revocation assertion.

`kf-verify-history --trust FILE --bundle FILE` performs no network access and
returns JSON or nonzero. Missing records, omitted/reordered history, wrong keys,
re-signed wrong scope/membership/references, ambiguous/legacy genesis, changed
checkpoint/lineage and unsupported supplements refuse.

## Acceptance and remaining gates

Test native authenticated governance, actual etcd transactions, immutable retry
and failed-mutation behavior, acknowledgement renewal/recreated service, approved
issuer-key change/new installation and retained old operation, all three revocation
targets and a separate offline verifier process after expiry. Corrupt history and
signed checkpoint/bindings; refuse legacy history, gaps and unapproved keys.

Remaining links: original OAuth/DPoP/mTLS transcript; operation-to-control sequence
and revocation CAS evidence; authenticated claim/dispatch/fence allocation;
registered tool-name mapping; target-signed proof and complete writer coverage.
Observer signatures do not independently prove correct ledger operation, clock,
hardware enrollment, key custody, latest head or absence of later revocations.
M4b4 operation-bound control evidence, pagination, observer deployment/RBAC,
automatic incidents/delivery, hard-crash and stale-backup restore fencing remain
open. M4/M5 enterprise release and independent-peer acceptance remain open.
