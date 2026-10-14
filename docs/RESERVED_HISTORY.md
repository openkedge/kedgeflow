# Reserved history and outcome refinement (M8b2)

[RFC 0039](rfcs/0039-reserved-history-refinement.md) adds the opt-in
`KF-RESERVED-LEAF-0.2-draft` profile and a separate historical wrapper,
`KF-RESERVED-LINEAGE-0.1-draft`. Existing v0.1 registrations keep their byte
representation, authority behavior and unknown budget holding. Frozen grant,
admission, receipt and HTTP records remain unchanged.

## Enrollment and custody

Put the same approved v0.2 `reservation` in the control, gateway and recovery
configurations. Native issuance/gateway still require managed control, exact
scope/issuer pins and an installed acknowledgement. Recovery validates its grant
role/audience against the registration. An omitted or mismatched v0.2 recovery
registration cannot retain a refinement receipt. It cannot fall back to ordinary
unreserved recovery.

[Public example fragment](../config/reserved-history.example.json) has illustrative
repeated digests and a public fixture key. Replace every deployment pin from
independently accepted material before using it. The protected control CLI retains
its commands:

```sh
kf-control --config /etc/kedgeflow/control.json --check
kf-control --config /etc/kedgeflow/control.json --enroll-reservation
kf-control --config /etc/kedgeflow/control.json --stop-reservation
kf-recover --config /etc/kedgeflow/recovery.json --check
kf-recover --config /etc/kedgeflow/recovery.json --once
```

Use a new approved root/namespace or an independently designed migration. Changing
a v0.1 registration to v0.2 cannot upgrade an existing enrollment or manufacture
history. There is no reset, reactivation, generation bump, replacement or refund.
Operator access, keys, etcd ACLs, restore witnesses and provider/target custody
remain deployment responsibilities.

## Conserved atomic history

Enrollment creates history genesis and the empty capacity snapshot together.
Allocation records its exact resource fence, approved fixed costs and operation
identity in the fence transaction. Issuance records the signed binding/grant;
claim records the original attempt and consumed unknown state; dispatch records
its active-root comparison. Stop records an inactive snapshot while preserving
all allowances. Each append compares the current snapshot and hash-linked head.
Retries/recreated issuers reuse the original authority and append no duplicates.

Every event carries a sequence, previous digest, registration digest and complete
resulting budget snapshot. Live authority checks validate the current head/latest
event against that snapshot. Complete export reads and verifies the retained
chain; a missing older event blocks export rather than synthesizing history.
State-only coordination mutation ports refuse v0.2 roots. Status remains a
non-authorizing read.

History is bounded to 256 events, with the final slot reserved for permanent stop;
snapshots are at most 128 KiB, individual events 256 KiB, and exported bundles
64 MiB. Capacity/history exhaustion refuses new authority. Repeated stop is
read-only. Exhaustion can also prevent later receipt/refinement retention: held
unknown capacity stays held and requires operator handling. No truncation or
recycling API is provided. The existing optional restore quarantine covers these
transactions; this does not qualify physical storage or restore repair.

## Native refinement

A native recovery worker retains a signed OutcomeService receipt and budget
refinement in one comparison transaction, under the original grant/root/nonce,
execution context, attempt, issuer binding, budget snapshot and history head.
Refinement may continue after expiry or stop because it creates no execution
permission.

- A reported committed original attempt becomes budget state `committed`.
- Pre-dispatch sealing with no dispatch-authorization journal becomes
  `proven_no_effect`. Raced dispatch or stop invalidates the worker's old snapshot;
  the worker must read/query again.
- Dispatch intent, timeout, unknown, pending, not-found and a query's no-effect
  wording do not establish this pre-dispatch barrier. They retain `unknown`.
  A failed/state-guard outcome also stays unknown in this budget profile.

Known states cannot reverse or move to another attempt. Both forward and
compensation costs remain held in every classification, including proven no
effect on an active root. Gateway outcome recording stays conservative until the
worker retains its signed receipt. A receipt reports a trusted observation; it
does not invent target-signed commit evidence or complete writer coverage.

## Independent historical verification

The privileged Rust `export_reserved_lineage` API carries the existing signed
admission/outcome chain, issuer bindings and complete budget history. A separately
approved observer signs their exact digests and the namespace/root registration,
selected operation/grant/attempt, event count/head and capture time. This is an
observer attestation, not an etcd signature or consensus/non-revocation proof.
The unversioned reserved export continues to refuse.

Use an independently approved public trust file with `registration`, `namespace`,
`observer_id`, `observer_keys` and `lineage` (the existing public
[admission lineage trust](../config/lineage-trust.example.json) shape). The verifier
never approves keys or scope from the bundle. Observer keys must be separate from
its admission/input/issuer/outcome roles.

```sh
kf-verify-reserved-lineage --trust approved-reserved-trust.json \
  --bundle reserved-lineage.json
```

The closed, bounded verifier re-evaluates historical admission/outcomes and
replays the whole budget chain. It checks fixed costs/scope, increasing allocated
fences and issuer equality, phase order, one original claim/dispatch, stop,
conservation and signed original-attempt refinements. The selected refinement
must occur in its retained outcome chain. A committed lineage cannot omit its
budget refinement. Even a correctly re-signed observer checkpoint cannot override
these invariants.

Output reports held allowances, classification and `execution_authority: false`.
The existing inner lineage's OAuth/PoP/governance/journal/tool/target gaps remain,
as do observer correctness, clock, ledger/custody/restore and physical writer
assumptions. This wrapper supplies no new execution capability.

[Required verification](../results/verification/rfc-m8-reserved-history-2026-10-14/README.md)
uses real etcd/native managed services, original-attempt receipt races, stop and
dispatch barriers, exhaustion/corruption and correctly re-signed negative bundles.
Shipping recovery/offline CLIs and an official SDK/native TLS/DPoP workflow are
included. Its providers, broker, effect and observations are software fixtures;
reserved SQL deployment, physical/hardware qualification and enterprise acceptance
remain open. Next M8 software work is hierarchical grants and authenticated A2A
scope narrowing, followed by durable saga/compensation and separate governed drain.
