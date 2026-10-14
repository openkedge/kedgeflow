# Retained operation control bindings

[RFC 0014](rfcs/0014-operation-control-bindings.md) implements bounded M4b4.
Managed admission, admitted issuance, claim and dispatch authorization retain
their observed control state atomically with the authority transition. Each
snapshot binds the governance head sequence/digest, exact installation and gateway
acknowledgement, checked clock, authority digest, optional attempt and compared
revocation targets. The transaction compares the head and immutable head event,
installed pointers, managed marker and applicable revocation absence.

Admission covers domain revocation. Issuance, claim and dispatch also cover the
grant's exact root and grant targets. A later governance publication, including
one that leaves installed pointers unchanged, invalidates a pending head comparison.
Retry after such a conflict requires fresh control observation. Successful
admission/issuance retries return the original retained binding; failed claim or
dispatch writes no new binding. Outcome recovery remains query-only and can
retain results after execution authority expires or is revoked.

## Operator export and offline verification

The privileged library method
`EtcdLedger::export_control_bindings(candidate, operation_key, observer, clock)`
exports [RFC 0013 history](CONTROL_HISTORY.md) and the retained bindings. Use the
same independently approved `HistoryObserver` and
[public history trust format](../config/control-history-trust.example.json).
Authorize disclosure before calling this method; there is no agent-facing export
listener. Protect observer ledger access and signing custody separately from the
runtime and administrative signing roles.

```sh
cargo run --locked -p kedgeflow --bin kf-verify-control-bindings -- \
  --trust /secure/trust/control-history-public.json \
  --bundle /secure/history/control-bindings.json
```

The CLI performs no network calls. It checks a closed 40 MiB bundle and 4 MiB trust
file; nested RFC 0013 carriage remains capped at 32 MiB, 64 events and 1 MiB per
signed record. Exactly three bindings are required for an undispatched attempt;
the retained `dispatch_authorized` journal phase requires a fourth binding.
Reordered, extra, missing or mismatched phases refuse. History pagination remains
unsupported; complete histories over 64 events refuse export.

The new `KF-CONTROL-BINDINGS-0.1-draft` observer assertion binds the complete history
bundle and ordered bindings, operation key, grant, attempt, namespace, tenant and
capture clock. The verifier authenticates the original signed authorization and
governance chains under independently approved trust, then reconstructs the latest
installation and acknowledgement through each exact observed sequence. It checks
scope/policy/ownership/issuer membership, per-phase acknowledgement freshness,
certificate/grant validity, phase order and exact revocation coverage.

An applicable revocation already present at the observed sequence refuses. A
later revocation can coexist with a valid historical snapshot, including when both
use the same millisecond clock value. The sequence establishes the observer's
claimed ordering; wall-clock timestamps alone do not establish it.

Acknowledgement renewal between admission and issuance is supported even when no
single acknowledgement covers both times. The new verifier checks each retained
phase against its own acknowledgement. The older RFC 0013 verifier and signature
format retain their original single-acknowledgement clock-cover semantics.

## Compatibility and limits

Unmanaged legacy authority has no retained bindings and cannot export this
supplement. Missing records are never reconstructed from current installed state.
Managed domains without history refuse control-checked authority transitions;
older operations missing bindings can still use the older lineage/history format.
Migration and backup restore need separate approved contracts. Frozen grant,
certificate, receipt, retained admission/issuance shapes and existing profiles
remain unchanged.

Successful verification reports **observer-attested retained control comparisons**.
It provides no live capability, consensus proof, trusted clock, original runtime
authentication transcript, authenticated fence allocation, registered tool-name
mapping or target-signed commit proof. The runtime and observer must operate
correctly with protected ledger access and key custody. Complete writer coverage,
independent implementations, production observer/RBAC, hard crashes and stale-backup
restore fencing remain open enterprise gates.

See [verification evidence](../results/verification/rfc-m4-control-bindings-2026-10-11/README.md).

[RFC 0036 v0.2 audit](LEASED_AUTHORIZATION_LINEAGE.md) adds historical lease and
membership snapshots to nested lineage. The exporter selects a matching v0.2
wrapper and checkpoint signature domain; mixed versions refuse. v0.1 schemas,
legacy serialization and signatures remain unchanged.
