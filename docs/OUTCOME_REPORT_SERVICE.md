# Deliver retained receipts and verify acknowledgements

[RFC 0011](rfcs/0011-outcome-report-http.md) implements bounded M4b1. A separate
collector accepts receipts already persisted by [recovery](RECOVERY_SERVICE.md),
then stores and returns a signed delivery acknowledgement. It performs no target
query, claim, credential exchange, dispatch or execution-state transition.

Start from [outcomes.example.json](../config/outcomes.example.json). Register the
exact reporter subject, verified mTLS source workload, dedicated report scope,
conflict domain, gateway audience and issuer/OutcomeService public keys. Provision
an independent collector signing seed and protected native TLS/etcd material.
The collector reads retained records and writes acknowledgements only. Production
least-privilege etcd roles and enrollment/key custody still require M5 qualification.

Assign this authority namespace and issuer key set exclusively to the configured
tenant. Frozen grants contain no tenant field: the acknowledgement's tenant is
that operator assignment, not verified signed proposal tenancy. Mixed-tenant
namespaces are unsupported until complete authorization-lineage verification.

```sh
cargo run --locked --bin kf-outcomes -- --config /etc/kedgeflow/outcomes.json --check
cargo run --locked --bin kf-outcomes -- --config /etc/kedgeflow/outcomes.json
```

`--check` validates local configuration/TLS/signing material without remote reads
or writes. Run the listener under your process supervisor. It is enabled separately
from the gateway and recovery worker. Inbound native TLS 1.3 and fresh OAuth/DPoP
authenticate the reporter even when the original execution grant is expired.
Source workload differs from the original executing workload.

Use the library's `OutcomeReportClient` with a pinned mTLS client, fixed collector
URL/identity and independent public-key registration, a report-scoped access token
and its confirmed DPoP key. Export the ordered receipts/evidence from the original
attempt with `EtcdLedger::export_outcomes`. Build a `DeliveryReceipt` from each exact
signed grant/receipt and its referenced evidence. Deliver oldest first. The client
creates a fresh DPoP proof, verifies report correlation and authenticates the exact
signed acknowledgement before returning it. Token acquisition/renewal and automatic
delivery scheduling are operator responsibilities in this increment.

`deliver(request_id, receipt)` submits the report. `lookup(request_id, receipt)`
returns the retained acknowledgement or None. Each call has a five-second deadline
and bounded request/reply size. On a lost response, perform lookup or retry the
same receipt with a fresh proof; both return the original signed acknowledgement.
New request IDs confer no new execution or report authority. A missing lookup is
a live snapshot; an in-flight report can commit later.

The collector requires the immutable receipt/evidence to match its authority
namespace. A signature on an invented receipt is insufficient. Each predecessor
must already be acknowledged by this collector; out-of-order reports return
predecessor_required. Duplicate and old unknown receipts remain deliverable after
a terminal receipt, without replacing the terminal execution state. Acknowledgements
bind the collector identity/URL, tenant assignment, grant/original attempt/receipt,
evidence, source and predecessor. Collector key rollover is not yet supported.

Artifacts can contain sensitive execution parameters/evidence and require authorized
storage/disclosure. The endpoint supplies no generic agent search or trace export.
It acknowledges durable delivery, not independently proven admission or target
effect. [M4b2 signed lineage](ADMISSION_LINEAGE.md) now exports and verifies the
historical admission chain separately. Installation/key history, separate-store restore, incidents, automated delivery,
key history and gateway/target crash qualification remain open.

See [fresh verification](../results/verification/rfc-m4-report-2026-10-11/README.md).
