# RFC 0011: Authenticated retained outcome delivery and acknowledgements

- Status: Draft
- Profile: `KF-OUTCOME-REPORT-0.1-draft`; receipts retain KF-JSON-0.2
- Milestone: bounded M4b1; full lineage and crash/restore qualification remain open
- Baseline: `3548798`; [RFC 0010](0010-outcome-recovery.md)
- Owners/reviewers: unassigned; runtime, resource, security and SRE owners

## Scope and trust

RFC 0010 retains signed OutcomeService receipts locally. This increment provides
a separately deployed collector for authenticated external delivery of those
retained receipts, with durable signed acknowledgements and acknowledgement lookup.
It accepts no new target observation or externally invented execution outcome.
An acknowledgement establishes durable delivery to this collector, not target
commit, admission correctness, incident resolution or renewed execution authority.

The collector uses verified native mTLS and pinned Ed25519 OAuth/DPoP. One approved
subject/workload/source assignment has a distinct outcome-report scope. Its
registration fixes tenant, conflict domain, grant audience and issuer/OutcomeService
keys. The frozen grant has no tenant field: tenant labels an operator-assigned,
dedicated authority namespace and issuer key set; this service checks the signed
conflict domain and grant audience. It cannot establish signed proposal tenancy
without the full admission-lineage work. Mixed-tenant namespaces are unsupported.
Source identity equals the verified reporter workload. Agents cannot submit
using execution/admission scopes. Grant expiry or revocation does not prevent
delivery of historical receipts; current reporter authentication remains required.

The collector has a separate acknowledgement signing key, disjoint from issuer
and outcome keys. Its configured identity and exact HTTPS URL bind acknowledgements.
The authority namespace is operator-selected, never supplied by a request. Etcd
credentials must permit retained-record reads and acknowledgement writes only;
production RBAC, key custody, enrollment/rotation and shared DPoP replay remain M5.
No target query, exchange, claim, dispatch, root/nonce change, refund or replacement
is performed by the collector.

## Closed HTTP contract

Native TLS 1.3/HTTP/1.1, exact endpoint/Host, no forwarded identity or browser
origin aliases, POST application/json only. Bodies are bounded to 2 MiB, admission
to 64 owned operations, body reads to ten seconds and ledger work to five seconds.
Owned work survives an HTTP disconnect within that deadline. Success/failure
responses use Cache-Control: no-store. No discovery, arbitrary record retrieval,
generic attempt search or agent-facing status endpoint is supplied.

The [separate draft schema](../../spec/drafts/outcome-report-v0.1.schema.json)
defines the following commands and replies. Every object is closed.

Report fields: profile, operation=report, request_id, signed_grant, signed_receipt,
evidence. The receipt and grant are exact signed KF-JSON strings; evidence is the
canonical JSON object referenced by the receipt's single resolution_evidence entry.
The collector authenticates signatures and binds its registered namespace tenant,
signed domain, source role/id,
grant/proposal/certificate/root/generation/attempt/fence/parameters digests. It
requires the receipt and evidence to match immutable retained records. It does
not treat a valid signature alone as a durable report.

Query fields: profile, operation=query, request_id, signed_grant, attempt_id,
receipt_digest. It returns the stored acknowledgement or a missing reply. Missing
means no acknowledgement at that live namespace snapshot, not cancelled delivery;
an in-flight report may commit later. Query never creates an acknowledgement.

Success fields: profile, operation=acknowledgement, request_id, acknowledgement.
Missing fields: profile, operation=missing, request_id, receipt_digest.
Failure fields: profile, operation=failure, request_id, code. Codes are
invalid_record, unsupported_profile, unauthenticated, forbidden, not_retained,
predecessor_required and authority_unavailable. Authentication failures use 401,
role/scope failures 403, absent/invalid retained reports and missing predecessors
409, malformed input 400 and dependency/ambiguous completion 503.

Request IDs are transport correlation only. Report identity is the domain digest
over collector identity/URL, tenant, grant digest, original attempt and receipt
digest. A new request ID cannot produce a second acknowledgement for the same
report. Exact content and authenticated scope are checked on retries too.

## Signed acknowledgement and persistence

The closed signed record contains profile, kind=acknowledgement, key_id, payload
and signature. Ed25519 signs the UTF-8 prefix
`KedgeFlow:KF-OUTCOME-REPORT-0.1-draft` followed by a NUL byte and the KF-JSON
canonical unsigned object. This domain is separate from frozen receipt signatures.

Payload fields: report_id, tenant, grant_digest, attempt_id, receipt_digest,
evidence_digest, source_id, collector_id, collector_url, previous_receipt_digest,
accepted_at. Times use safe-integer UTC milliseconds. Null predecessor identifies
the first receipt. Collector identity/URL and public key are separately trusted,
never selected from the report. A client must verify the acknowledgement signature
and every expected binding before considering delivery complete.

The acknowledgement is stored under the original attempt and collector identity
by receipt digest. The transaction compares original consumed root/grant/nonce,
recorded context/index, immutable receipt/evidence, absence of this acknowledgement
and the exact prior acknowledgement where required. A predecessor must already
be acknowledged by this collector; out-of-order delivery refuses and may be retried
after delivering that predecessor. Terminal receipts can follow earlier unknown
receipts; delivery does not overwrite earlier observations or acknowledgements.

Only one acknowledgement wins concurrent first submissions. Duplicates or lost
replies reread and authenticate that exact winning envelope, including its original
acceptance time. No fresh candidate is returned as durable after an ambiguous
write. Lookup remains valid after grant expiry/revocation. Restart needs retained
keys/namespace, not a process-local idempotency cache.

## Implementation and acceptance

Implement the service, native `kf-outcomes` listener/configuration, signed ack
verification helper and bounded reporting client. Test with actual etcd and native
TLS: duplicate submissions, recreated collector, lost replies, query before/after
delivery, predecessor ordering and old receipts after terminal resolution. Test
wrong workload/scope/subject/proof URL, untrusted signatures, substituted lineage,
evidence tampering, signed-but-unretained receipts and malformed closed commands.
Verify the consumed root/nonce and original attempt stay unchanged.

The bounded service/client implementation and five new native acceptance cases
are recorded in [fresh verification](../../results/verification/rfc-m4-report-2026-10-11/README.md).

## Compatibility and remaining gates

No frozen record, receipt signing domain or worker query profile changes. Delivery
is explicitly enabled through its own listener/configuration. Worker scheduling
of delivery, independently administered remote evidence stores, full admission
lineage, signer history, incident deadlines, contradictory late terminal reports,
gateway/target hard-crash coverage and stale-backup fencing remain open. This
bounded shared-ledger collector is not independent storage/restore qualification.
