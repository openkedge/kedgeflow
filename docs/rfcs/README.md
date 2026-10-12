# KedgeFlow RFCs

These are **Draft** engineering contracts, started 10 October 2026 against
runtime `769c0a8` and the frozen white paper v0.9. They do not assert released
interoperability or completed enterprise integration. See the
[review](../IMPLEMENTATION_REVIEW_2026_10_10.md),
[milestones](../IMPLEMENTATION_ROADMAP.md), and
[active profile index](../PROTOCOL_PROFILES.md).

| RFC | Contract | Milestone | Status |
| --- | --- | --- | --- |
| [0001](0001-authority-and-trust.md) | Authority, operation identity, trust and versioning | M1 | Draft |
| [0002](0002-enforcement-control.md) | Policy/registry publication, installation and revocation | M1 → M2 | Draft |
| [0003](0003-admission-and-issuance.md) | Evidence, admission, certificate validation and issuance | M1 → M2 | Draft; input-chain/issuance libraries tested |
| [0004](0004-execution-and-outcomes.md) | Execution, token exchange, status, outcomes and recovery | M1 → M3/M4 | Draft |
| [0005](0005-cedar-leaf-admission.md) | Cedar policy ABI, rule pins and durable certificate production | M2b | Draft; library tested |
| [0006](0006-leaf-control-http.md) | Authenticated HTTP admission/issuer, chain retention and resource fences | M2b | Draft; native TLS/etcd service tested |
| [0007](0007-enforcement-control-http.md) | Signed administration, installed gateway scope/acknowledgements and revocation serialization | M2c | Draft; native TLS/etcd lifecycle tested |
| [0008](0008-agent-replay-and-status.md) | Live Node Agent Adapter, original-attempt resolution and query-only retained status | M3a | Draft; official SDK/native TLS/etcd workflow tested |
| [0009](0009-operation-status.md) | Signed-proposal historical status and ambiguous issuer/provider replies | M3b | Draft; bounded native service and official client fault tests |
| [0010](0010-outcome-recovery.md) | Retained journal, query-only worker, signed outcome receipts and offline receipt-chain verifier | M4a | Draft; bounded software recovery and native worker tests |
| [0011](0011-outcome-report-http.md) | Authenticated retained receipt delivery, signed acknowledgements and lookup | M4b1 | Draft; bounded native collector/client tests |
| [0012](0012-admission-lineage.md) | Historical signed admission lineage export and offline verification | M4b2 | Draft; bounded retained chain and separate verifier tests |
| [0013](0013-control-history.md) | Atomic governance retention, observer checkpoint and historical key membership | M4b3 | Draft; bounded native history and separate offline verifier tests |
| [0014](0014-operation-control-bindings.md) | Atomic per-transition control snapshots and observer-attested offline CAS bindings | M4b4 | Draft; native phase retention, head conflict and separate offline verifier tests |
| [0015](0015-process-crash-qualification.md) | Gateway/worker process termination boundaries and conserved query-only recovery | M4c1 | Draft; nine shipping-binary SIGKILL/restart cases against native etcd and software target |
| [0016](0016-restore-quarantine.md) | Independent write-ahead witness, empty enrollment and stale/pending authority quarantine | M4c2 | Draft; separate native witness cluster, shipping operator CLI and bounded rollback/fault tests |
| [0017](0017-outcome-supervision.md) | Owned unknown deadlines, incident event retention and bounded automatic receipt delivery | M4c3 | Draft; native collector/ledger faults plus shipping supervisor kill/restart and continuous polling |
| [0018](0018-shared-authentication.md) | Shared atomic DPoP consumption and subject/workload/scope registration | M5a | Draft; bounded native replica/restart/fault qualification |
| [0019](0019-broker-authorization.md) | Independent grant/original-claim/target authorization before one credential mint | M5b | Draft; trusted library and bounded real-etcd authorization/fault tests; provider mint integration open |

The white paper's six interfaces map to RFCs as follows: Enforcement Control
→ 0002; Evidence and Admission → 0003; Execution, Credential Exchange and
Outcome → 0004. RFC 0001 supplies common semantics. These are semantic
interfaces; co-location does not combine their authorization roles.

## Structure and review

Use [the template](0000-template.md) for future RFCs. Each RFC must state its
scope, trust boundary, request/response contract, failures, compatibility,
implementation mapping, executable acceptance tests and unresolved decisions.
Status progresses Draft → Accepted → Implemented → Superseded. Acceptance
requires recorded review by policy, resource, security and runtime owners;
implementation requires the milestone's test evidence. Until then, MUST and
SHOULD in a draft describe the proposed contract only.

Frozen v0.9 records, fixtures and paper files remain immutable. Draft additions
live in `spec/drafts`, with separate identifiers. A wire change requires a new
profile identifier and compatibility analysis. Never silently reinterpret a
frozen field, broaden an executable profile, or make a successful signature
verification stand in for semantic admission.

## Next implementation increments

1. M2a: implemented and tested as a library prerequisite: certificate constraints,
   role/tenant checks, operation-wide issuance deduplication and concurrency.
2. M2b: raw input verification, Cedar evaluation, durable certificate/chain
   retention and authenticated admission/issuer services are implemented and
   tested. The issuer owns identifiers/nonces and durable resource fences.
   Operator-approved pins now have live installed-state checks; target bootstrap remains open.
3. M2c: signed authorized publication/registration/install/revoke/query and
   gateway acknowledgement renewal are implemented, with authority-transition
   comparisons and native race tests. Deployment/owner qualification remains open.
4. M3a: live client admission flow and retained grant/attempt status are implemented
   with the official SDK, native TLS/etcd, lost-reply and restart cases.
5. M3b: signed-proposal operation lookup and lost issuer/provider reply or grant
   persistence failure resolution are implemented. Wider provider/persistence
   deployment qualification remains open.
6. M4a: retained execution context/journal, query-only polling worker and signed
   receipts are implemented. M4b1 supplies authenticated retained report delivery,
   signed acknowledgement/lookup and bounded native client verification. M4b2 adds signed admission-lineage export and historical offline checks.
   M4b3 adds atomic governance history and observer-attested offline reconstruction.
   M4b4 adds operation-bound retained control comparisons and a separate offline verifier.
   M4c1 qualifies bounded gateway/worker process kills and query-only restart.
   M4c2 adds a bounded write-ahead restore witness; M4c3 adds owned incidents and
   ordered automatic delivery. M5a adds opt-in shared replay and subject/workload/scope registration. M5b adds independent broker authorization before a one-shot mint. Real identity/provider and production gates remain open.

The bounded M2 software path is delivered; acceptance and deployment qualification
remain open. Prefer `validate_inputs` with an opaque
verified input chain. The older trusted-context API remains for authority callers
and tests. Neither privileged library API is an agent-callable endpoint. See the
[fresh lifecycle verification](../../results/verification/rfc-m2-control-2026-10-11/README.md).
