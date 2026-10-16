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
| [0020](0020-pinned-exchange-identities.md) | Pinned OAuth subject and ES256 JWT-SVID signatures, bounded trust refresh and withdrawal | M5c prerequisite | Draft; software keys and native-etcd composition tested; actual providers/mint/custody open |
| [0021](0021-broker-token-http.md) | Native closed token exchange, one-shot mint and independently verified reference target credential | M5c2 prerequisite | Draft; native TLS/etcd/client and shipping broker restart checks; enterprise providers/target acceptance open |
| [0022](0022-identity-refresh.md) | Signed per-exchange identity refresh, protected exact head and retained epoch checks | M5c3 prerequisite | Draft; generated-key/source negatives and shipping broker live rotation; publisher/custody/enterprise acceptance open |
| [0023](0023-postgres-reservation.md) | Conditional PostgreSQL reservation, atomic retained outcome and query | M6a prerequisite | Draft; Rust records and real SQL storage tests; RFC 0024 supplies native target; RFC 0025 connects fresh gateway mapping; pilot acceptance open |
| [0024](0024-postgres-target-http.md) | Authenticated native SQL target/query, COMMIT-bound driver and fixed adapter client | M6b1 prerequisite | Draft; actual mTLS/SQL and shipping restart; RFC 0025 connects the fresh CTD-driven agent path; pilot acceptance open |
| [0025](0025-postgres-leaf-binding.md) | Named SQL CTD schema, explicit gateway adapter and fresh official SDK/native broker/SQL/recovery | M6b2 | Draft; required fresh native composition/query-only restart and schema-valid ID regression pass; enterprise acceptance open |
| [0026](0026-sql-failure-qualification.md) | Fresh SQL process failures, witnessed restore refusal and retained incident/collector delivery | M6c | Draft; eleven composed cases and required regression pass; pending repair, physical storage/restore and enterprise acceptance open |
| [0027](0027-postgres-enrollment.md) | Standalone SQL role catalog guard and explicit native database preflight | M6d1 | Draft; column/PUBLIC/membership/owner negatives and native active/offline checks; OS/peer custody and enterprise acceptance open |
| [0028](0028-postgres-custody.md) | Explicit SQL-target descriptor/mode file loading and real peer fixture | M6d2a | Draft; filesystem/native startup and peer-map negatives pass; independent OS/ACL/mount/rotation and deployed bypass coverage open |
| [0029](0029-postgres-peer-transport.md) | Pinned kernel Unix peer before SQL bytes; separate-account Linux fixture | M6d2b prerequisite | Draft; native local peer transport tested; Linux account and deployed custody observations open |
| [0030](0030-postgres-restore-rehearsal.md) | Fenced stale logical SQL restore, external lost-history preservation and storage budgets | M6d3a prerequisite | Draft; actual pg_dump/pg_restore and fresh storage workload tested; service cutover/physical restore/owner acceptance open |
| [0031](0031-review-consumption.md) | Canonical WebAuthn assertion verification and durable challenge/counter consumption | M7a prerequisite | Draft; synthetic ES256 authenticator and real-etcd state tested; panel/lease/hardware integration open; RFC 0034 adds native reviewed evidence |
| [0032](0032-coordination-reservations.md) | Hierarchical forward/compensation reservation conservation | M8a prerequisite | Draft; real-etcd contention/narrowing/unknown holding tested; native grant/A2A/saga/drain integration open |
| [0033](0033-release-conformance.md) | Required software conformance runner and immutable evidence with open release gates | M9a prerequisite | Draft; local software corpus; independent wire exchange/reproduction and release acceptance open |
| [0034](0034-native-review-evidence.md) | Protected native reviewed evidence and exact consumed-challenge/active-enrollment comparisons in admission and issuance | M7b | Draft; native mTLS/DPoP/etcd, shipping crash/restart and authority revocation races; browser/hardware open; native leases in RFC 0035 |
| [0035](0035-static-admission-leases.md) | Exact-proposal static leases, fresh JIT evidence and live membership generation comparisons | M7c | Draft; native mTLS/DPoP/etcd, replicas, withdrawal races and shipping crash/CLI; v0.2 lineage in RFC 0036; Node client in RFC 0037; hardware acceptance open |
| [0036](0036-leased-authorization-lineage.md) | Original authority membership/cache retention and independent v0.2 leased lineage/history/control-binding verification | M7d1 | Draft; real-etcd/TLS flow, withdrawal/replacement, tamper/version refusal and shipping offline CLIs; observer/ledger/clock and lifecycle history remain trusted/open |
| [0037](0037-agent-static-lease-workflow.md) | Node static preparation/cache reuse, fresh JIT acquisition and permanent query-only recovery boundary | M7d2 | Draft; official SDK/native mTLS/DPoP/etcd, separate processes and reply/write loss; physical storage/hardware/enterprise acceptance open |
| [0038](0038-native-reserved-leaf.md) | Fixed-cost native leaf budget allocation, signed immutable binding, original-attempt claim and stopped-root dispatch | M8b1 | Draft; managed native TLS/DPoP/etcd, contention/stop races and shipping CLIs; v0.1 holds unknown, RFC 0039 adds opt-in history/refinement; wider coordination open |
| [0039](0039-reserved-history-refinement.md) | v0.2 budget history/fence replay, native signed-outcome refinement and reserved-lineage observer wrapper | M8b2 | Draft; actual etcd, receipt/dispatch/stop races, exhaustion/corruption, SDK and shipping recovery/audit CLIs; allowances held; wider coordination/enterprise gates remain open |
| [0040](0040-a2a-root-resolution.md) | Activated A2A root-reference resolution, immutable reader ACL and narrowed non-authorizing views | M8c1 | Draft; native TLS/DPoP/etcd, pinned client and shipping lifecycle tests; hierarchical execution/full A2A peers remain open |
| [0041](0041-static-hierarchical-leaf-authority.md) | Signed static composite hierarchy and atomic independently admitted child-cost/issuance with native claim/dispatch lineage | M8c2 | Draft; managed etcd/TLS, contention/stop races, signed-role/scope negatives, shipping CLIs and official SDK; complete hierarchy history/dynamic delegation/enterprise acceptance open |
| [0042](0042-hierarchical-history.md) | Audited static hierarchy, atomic child-cost/issuance history, signed outcome refinement and all-leaf independent replay | M8c3 | Draft; native etcd/TLS, bounded history, corruption/exhaustion, signed semantic negatives, shipping CLIs and SDK; allowances held; dynamic delegation and enterprise acceptance open |
| [0051](0051-inverse-sql-restore.md) | Consumed native inverse authority across real stale logical SQL restore, query-only copy and retained original outcomes | M8d3e | Draft; local pg_dump/pg_restore, role fences, original unknown/committed receipts and held costs; physical cutover/custody and fresh deployment acceptance open |
| [0050](0050-inverse-failure-recovery.md) | Shipping inverse target SIGKILL before effect/after COMMIT and separate-witness stopped authority rollback | M8d3d | Draft; local real SQL/native broker/mTLS, original query-only recovery and held costs; physical inverse storage restore, wider process/deployment and independent acceptance remain open |
| [0049](0049-compensation-lineage.md) | Complete bounded saga and selected inverse lineage, native read CAS and independently pinned offline verification | M8d3c | Draft; local native/real-SQL, states, omission/re-signed substitution/race and shipping verifier tests; independent peer/failure/deployment acceptance open |
| [0048](0048-postgres-compensation-target.md) | Actual conditional SQL inverse, original terminal barrier, separate applicability evaluator and explicit native target/adapter | M8d3a | Draft; local real-SQL/native broker/mTLS and shipping commands; complete saga/SDK/writer acceptance remains open |
| [0047](0047-native-compensation-authority.md) | Fresh inverse admission, mandatory signed compound binding, held spending and original-attempt claim/dispatch/recovery | M8d2b2 | Draft; bounded one-contract paired service; actual target/barrier and complete saga acceptance remain M8d3 |
| [0046](0046-paired-action-domain.md) | Explicit fresh-domain paired exact controls, shared native resource fences and permanent physical-domain stop | M8d2b2a | Draft; native scope/stop/recovery/proof CAS and shipping operator CLI; RFC 0047 adds explicit fresh inverse execution |
| [0045](0045-inverse-contract-qualification.md) | Protected inverse CTD/contract, independently signed original-effect/barrier/applicability verification and native proof journal | M8d2b1 | Draft; bounded native CAS/refusal/concurrency and shipping CLI qualification; fresh inverse authority M8d2b2 and actual target/barrier M8d3 remain open |
| [0044](0044-native-forward-saga.md) | Protected preallocated forward DAG, signed committed predecessor gates and complete issued-leaf replay | M8d2a | Draft; native dependency/proof/stop CAS, CLI and SDK qualification; inverse authority M8d2b and complete saga acceptance M8d3 remain open |
| [0043](0043-durable-saga-observation.md) | Protected saga DAG, durable query-only original-operation/outcome observation and blocked inverse intent | M8d1 | Draft; real-etcd concurrency/restart, receipt CAS, bounds/corruption and shipping TLS CLI; native dependency enforcement, fresh inverse admission/execution and complete saga acceptance remain M8d2/M8d3 |

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
   ordered automatic delivery. M5a adds opt-in shared replay and subject/workload/scope registration. M5b adds independent broker authorization before a one-shot mint. RFC 0020 adds bounded cryptographic subject/actor verification and atomic trust refresh. RFC 0021 connects native token exchange to one-shot minting and a verified reference target credential. Real identity/provider and production gates remain open.

The bounded M2 software path is delivered; acceptance and deployment qualification
remain open. Prefer `validate_inputs` with an opaque
verified input chain. The older trusted-context API remains for authority callers
and tests. Neither privileged library API is an agent-callable endpoint. See the
[fresh lifecycle verification](../../results/verification/rfc-m2-control-2026-10-11/README.md).
