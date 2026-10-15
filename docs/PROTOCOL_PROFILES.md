# Protocol profile index

| Profile | Role | Current status |
| --- | --- | --- |
| KF-JSON-0.2 / frozen v0.9 schema | Signed records, canonicalization and digests | Proposed; shared fixtures and Rust cryptographic/executable-grant validation |
| KF-MCP-0.1 / MCP 2026-07-28 | Discovery, remediation and governed calls | Bounded Rust gateway and Node Agent Adapter with official client; fresh admission/issuance to guarded mock execution |
| KF-GRANT-REF-0.1 | Immutable signed-envelope retrieval | Optional bounded Rust resolver; not an authority publisher |
| KF-LEAF-CONTROL-0.1-draft | Admission/issuance/status operation carriage | Draft; authenticated admission/issuance implemented; its generic lookup/status carriage remains proposed; RFC 0009 supplies separate signed-proposal lookup |
| KF-LEAF-HTTP-0.1-draft | Native TLS binding for the two control operations | RFC 0006 draft; real-TLS/etcd tests; uses existing control wire profile |
| KF-ENFORCEMENT-CONTROL-0.1-draft | Signed administrative publication/install/ack/revoke/query | RFC 0007 draft; bounded native service and gateway lifecycle; single registered acknowledger |
| KF-OPERATION-STATUS-0.1-draft | Query-only signed-proposal operation status without a local grant | RFC 0009 draft; native authenticated lookup, lost issuer/provider replies and failed grant persistence |
| KF-EXECUTION-STATUS-0.1-draft | Negotiated query-only retained grant/attempt status | RFC 0008 draft; current disclosure scope, expired/revoked history and original-attempt resolution |
| KF-OUTCOME-RECOVERY-0.1-draft | Internal retained journal, query-only worker and linked outcomes | RFC 0010 draft; bounded recovery/receipt-chain verification; full lineage/reporting/restore gates open |
| KF-OUTCOME-REPORT-0.1-draft | Authenticated retained outcome delivery and signed acknowledgement/lookup | RFC 0011 draft; native collector/client and actual-etcd duplicate/lost-reply/order tests; no execution authority changes |
| KF-ADMISSION-LINEAGE-0.1-draft | Historical signed admission and outcome export with independently pinned offline verification | RFC 0012 draft; signed-time freshness/Cedar/issuer checks and explicit remaining runtime/history/target-proof gaps |
| KF-CONTROL-BINDINGS-0.1-draft | Observer-attested per-transition control snapshots bound to signed lineage and governance history | RFC 0014 draft; atomic authority retention, exact head/ack/revocation checks and offline verifier; observer correctness/custody/clock trusted |
| KF-CONTROL-HISTORY-0.1-draft | Observer-attested governance history bound to signed admission lineage | RFC 0013 draft; native atomic retention, approved issuer membership, renewal/recreation and offline verifier; operation-bound control state unproven |
| KF-CEDAR-LEAF-0.1-draft | Local Cedar ABI, evidence-rule registration and certificate production | RFC 0005 draft; Rust library and bounded service with static operator pins |
| KF-RESTORE-GATE-0.1-draft | Internal independently retained write-ahead head and restore quarantine | RFC 0016 draft; empty enrollment, gate on runtime ledger transactions and separate software witness tests; pending repair and production deployment open |
| KF-OUTCOME-SUPERVISION-0.1-draft | Internal owned unknown incidents and verified delivery progress | RFC 0017 draft; bounded polling, ordered native collector delivery and shipping supervisor fault cases; production routing/identity and deployment remain open |
| KF-BROKER-AUTHORIZATION-0.1-draft | Internal one-shot broker authorization permit | RFC 0019 draft; trusted provider boundary and original claim/target CAS; actual AS/token mint integration open |
| KF-PINNED-EXCHANGE-IDENTITY-0.1-draft | Protected subject/actor trust snapshot and provider verifier | RFC 0020 draft; Ed25519 subject/ES256 JWT-SVID signatures and bounded atomic refresh; real providers/mint integration open |
| KF-BROKER-TOKEN-HTTP-0.1-draft | Native fixed token-exchange endpoint | RFC 0021 draft; strict form/gateway mTLS and original permit before one mint; enterprise deployment open |
| KF-TARGET-TOKEN-0.1-draft | Signed reference target credential | RFC 0021 draft; closed Ed25519 token with exact permit/grant/root/attempt/gateway/audience/scope/expiry; native SQL target verifies this credential; enterprise custody remains open |
| KF-IDENTITY-REFRESH-0.1-draft | Signed identity publication and protected current-head records | RFC 0022 draft; per-exchange reads, signature/realm/role and retained epoch/digest checks; external publisher/custody and delivery acceptance open |
| KF-POSTGRES-RESERVATION-0.1-draft | Internal one-row reservation dispatch/outcome records | RFC 0023 draft; closed Rust records and atomic PostgreSQL storage/query; RFC 0024 adds native target/query; RFC 0025 adds the fresh SQL leaf path; pilot acceptance remains open |
| KF-POSTGRES-TARGET-HTTP-0.1-draft | Authenticated fixed SQL dispatch and separate retained query | RFC 0024 draft; native mTLS, signed grant/reference token, Unix-socket roles, COMMIT and shipping restart; RFC 0025 fresh SQL mapping/composition; pilot acceptance open |
| KF-POSTGRES-LEAF-0.1-draft | Named SQL CTD parameters, discovery and protected gateway opt-in | RFC 0025 draft; fresh official SDK/admission/issuance/native broker/SQL/recovery; enterprise acceptance open |
| KF-SQL-FAILURE-QUALIFICATION-0.1-draft | Test-only composition and evidence requirements; no new wire interface | RFC 0026 draft; eleven fresh SQL kill/restore/incident cases; same-host generated custody, logical ledger rollback and shared collector storage only |
| KF-POSTGRES-ENROLLMENT-0.1-draft | Local operator report and shared fixed SQL role check; no execution wire change | RFC 0027 draft; effective column/PUBLIC rights, standalone membership and owner/admin scope refusal; explicit read-only native preflight; deployed custody open |
| KF-POSTGRES-CUSTODY-0.1-draft | Explicit local SQL-target file loading/report; no execution wire change | RFC 0028 draft; anchored descriptor/UID/mode snapshots and same-UID peer fixture; deployed custody and other service loaders unqualified |
| KF-POSTGRES-PEER-0.1-draft | Opt-in PostgreSQL kernel peer transport; no execution wire change | RFC 0029 draft; socket mode/path and connected server UID checks before SQL bytes; same-host native tests; separate-account/deployed acceptance open |
| KF-POSTGRES-RESTORE-0.1-draft | Test-only stale SQL restore and storage budget evidence | RFC 0030 draft; actual fenced logical backup restore, lost external commit remains unresolved; no automatic service resume/physical restore acceptance |
| KF-REVIEW-0.1-draft | Trusted library enrollment/challenge/assertion consumption | RFC 0031 draft; narrow ES256 original-byte verification and real-etcd replay/counter state; synthetic authenticator, no hardware/HTTP/HITL admission or lease claim |
| KF-COORDINATION-0.1-draft | Trusted library reservation state | RFC 0032 draft; atomic nested scope/budget conservation and consumed unknown holding; no execution grant/A2A/saga/drain claim |
| KF-A2A-ROOT-RESOLUTION-0.1-draft | Activated read-only reservation root/parent views and AgentCard extension fragment | RFC 0040 draft; native mTLS/DPoP/etcd, immutable reader ACL, scoped views, pinned client and shipping control lifecycle; no child allocation/grants, core task server or independent A2A peer acceptance |
| KF-SOFTWARE-CONFORMANCE-0.1-draft | Reproducible required local software check bundle | RFC 0033 draft; full retained corpus and explicit open gates; no independent peer or released protocol acceptance |
| Python spec/v0.1 | Early facade and simulator concepts | Legacy exploratory profile; not normative for the Rust gateway |
| KF-SHARED-AUTH-0.1-draft | Internal protected DPoP consumption and subject/workload/scope registration | RFC 0018 draft; optional shared path, bounded reference store; real identity lifecycle remains open |
| KF-REVIEW-EVIDENCE-HTTP-0.1-draft / KF-REVIEW-RESULT-0.1-draft | Native review requests and closed result in existing signed Evidence | RFC 0034 draft; protected file loader, server renderer, consumed challenge/enrollment CAS in native admission/issuer and shipping crash/retry; browser/hardware open; native leases in RFC 0035 |
| KF-STATIC-LEASE-HTTP-0.1-draft | Static-only prevalidation and leased final admission using the frozen non-authorizing AdmissionLease record | RFC 0035 draft; exact retained static evidence, fresh JIT, member generations/CAS through native issuer and shipping retry; v0.2 audit in RFC 0036; Node acquisition in RFC 0037; physical/enterprise acceptance open |
| KF-ADMISSION-LINEAGE-0.2-draft / KF-CONTROL-HISTORY-0.2-draft / KF-CONTROL-BINDINGS-0.2-draft | Historical lease static cache and authority membership snapshots, with matching observer wrappers | RFC 0036 draft; atomic admission/issuance retention, independent cache identity/full input verification and shipping offline CLIs; lifecycle/observer/ledger/clock/hardware limits remain |
| KF-AGENT-LEASE-STATE-0.1-draft | Local durable static preparation and permanent authority-start marker | RFC 0037 draft; official SDK/native TLS/etcd workflow; local storage/custody and physical ceremony remain unqualified |
| KF-RESERVED-LEAF-0.1-draft | Native fixed-cost root-level leaf allocation and issuer-signed reservation binding | RFC 0038 draft; allocation/fence and original-attempt claim CAS, stopped-root dispatch and offline statement verification; v0.1 holds unknown, v0.2 adds history/refinement; hierarchical grants/A2A/saga/drain and enterprise acceptance open |
| KF-RESERVED-LEAF-0.2-draft / KF-RESERVED-LINEAGE-0.1-draft | Explicit opt-in atomic budget history, native signed-receipt refinement and reserved admission/outcome/history wrapper | RFC 0039 draft; original-attempt holding without refunds, fixed scope/cost/fence replay, separate observer/role pins and shipping recovery/audit CLIs; bounded history, custody/physical and wider coordination gates remain |

The [RFC index](rfcs/README.md) is the starting point for implementation-oriented
protocol work. Frozen [v0.9 schema](../spec/kedgeflow.schema.json) and paper records
remain unchanged. Draft supplements live under `spec/drafts` and cannot be used
to claim released compatibility. Read the [review](IMPLEMENTATION_REVIEW_2026_10_10.md)
for the gap between executable coverage and architectural claims.

[RFC 0015](rfcs/0015-process-crash-qualification.md) qualifies process termination
and conserved recovery for existing profiles. It introduces no new wire profile
or production crash-control API; its nine Unix tests use shipping binaries in
explicit unmanaged fixture mode with a software broker/target.

[RFC 0026](rfcs/0026-sql-failure-qualification.md) composes fresh SQL authority and
shipping process failures with the restore witness and retained incident delivery.
Its [scope and limits](SQL_FAILURE_QUALIFICATION.md) remain separate from enterprise
acceptance and physical/stale SQL restore.
