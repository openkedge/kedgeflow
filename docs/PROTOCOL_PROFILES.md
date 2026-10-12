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
| KF-TARGET-TOKEN-0.1-draft | Signed reference target credential | RFC 0021 draft; closed Ed25519 token with exact permit/grant/root/attempt/gateway/audience/scope/expiry; actual target effects remain M6 |
| Python spec/v0.1 | Early facade and simulator concepts | Legacy exploratory profile; not normative for the Rust gateway |
| KF-SHARED-AUTH-0.1-draft | Internal protected DPoP consumption and subject/workload/scope registration | RFC 0018 draft; optional shared path, bounded reference store; real identity lifecycle remains open |

The [RFC index](rfcs/README.md) is the starting point for implementation-oriented
protocol work. Frozen [v0.9 schema](../spec/kedgeflow.schema.json) and paper records
remain unchanged. Draft supplements live under `spec/drafts` and cannot be used
to claim released compatibility. Read the [review](IMPLEMENTATION_REVIEW_2026_10_10.md)
for the gap between executable coverage and architectural claims.

[RFC 0015](rfcs/0015-process-crash-qualification.md) qualifies process termination
and conserved recovery for existing profiles. It introduces no new wire profile
or production crash-control API; its nine Unix tests use shipping binaries in
explicit unmanaged fixture mode with a software broker/target.
