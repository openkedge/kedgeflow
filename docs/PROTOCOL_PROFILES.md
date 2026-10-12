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
| KF-CEDAR-LEAF-0.1-draft | Local Cedar ABI, evidence-rule registration and certificate production | RFC 0005 draft; Rust library and bounded service with static operator pins |
| Python spec/v0.1 | Early facade and simulator concepts | Legacy exploratory profile; not normative for the Rust gateway |

The [RFC index](rfcs/README.md) is the starting point for implementation-oriented
protocol work. Frozen [v0.9 schema](../spec/kedgeflow.schema.json) and paper records
remain unchanged. Draft supplements live under `spec/drafts` and cannot be used
to claim released compatibility. Read the [review](IMPLEMENTATION_REVIEW_2026_10_10.md)
for the gap between executable coverage and architectural claims.
