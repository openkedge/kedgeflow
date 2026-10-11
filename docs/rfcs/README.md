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
   Static pins still need live installed-control ingestion and target bootstrap.
3. M2c: authorized publish/register/revoke/install services and race tests.
4. M3: live client admission flow and scope-authorized status/replay resolution.

M2's full service lifecycle exit gate remains open. Prefer `validate_inputs` with an opaque
verified input chain. The older trusted-context API remains for authority callers
and tests. Neither privileged library API is an agent-callable endpoint. See the
[fresh service verification](../../results/verification/rfc-m2-service-2026-10-11/README.md).
