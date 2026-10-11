# RFC 0001: Single-action authority and trust

- Status: **Draft**, 10 October 2026
- Proposed supplement: `KF-LEAF-CONTROL-0.1-draft`
- Baseline: runtime `769c0a8`; immutable v0.9 / KF-JSON-0.2
- Milestone: M1; implementation increments M2–M4
- Owners/reviewers: unassigned

## Problem and scope

The runtime consumes preissued grants but does not yet implement the complete
admission-to-issuance chain. This series defines one nondelegated operation on
one resource incarnation, one `version_eq` predicate, Level A fencing and
dispatch-bound completion. A claim consumes one allowance. Target completion
requires separate correlated evidence. Saga budgets, physical drain and shared
capacity policy remain outside this executable slice.

## Roles and authority

The Policy Authority publishes policy and authorized obligation definitions.
The Resource Registry binds actions, incarnations, ownership, adapter contracts
and writer coverage. Evidence Providers attest approved questions. The Admission
Controller evaluates verified facts and policy and signs an AdmissionCertificate.
The Grant Authority independently validates admission, narrows constraints and
persists one allowance. The Execution Gateway claims it before obtaining a target
credential. The Resource Adapter enforces the declared target guard and records
target correlation. The Outcome Service retains observations and reconstruction
links. The Agent Adapter proposes actions and carries records; it cannot publish
policy, install control, issue authority or establish target completion.

Co-located roles MUST have distinct authorized operations and role-scoped keys.
A key ID is a lookup label, never authority to fetch a new trust anchor. Trusted
configuration binds key → role → tenant/action/audience scope → validity and
revocation state. Workload identity comes from verified mTLS; subject/delegation
comes from independently configured token issuers and DPoP validation. Request
fields cannot select issuer, registry, broker, target, trust store or executable.

The deployment claim requires removal of equivalent target credentials and
alternate mutation paths from agents and descendants. Administered break-glass
writers must be declared in coverage. A local demo does not establish this.

## Identity and records

All signed records retain KF-JSON-0.2 canonicalization, domain separation and
frozen schema/kind binding. Transport parses strict JSON before verification.
Signature validity is followed by closed payload and semantic validation. Times
are integer Unix milliseconds; expiry is exclusive. Evidence observed in the
future, expired keys or uncertain validity fail closed. A clock-uncertainty policy
must be configured before production; widening validity silently is forbidden.

The stable logical identity is `(tenant, authenticated subject, workload, proposal
qid)`. The authority derives a domain-separated digest from these fields. It
excludes transport request ID, certificate ID, root ID, nonce, issuance timestamp,
policy epoch and caller-selected retry token. Retries and recertification of that
operation cannot mint another allowance. A changed action requires a new proposal
and admission; an agent can propose many operations, but policy must independently
admit each and account for any aggregate limits.

The issuance record binds this identity to exact proposal/delegation/certificate
and approved constraints, policy/ownership, persisted signed grant and root.
Conflicting semantic bindings for an existing identity refuse. RFC 0003's first
implementation deliberately treats a changed certificate as a conflict; safe
recertification/replacement requires a later explicit transition preserving the
same allowance and consumed state.

## Common errors and retries

Draft codes: `invalid_record`, `unauthenticated`, `forbidden`,
`unsupported_profile`, `stale_control`, `missing_evidence`, `admission_denied`,
`issuance_conflict`, `authority_consumed`, `authority_unavailable`,
`outcome_unknown`. Responses expose only scope-authorized identifiers and facts.
Diagnostic text cannot carry credentials or private evidence.

Unavailable dependencies never authorize a local fallback. A lost write reply is
ambiguous: retry the same stable operation or perform an authorized query. Do not
invent another operation identity to resolve uncertainty. A timeout never proves
that an allowance was not consumed or that a target effect did not happen.

## Versions and acceptance

Draft control requests use the separate
[leaf-control schema](../../spec/drafts/leaf-control-v0.1.schema.json). It defines
proposed operation/result carriage; the concrete HTTP binding and authentication
configuration remain review decisions. Discovery must expose exact profiles and
limits; unknown profiles fail closed. No v0.1 Python facade claim automatically
applies to the Rust profile. No frozen v0.9 artifacts change during this work.

Acceptance: wrong-role signatures, cross-tenant/key scopes, changed identities,
unknown fields and unsupported contracts refuse; one logical operation has one
allowance across replicas and roots; independently authorized status has no effect.
Enterprise identity lifecycle and isolation acceptance remain M5/M6 gates.

## Open decisions

- Key distribution/rotation and revocation store, tenant namespace enforcement.
- Maximum clock uncertainty and validity budgets per deployment.
- Owner assignment and external protocol review before Accepted status.

Canonicalization reference: [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).
