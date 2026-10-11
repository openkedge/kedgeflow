# RFC 0005: Cedar leaf policy and durable certificate production

- Status: **Draft**, 11 October 2026
- Profile: `KF-CEDAR-LEAF-0.1-draft`, with frozen `KF-JSON-0.2` certificates
- Milestone: M2b
- Owners/reviewers: unassigned

## Scope and trust boundary

This supplement specifies the local policy ABI and admission persistence used by
[RFC 0003](0003-admission-and-issuance.md). It supports one mock resource and one
verified witness per required obligation. Trusted authority configuration supplies
the policy source, required rules, provider keys and installed pins. Agents cannot
provide policy expressions, Cedar entities, optional context fields or signers.
Control publication/installation and public service authentication remain M2 work.

The library uses Cedar 4.7.1 with extensions disabled. It is the newest published
Cedar release compatible with the repository's Rust 1.88 requirement; 4.8 and
later currently require 1.89. A compiler/dependency upgrade needs qualification.
Source: [official crate metadata](https://docs.rs/crate/cedar-policy/4.7.1).

## Registered rules and policy identity

An installed evidence requirement fixes obligation ID, predicate digest, stage,
execution relevance, provider identity/version, role-scoped verifying keys,
question reference, closed local result schema/reference, maximum age and an
ordered list of server-selected comparisons. Supported comparison records are:

| `kind` | Fields | Result |
| --- | --- | --- |
| `integer_at_least` | `field`, `minimum` | Integer value meets minimum |
| `string_equals` | `field`, `expected` | Exact string equality |
| `boolean_equals` | `field`, `expected` | Exact Boolean equality |

Wrong types or missing fields are unknown; false comparisons are violated. Every
comparison must be satisfied before an opaque verified input is constructed.
The provider's `satisfied` result field cannot select or override these rules.

In this supplement:

- `predicate_digest = digest("evidence-predicate", predicates)` with tagged
  comparison objects as above, preserving list order.
- `obligation_manifest_digest = digest("obligation-manifest", {profile,
  obligations})`, where `profile` is this draft ID and `obligations` is an object
  keyed by obligation ID. Each value contains `obligation` (predicate digest,
  stage, execution relevance), `provider_id`, `provider_version`, `keys`,
  `question`, `result_schema_ref`, `result_schema`, `max_age_ms`, and `predicates`.
  `keys` maps key IDs to lowercase hex Ed25519 public keys. References contain
  `id`, `schema`, `digest`. Result-schema digests follow RFC 0003.
- The policy definition contains `tenant`, `policy_id`, exact `cedar` source,
  `obligation_manifest_digest`, and positive `max_certificate_lifetime_ms`.
  `PolicyRef.digest = digest("policy", {profile, definition, schema})` where
  `schema` is the parsed local Cedar ABI below. `PolicyRef.id` matches the
  definition ID and its positive epoch comes from authorized installation.

Changing rules, provider keys, schemas, source, ABI or certificate lifetime
changes the pin. These rules define a new draft registration profile; they do
not reinterpret the frozen example fixtures' registration identities.

## Cedar request ABI

The local [Cedar schema](../../spec/drafts/cedar-leaf-v0.1.schema.json) is Cedar
schema JSON, not a JSON Schema document. Policies must parse and pass Cedar
strict validation against it. Templates are unsupported. The action is
`KedgeFlow::Action::"admit"`. Subject and Resource entities have no caller-supplied
attributes or ancestry.

Principal ID is `digest("cedar-subject", {tenant, subject})`; resource ID is
`digest("cedar-resource", {tenant, resource})`, including incarnation. Both IDs
are authority-derived. The context is closed and constructed from verified
inputs and authority time:

| Type | Context fields |
| --- | --- |
| String | `tenant`, `subject_issuer`, `subject_id`, `workload_id`, `qid`, `action_id`, `action_version`, `descriptor_digest`, `parameters_digest`, `resource_id`, `resource_incarnation`, `audience`, `conflict_domain`, `delegation_digest`, `proposal_digest`, `evidence_manifest_digest`, `obligation_manifest_digest` |
| Long | `policy_epoch`, `ownership_epoch`, `now_ms` |
| Set of String | `obligation_ids` |

No raw evidence result, caller assertion or independently supplied Cedar context
enters evaluation. This ABI permits policy over the verified operation and
complete required discharge set; richer evidence facts require another ABI.
For example, an installed policy could require:

```cedar
permit(principal, action == KedgeFlow::Action::"admit", resource)
when {
    context.tenant == "tenant-42" &&
    context.workload_id == "spiffe://test/agent" &&
    context.obligation_ids.contains("capacity")
};
```

Default deny and forbid precedence apply. Any evaluation error refuses the
whole decision, even when another policy permits. This application rule checks
Cedar diagnostics explicitly because Cedar's usual algorithm skips errored
policies. See [Cedar authorization](https://docs.cedarpolicy.com/auth/authorization.html)
and [policy validation](https://docs.cedarpolicy.com/policies/validation.html).

## Certificate production and persistence

`AdmissionController::prepare` accepts only `VerifiedAdmissionInputs` and a
trusted clock. It requires matching tenant/policy/obligation pins, fresh inputs,
a permit without diagnostics and an admission signing key distinct from every
input record role. It generates a cryptographically random certificate ID and
copies exact constraints and verified witness references/times. It fixes one
attempt, no saga and no lease. Validity ends at the minimum of verified-input
validity and admission time plus the installed certificate lifetime. The signed
certificate must pass the unchanged frozen certificate schema.

The returned candidate is opaque. `EtcdLedger::admit` MUST persist it before
the certificate is returned to a client. It uses the same stable operation key
as issuance (`tenant`, subject, workload, qid) in a separate global admission
namespace. Its binding digest covers verified context, action/resources,
parameter/predicate/adapter bindings, input validity end and witness references
and times. Candidate IDs, signature, verification time and derived TTL are
excluded; the policy digest already binds the installed TTL definition.

One etcd transaction compares admission-key absence and current policy/ownership,
then stores the original canonical signed certificate, digest, binding and times.
It creates no root, grant, nonce, credential or execution allowance. After a
failed compare, a linearizable read under current policy/ownership may return
only an existing matching binding. Concurrent replicas and unchanged retries
return that exact original certificate. Lost commit replies are unavailable;
retry resolves the retained record without rewriting it.

Changed bindings conflict. Expired originals remain retained and refuse renewal
under the same operation identity, even if a new candidate has later validity.
No automatic deletion or allowance restoration occurs. A new operation requires
a newly identified proposal and fresh admission. Revoked policy/ownership blocks
both creation and duplicate return. Descriptor installation and explicit scoped
revocation serialization remain RFC 0002 implementation work.

## Acceptance and remaining work

The implementation maps to `policy.rs`, verified input validation in `admission.rs`
and `EtcdLedger::admit`. Tests cover strict typing/source pins, default deny,
forbid, runtime diagnostics despite a permit, rule/key/freshness pins, distinct
signers, expiry, 16 concurrent preparations returning one certificate, unchanged
retry, changed evidence, stale control state, and certificate → issuance → one
claim → consumed retry on real etcd. See [verification](../../results/verification/rfc-m2-cedar-2026-10-11/README.md).

Remaining M2 gates: authenticated admission/issuer endpoints, independently
provisioned trust and installed-control ingestion, issuer-owned grant IDs/fences,
control APIs and revocation races. Fixtures establish software mechanics with
synthetic authenticated identities, not enterprise identity enrollment or target
truth. Public wire/schema binding and owner acceptance remain open; this draft
does not declare live service or independent interoperability completion.
