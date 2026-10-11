# RFC 0003: Admission and atomic single-action issuance

- Status: **Draft**, 10 October 2026
- Profile: KF-JSON-0.2 records; `KF-LEAF-CONTROL-0.1-draft` carriage
- Milestone: M1 → M2
- Owners/reviewers: unassigned

## Contract and trust

Admission consumes a frozen signed Proposal, current signed CTD, policy/obligation
definitions, EvidenceManifest and referenced witnesses. The service independently
authenticates caller subject/workload/delegation, obtains installed policy and
registry state and verifies each signer in its role and scope. Agent-supplied
facts, URLs and result expressions never become policy inputs without validation.

Evidence requests bind an approved question/schema, proposal digest, resource
incarnation/state and freshness deadline. Evidence responses bind provider
identity/version, question reference, result schema, observed/expiry time and
provenance. Validate provider permissions and closed result schema locally;
never fetch arbitrary caller-selected schemas. Manifest references must resolve
to exact verified records with matching obligation and expiry. Human witnesses
use their separately approved canonical review contract; fixture signatures do
not establish production enrollment.

Admission verifies exact parameters against the CTD's pinned local schema;
recomputes parameter/descriptor/delegation/manifest digests; checks action,
incarnation, ownership, audience and completion contract. Required obligations
have `satisfied`, `violated` or `unknown` results. Missing, expired, contradictory,
malformed or untrusted evidence is unknown/violated and cannot admit. Required
obligation coverage comes from installed policy, never a caller's list.

Use Cedar first with server-constructed verified inputs. Evaluation diagnostics
deny; a permit does not bypass discharge checks. Only complete satisfied coverage
produces a signed AdmissionCertificate. Certificate validity is bounded by
delegation, policy/descriptor, constraints and witness freshness. Admission is
not an execution claim and does not consume or mint target credentials.

## Issuer verification

The Grant Authority is independently authorized. It verifies the complete chain
and current installed control state, then issues a narrower ExecutionGrant.
Compare certificate/proposal/delegation/descriptor/policy/ownership digests and
identity, required obligation coverage and exact constraint digest. Grant action,
resources, parameters, predicate, adapter, audience and completion must match the
approved scope. The leaf slice fixes `max_attempts=1`, no lease reuse or saga, no
parent grant and generation 1 at initial issuance. The issuer chooses root, gid,
nonce and fence; agents cannot choose them. All temporal bounds intersect and
expiry is exclusive. Final claim/dispatch checks still apply after issuance.

## Stable deduplication and persistence

Derive `issuance_key = digest("issuance-key", {tenant, subject, workload_id, qid})`
from independently verified proposal and authenticated context. Root IDs and
transport request IDs cannot affect it. Retain the key across certificate expiry,
claim, failure and outcome retention; expiring a grant never makes a key reusable.
For the first increment, changed certificate/proposal bindings under the same
operation identity are conflicts, even if a new certificate is valid.

One etcd transaction MUST compare absence of the global issuance key, candidate
root/grant/nonce, current policy and ownership; it writes the issuance record,
unclaimed root and grant digest together. The issuance namespace is above conflict
domains so moving a request between domains cannot evade deduplication. Store
the original canonical signed envelope and binding digest durably.

On compare failure, atomically read the existing issuance with current policy
and ownership. Return its exact envelope only for matching identity/binding and
current authority context. Changed semantic context refuses. Missing issuance
after a failed creation is refusal/unavailability, never permission for an
unrelated root. A duplicate read performs zero issuance writes and does not
restore consumed authority. The original grant may later be consumed; callers
must resolve execution separately. Concurrent replicas with fresh candidate IDs
all converge on one persisted grant.

## First implementation increment and limitations

`issuance.rs` implements closed typed AdmissionCertificate fields, a separately
configured tenant-scoped admission-role key set, pinned proposal/delegation/descriptor/policy/
obligation context, fresh satisfied discharges and exact grant constraints.
`EtcdLedger::issue_admitted` accepts its opaque validated candidate and performs
the atomic transaction above. The candidate's signature/executable profile is
verified through the configured issuer `GrantVerifier` before storage.
The persistence boundary rechecks candidate validity using an authority clock,
so retaining a validated candidate past expiry cannot refresh its authority.

The original entry point trusts an **authority-side AdmissionContext** supplied
by its caller. A stronger entry point now validates an independently verified raw
record chain as described below. A separate producer now evaluates Cedar before
certificate persistence. These verifiers are library prerequisites; the
[HTTP supplement](0006-leaf-control-http.md) now composes them with authenticated
endpoints, raw-chain persistence and authority-owned grant/fence production.
The existing trusted `AuthorityLedger::issue` remains for the legacy test path;
it does not acquire certificate verification by implication. Agents must never
reach either privileged ledger API. M2 is complete only after the full service
exit tests in the roadmap pass.

Acceptance for this increment: wrong admission key/role, missing fields,
unknown fields, bad digests, missing/duplicate/stale discharges, broadened
constraints and expired certificates fail before mutation. Real-etcd concurrency
must produce one grant across fresh roots; rebinding one qid conflicts; retry
after claim returns the original envelope without another allowance; stale policy
blocks creation and duplicate return. These library checks now pass on real etcd.

## M2b input-chain increment — 11 October 2026

`schema.rs` validates all frozen record fields and formats from the embedded
v0.9 schema, with external file/network retrieval disabled. Application schemas
must be locally registered closed objects. In this draft increment, registered
result-schema references bind `digest("result-schema", local_schema)`; this does
not change the frozen fixtures or their registered reference values.

`AdmissionTrust::verify_inputs` takes authenticated Identity, role-scoped keys,
workload assignment, current descriptor/policy/ownership pins and approved
evidence requirements from authority configuration. It verifies signed Proposal,
CTD, WitnessManifest and Evidence records; exact delegation/subject/workload,
parameters and descriptor digests; one incarnation/version guard and baseline
state; complete manifest coverage; approved provider/question/result schema;
observed times, expiries and configured maximum ages. Server-selected ternary
comparisons evaluate the validated evidence result. A provider's `satisfied`
label cannot override a violated or unknown required comparison.

Supported inputs remain the mock leaf profile: `node` and positive integer
`expected_version`, one baseline resource, one witness per required obligation,
no provenance graph, human witness, lease, workflow/dependencies or compensation.
Evidence assertions remain statements by trusted providers; they do not prove
the target's final state or establish deployed writer coverage independently.

`IssuanceVerifier::validate_inputs` accepts the opaque result and additionally
binds certificate constraints and every discharge to those verified inputs.
The validity intersection covers delegation, baseline, proposal age, evidence
expiry and evidence age. Delayed/expired inputs cannot supply fresh issuance.
The original trusted-context API remains available and does not inherit this
stronger cross-record proof automatically.

Fresh tests cover authentic but changed records, unapproved/stale/unknown evidence,
manifest substitution, certificate/grant changes, disabled schema retrieval,
all thirteen unchanged frozen vectors and verified-chain issuance/claim/reuse
on real etcd. See [verification](../../results/verification/rfc-m2-2026-10-11/README.md).

The [Cedar supplement](0005-cedar-leaf-admission.md) now pins the actual evidence
rules and policy source/ABI, evaluates only opaque verified inputs and produces
signed certificates. Admission persistence returns the original certificate for
unchanged retries, preserving issuance's stable certificate binding. Changed
evidence conflicts and an expired original cannot be renewed under the same qid.

RFC 0006 now implements authenticated live admission/issuer endpoints, atomic
raw-chain retention and revalidation, issuer-owned IDs/nonces and a durable
tenant/resource/incarnation fence counter within one ledger namespace.
Remaining M2 work: live installed-control ingestion, authorized control
publication/install/revoke APIs and race qualification. Target bootstrap, writer
coverage and restore barriers remain required before a real-target claim.

## Open decisions

- Full chain trust provisioning and accepted provider/Cedar registration profile.
- Counter bootstrap, writer coverage, retention and recovery limits for real targets.
- Explicit same-operation replacement protocol after safe fresh admission.
