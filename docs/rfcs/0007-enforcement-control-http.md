# RFC 0007: Signed administrative control and installed-state enforcement

- Status: **Draft**, 11 October 2026
- Profile: `KF-ENFORCEMENT-CONTROL-0.1-draft`
- Milestone: M2c; next integration milestone M3
- Owners/reviewers: unassigned

## Scope and trust

This is the bounded HTTP implementation of [RFC 0002](0002-enforcement-control.md).
It supplies policy publication, signed descriptor registration, expected-version
installation, enrolled-gateway acknowledgements, permanent scoped revocation and
operator query. It adds a separate [draft schema](../../spec/drafts/enforcement-control-v0.1.schema.json);
the frozen paper and KF-JSON-0.2 records remain unchanged. One administrative
listener serves one approved tenant, conflict domain, action and resource.

`kf-governance` uses native verified mTLS, fixed HTTPS endpoint/Host/Origin checks,
POST and exact `application/json`. Bodies are limited to 1 MiB and a ten-second
read. The native transport limits connections to 64; another 64-operation limit
stays held after HTTP disconnect. Strict JSON and a locally embedded schema
reject duplicate keys, unsafe numbers, unknown fields and unsupported variants.
Schema retrieval from caller-selected files or URLs is disabled.

For publication, registration, installation, revocation and query, authorization
requires the configured subject, workload certificate and distinct operation
scope, plus a pinned issuer's access token and URL/token-bound DPoP proof.
Mutations also require the corresponding administrative record signing role.
Those keys are distinct from input, admission, issuer and gateway-acknowledgement
keys. Agent workload assignments cannot become administrator assignments.
Co-location may share a compromise domain; key separation does not prove isolation.

Acknowledgement is a component operation: it requires the enrolled gateway's
verified workload certificate and record signature. It uses no human delegation
token. Replaying an unchanged acknowledgement cannot extend its signed lifetime.
Key enrollment/rotation, shared token proof replay and production RBAC provisioning
remain M5 work. etcd and private files must have independently administered ACLs.

## Closed carriage and signatures

An apply request has `profile`, `operation: "apply"`, `request_id`, and `record`
(the exact signed JSON envelope serialized as a string). A query has `profile`,
`operation: "query"` and `request_id`. The service's configured scope determines
lookup; callers cannot supply another namespace, endpoint or component.

Signed envelopes contain exactly `profile`, `kind`, `key_id`, `payload`, and
`signature`. The signature is Ed25519 over the UTF-8 bytes
`KedgeFlow:KF-ENFORCEMENT-CONTROL-0.1-draft` followed by NUL, followed by canonical
JSON of `{profile, kind, key_id, payload}`. Signatures use unpadded base64url.
Record identity is `digest("enforcement-record", full_signed_envelope)` using the
existing safe-integer canonical digest function, including the signature and
this new profile. These domains do not reinterpret a frozen record kind.

| Kind | Closed payload and signer |
| --- | --- |
| `publish_policy` | Approved `registration`, exact Cedar `definition`; Policy Authority |
| `register_descriptor` | Approved `registration`, signed frozen `descriptor`; registry administrator plus independently verified CTD signer |
| `install` | `registration`, `revision`, `expected_revision`, exact policy/descriptor publication digests; coordinator |
| `acknowledge` | Installation digest/revision, component/workload, coverage, installed/expiry times; enrolled gateway |
| `revoke` | Tenant/domain, target, revision 1, reason digest; assigned revocation authority |

The registration binds tenant; exact conflict domain, action/descriptor digest,
resource/incarnation, gateway audience, adapter contract and predicate; policy,
ownership, obligation and trust pins; issuer public keys; and one required
acknowledger with its key and positive lifetime capped at 60 seconds.
`trust_digest = digest("enforcement-trust", {tenant, proposal_keys, registry_keys,
manifest_keys, obligation_manifest_digest, admission_keys, issuer_keys})`.
Each key map contains key IDs and lowercase hex public keys. The obligation pin
already binds approved provider keys, questions, schemas and rules under RFC 0005.

This first service accepts only its operator-approved registration/source.
Changing policy, descriptor or trust requires an approved operator snapshot and
the appropriate new epochs/revision; signed caller-selected policy does not
replace configured trust automatically. The selected execution contract remains
one mock resource, `version_eq`, Level A fencing and dispatch-bound completion.

HTTP 200 returns `applied` with kind/digest/exact retained record, or `snapshot`
with nullable retained installation and acknowledgement records. Query does not
assert that the snapshot is ready, current enough, or target-covered. Errors are
closed `failure` envelopes: 400 `invalid_record`/`unsupported_profile`, 401
`unauthenticated`, 403 `forbidden`/`control_refused`, and 503
`authority_unavailable`. Endpoint/method/media-type rejection follows the native
transport's status; owned-task failure is 500 `authority_unavailable`. Application
responses use `Cache-Control: no-store`. TLS rejection can precede any envelope.

## Publication and installation ordering

Publication retains immutable signed records and a current pointer in one etcd
transaction. Compare-and-swap protects the pointer. Tenant, resource ID, action ID
and policy ID cannot be reassigned in that domain. Policy/ownership epochs never
decrease. Equal policy epochs with changed policy/rule/trust pins refuse; equal
ownership epochs with changed descriptor/incarnation refuse. Exact current-record
repetitions are idempotent. A confirmed compare conflict may require an unchanged
retry; an ambiguous transport reply is unavailable, never permission to invent a
different record. Superseded immutable records remain retained.

Installation references the exact current, matching publications. The first
revision is 1 with expected revision 0; subsequent revisions advance by exactly
one. One CAS compares the old installation, current publications, policy and
ownership floors, and domain-revocation absence. It atomically writes the signed
installation, installed policy/ownership and a permanent managed-domain marker.
It produces no grant or execution allowance. Exact unchanged installation retry
retains its original record and acknowledgement; stale/conflicting revisions
refuse. A new revision immediately makes an older acknowledgement unusable.

The marker prevents the legacy grant-shaped publication port from overwriting
managed control. Legacy direct issuance, unallocated certificate issuance and
replacement ports also refuse in managed domains. Unmanaged fixtures remain
explicitly supported. Production control/gateway configurations set
`require_control: true`, which refuses even before the first marker exists.
There is no endpoint to uninstall the marker or delete consumed authority.

## Gateway acknowledgement and authority transitions

The native gateway verifies the coordinator's installation signature against its
configured public keys. It compares the installed action/resource/domain,
adapter/predicate identity, audience and issuer key set with its actual tool and
verifier configuration. It checks its enrolled component/workload and private
acknowledgement key. Only then can it sign `coverage: "gateway_control_checks"`.
This does not assert target guards, writer coverage, availability, or OS isolation.

When enrollment is configured, `kf-proxy` acknowledges before accepting calls
and renews at one third of the installed lifetime (100 ms–10 s bounds). Check-only
mode validates local key/TLS material and publishes nothing. Failed renewal
does not extend an acknowledgement; current-state reads refuse when it expires.
A changed supported revision can be acknowledged; an incompatible scope refuses
until the operator installs matching gateway configuration. One required gateway
is supported; multi-component coverage/adapter acknowledgements remain future work.

Acknowledgement persistence verifies signature, exact installation identity,
component/workload, exclusive expiry and bounded lifetime. It compares the current
installation and old acknowledgement. Refresh time cannot go backward or repeat
with different content. Installation/acknowledgement/managed-marker values and
revocation absence are then compared in the **same transaction** as admission,
fence allocation, issuance, claim and final dispatch authorization. Changed state
between lookup and mutation refuses. Reads are linearizable and quorum failure
has no cache fallback. Admission/issuer configuration additionally pins the
installed trust digest. Duplicate issuance checks the original retained root and
grant, rather than the newly generated candidate IDs.

Freshness is evaluated with the authority clock before transactions, with native
RPC deadlines and final gateway validity checks. Production clock uncertainty,
process-pause budgets and expiry qualification remain deployment gates; an
acknowledgement is not an atomic target-time lease or a target commit deadline.

## Revocation, outcomes and remaining gates

Targets are the whole configured domain, one root ID, or one grant ID. This slice
stores immutable revision-1 tombstones with signed issuer and reason digest.
Exact retries are idempotent; conflicting replacements or unrevocation refuse.
Domain revocation permanently stops new authority in that domain. Resuming under
a new domain does not recycle operation IDs, old roots or resource fences.

Revocation compares the current installation and tombstone absence. Admission/
issuance/claim/dispatch compare the corresponding absence in their own CAS.
Whichever transition linearizes first determines permission. If dispatch
authorization wins, revocation cannot retract an already possible send. No target
effect is inferred from either result. Existing attempt/status/outcome records
remain retained and can be resolved without a new claim or allowance refund.

Eight new tests cover native administrative authentication, signed/schema/role
refusals, publication/installation, missing/expired/old acknowledgements, native
gateway renewal, the combined native admission/issuer path, consumed retention,
and revocation races with issuance, claim and dispatch. See
[verification](../../results/verification/rfc-m2-control-2026-10-11/README.md).
Software enrollment and one-host etcd do not establish enterprise deployment.

The bounded M2c software path is delivered. [RFC 0008](0008-agent-replay-and-status.md)
now supplies M3a's live Agent Adapter, coherent delegation and retained attempt
status. M3b operation lookup and wider client/provider fault qualification remain.
Owner acceptance, dynamic trust lifecycle, multi-component acknowledgements,
authorized counter bootstrap, legacy-data migration, restore barriers and real
target coverage remain open. A stale backup cannot be qualified by replaying
these installation records; M4/M6 must supply the restore/fencing barrier.
