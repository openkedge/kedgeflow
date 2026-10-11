# RFC 0006: Authenticated leaf admission and issuer HTTP binding

- Status: **Draft**, 11 October 2026
- Binding: `KF-LEAF-HTTP-0.1-draft`
- Wire profile: existing `KF-LEAF-CONTROL-0.1-draft`; frozen `KF-JSON-0.2` records
- Milestone: M2b; control lifecycle continues in M2c
- Owners/reviewers: unassigned

## Scope and authentication

This supplement implements the admission and issuance operations from
[RFC 0003](0003-admission-and-issuance.md), using the Cedar registration in
[RFC 0005](0005-cedar-leaf-admission.md). The binding name identifies this draft
transport contract; the JSON `profile` remains `KF-LEAF-CONTROL-0.1-draft`.
The existing [carriage schema](../../spec/drafts/leaf-control-v0.1.schema.json)
is unchanged. Its status operations remain unimplemented.

One native HTTPS listener exposes two operator-pinned, distinct paths, typically
`/admit` and `/issue`. Both require verified workload client certificates, a
pinned issuer's EdDSA access token and a DPoP proof binding that token to POST
and the exact endpoint URL. Workload identity comes from verified TLS state;
caller identity headers are not trusted. Host, path and Origin checks use the
existing endpoint policy. Browser origins are refused. Queries are unsupported.

The endpoints share a configured delegation audience and authorization-server
issuer. DPoP's `htu` differs by endpoint. This preserves the proposal's exact
delegation digest across admission and issuance; a changed token or delegation
cannot silently replace the retained binding. The grant separately names the
configured gateway audience. Connecting this delegation contract to a live
Agent Adapter and gateway is an M3 integration gate.

Authority configuration assigns an allowed subject set, one workload, tenant,
and three distinct scopes: admission permission, issuance permission and the
action permission checked in the signed proposal chain. Agent permissions do
not expose administrative ledger methods. Proposal, registry, manifest,
provider, admission and issuer signing roles are checked for incompatible key
reuse. Co-location still shares a process compromise domain.

## Requests, bounds and results

Requests use POST and exact `Content-Type: application/json`. The complete body
is limited to 1 MiB and a ten-second read; identifiers are limited to 1,024 UTF-8
bytes, each signed-record string to 1 MiB, and witnesses to 64. Strict JSON
parsing rejects duplicate keys, unknown fields and unsafe numbers. Signed
records are embedded as strings and independently parsed, schema-checked and
verified. There are no caller-selected fetches, policy expressions, root IDs,
grant IDs, nonces or fences.

| Path | Request operation and additional fields | Successful response |
| --- | --- | --- |
| Configured admission path | `admit`: `proposal`, `descriptor`, `manifest`, `witnesses` | HTTP 200 `admitted`, exact retained `certificate` |
| Configured issuance path | `issue`: `proposal`, `certificate` | HTTP 200 `issued`, `issuance_key`, `reused`, exact retained `grant` |

Every request also contains `profile` and `request_id`; responses echo the
identifier when available. Request IDs are correlation only. All application
responses use JSON and `Cache-Control: no-store`. The failure envelope contains
`operation: "failure"` and a closed schema code; unavailable request identifiers
are represented by the literal `"unavailable"`.

The native server caps simultaneous connections at 64 with existing TLS/header
deadlines. A separate 64-operation limit remains held by an owned task after
HTTP disconnect, preventing abandoned requests from bypassing that bound.

| HTTP status | Condition / code |
| --- | --- |
| 400 | Malformed record / `invalid_record`; unsupported profile / `unsupported_profile` |
| 401 | Invalid token/proof / `unauthenticated` |
| 403 | Caller permission / `forbidden`; admission refusal / `admission_denied`; issuance refusal / `issuance_conflict` |
| 404 | Unconfigured route / `unsupported_profile` |
| 405 / 415 | Wrong method / media type, `invalid_record` |
| 503 | Ledger, replay-capacity or other authority unavailability / `authority_unavailable` |
| 500 | Owned operation task failure / `authority_unavailable` |

Endpoint rejection uses its configured HTTP status and `invalid_record`.
TLS/HTTP transport rejection may terminate before an application envelope.
This slice uses coarse refusal codes: it does not expose a structured
NeedsEvidence response, administrator details or a status service.
DPoP replay storage remains bounded and process-local. Shared replay state,
administered enrollment and rotation are M5 work.

## Durable admission and chain lookup

Admission verifies the complete signed input chain and required evidence before
Cedar evaluation. One etcd transaction compares current policy/ownership and
absence of both global admission records, then stores the canonical certificate
and the original raw signed proposal/descriptor/manifest/witness packet together.
The packet is retained evidence, not a trusted cache of verified facts.

Unchanged admission retries return the original certificate with its original
expiry. Changed evidence conflicts; expired certificates cannot be renewed under
the same operation identity. On issuance, the service first authenticates the
caller and verifies the signed proposal's identity/delegation to derive the
global operation key. Only then does it read the retained certificate and chain.
The supplied certificate must match the retained canonical envelope; JSON
whitespace differences are harmless. Proposal payload digests must match.
The issuer revalidates every retained signed input with current trust, identity
and time, then binds every certificate constraint and discharge to that chain.

Missing or damaged chains refuse. Records created before atomic chain retention
are not automatically backfilled or reissued. Any migration needs authorized
provenance and unchanged operation/allowance retention, or a new operation.
Retention must protect the certificate, chain, issuance and fence records through
the replay/outcome horizon. This implementation does not garbage-collect them.

## Authority-owned identifiers and fences

The issuer generates cryptographically random 256-bit root IDs, grant IDs and
nonces, fixes generation 1 and one attempt, and signs a schema-valid leaf grant.
Full chain and grant validation precedes fence allocation. A matching existing
issuance is verified and returned unchanged before any allocation write.

Within one ledger authority namespace, the resource counter key is
`digest("fence-resource", {tenant, resource})`, where `resource` contains ID and
incarnation. It excludes conflict domain, so changing domains does not reset
that counter. A missing counter starts at one. A compare-and-swap transaction
checks current policy/ownership, counter revision, absence of issuance and
absence of allocation; it atomically advances the counter and retains one
allocation bound to the global operation key, issuance binding and resource.
Concurrent retries converge on that allocation. Values above the KF-JSON safe
integer maximum refuse. At most 64 confirmed compare failures are retried;
ambiguous transport failures return unavailable and are resolved by a fresh
request. Gaps after failures confer no authority and are never recycled.

Issuance compares the exact retained allocation together with current controls
and root/grant/nonce/global-operation absence. The root, grant digest and issuance
record are written atomically. Concurrent producer candidates with different
random IDs converge on one persisted signed grant. Consumed retries return that
grant without replenishing its allowance. HTTP disconnect does not cancel the
owned operation task; a fresh DPoP proof can resolve a lost reply while the
original bindings and validity remain acceptable.

Counter scope is one namespace and tenant/resource/incarnation. It does not
coordinate another authority prefix, legacy issuance API or external writer.
Starting at one requires a fresh covered target population; an existing target
needs authorized counter bootstrap above its accepted fence. M2c/M4/M6 must
qualify installation, restore barriers, writer coverage and target acceptance.
A higher issued fence is not proof that an earlier effect committed.

## Configuration, implementation and acceptance

`kf-control` loads a closed operator-owned snapshot with public record-role pins,
Cedar/evidence registration, subject/workload permissions, separate signing-key
files and separately configured service/etcd TLS identities. Production etcd
requires HTTPS, a pinned CA and an RBAC token file. Configuration computes the
rule and policy digests; loading it never publishes or acknowledges authority.
Current policy/ownership must already be installed by a trusted authority caller.
The [administrative supplement](0007-enforcement-control-http.md) now supplies
signed publication/install/revoke and installed-scope/trust/acknowledgement checks.
Operator-approved definitions still require controlled configuration changes.
See the [operator guide](../CONTROL_SERVICE.md).

Implementation: `control.rs`, `control_config.rs`, `bin/kf-control.rs`, the native
TLS router in `server.rs`, raw chain retention in `ledger.rs`, and production
`GrantAuthority` in `issuance.rs`. Existing trusted library issuance remains for
fixtures and does not automatically acquire the producer's fence allocation.

Seven new tests include six using actual native TLS and a required real etcd cluster.
They cover restart with retained chains, sixteen concurrent issue requests,
one conserved claim and consumed retry, proof/role/workload refusal, closed
payloads, certificate substitution, stale/missing controls, evidence tampering,
resource fences across domains, counter exhaustion and public-only pin output.
Wire responses are checked against the unchanged draft schema.
See [verification](../../results/verification/rfc-m2-service-2026-10-11/README.md).
Software keys and generated TLS enrollment establish mechanics. They do not
establish enterprise enrollment, a complete agent workflow or target coverage.

The bounded M2c software lifecycle is now delivered under RFC 0007.
Next: M3 live Agent Adapter and durable execution/status correlation.
Draft acceptance, independent interoperability and deployment qualification
remain open.
