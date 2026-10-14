# Native reviewed evidence (M7b)

[RFC 0034](rfcs/0034-native-review-evidence.md) supplies `kf-review`, a native
mTLS/OAuth/DPoP provider for the narrow ES256 subset in RFC 0031. Its signed,
closed result travels in the existing Evidence envelope. Explicit admission
registration checks the exact rendered context and requires a consumed challenge
and active enrollment in admission, allocation and issuer transactions. A signed
`approved: true` label alone cannot discharge this obligation.

## Configure and enroll

[Provider configuration](../config/review.example.json) and
[admission evidence entry](../config/review-evidence.example.json) are software
examples with public test keys, synthetic enrollment and placeholder descriptor/
policy/question pins. Replace them with the approved context before use. Private
seeds and tokens are referenced by file; the examples contain no service secrets.
They do not establish approved enrollment or attestation provenance.

1. Register a distinct reviewer subject/workload/scope and provider signer. The
   reviewer workload must differ from the initiating agent. Pin the credential
   public key, user handle, RP and HTTPS origin. This profile refuses hardware-bound
   enrollment, backup/extension flags and zero/non-monotone signature counters.
2. Select the fixed template digest returned by `kf-review --print-template-digest`
   in the signed CTD rendering. Use `text/plain`: the body is canonical JSON shown
   as UTF-8 plain text, compatible with the frozen CTD media enum. Repin the CTD,
   proposal action, admission configuration and installed scope after changing it.
3. Add the example review entry alongside the existing fresh capacity obligation
   in control/lineage configuration. Preserve the `review` rule, exact result
   schema/reference, provider key/question pins and `approved` predicate. Recompute
   the registered obligation digest and Cedar policy reference, then install the
   same policy/ownership scope used by the provider. Legacy entries omit `review`
   and retain their previous obligation digests. Old readers refuse the new field.
4. Prepare an explicit protected directory, owned by the effective non-root service
   UID or root, with no group/world writable path components. Put configuration,
   certificates, keys and tokens beneath it using absolute paths. Public files may
   be 0644; private keys, provider seed and etcd tokens must be 0600 or stricter.
   Symlinks, hardlinks, writable ancestors, special files and paths outside the root
   refuse. TLS and signing use the checked descriptor bytes without reopening paths.
5. Run `kf-review --custody-root /etc/kedgeflow/review --config
   /etc/kedgeflow/review/review.json --check`. This checks local material without
   contacting etcd, creating a listener or enrolling credentials. Configure the
   shared replay store and independent restore gate for the intended deployment;
   their existing registration and quarantine requirements still apply. The example
   requires installed control. An authenticated fixed HTTPS etcd origin is mandatory.
6. A privileged operator runs the same command with `--enroll` to create only the
   configured credentials, then without an operation flag to serve `/review`.
   `--revoke` withdraws those credentials. Batch administration applies credentials
   in order and may partially succeed before an error; it is not one transaction.
   Enrollment never resets an existing counter or reactivates a revoked credential.
   These operations have no HTTP route accessible to an agent.

## Native client and authority path

Send POST application/json to the exact configured `/review` URL with the enrolled
reviewer workload certificate and current DPoP-bound reviewer access token scoped
to `kf.review`. The provider verifies signed proposal/CTD, single-resource leaf
parameters/version/baseline, initiating identity and freshness. A `begin` request
contains the draft profile, request id, credential id, signed proposal/descriptor
strings and approve/reject verdict. It returns server approval, challenge and the
exact rendered string. Request shape and response definitions are in the
[closed HTTP schema](../spec/drafts/review-evidence-http-v0.1.schema.json).

The client retains the returned approval, binds the authenticator assertion to its
challenge and submits `complete` with the same signed proposal/descriptor, approval
and assertion. The narrow verifier checks original clientDataJSON bytes, RP/origin,
UP/UV, signature and a positive increasing counter. This increment does not supply
or certify a protected display or browser ceremony. Direct browser Origin requests
refuse. The configured credential owner must equal the authenticated reviewer.

Completion durably consumes the challenge/counter, then publishes a create-only,
provider-signed Evidence envelope with the original verification time and approval
expiry. A fresh authenticated retry with the exact assertion returns the same
bytes, including after process death between consumption and publication. A new
`begin` creates a new challenge; an unreceived begin reply is not recoverable by
request id. Orphan challenges confer no execution permission. Changed context,
assertion, publisher registration, policy, ownership, expiry or enrollment refuses.
Old consumed library records without completion metadata cannot be published.

An existing manifest assembler includes this witness plus fresh capacity evidence
under their respective registered obligations; the native admission/issuer path
then compares active enrollment and exact durable consumption. Disconnect cannot
cancel an owned publication. Revocation racing the admission/allocation/issuance
transaction wins its comparisons and blocks authority production. If a fence was
allocated before revocation, it stays allocated; no grant follows the refused issuer
transaction. Revoking enrollment does not revoke already issued execution grants:
normal explicit authority revocation still applies.

Offline lineage verification checks signed context and evidence time at historical
admission, but cannot certify current credential status or the live consumption CAS.
It must not be presented as verification of today's enrollment state.

## Verification and remaining work

The required native suite uses actual loopback mTLS/DPoP and a three-member etcd
cluster with software-generated credentials. It covers composition through native
admission/issuance; fabricated signed facts; wrong subject/workload/scope; replay;
closed inputs; UV/signature/origin/substitution; rejection; expiry and policy change;
revocation before admission/issuance and during all three authority CAS boundaries.
A shipping `kf-review` SIGKILL at an observed consumed/unpublished state recovers the
original fact, then another restart returns identical evidence. Offline custody
checks refuse exposed or symlinked seeds, and duplicate enrollment cannot reset it.

The [required conformance record](../results/verification/rfc-m7-native-review-2026-10-14/README.md)
retains source, tool and log pins. Same-host generated credentials and software
assertions do not qualify independent custody, a human viewing the exact rendered
bytes, physical authenticator enrollment/attestation or enterprise owner acceptance.
Frozen HitlWitness variants and AdmissionLease reuse remain unsupported. The next
M7 increment needs an exact-proposal static lease contract, fresh JIT evidence and
invalidation tests; protected browser/hardware qualification remains a separate gate.
