# Pinned broker exchange identities

[RFC 0020](rfcs/0020-pinned-exchange-identities.md) supplies a bounded
`ExchangeIdentityProvider` implementation for the [broker authorizer](BROKER_AUTHORIZATION.md).
It verifies the existing closed Ed25519 subject access token and an ES256
JWT-SVID actor assertion with independently enrolled keys. No HTTP authorization
server, provider refresh client, SPIRE provisioner or token mint is supplied.

## Protected integration

Load protected JSON with `PinnedExchangeIdentityProvider::from_json(bytes,
minimum_epoch)`. The loader rejects duplicate fields, unknown members, oversized
configuration and invalid registrations. The minimum epoch must be retained
independently of any restorable broker filesystem. Do not source it from the
snapshot being checked. `new(snapshot, minimum_epoch)` is the typed trusted API.
Snapshots contain public keys and registrations; they contain no signing secrets.

Pass the provider as `Arc<dyn ExchangeIdentityProvider>` to `BrokerAuthorizer`.
The broker checks the actual verified gateway mTLS identity, independently signed
grant and original undispatched claimed attempt. Subject tokens retain the
admission audience; the actor assertion has the separately fixed broker audience.
Neither audience is the eventual target audience. Exact registered scopes bind
subject/workload authorization. The token's scope order remains part of the
canonical delegation digest, shared with admission authentication.

Subject keys are Ed25519 public bytes. Actor keys are uncompressed 65-byte P-256
SEC1 points. Both are base64url without padding, selected only by explicit `kid`.
Actor keys additionally require exact trust domain, `alg: ES256`, `use: jwt-svid`.
Importing a SPIFFE bundle is an operator/provider responsibility: never import a
JWK with another use or derive trusted keys from the presented token. This is a
restricted JWT-SVID subset: RSA, other curves, absent key IDs, multiple audiences
and private claims refuse. It supports optional `typ: JWT`/`JOSE`, `iat` and `nbf`.

## Refresh, rotation and withdrawal

Each snapshot has a strictly positive epoch and at most five minutes of validity.
`replace(next)` validates all configuration before acquiring the write lock,
requires a newer epoch and nondecreasing validity start, and preserves issuer and
both audiences. All clones share one atomic snapshot. Each verification holds its
read lock throughout key and registration checks. Concurrent updates proposing
the same epoch have one winner; invalid updates preserve the current snapshot.

For planned rollover, publish a fresh higher-epoch snapshot containing both keys,
rotate issuance, then publish another higher epoch removing the retired key.
Acceptance intervals and snapshot expiry bound returned credential validity even
when the signed tokens live longer. Expired or not-yet-valid snapshots/keys refuse;
a failed refresh never extends the last snapshot. A provider-owned update mechanism
must refresh before expiry. There is no automatic discovery or stale-key fallback.

Withdraw a workload by removing its subject/workload registration or withdrawing
its signing key. Withdraw a subject token by including the lowercase SHA-256 digest
of its exact compact bytes in `withdrawn_subject_tokens`. Keep withdrawal coverage
until the token can no longer be accepted. Refresh must reach every replica within
the approved revocation budget. These checks apply to subsequent verification;
they do not revoke an authorization already returned or an existing target token.
RFC 0019's independent control/claim CAS and final dispatch remain necessary.

The trusted caller supplies the service clock, never a request timestamp.
Provider freshness is bounded; this does not establish an instantaneous
introspection/revocation contract. Production clock monotonicity/uncertainty,
protected refresh authentication, durable epoch publication, stale restore,
replica convergence and key custody require actual deployment qualification.

## Evidence and remaining work

Software-key tests verify signatures, exact admission delegation, key/domain and
scope substitution, freshness, bounded lifetime, overlapping rotation/retirement,
workload/token withdrawal, epoch rollback, rejected updates, closed JSON and
concurrent replacement. One native-etcd composition test verifies actual tokens,
refuses an unclaimed or withdrawn execution, and races two brokers for one permit
on the original claim without refund or target mutation.

See [fresh verification](../results/verification/rfc-m5-provider-2026-10-12/README.md).
Generated keys and loopback etcd establish this library behavior. The approved AS,
SVID issuer/refresh/revocation delivery, native mint service, actual target credential
contract, production RBAC and bypass evidence remain M5c requirements in
[enterprise qualification](ENTERPRISE_QUALIFICATION.md). M6–M9 acceptance stays open.

[RFC 0021](rfcs/0021-broker-token-http.md) now composes this verifier with a
[native token endpoint](BROKER_TOKEN_SERVICE.md) and reference target mint.
Protected refresh, actual provider provisioning and enterprise target acceptance
still require the deployment gates above.
