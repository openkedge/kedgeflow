# RFC 0058: Explicit Keycloak and SPIRE identity pilot

- Status: Pilot draft; no enterprise or release acceptance
- Profile: `KF-KEYCLOAK-SPIRE-0.1-pilot`
- Milestone: M5c / M6 self-hosted provider prerequisite
- Owners/reviewers: unassigned

## Enrollment and subject verification

Trusted construction selects `with_keycloak_pilot(client_id)` explicitly. Shipping
control, gateway and broker loaders select the exact `identity_profile` object
with `profile` and `client_id`; the official Node SDK selects `identityProfile`
with `profile` and `clientId`. See the [configuration](../SELF_HOSTED_PILOT.md).
Absence retains the original profile; null, incomplete or unknown selections
refuse. No loader or verifier infers selection from a token header, issuer or
request. Subject issuer, one string audience, authorized
client, signing keys, subject/workload registration and allowed scopes are
operator pins. No presented JWT can supply its verification key.

Accept only the closed EdDSA header `alg`, `typ: JWT`, explicit nonempty `kid`;
caller-selected `jwk` refuses. The complete closed claims are `iss`, `sub`, string
`aud`, integer `exp`/`iat`, string `scope`, `typ: DPoP`, matching client `azp`,
nonempty bounded `jti`, and `cnf`. Confirmation contains exactly `jkt` and
`kc-jkt-type: DPoP`. Missing, duplicate, extra or wrong-type fields refuse. This
is the bounded confidential-client DPoP output observed from Keycloak 26.8.1,
not a general Keycloak/OIDC token parser. Bearer tokens and multi-audience claims
are outside the profile.

Verify the original Ed25519 signature, exact issuer/audience/client, time bounds,
confirmation and scopes. Preserve the raw compact token. Only after verification
map its common claims to the existing admission identity/delegation representation.
The original token digest, scope order and confirmation key remain unchanged.
No internal re-signing or token translation is allowed by this profile.

## Workload and broker verification

Native mTLS verifies the actual SPIRE X.509 chain and obtains the workload URI
from the authenticated leaf. Native DPoP continues to require the Ed25519 proof,
exact POST URL, token hash, confirmation key, freshness and replay consumption.
Shared consumption remains the separately selected existing ledger profile.

The independent broker verifier checks the original subject token under the
same explicit Keycloak profile, then performs all existing ES256 JWT-SVID trust
domain/audience/signature/time, registration, scope, withdrawal, snapshot and key
interval checks. Admission and broker must compute the same delegation digest.
The existing snapshot replacement and epoch-floor rules remain applicable.

The disposable runner pins the Keycloak TLS CA and public JWKS from its isolated
provider, and the SPIRE bundle through its local administrative API. These are
fresh trusted bootstrap observations. An epoch-one fixture snapshot does not
establish durable rollback-floor custody or cross-replica revocation delivery.

## Qualification and limits

Run actual Keycloak/SPIRE issuance, registered/unregistered kernel UID tests and
native loopback mTLS authentication. Verify equal delegation digests, DPoP replay
and key substitution refusal, wrong client/audiences, workload registration,
withdrawal and original-profile refusal. Re-signed semantic negatives must reject
changed Keycloak type/confirmation/client/claims without depending on a broken
signature. Run the original authentication and broker regressions with required
real etcd. Retain source/image/tool pins and public results without credentials.

The subsequent opt-in SQL qualification uses the shipping loaders and official
SDK with actual subject/SVID credentials, fresh admission/issuance, a broker mint
permit and target credential, and a real SQL commit. It covers pinned and signed
refresh identity sources, a lost SDK response and query-only recovery after
actual grant expiry, domain stop and shipping gateway restart. Each case retains
one original permit and SQL attempt. Administrative PKI/evidence/native ledger
relay remain generated same-host fixtures; workload credentials are temporarily
copied from the isolated provider container. See the [qualification record](../../results/verification/rfc-m5-selfhosted-sql-2026-10-30/README.md).

Approved identity administration/rotation/revocation delivery, database durability,
independent custody and deployed role/owner acceptance remain open. The existing
M8 frozen evidence is unchanged.

## Provider lifecycle qualification — 31 October 2026

The separate `--identity-lifecycle` mode obtains an actual newly generated
Keycloak Ed25519 signing key through the realm administration API. It requires
a different key ID/public key, overlap verification of old/new actual tokens,
and new-key/subject continuity after provider restart. Administrative credentials
stay under a root-only directory; the registered workload must fail to read them.

A shipping broker with signed refresh refuses withdrawn tokens/registrations,
unpublished keys, invalid or missing publications, rollback and stale restored
snapshot/head material before spending a mint permit. A separate native verifier
checks overlap and retired-key refusal. Hot reloads retain the process PID; local
startup checks reject stale material under the retained head/floor. Restart with
fresh approved publication consumes the original claim once; replay cannot mint
again. The [retained record](../../results/verification/rfc-m5-selfhosted-lifecycle-2026-10-31/README.md)
qualifies generated publisher/head/floor/service PKI and loopback ledger fixtures.
It does not qualify provider database restore, SPIRE issuer rollover, independent
custody, replica delivery budgets or deployed owner acceptance. No new token or
execution profile is introduced and earlier frozen evidence is unchanged.
