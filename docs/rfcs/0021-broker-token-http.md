# RFC 0021: Native broker token exchange and reference target credentials

- Status: Draft
- Milestone: M5c2 software integration prerequisite
- Baseline: `32fd291`; RFCs 0019 and 0020
- Owners/reviewers: unassigned; broker, target and security owners
- Profiles: `KF-BROKER-TOKEN-HTTP-0.1-draft`, `KF-TARGET-TOKEN-0.1-draft`

## Purpose and boundaries

Connect the existing [RFC 8693 client](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1)
to a native independently administered broker. Standard exchange fields use their
registered values; KedgeFlow grant/digest/attempt fields are a named extension.
Only the bounded one-resource leaf is accepted. This reference broker is not a
claim of third-party AS interoperability or enterprise target enforcement.

The TLS acceptor independently verifies the gateway client certificate. The
endpoint requires its exact registered SPIFFE identity, fixed Host/path, POST,
no query/browser Origin and exact `application/x-www-form-urlencoded` content
type. Identity headers do not select the workload. Bound body acquisition to ten
seconds and 2 MiB, with 64 in-flight operations. Owned tasks continue after client
disconnection; the operation itself has a ten-second deadline.

## Closed request and errors

Require exactly one each of: `grant_type`, `subject_token`, `subject_token_type`,
`actor_token`, `actor_token_type`, `requested_token_type`, `audience`, `scope`,
`kedgeflow_grant`, `kedgeflow_grant_digest`, `kedgeflow_attempt_id`. Reject unknown,
missing, empty, duplicate or percent-decoded duplicate names. Percent escapes
and UTF-8 must be valid. No alternative resource/client/refresh-token fields are
accepted. The grant is canonical base64url without padding of the exact signed
bytes; do not normalize its JSON. Subject/actor access/JWT token types and exchange
grant type must equal the values already sent by the shipped client.

Wrong gateway refuses before body interpretation/provider/ledger/mint use. Bad
carriage returns a redacted error. Refused authorization returns `invalid_grant`;
dependency failure/timeout returns `temporarily_unavailable`. No exception text,
credentials, token fragments or signed grant are reflected. All replies carry
`Cache-Control: no-store` and `Pragma: no-cache`. No redirect or token lookup exists.

## One authorization, one mint invocation

Invoke RFC 0019 against the original durable claim, with the RFC 0020 provider.
Only a successful immutable permit CAS authorizes one call to the trusted
`TargetTokenMinter`. Check the service clock and permit validity immediately
before minting. Minting has a five-second maximum within the remaining permit and
operation budget. Never retry a mint, even after timeout, cancellation, transport
ambiguity, malformed result, lost response, process death or signature failure.
The permit and root remain consumed. Repeated requests refuse, including across
service recreation. There is no timer refund, renewal or replacement allowance.

The configured independent credential verifier checks the actual returned token
signature, role key, issuer, audience, single scope, validity and exact permit
correlation before returning it. Check clock/validity again after mint and before
reply. A provider's unauthenticated metadata is insufficient. Invalid/broader
credentials are not returned, but they may already exist at that provider; custody
and revocation of such tokens are deployment responsibilities.

## Named reference target-token profile

The shipped reference minter signs a closed compact Ed25519 JWT, `typ:
kf-target+jwt`, explicit enrolled `kid`. Closed claims: `profile`, `iss`, `aud`,
`scope`, `iat`, `exp`, `permit_id`, `grant_digest`, `root_id`, `attempt_id`,
`gateway_workload`. Issuer and target audience/scope are pinned. Numeric dates are
safe integer seconds. Expiry rounds the permit bound down to a whole second;
less than one full usable second refuses. Token validity never exceeds the permit
or five minutes. `iat` may not be in the future; no skew extension is accepted.

The target verifier requires exact trusted grant/root/attempt, authenticated gateway,
audience/scope and maximum expiry. A signature or permit ID is not evidence of an
actual target commit or a final dispatch authorization. Target-side transaction,
incarnation/version/fence, original-attempt deduplication and query remain M6.
This is a custom reference token, not an OAuth provider's arbitrary JWT/introspection
contract. Its schema has a new draft identifier; frozen grant records are unchanged.

Successful replies use the shipped client's closed five-field JSON response:
`access_token`, `issued_token_type`, `token_type: Bearer`, `expires_in`, `scope`.
Remaining usable lifetime rounds down to seconds, with 1..300 required. The target
must check the actual signed expiry. Tokens are not persisted or logged here.
The client retains its own conservative deadline checks and never clamps widening.

## Deployment and verification

`kf-broker` loads protected TLS/etcd material, independent Grant Authority keys,
RFC 0020 snapshot and an independently retained epoch floor, fixed registration,
reference mint key and separate target verification pins. The subject-token
`delegation_audience` and execution-grant `gateway_audience` are distinct pins. Role overlap refuses.
Managed control is required unless an explicit software-fixture flag is set.
An optional restore gate attaches through the existing ledger path. `--check`
validates material without listening or querying/writing records. Snapshot refresh
is not automated; expiry refuses until a protected restart or integrated trusted
refresh. Never derive the epoch floor from the restorable snapshot itself.

Tests: strict form negatives before authority use; actual mTLS identity and real
subject/actor signatures; shipped client exchange to independently verified token;
concurrent one mint, recreate/replay refusal, failed/delayed/invalid mint, client
response loss and operation expiry; exact target binding and expired/wrong-role
signature rejection; shipping material-only check. Record native-etcd results.
Real AS/SVID provisioning/refresh, protected floor and signing-key custody, actual
target enforcement, production RBAC/bypass, power loss and combined managed restore
remain [enterprise acceptance gates](../ENTERPRISE_QUALIFICATION.md).
