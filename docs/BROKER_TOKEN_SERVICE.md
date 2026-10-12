# Native broker token service (M5c2)

[RFC 0021](rfcs/0021-broker-token-http.md) connects the shipped RFC 8693 client to
`kf-broker`. The independently verified gateway mTLS identity, [pinned subject and
JWT-SVID verifier](EXCHANGE_IDENTITIES.md), [original-claim authorizer](BROKER_AUTHORIZATION.md)
and reference target minter form one bounded software path. Frozen grants and
paper fixtures remain unchanged. The custom target token is a new draft profile.

## Protected material and startup

[Broker configuration](../config/broker.example.json) and [identity snapshot](../config/exchange-identities.example.json)
contain placeholders and must be enrolled by the operator. Use a distinct broker
certificate/key and etcd role, independent Grant Authority verification pins,
subject/actor trust, and separate reference target signing/verification keys.
The signing seed file contains a 32-byte Ed25519 seed encoded as standard base64;
public verifier keys also use standard base64. RFC 0020 subject/actor keys use
base64url without padding. No secret belongs in the configuration JSON.

```sh
cargo build --locked --bin kf-broker
cargo run --locked --bin kf-broker -- --config /etc/kedgeflow/broker.json --check
cargo run --locked --bin kf-broker -- --config /etc/kedgeflow/broker.json
```

`--check` validates protected material and role pins without listening or using
network authority. It does not establish current provider freshness or approve
execution. Managed startup requires an installed trust digest and HTTPS etcd;
`allow_unmanaged_fixture: true` is only for explicit isolated software tests.
An optional existing `restore_gate` attaches to every ledger transaction. Real
TLS/RBAC/witness deployment remains an enterprise qualification gate.

The identity snapshot's actor audience equals the exact broker token URL; its
subject audience equals `delegation_audience`. The independently configured
`gateway_audience` is the execution grant audience; these two audiences may differ. The epoch floor
file contains a positive integer retained independently of the restorable broker
and snapshot. The program does not derive or write that floor. Static mode loads the
snapshot once. In static mode, file changes alone do not reload it: use protected restart
with a fresh snapshot/floor, or integrate the trusted replacement API separately.
Expired snapshots refuse exchange. Protected refresh and durable epoch custody
are not supplied by this binary.

## Carriage and credential binding

The endpoint accepts one fixed POST form, exact Host/path and gateway SPIFFE ID.
It refuses browser Origin, query aliases, unknown/missing/duplicate fields,
malformed percent escapes/UTF-8 and unsupported token types. The grant extension
preserves exact signed bytes with canonical base64url carriage. Calls use native
TLS 1.3, bounded connections/body/operations, and redacted non-cacheable replies.

The original undispatched claimed attempt must win one immutable permit CAS.
Only then does `TargetTokenMinter` receive the permit, once. Failure, timeout,
client disconnection, invalid minted token or process death never causes another
mint call, token renewal, root replacement or refund. A persisted permit may
remain unavailable after a failed or lost mint. Recovery requires a future
provider-specific custody/idempotency contract; the current service deliberately
has no token lookup or redelivery API.

`ReferenceTokenMinter` signs a closed Ed25519 `kf-target+jwt` with the new
`KF-TARGET-TOKEN-0.1-draft` claims. The service independently verifies the actual
signature, issuer, target audience/scope, original grant/root/attempt, gateway and
permit before returning it. Expiry rounds down within the permit bound; returned
`expires_in` also rounds down, and a full usable second must remain. Minted
credentials are neither logged nor retained in this service.

`TargetTokenVerifier::verify` accepts a trusted `TokenBinding`. A target must
construct that binding from independently verified request/grant/connection
context, never copy claims from the submitted token as its expectations. Match
maximum expiry to the grant, exact grant/root/attempt and authenticated gateway,
fixed audience and single scope. Token verification authorizes only the named
credential profile. The actual target still needs its atomic incarnation/version/
fence/effect/attempt contract, deduplication and durable query. Those are M6 work;
no real SQL/Kubernetes effect or third-party AS format is implemented here.

## Verification and enterprise gate

[Fresh evidence](../results/verification/rfc-m5-token-2026-10-12/README.md) covers
strict form parsing, actual gateway mTLS and subject/actor signatures, shipped
client exchange, independent target verification, concurrent one mint,
service recreation, failed/overbroad/expired/invalid mint, mint timeout and lost
client reply. The actual shipping binary validates material without network use
and preserves one-shot exchange across process termination/restart.

Tests use generated keys and same-host native etcd in unmanaged fixture mode.
Approved AS/SVID provisioning/revocation delivery, authenticated refresh and floor
custody, production key/RBAC/bypass, combined managed restore and actual target
enforcement remain [enterprise gates](ENTERPRISE_QUALIFICATION.md).

[RFC 0022](rfcs/0022-identity-refresh.md) now adds opt-in [signed identity refresh](IDENTITY_REFRESH.md)
with a protected head read before/after every exchange, independent authority pins
and observed epoch/digest checks. Live key/registration changes do not require
broker restart in that mode; external publisher and durable custody remain open.
