# Self-hosted identity pilot

Selected on **30 October 2026**: Keycloak for client/subject identity, SPIRE for
workload identity, and Linux service accounts. The identity prototype qualifies
real provider-issued identities against native
KedgeFlow authentication and broker identity verification. The shipping increment
connects the same profile to shipping services and the official Node SDK for a
fresh-authority SQL workflow. SQL target account isolation has a
[separate retained qualification](../results/verification/rfc-m6-pilot-isolation-2026-10-30/README.md).
The [identity qualification record](../results/verification/rfc-m5-selfhosted-identity-2026-10-30/README.md)
retains the real-provider pass, eight native negatives, UID/key/socket refusals,
70 required Rust tests and 47 Python tests.

## Reproduce the disposable prototype

Use an explicitly selected local Docker socket backed by an isolated Linux VM.
Install the repository's Python development dependencies and locked Rust
dependencies first. No enterprise credentials are required. The realm's client
secret, TLS CA/key and DPoP key are generated for each run; none are checked in.

```sh
docker pull quay.io/keycloak/keycloak:26.8.1@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b
docker build --build-arg TARGETARCH=arm64 -t kf-selfhosted-workload:20261030 pilots/self-hosted
cargo build --locked --bin kf-pilot-identities
python scripts/selfhosted-pilot.py \
  --docker /absolute/path/to/docker \
  --docker-host unix:///absolute/path/to/isolated/docker.sock \
  --checker "$PWD/target/debug/kf-pilot-identities" \
  --output results/local/selfhosted-new
```

Set `DOCKER_HOST` for the pull/build commands to that same socket. Use
`TARGETARCH=amd64` when building on native AMD64 Linux. Both SPIRE release archive
checksums are pinned in the Dockerfile; ARM64 execution is the locally observed
platform. The Debian and Keycloak images are pinned by manifest digest. Output
must be a new directory. The script removes only its randomly named containers
and internal Docker network, including after a failed bootstrap or checker.

Keycloak serves HTTPS only on the internal network, with a per-run CA verified
by the client. No host ports, host mounts or privileged mode are requested.
The prototype uses a confidential service-account client with required DPoP;
password login and browser flows are disabled. It does not qualify a human login
ceremony. Keycloak's embedded disposable database and the local VM are prototype
infrastructure, not an accepted production identity deployment.

The independent `selfhosted-identity` CI job runs the bootstrap, native checker
and shipping SQL workflow on AMD64. The workflow is prepared in the working tree; remote execution
is not implied by a local pass.

SPIRE uses a one-time node join token and an explicitly supplied bootstrap bundle.
Its Unix workload attestor maps UID 1002 to the exact gateway SPIFFE ID. UID 1003
has no registration and must fail JWT-SVID acquisition. Server and agent are
fixture infrastructure within the workload container; independent host/service
administration remains deployment work.

## Native checks

The registered UID obtains an actual Keycloak Ed25519 DPoP-bound access token,
SPIRE ES256 JWT-SVID and SPIRE X.509-SVID through the Workload API. Private
credentials are copied into a short-lived mode-0700 directory for the native
checker and removed on exit. Public output includes token header/claim names,
the SPIRE public bundle, identities, delegation digest and refusal results.
Raw tokens, DPoP seeds, workload keys and provider logs are not retained.

`kf-pilot-identities` starts a loopback TLS endpoint using the normal native
server and `DualAuthenticator`. The client authenticates with its actual SPIRE
certificate; the server verifies it against the SPIRE bundle. The independently
invoked broker provider verifies the original subject token and JWT-SVID. Their
subject, workload and delegation digest must match without translating or
re-signing the access token.

The checker requires refusal of repeated DPoP proof, substituted DPoP key, wrong
client, subject/actor audience, unregistered workload, withdrawn subject token
and use of the original token profile. Re-signed synthetic profile vectors
separately test changed token type, confirmation marker, scopes, audience shape,
empty token ID and additional claims. Existing identity/broker tests remain
required with real etcd.

## Explicit profile boundary

[RFC 0058](rfcs/0058-self-hosted-identity-pilot.md) defines
`KF-KEYCLOAK-SPIRE-0.1-pilot`. Select the following operator-owned setting in
protected control, gateway and broker configuration:

```json
"identity_profile": {
  "profile": "KF-KEYCLOAK-SPIRE-0.1-pilot",
  "client_id": "kf-pilot-agent"
}
```

Select the matching official Node `AgentAdapter` configuration:

```json
"identityProfile": {
  "profile": "KF-KEYCLOAK-SPIRE-0.1-pilot",
  "clientId": "kf-pilot-agent"
}
```

Absence preserves the original profile. Explicit null, incomplete selection,
unknown fields/profile or invalid client refuse. Tokens cannot select the
verifier. Rust construction also supports `with_keycloak_pilot(client_id)`.
The broker applies the selection to both pinned and signed refreshing identity
providers; signature, exact head, realm and epoch-floor checks still apply.

## Shipping SQL qualification

Install the locked SDK (`npm ci --prefix tests/sdk`), PostgreSQL 18.3, etcd 3.6.5
and the locked Rust dependencies. Build the provider image as above, then run:

```sh
ETCD_BINARY=/absolute/path/to/etcd python scripts/selfhosted-pilot.py \
  --docker /absolute/path/to/docker \
  --docker-host unix:///absolute/path/to/isolated/docker.sock \
  --sql-workflow --postgres-bindir /absolute/path/to/postgresql-18.3/bin \
  --output results/local/selfhosted-sql-new
```

This explicitly enables the `selfhosted-pilot-tests` Cargo feature. The selected
case requires actual providers, SDK, fresh peer PostgreSQL and a three-member
etcd fixture; missing dependencies fail instead of silently skipping. The normal
conformance suite retains the provider-independent profile vectors.

The [retained SQL record](../results/verification/rfc-m5-selfhosted-sql-2026-10-30/README.md)
covers the shipping `kf-control`, `kf-broker`, `kf-proxy` and
`kf-postgres-target` processes. The SDK uses the original Keycloak token and
DPoP key plus the actual SPIRE X.509-SVID. A SPIRE JWT-SVID authenticates the
actor during broker exchange. Fresh evidence, signed admission and issuance
precede the broker permit, target credential and actual SQL commit.

One case uses a pinned identity snapshot; the lost SDK response case uses signed
refresh with a separate head/floor. Each commits once, then restarts the shipping
gateway after domain stop and actual grant expiry. A new SDK process resumes the
original durable operation using query-only status: the permit remains unchanged,
with one broker exchange and one SQL attempt. Lost SDK response means the SDK
consumed the real response before simulating a transport error; it does not claim
a lost SQL target reply in this provider-specific case.

Provider processes run in Linux ARM64 containers; native services, SDK and SQL
run on Darwin ARM64. Generated administration, evidence, service PKI and a native
TLS-to-etcd fixture relay remain same-host test infrastructure. Actual workload
credentials are temporarily copied into a private directory. This does not
combine the separate Linux account isolation record into an independently
isolated deployment. Independently approved publisher/head/floor custody, key
rotation and revocation delivery, service isolation, identity storage backup /
restore, writer boundaries and owner acceptance remain the
[protected pilot gates](PROTECTED_PILOT.md).


## Issuer rollover and broker trust lifecycle

The [31 October lifecycle record](../results/verification/rfc-m5-selfhosted-lifecycle-2026-10-31/README.md)
qualifies actual Keycloak signing-key rollover and restart continuity with SPIRE
workload assertions, plus the shipping broker's signed trust lifecycle. Run this
separately from the SQL mode using the rebuilt workload image:

```sh
ETCD_BINARY=/absolute/path/to/etcd python scripts/selfhosted-pilot.py \
  --docker /absolute/path/to/docker \
  --docker-host unix:///absolute/path/to/isolated/docker.sock \
  --identity-lifecycle --output results/local/selfhosted-lifecycle-new
```

This mode imports a temporary realm administration service account. Its generated
secret is copied only to the root-owned private directory in the disposable
workload container; registered workload UID 1002 must fail to read it. The helper
creates a new generated EdDSA key provider with a higher priority, without copying
stored private-key parameters. Both signing key ID and public key must change.
After Keycloak restarts, new issuance must use the same new key and subject.
This follows [Keycloak's generated-provider rollover procedure](https://www.keycloak.org/docs/26.2.5/server_admin/#rotating-keys).

A generated refresh publisher then drives fourteen bounded checks. The shipping
broker rejects an unpublished new issuer key, withdrawn subject token or workload
registration, live rollback, missing or invalid publication, a restored stale
snapshot under the retained head, and a stale pair under the retained floor.
A valid-identity request with an absent attempt exercises identity verification
without minting before the outage checks. All rejection probes leave the valid
original claim unspent with zero credential permits.

The independent native refresh verifier checks overlap acceptance of both actual
issuer tokens and old-key retirement. Those two checks do not spend a broker
permit. Hot shipping-broker reloads keep the same PID; startup `--check` refuses
stale restored material. A final shipping broker restart with the fresh signed
publication redeems the original claim once; replay leaves the one permit
unchanged. No SQL action runs in this mode.

The publisher, grant, head/floor and service PKI remain generated same-host
fixtures, and broker ledger transport uses loopback etcd in this qualification.
Keycloak restart continuity does not establish provider database backup/restore.
SPIRE issuer-key rollover, cross-replica revocation delivery budgets, independent
publisher/head/floor custody and deployed role isolation remain open. Withdrawal
is an explicit signed broker publication; disabling a Keycloak client or SPIRE
entry is not treated as automatic revocation of already issued credentials.


## Cold provider storage backup and restore

The [storage qualification](../results/verification/rfc-m5-selfhosted-storage-2026-10-31/README.md)
extends the lifecycle mode with actual copies of Keycloak's H2 database and
SPIRE's SQLite datastore plus disk signing keys. Rebuild the workload image,
then run:

```sh
ETCD_BINARY=/absolute/path/to/etcd python scripts/selfhosted-pilot.py \
  --docker /absolute/path/to/docker \
  --docker-host unix:///absolute/path/to/isolated/docker.sock \
  --identity-storage-restore --output results/local/selfhosted-storage-new
```

The fixture gracefully stops the SPIRE server/agent, checks SQLite integrity,
stops Keycloak and requires both containers to be stopped before copying data.
It retains two private cold copies: before and after Keycloak signing-key rollover.
The copied directories are `/opt/keycloak/data/h2` and `/var/lib/spire/server`.
The latter contains both the datastore and the disk key manager's `keys.json`.

Each restore removes both owned containers and creates fresh containers from the
pinned provider images. Realm import and SPIRE registration seeding stay disabled
on restore. TLS/client bootstrap files are supplied separately. The agent uses
fresh node attestation and memory keys; agent private state is not restored.
The sequence restores the latest, initial, then latest copy, requiring fresh
issuance each time. New container IDs and archive hashes/sizes are public;
backup contents remain in a private temporary directory and are deleted on exit.

Native verification uses issuer public keys captured before restoration. It
requires the latest copy to preserve that issuer key and subject, and the stale
copy to issue a genuine, independently valid old-key token.
That newly issued stale credential must fail against retained current broker
trust before minting. Fresh SPIRE assertions must verify under the original
server JWT signing keys, demonstrating restored enrollment and key continuity.
The complete fourteen-case broker lifecycle still runs; final restart redeems
the original claim once and replay cannot add another permit.

This qualifies stopped, same-version H2/SQLite/disk-key copies in disposable
same-host containers. It does not qualify online or distributed backup, a
production Keycloak database, cross-version migration, HSM/KMS key recovery,
physical storage durability, revocation delivery or independent custody. Realm
export is not used as a database backup; see [Keycloak's export/import limitations](https://www.keycloak.org/server/importExport).
The [SPIRE disk key manager](https://github.com/spiffe/spire/blob/main/doc/plugin_server_keymanager_disk.md)
persists private signing keys separately from database configuration, so both
are included in this fixture's server directory copy.

Provider references: [Keycloak DPoP](https://www.keycloak.org/securing-apps/dpop),
[SPIRE workload identities](https://spiffe.io/docs/latest/spire-about/use-cases/),
[SPIRE 1.15.5 release and asset digests](https://github.com/spiffe/spire/releases/tag/v1.15.5).
