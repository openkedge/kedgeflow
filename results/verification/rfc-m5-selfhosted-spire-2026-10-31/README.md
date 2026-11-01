# SPIRE JWT and X.509 issuer rollover — 31 October 2026

**Passed the bounded SPIRE issuer rollover qualification.** Actual SPIRE 1.15.5
local-authority prepare/activate/taint/revoke ran for JWT and X.509 signers.
The required native test executed fourteen JWT/broker cases and seven actual mTLS
connections. See the [summary](summary.json), [native results](identity-lifecycle.json)
and [execution log](identity-lifecycle.log).

The root-only administrative helper verifies that revoking an untainted old
key refuses for both authority kinds, then taints/revokes it. Authority-bound
precondition evidence persists through restart. Workload UID 1002 must fail to
prepare either authority through the private socket. New authority IDs survive
server/agent restart after activation and again after retirement; the final
bundle contains only the new authorities. The public [initial](spire-bundle.json),
[overlap](spire-overlap.json) and [retired](spire-retired.json) bundles are retained.
Their JWT key IDs and X.509 subject key identifiers match the authority IDs
reported by SPIRE. No private signing material is published.

The workload renews its SPIRE JWT-SVID and X.509-SVID while preserving the exact
original Keycloak subject token and DPoP seed. Its authenticated workload URI and
delegation digest remain identical. Verification pins are taken from the overlap
bundle before retirement/restart; the final advertised new key must match them.
Old actor credentials remain cryptographically valid under original trust but
refuse under current approved trust, isolating retirement from token expiry.

The shipping broker rejects an unpublished new actor key, a retired actor, live
snapshot/head rollback, a missing higher publication, rollback after observing
that higher head, and a malformed publication after valid current-identity
verification. Every negative HTTP probe asserts zero mint permits. Startup
`--check` refuses a stale pair under a retained floor. Hot JWT-trust reloads keep
the same broker PID. Fresh epoch/floor five and broker restart allow the new actor
to redeem the original claim once. Old and new actor replays leave the one permit
unchanged; the returned reference target credential verifies. No new subject
token or execution grant is required, and no target dispatch or SQL action occurs.

The native mTLS matrix uses actual SPIRE-issued client certificates:

| Certificate | Initial CA | Overlap CAs | Retired/new CA |
| --- | --- | --- | --- |
| Old leaf | Accepted | Accepted | Refused |
| New leaf | Refused | Accepted | Accepted |
| Fresh post-restart new leaf | — | — | Accepted |

Every positive connection extracts and checks the authenticated SPIFFE URI.
The probes construct each phase's CA configuration and establish fresh TLS
connections. They do not implement automatic CA-file reload or invalidate already
established sessions. Agent memory-key reattestation avoids reliance on background
SVID/JWT cache timing; automatic streaming delivery budgets remain unqualified.

The [75 supporting Rust identity/configuration/broker regressions](required-auth.log)
passed with required real three-member etcd and no runtime skips. All
[50 Python tests](python.log), [feature-enabled clippy](clippy.log),
[format](format.log), [Ruff](ruff.log), [mypy](mypy.log) and the
[frozen paper/contract check](whitepaper.log) passed. The cleanup regression includes
SPIRE mode, and [CI](../../../.github/workflows/ci.yml) runs it explicitly with
artifact retention. Remote AMD64 CI execution remains unobserved.

The [411 source hashes](source.json) match the [pre-run source archive](source.tar.gz)
and remained unchanged throughout execution. The [baseline revision](revision.txt)
is `5b46237`; the archive captures this increment before its subsequent commit.
The native result pins the broker binary SHA-256. [Tools](tools.json),
[workload image metadata](workload-image.json), [image build](workload-build.log)
and [four helper source hashes](image-source.log) retain build/runtime inputs.
The provider images and SPIRE release checksums remain pinned in source.

Providers run in Linux ARM64 containers within the isolated local VM. Native
broker, mTLS probes and three-member loopback etcd run on Darwin ARM64. Publisher,
head/floor, grant and service PKI remain generated same-host fixtures, and the
broker uses explicit unmanaged test ledger transport. This does not qualify
independent publisher/storage/key custody, production CA rollout, cross-replica
revocation timing, HSM/KMS recovery or deployed owner acceptance. Key retirement
means removal from current verification trust, not erasure of every historical
copy of the old key. Earlier SQL, storage and Linux isolation qualifications
remain separate; their frozen artifacts are unchanged.

Private tokens, DPoP seed, workload keys and provider logs are excluded from
public output. UID/key/socket refusal probes still run. Both exact owned
containers and their internal network are removed, private temporary credentials
are deleted and native test services/etcd are stopped. No host mounts, published
ports or privileged mode are used. The [VM stop log](vm-stop.log) returns the
initially stopped VM to that state while preserving its existing cluster/disk.

See the [runbook](../../../docs/SELF_HOSTED_PILOT.md#spire-jwt-and-x509-issuer-rollover)
and [versioned SPIRE CLI](https://github.com/spiffe/spire/blob/v1.15.5/doc/spire_server.md)
for reproduction and API details. The [artifact manifest](artifact-sha256.json)
covers this retained record.
