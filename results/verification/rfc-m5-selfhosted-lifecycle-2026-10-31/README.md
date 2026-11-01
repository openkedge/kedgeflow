# Self-hosted issuer and broker trust lifecycle — 31 October 2026

**Passed the bounded identity lifecycle qualification.** Actual Keycloak 26.8.1
generated a different Ed25519 signing key through its administration API and
retained the new key/subject across provider restart. The shipping `kf-broker`
then exercised signed trust publication, withdrawal and stale trust restore
refusal with actual Keycloak tokens and SPIRE 1.15.5 JWT-SVIDs. See the
[summary](summary.json), [fourteen cases](identity-lifecycle.json) and
[required native log](identity-lifecycle.log).

The native test requires both key ID and public key to change. An independent
native refresh verifier accepts old/new actual tokens during overlap and refuses
the old token after its key is retired from the approved snapshot. Those two
checks do not spend a broker permit; issuer retirement here is broker trust
retirement, not deletion of Keycloak's old key provider.

Against a valid original claimed grant, the shipping broker refuses the new
issuer key before publication, explicit subject-token withdrawal, workload
registration withdrawal, live pair rollback, a missing higher publication,
rollback after that higher head was observed, invalid/missing publication after
identity verification, and a stale snapshot under the retained head. Every
rejection probe asserts zero credential permits. Native startup `--check` also
refuses a stale snapshot/head pair under the independently retained fixture floor.
The same broker PID handles all hot publication transitions. A final broker
restart with the fresh epoch-six publication and fixture floor four redeems the same original claim
once; the returned target credential verifies, and replay leaves the single
credential permit unchanged. No target dispatch or SQL mutation occurs.

The [75 identity/configuration/broker Rust regressions](required-auth.log)
passed with required actual three-member etcd and no runtime skips. All
[48 Python tests](python.log), [feature-enabled clippy](clippy.log),
[format](format.log), [Ruff](ruff.log), [mypy](mypy.log) and the
[frozen paper/contract check](whitepaper.log) passed. Cleanup tests cover both
ordinary and lifecycle bootstrap failure while keeping secrets off argv and
public artifacts. The existing no-client-certificate test accepts equivalent
TLS alert/closed-pipe/reset refusals while still requiring no HTTP response.

The [409 source hashes](source.json) match the [pre-run archive](source.tar.gz)
and remain unchanged through final execution. The [baseline revision](revision.txt)
identifies the checkout; new implementation remains in the working tree. The
broker binary SHA-256 is in the native report. [Current tools](tools.json),
[workload image metadata](workload-image.json), [image build](workload-build.log)
and [helper source verification](image-source.log) retain execution inputs.
[CI](../../../.github/workflows/ci.yml) now includes the required lifecycle mode;
remote AMD64 execution remains unobserved.

Provider processes run in Linux ARM64 containers in the isolated local VM;
native broker and three-member loopback etcd run on Darwin ARM64. Service PKI,
execution grant, refresh publisher/key, head and epoch floor remain generated
same-host fixtures. The broker uses the explicit unmanaged test transport to
loopback etcd. This does not qualify deployed ACLs, publisher authentication,
physical storage independence, replica delivery budgets or enterprise acceptance.
Keycloak restart continuity does not qualify provider database backup/restore;
SPIRE issuer-key rollover also remains open. Withdrawal requires an explicit
signed broker publication and is not automatic remote-provider revocation.

The extra realm administration credential is generated per run, held under the
root-only private workload-container directory and refused to workload UID 1002.
Unregistered UID and SPIRE key/admin-socket refusals still run. No raw tokens,
DPoP seeds, workload keys, administration secrets or provider logs are retained
publicly. Both exact owned containers and their internal network are removed;
no host mounts, published ports or privileged mode are used. Private temporary
credentials and loopback etcd/services are cleaned up. The [VM stop log](vm-stop.log)
returns the initially stopped VM to that state, preserving the existing cluster.
Earlier qualification artifacts remain unchanged.

The [first preflight](../rfc-m5-selfhosted-lifecycle-2026-10-30-preflight-1/README.md)
was rejected for source drift during a cleanup test correction. The
[31 October failed preflight](../rfc-m5-selfhosted-lifecycle-2026-10-31-failed-1/README.md)
was rejected because a generated Cedar parser was missing from the local Cargo
cache. The [targeted cache rebuild](cache-repair.log) succeeded before fresh
credential issuance for this final run. These records do not claim a complete
qualification pass. The runner now explicitly reports `failed_source_changed`
if source drift is detected, rather than leaving an earlier success label.

See the [runbook](../../../docs/SELF_HOSTED_PILOT.md#issuer-rollover-and-broker-trust-lifecycle)
for `--identity-lifecycle` reproduction and the remaining deployment gates.
The [artifact manifest](artifact-sha256.json) covers this record's retained files.
