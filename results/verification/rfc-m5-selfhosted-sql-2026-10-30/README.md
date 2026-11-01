# Self-hosted shipping SQL pilot — 30 October 2026

**Passed the bounded shipping SQL pilot.** Actual Keycloak 26.8.1 DPoP-bound
subject credentials and SPIRE 1.15.5 JWT/X.509-SVIDs flow through the official
Node SDK and the shipping `kf-control`, `kf-broker`, `kf-proxy` and
`kf-postgres-target` processes. See the [summary](summary.json),
[workflow results](sql-workflow.json) and [required execution log](shipping-sql.log).
This is a new qualification; earlier frozen records remain unchanged.

Both fresh workflows acquire signed evidence/admission/issuance, spend one native
broker mint permit, obtain the target credential and commit actual PostgreSQL.
One uses a pinned identity snapshot; the lost SDK response case uses signed
identity refresh with a separately generated authority key, exact head and epoch
floor. Raw Keycloak subject tokens remain unchanged through SDK, admission,
gateway and broker verification.

Each case then stops the domain, waits for actual grant expiry, restarts the
shipping gateway and launches a new SDK process against its durable operation
store. Query-only recovery returns the same original attempt/grant: one broker
exchange, unchanged permit, one retained SQL attempt, and resource version
241 → 242 with the original fence and `booking:pilot` reservation. Resume performs
no new admission, issuance or grant-bearing execution. The lost SDK response is
simulated after consuming the real shipping response; a lost target response is
covered separately by the existing SQL regression tests.

The [75 identity/configuration Rust tests](required-auth.log) passed with required
real three-member etcd and no runtime skips. The [33 existing SQL/crash/SDK
regressions](sql-regression.log) passed with required SDK, peer PostgreSQL and
real etcd: two SQL leaf cases, eleven SQL failure/restore cases and twenty live
agent cases. The first thirteen preceded the final pilot-only closed-header
tightening; the twenty live-agent cases and final identity/provider checks ran
after it. All [five Node vector suites](node.log), [47 Python tests](python.log),
[feature-enabled clippy](clippy.log), [format](format.log), [Ruff](ruff.log),
[mypy](mypy.log) and [frozen paper/contract check](whitepaper.log) passed.
Signed semantic negatives cover malformed profile selection, wrong client/type,
closed claims/header, explicit null JWK and absence of original-profile fallback.

The [405 source input hashes](source.json) match the [pre-run archive](source.tar.gz)
and remained unchanged throughout the final provider/SQL run. The [baseline
revision](revision.txt) identifies the checkout; the working tree contains the
new implementation. Exact shipping binary SHA-256 values are in the workflow
report. [Tool versions](tools.json), [workload image metadata](workload-image.json),
[image build](workload-build.log) and [workload source verification](image-source.log)
retain the build context. Keycloak and Debian are digest-pinned; SPIRE release
archive checksums are pinned in the Dockerfile. PostgreSQL 18.3, etcd 3.6.5,
Rust 1.98.0, Node 25.2.1 and official MCP client 2.3.0 were used.

Provider processes ran in Linux ARM64 containers in an isolated local VM.
Shipping native services, SDK, PostgreSQL and the three-member etcd fixture ran
on Darwin ARM64. Administrative PKI, evidence and service certificates are
generated fixtures; a same-host mTLS relay forwards native ledger transactions
to loopback etcd. Its role/token gate is fixture infrastructure, not deployed
native ACL qualification. Actual workload credentials were copied through a
short-lived private directory. All native services use this host's one OS UID.
This does not establish protected cross-host workload-key custody or combine
the [separate Linux account isolation record](../rfc-m6-pilot-isolation-2026-10-30/README.md)
into an isolated end-to-end deployment.

The runner verifies unregistered UID credential/client-secret refusal and the
registered workload's denial of SPIRE signing keys/admin socket. Both randomly
named containers and their internal network were removed. No published ports,
host mounts or privileged mode were used. Private credentials/provider logs are
excluded from public artifacts. Temporary SQL, etcd and service processes were
stopped; the [VM stop record](vm-stop.log) restores the initially stopped VM.
The [artifact manifest](artifact-sha256.json) covers this record's retained files.

The [runbook](../../../docs/SELF_HOSTED_PILOT.md) documents explicit Rust-loader
`identity_profile` and SDK `identityProfile` selection and reproduction with
`--sql-workflow`. The `selfhosted-pilot-tests` feature opts into the external
provider case; missing required dependencies fail. CI includes both the native
identity check and shipping SQL mode, plus the new SDK vectors. Remote AMD64 CI
execution is unobserved. Approved identity administration/rotation/revocation,
provider database backup/restore, independent publisher/head/floor custody,
deployed role/writer boundaries and owner acceptance remain open.
