# Protected SQL pilot preparation

The **12 November cura SQL pilot** now distinguishes [Milestone A infrastructure
and Milestone B acceptance](SQL_PILOT_RELEASE.md), with [operational and physical
restore procedures](PILOT_OPERATIONS.md). Cloud resources, security approval,
independent custody, actual SRE ownership and deployed evidence remain
**BLOCKED_EXTERNAL_INPUT**. Current work prioritizes the SQL foundation; new
Terraform, Kubernetes and durable-capacity expansion is deferred.

Status: **31 October 2026**. Next gates: M5c approved providers/custody, then M6
isolated deployment acceptance. The [bounded M8 software
exit](M8_ACCEPTANCE.md) is recorded against its frozen source. New fixture or
deployment changes need their own evidence and do not extend that record.

The first production target is self-hosted Linux with systemd and separate
service accounts. Follow the [production readiness worklist](PRODUCTION_READINESS.md)
for runtime controls, packaging, operational qualification and release exits.

**Selected provider path:** self-hosted Keycloak and SPIRE. The
[executable identity prototype](SELF_HOSTED_PILOT.md) obtains actual provider
credentials and checks native mTLS/DPoP and broker identity verification. This
shipping-loader/SDK increment also qualifies a same-host fresh-authority SQL
commit and original-attempt recovery with pinned and signed refresh identity
sources. Generated administration/evidence and a native TLS relay remain fixture
infrastructure. The [lifecycle qualification](../results/verification/rfc-m5-selfhosted-lifecycle-2026-10-31/README.md)
adds actual Keycloak signing-key rollover/restart and shipping broker trust
withdrawal/restore refusal. The [cold provider storage qualification](../results/verification/rfc-m5-selfhosted-storage-2026-10-31/README.md)
adds same-host H2/SPIRE datastore/key copies into fresh containers and stale
issuer refusal under retained trust. The [SPIRE rollover qualification](../results/verification/rfc-m5-selfhosted-spire-2026-10-31/README.md)
adds JWT and X.509 issuer transitions, native mTLS and fresh-actor original-claim
redemption. Production storage recovery, service CA rollout, delivery budgets
and independent custody/deployed isolation remain open.

## Work that can run before provider approval

The disposable [Linux account fixture](../scripts/qualify-postgres-isolation.py)
now extends SQL enrollment preflight to a live protected `kf-postgres-target`.
It provisions four fresh OS accounts: database, target, agent and recovery. The
target pins the separate database kernel UID and loads protected material.
Recovery uses its own CA-issued workload certificate and the target query token
to query a missing original attempt through the real TLS/HTTP/SQL path.

The expected positive response is `404 unknown_outcome`, which means the exact
attempt has no retained SQL outcome. It is not positive no-effect evidence for
an executed attempt, a completed action, or permission to retry.

The fixture must observe:

| Probe | Required result |
| --- | --- |
| Enrolled recovery identity and correct bearer | `404 unknown_outcome` through the live target |
| CA-issued agent identity with correct query bearer, query and dispatch | `401 invalid_workload` for each endpoint |
| Enrolled recovery identity with wrong bearer | `401 invalid_credential` |
| No client certificate | TLS refusal, with no HTTP success |
| Agent reads recovery private key or fixture CA private key | OS denial |
| Recovery connects directly as the SQL reader | OS/socket denial |
| Existing agent file/socket/shell/Python and SQL role bypass probes | Denial |
| Retained SQL attempt count after all probes | Zero |

Run only on a disposable Linux host with the pinned PostgreSQL 18.3 installation
and a freshly built target binary. The standalone command is:

```sh
cargo build --locked --bin kf-postgres-target
sudo python3 scripts/qualify-postgres-isolation.py --ephemeral-host \
  --bindir /absolute/path/to/postgresql-18.3/bin \
  --target "$PWD/target/debug/kf-postgres-target" > postgres-isolation.json
```

The independent `postgres-isolation` [CI job](../.github/workflows/ci.yml) builds
the [disposable image](../scripts/postgres-isolation.Dockerfile) from a
digest-pinned Rust 1.98.0 base and checksum-verified PostgreSQL source. Its build
context is allowlisted to source, schemas, migrations and the example target
configuration. Runtime has no external network, published ports, host mounts or
privileged mode; only its loopback TLS and private Unix socket are used. No host
accounts are created. This job runs independently of the Kubernetes job.

```sh
docker build -f scripts/postgres-isolation.Dockerfile -t kf-postgres-isolation:local .
docker run --rm --network none --pids-limit 256 --memory 1g \
  kf-postgres-isolation:local > postgres-isolation.json
```

CI retains the exact source archive and SHA-256 manifest, target binary hash,
image/container metadata, package/tool versions, build log and probe report in
the `postgres-isolation` artifact. The cleanup step removes only that fixture
container, including if evidence copying fails. This container fixture qualifies
its separate UIDs and declared access paths within one Linux kernel; deployed
administrator, mount, ACL and launcher boundaries remain independently accepted
pilot work.

The fixture creates accounts and a private database; it never accepts an existing
database. It stops the target process group and database and deletes its accounts
before returning success. The public report contains case outcomes, kernel UIDs
and the target binary hash; client keys and bearer values are excluded. Retain
the CI source revision and build/tool logs alongside that report. A local Mac
probe can qualify TLS/query mechanics but cannot qualify Linux account isolation.
The [30 October Linux ARM64
record](../results/verification/rfc-m6-pilot-isolation-2026-10-30/README.md)
observes all ten groups and five live probes in a fresh network-disabled
container, four distinct non-root role UIDs, zero retained SQL attempts and no
remaining fixture users/groups after cleanup. The container was removed.
Linux AMD64 CI execution and deployed/independent acceptance remain open.

## Required deployment inputs

Keep secrets in approved protected configuration. Record references and decisions
in the pilot evidence, rather than copying credentials into this repository.

| Input | Responsible owner | Needed before |
| --- | --- | --- |
| Approved AS subject-token and workload SVID contracts, audiences/algorithms, registration and rotation/revocation rules | Identity/security | Provider integration |
| Exact provider mint/introspection and effective target credential scope/lifetime contract | Identity/resource | Broker/target integration |
| Isolated target/version, exact registered action/resource/incarnation and all writer/admin/break-glass boundaries | Resource/database | Deployed SQL enrollment |
| Service identities, native ACLs, launcher/config paths, socket/egress/file access and key custody | Deployment/security | Launch and bypass qualification |
| Independently held ledger/storage head and floor, restore authority, retention and physical restore/cutover procedure | Storage/SRE | Failure and restore rehearsal |
| Workload budgets, refusal/unresolved-age thresholds, incident routing, on-call and abort/exit ownership | Resource/SRE | Pilot acceptance |
| Explicit review profile: no-review leaf, or separately qualified M7 ceremony/hardware | Policy/security | Admission enrollment |

The repository has no approved enterprise provider configuration. Generated
fixture identities do not approve these inputs. Implement a provider adapter
against the supplied contract; different subject/actor semantics require an
explicit compatible profile.

## Deployment qualification sequence

1. Pin source/binaries and approved input revisions. Enroll the exact action,
   SQL roles, service identities and target. Run the shipping target's protected
   `--check-custody` and `--check-database` modes under its actual service identity;
   preserve the independently approved database peer UID. See
   [SQL custody](POSTGRES_CUSTODY.md) and [enrollment](POSTGRES_ENROLLMENT.md).
2. Integrate the actual subject/SVID verifier and one-shot mint/target contract.
   Exercise rollover, withdrawal, stale keys, replica/restart replay, outage,
   delayed exchange and overbroad/expired credentials. Preserve the original
   permit and attempt on every lost response.
3. Exercise the fresh signed admission/issuance, gateway, broker, SQL commit and
   authenticated original outcome query under separate deployed roles. Attempt
   file/socket/shell/SDK/egress bypass from the actual agent and descendants.
   Generated fixture credentials remain fixture evidence only.
4. Rehearse covered competing writers, stopped/unknown operations, target and
   service failure, credential rotation and stale/physical storage restore with
   the independent head/floor intact. Recovery must query the original attempt;
   uncertainty retains consumed authority without resend or refund.
5. Retain source/config references, tool versions, commands, positive and negative
   observations, attempted/claimed/dispatched/committed/refused/unresolved counts,
   end-to-end latency and unresolved age. Resource, security, deployment and SRE
   owners record their acceptance or remaining gaps.

The acceptance report must distinguish local software observations, deployed
observations and independent owner decisions. The fixture's `passed` status
closes only its named disposable cases. M8 physical operations and M9 independent
peer/release acceptance remain separate gates.
