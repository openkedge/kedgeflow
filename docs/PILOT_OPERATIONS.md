# cura pilot operations and recovery

These procedures implement the [SQL-only contract](SQL_PILOT_RELEASE.md). They
are unexercised deployment procedures until the actual environment and owners
supply evidence. Every drill must retain exact source, package, configuration,
resource/incarnation, writer inventory, commands, clock and positive/negative
observations. A signed audit proves its signed content; an unsigned metric is
operational telemetry, not authority.

## Installation and canary

1. Approve account/budget/AMI/KMS, mount identities and full writer inventory.
   Confirm private networking, SSM-only administration and explicit egress rules.
   Inventory privileged/root/SSM, metadata, SQL owner, migrations, extensions,
   triggers, maintenance, backup and break-glass paths. An unmediated writer
   remains a blocker until removed or separately qualified.
2. Verify source/package/provenance and externally authenticated publisher digest.
   Stage immutable release bytes. Provision shipping accounts and protected roots
   using the bundled sysusers/tmpfiles declarations. Service roots are root-owned,
   mode 0750, grouped to the exact service; material uses native protected-loader
   modes. Never put secrets in manifests, unit command arguments or retained logs.
3. Map database/target to the same approved host, exact nonzero database peer UID,
   private Unix socket and distinct SQL executor/query roles. Apply migration 0001
   only through the separately administered migration owner. Do not grant direct
   table/schema writes to the target, recovery or agent.
4. Provision Keycloak with its production database, persistent SPIRE server store,
   approved subject/actor audiences, service PKI and protected publisher. Qualify
   rotation/withdrawal across restart and replicas. Do not reuse the disposable H2
   provider fixture as the deployment database.
5. Give each service an individually managed etcd identity/token. Restrict native
   permissions to the approved tenant namespace and separately hosted witness;
   audit every effective permission, including reads. Finer per-key permissions
   must be derived from the actual native transaction inventory and tested; the
   witness transaction may need comparisons across several keys. Never "fix" a
   refusal by granting cluster-wide authority. Enroll only a genuinely empty new
   namespace using the shipping `kf-restore --enroll-empty` ceremony. Never enroll
   an existing namespace or reset the witness to resolve a fault.
6. Run native local preflight on each role host and live read-only target custody/
   database checks. Enroll monitor identities and exact `/ops/ready` endpoints
   using [service operations](SERVICE_OPERATIONS.md). Use fresh probes, not
   `systemctl is-active`, as prerequisite observations. Canary one approved action;
   independently query its original committed outcome and effect.
7. Run actual agent and descendants through shell/file/socket/groups/SDK/direct
   SQL/API/egress/metadata/artifact-substitution probes. Retain denied and allowed
   paths, not only a count. Acceptance remains blocked on an unexplained bypass.

## Monitoring, unknowns and incident ownership

Use [pilot-monitor.py](../scripts/pilot-monitor.py) with a protected `cura` JSON
configuration containing all eight monitor roles. Every endpoint has `role`,
`url`, `ca`, `certificate`, `private_key`; URLs must be exact HTTPS `/ops/ready`
origins and paths enrolled in the relevant service. The collector validates fresh
mTLS reports, complete typed checks, no-store, role and HTTP/result consistency.
It emits only readiness, probe validity and latency in Prometheus format. No
report, bearer, private key or response body is logged.

Install the [alert rules](../deploy/pilot/cura/alerts.yaml) and fill the
[SLO/retention template](../deploy/pilot/cura/slo-template.json) with actual SRE
and resource owners. Alerts need a real route and a rehearsed responder; template
thresholds and missing values are not accepted service-level objectives.

Integrate retained admission/claim/dispatch/broker/target/receipt/incident streams
into counters and distributions before acceptance: allow/refusal by bounded
reason; issued/claimed/dispatched/committed/query counts; original unknown count
and oldest age; owner deadlines; incident and outbox backlog; head/floor lag;
key expiry; service resource/memory/CPU and storage consumption. Correlate trace
IDs with signed audit roots and original attempt IDs without high-cardinality
Prometheus labels or credential contents. The supplied monitor exports readiness
only; unknown/incident event aggregation and dashboard/routing integration are
still implementation work. Missing age telemetry has its own alert and must
never appear as zero unknowns.

On unready/refused or unknown-age alert: stop new admission/issuance for the exact
scope through approved governance. Preserve query-only recovery, audit and
collector access. Identify the original attempt and owner; query its authoritative
outcome. A missing result after possible send remains unknown. Never resend,
refresh a consumed grant, mint again, refund by timeout, or run compensation
without separately admitted fresh inverse authority and applicability evidence.
Acknowledge an incident separately from resolving the underlying unknown effect.

## Backup, stale restore and cutover

The new disposable commands exercise two different boundaries:

```sh
ETCD_BINARY=/approved/etcd scripts/start-etcd.sh -- \
  cargo test --locked --test restore -- --nocapture --test-threads=1
python scripts/qualify-postgres-cold-restore.py --ephemeral-host \
  --bindir /approved/postgresql-18.3/bin
```

The authority test copies a **stopped** fixture member's WAL/backend files, keeps
a separate witness process/storage untouched, demonstrates stale refusal through
the shipping guard/CLI, and recovers the latest nonce/fence. PostgreSQL copies a
stopped private data directory and compares restored resource/outcome state with
a separately retained fixture floor. Both restored application SQL roles stay
fenced; the harness does not enable production cutover. It dispatches one fixture
mutation and never redispatches on restore. These are same-host fixture snapshots,
not independent backups, cloud volume recovery or a quorum-wide disaster rehearsal.

For deployed recovery: freeze all target writers and authority mutations; retain
current independent witness/head/floor, snapshot IDs, signing history, source and
configuration. Verify physical snapshots and restore to quarantined storage with
application connections denied. Independently check target incarnation/version/
fence, original attempts, nonces, outbox and signed audit continuity. Run the live
shipping restore guard with independently retained witness configuration. A
stale/missing/pending/mismatched head or missing outcome keeps execution closed.
Do not restore both authority and its independent witness together. Do not invent
a new witness namespace, modify the floor, or delete attempts as recovery.
Only the actual storage/resource/security owners may approve fenced cutover after
all checks; preserve unresolved authority and query the original attempt.

## Upgrade, rollback, uninstall and re-enrollment

Stage the candidate alongside the old immutable bundle. Stop new authority and
quiesce writers; keep original queries and evidence available. Back up exact
state, validate candidate schema/profile compatibility and compare retained
head/floor, nonces, fences, attempts, signing history and outbox before and after
a canary. Require no duplicate effect on lost COMMIT reply and restart.

Rollback may switch binaries only when they can interpret the current persisted
schema, signatures, counters and restore enrollment. An old binary that omits a
guard or cannot read new state is not a rollback option. Unknown compatibility
blocks restart; never roll storage or authority floors backward to accommodate a
binary. There is no automatic production cutover or schema downgrade in these
tools. Retain configuration/package hashes and the actual owner decision.

Uninstall stops execution and withdraws credentials while preserving query,
audit, target attempts and consumed authority for the agreed retention period.
Detach and preserve retained volumes and backups. Delete no consumed state as
cleanup. Re-enrollment is only a new explicitly approved incarnation/empty
namespace, never a way to reopen an old spent root. Resource, storage, audit and
SRE owners approve final retention and access withdrawal.
