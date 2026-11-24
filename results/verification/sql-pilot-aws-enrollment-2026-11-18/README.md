# Cura deployed runtime foundation — 18 November 2026

[Observations](observations.json) record actual operator-managed AWS execution
using profile `cura` in `us-west-2`. This advances Milestone B deployment work;
it supplies no independent enterprise acceptance. The earlier
[unenrolled foundation snapshot](../sql-pilot-aws-bootstrap-2026-11-17/README.md)
remains historical and unchanged. The nine hosts were subsequently resumed
within the original window ending **2026-11-18 23:16:43 UTC**.

Eight explicitly identified new EBS data filesystems were enrolled with retained
UUIDs and `nodev,nosuid,noexec`. Persistent PostgreSQL-backed Keycloak and
disk/SQLite-backed SPIRE run under separate non-root identities. Provider restart
preserved public issuer keys, SPIRE registrations and attested node identities.
Both actual registered workload UIDs obtained signature-verified JWT-SVIDs and
chain/URI-verified X.509-SVIDs before and after restart; cross-host unregistered
UIDs and private provider/node key reads refused. Consumed join files and both
encrypted delivery parameters were removed. The temporary three-policy stack was
deleted; all three affected node roles returned to their original SSM-only policy.

The dedicated PostgreSQL 18.3 reservation database uses checksums and synchronous
durability with no TCP listener. Its exact target peer maps and function-only
execution/query roles passed. Database restart preserved resource/attempt state;
agent, recovery and gateway database logins, owner impersonation, direct table
access and agent database-file reads refused. No SQL action was dispatched and
the target listener has not started.

Fourteen operator transport certificates bind keys generated on their owning
hosts. The three-member etcd authority cluster and separate singleton witness use
private TLS client/peer authentication. Each topology has nine individual ordinary
principals: eight namespace-scoped service users and one read-only observer.
Unauthenticated reads, outside-namespace reads/writes, root metadata access and
observer writes refused. Each member was restarted sequentially; all endpoints
remained healthy, cluster/member IDs persisted and authentication/scope checks
passed again. These stores remain under the same account/operator administration.
Ordinary permissions currently cover the native pilot namespace; finer per-key
service qualification and token publication/renewal remain pending.

Provider, database, SPIRE node and ledger units were enabled only after their
named continuity checks. Native restore namespace/head/floor enrollment and the
admission/issuer/gateway/broker/recovery/audit application workflow remain pending.
Successful storage/provider checks do not demonstrate a guarded SQL COMMIT,
complete writer isolation, physical/stale restore, rotation/revocation, measured
operating budgets, independent custody or seven signed owner decisions.

Local validation: **197 Python tests and six subtests**, no skips; Ruff, mypy,
six CloudFormation variants and all 58 frozen protocol files/24 contract pins
passed. Native bundle/source pins remain those of Milestone A; no native binary
was rebuilt for this deployment increment. Exact automation hashes appear in the
observation. Detailed resource identifiers and invocation metadata remain in the
protected operator packet; no secrets, private keys, bearer tokens, raw provider
logs or fabricated acceptance records are published.
