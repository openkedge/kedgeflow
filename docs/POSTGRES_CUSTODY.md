# SQL target file custody and peer fixture (M6d2a)

[RFC 0028](rfcs/0028-postgres-custody.md) supplies explicit protected-file loading
for `kf-postgres-target` and real PostgreSQL peer tests. This qualifies descriptor,
UID/mode and mapping mechanics in software fixtures. It does not qualify an
enterprise deployment or separate owner/target/agent OS accounts.

## Select protected loading

Use an independently protected, absolute directory for the target's configuration,
certificate, CA, private TLS key and query token. Run the target under its dedicated
non-root account. Public configuration/certificate/CA files may be 0644; secrets
must have no group/other permissions, typically service-owned 0600. Directories
must be owned by root or that service UID, without set-ID bits or group/other write. The loader
allows root-owned sticky ancestors above the protected root, but not a writable
root or descendant. It refuses symlinks, hard-linked files, executable/special files,
parent traversal, paths outside the root, FIFOs and oversized material.

```sh
kf-postgres-target --config /etc/kedgeflow/sql-target/target.json \
  --custody-root /etc/kedgeflow/sql-target --check-custody
kf-postgres-target --config /etc/kedgeflow/sql-target/target.json \
  --custody-root /etc/kedgeflow/sql-target --check-database
kf-postgres-target --config /etc/kedgeflow/sql-target/target.json \
  --custody-root /etc/kedgeflow/sql-target
```

Every referenced file path must be absolute and under the selected root. Use actual
paths without symlink components; symlink-based secret/config projections need a
separately qualified delivery profile. Custody root selection belongs to the
protected service launcher, never an agent request.

The root is anchored by a verified directory descriptor. Each child is opened
relative to a verified descriptor with NOFOLLOW; file metadata is checked before
and after a bounded read. TLS and the target service consume those exact bytes.
The loader does not check a pathname and then reopen it through the legacy loader.
An anchored descriptor survives root pathname replacement. Administrative writes
and multi-file generation consistency remain trusted/unqualified.

`--check-custody` requires `--custody-root`, conflicts with `--check` and
`--check-database`, starts no listener and contacts no database. It also validates
local TLS/registration/token material. Its unsigned local observation is:

```json
{"profile":"KF-POSTGRES-CUSTODY-0.1-draft","operation":"check_custody","effective_uid":1001,"files_checked":5,"status":"passed","scope":"uid_mode_descriptor_snapshot"}
```

With the root selected, ordinary startup and both existing check modes use the
same protected loader. Offline `--check` still makes no database call; active
`--check-database` adds the [standalone SQL role checks](POSTGRES_ENROLLMENT.md).
Any custody failure exits nonzero before a listener or SQL operation. No fallback
or automatic chmod/chown/repair is performed. Omitting the root retains legacy
loading and provides no file-custody qualification.

## Reproduce peer qualification

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 \
  python scripts/test-postgres.py --bindir /path/to/postgresql-18.3/bin --peer \
  --command scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture --test-threads=1
```

The launcher creates only its own disposable cluster. It selects the kernel OS
username, disables TCP, restricts its socket to 0700 and installs peer/reject HBA
rules. Exact maps cover the fixed target roles; anchored regex entries cover only
the randomized enrollment test roles. The regex entries are fixture-only and must
not be copied into a deployment. Default launcher mode remains explicit trust
fixture authentication for prior reproduction.

[PostgreSQL peer authentication](https://www.postgresql.org/docs/18/auth-peer.html)
uses kernel identity; [user maps](https://www.postgresql.org/docs/18/auth-username-maps.html)
and [socket permissions](https://www.postgresql.org/docs/18/runtime-config-connection.html)
are independently administered deployment controls. The fixture verifies parsed
rules, permitted fixed/randomized role logins, unmapped agent/owner suffix denial,
wrong-map denial and restored access without changing retained SQL outcomes.

## Evidence and boundaries

The [M6d2a verification](../results/verification/rfc-m6-custody-2026-10-13/README.md)
retains **269 Rust tests across 40 binaries**, five filesystem groups, a shipping
custody test within ten native SQL cases, all eleven M6c failures, **fifteen SQL
storage/peer groups** and **32 Python tests**. SQL/etcd/SDK are required. Prior
verification, frozen records/paper and the SQL migration remain unchanged.
Rustix 1.1.5 was already pinned transitively; it is now a direct dependency for safe
Unix descriptor operations. No dependency package version changes.

The shipping test distinguishes offline/active modes, rejects unsafe modes,
symlink/root escape and conflicting flags before effect, then starts a protected
service, changes the on-disk token and observes retention of the startup snapshot.
A new check rejects the unsafe replacement. Normal authorized commit/query still
works once. File replacement is not automatic secret revocation or rotation.

Same-UID fixtures can authenticate as mapped target roles and administer their
owner database; an unmapped database username is not an independent agent OS
account. Actual separate-account agent/descendant socket/file/shell/SDK denial,
Darwin stripped requested set-ID file bits in the fixture; executable-mode refusal
is observed, while isolated set-ID semantics on Linux remain unqualified.
ACLs, mounts/namespaces, privileged processes, file/secret rotation and deployed
launcher downgrade protection remain M6d2b gates. The runtime file mode does not
inspect pg_hba or certify the database socket's ownership/server identity. Other
services retain their existing loaders and have no new custody claim. Physical/
stale restore, retention, budgets and real owner acceptance remain M6d3/M5c gates.

## Connected PostgreSQL peer pin

[RFC 0029](rfcs/0029-postgres-peer-transport.md) adds an explicit
--postgres-peer-uid option requiring protected file loading. It checks socket
path/mode snapshots and the kernel UID of the connected stream before SQL bytes.
The driver uses that same stream for both enrolled roles. File custody alone
retains its earlier limits. [New prerequisites](MILESTONE_PREREQUISITES.md) describe
the Linux account fixture, restore rehearsal and remaining deployment gates.
