# RFC 0028: PostgreSQL target file custody and peer fixture

- Status: Draft
- Profile/version: KF-POSTGRES-CUSTODY-0.1-draft
- Milestone: M6d2a bounded custody prerequisite; deployed M6d2 acceptance open
- Baseline: b3aceb8; RFCs 0023–0027
- Owners/reviewers: unassigned

## Scope

Add explicit SQL-target protected-file loading and real PostgreSQL peer
qualification in disposable software fixtures. Keep existing legacy loading
separate and unqualified for file custody. No frozen record, target action,
configuration field, SQL function or migration changes. Reuse pinned rustix for
safe descriptor-relative Unix operations; declare it directly in the lockfile.

This host has no container runtime or independently provisioned service accounts.
Same-UID tests cannot prove that an agent cannot acquire target credentials or
modify target files. POSIX UID/mode and descriptor mechanics plus real kernel peer
mapping are prerequisites, not enterprise OS/ACL/mount/namespace containment.

## Protected file contract

The native target opts in with --custody-root. --check-custody requires that root
and conflicts with other check modes. It checks local material only, starts no
listener and contacts no database. With the root selected, ordinary startup,
--check and --check-database consume the same protected loader.

Require a non-root effective UID and an absolute custody root. Open each directory
component from an anchored descriptor with DIRECTORY/NOFOLLOW/CLOEXEC. Accept only
root or service UID ownership and no group/other write. A root-owned sticky ancestor
such as /tmp is allowed only above the protected root; the root and descendants
must be non-writable by other users. Reject parent traversal and symlink roots,
directories or files. All five file paths must be absolute and beneath the root.

Configuration, certificate and CA files are bounded regular single-link files,
owned by root/service UID, not executable/special and not group/other writable.
TLS private key and query bearer additionally have no group/other permissions.
Use NONBLOCK to avoid hanging on FIFOs/devices, then validate the opened descriptor.
Read bounded bytes from that descriptor, validate metadata before/after, and build
TLS/service state directly from those bytes. Never validate a path then reopen it
with an unprotected loader. Atomic rename can publish a new file; an existing
opened descriptor remains bound to its original inode. Owner/admin writes remain
trusted and cross-file generation atomicity is not established.

The unsigned local report states profile, operation, effective UID, five checked
files and passed descriptor/mode scope. It contains no private material or owner
acceptance. Extended ACLs, privileged processes, shared UID, mounts, remote
filesystems, memory dumps and secret rotation/custody remain separate gates.

## PostgreSQL peer fixture

Add explicit --peer mode to the disposable launcher. Pin the actual kernel OS
username, reject TCP, use a private socket directory and 0700 socket mode. Exact
maps enroll the fixed executor/query roles; anchored regex maps cover only the
existing randomized enrollment fixture roles. Those regex entries are test-only.
Owner access remains the fixture's kernel user, so this does not model independent
owner/target/agent OS accounts.

Confirm parsed HBA/ident rules, permitted target-role logins, unmapped agent login
refusal, wrong OS-map refusal followed by restored access, and conserved SQL state.
Run the entire required Rust SQL/etcd/SDK suite under peer mode. Keep default trust
fixture mode explicit for prior reproduction; never label its evidence peer proof.

## Qualification and rollout

Test symlink/root escape, hard link, FIFO, oversized file, unsafe file/directory
modes and ownership policy; retained descriptor under path replacement; valid
public/secret material and native check/startup refusal with no SQL effect. Legacy
flags remain compatible and do not silently acquire custody claims. Production
startup must explicitly select this bounded profile through protected deployment.

Retain source-pinned logs and new evidence separately. M6d2b must qualify separate
OS accounts, deployed agent/descendant socket/file/shell/SDK bypasses, ACL/mount
policy, peer-map administration and secret/configuration rotation. M6d3 retains
physical/stale restore, retention, budgets and real owner acceptance; M5c provider
acceptance remains open. Do not create host users or modify existing targets here.

The [operator guide](../POSTGRES_CUSTODY.md) states supported loading/check modes
and remaining deployment gates. [Source-pinned verification](../../results/verification/rfc-m6-custody-2026-10-13/README.md)
retains five filesystem groups, shipping startup and peer/refusal observations
alongside the complete required regression.

## References

PostgreSQL [peer authentication](https://www.postgresql.org/docs/18/auth-peer.html),
[exact and regex user maps](https://www.postgresql.org/docs/18/auth-username-maps.html)
and [Unix socket permissions](https://www.postgresql.org/docs/18/runtime-config-connection.html)
provide the fixture mechanics. Root/UID/mode observations are not a complete OS
security proof.
