# RFC 0029: Pinned PostgreSQL Unix peer transport

- Status: Draft
- Profile/version: KF-POSTGRES-PEER-0.1-draft
- Milestone: M6d2b transport prerequisite; deployed acceptance open
- Baseline: ee1a0ff; RFCs 0027–0028
- Owners/reviewers: unassigned

## Contract

The protected launcher may select `--postgres-peer-uid N` together with
`--custody-root`. N is the nonzero database server kernel UID, selected by the
operator, never a request. Before sending PostgreSQL startup/authentication bytes,
connect a Unix stream, verify its kernel peer UID, then pass that same stream to
the SQL driver. Repeat on every executor and query connection. There is no retry
or fallback to the legacy transport. Unsupported hosts refuse this profile.

Check the absolute socket-directory path without symlink or parent traversal.
Ancestors must be owned by root, caller or pinned database UID, not group/other
writable; root-owned sticky ancestors above the socket directory are allowed.
The socket directory must be database-owned and not group/other writable. The
socket inode must be database-owned, a socket, have no other permissions or special
bits, and have permissions only for owner/group. Group write on the
socket permits connection; it does not permit directory-entry replacement. Retain
directory/socket device and inode snapshots before and after connection and refuse
changes. A two-second deadline covers connect and SQL startup.

Kernel peer identity binds the connected stream even if a path is replaced.
Same-UID administrator processes, root, ACLs, mounts and namespaces remain trusted
or unqualified. These checks do not inspect HBA/ident administration or prove
independent agent containment. `--check-custody` remains local-file-only;
`--check-database` uses pinned transport plus catalog enrollment. Existing loading
and unpinned transport keep their declared legacy scope.

## Verification

Exercise a real local Unix listener: correct UID connects; wrong UID, permissive
directory/socket, symlink and traversal refuse before SQL bytes. Exercise the
shipping target with the actual PostgreSQL server UID: enrolled roles pass,
incorrect pin refuses without resource mutation. Preserve all previous fixtures
and evidence. A disposable Linux qualification harness may provision distinct
accounts only on a fresh CI/container host and must retain actual observations;
adding a harness alone does not close deployed acceptance.

M6d2b additionally requires independently administered service identities,
ACL/mount/namespace and launcher policy, remaining service material loading,
rotation, and deployed agent/descendant bypass observations. No automatic rotation
or isolation claim follows from this transport.
