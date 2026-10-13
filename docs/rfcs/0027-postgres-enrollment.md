# RFC 0027: PostgreSQL function-role enrollment preflight

- Status: Draft
- Profile/version: KF-POSTGRES-ENROLLMENT-0.1-draft
- Milestone: M6d1 deployment prerequisite; M6d/enterprise acceptance remains open
- Baseline: 7e30c8a; RFCs 0023–0026
- Owners/reviewers: unassigned

## Problem and scope

The target's fixed Unix-socket driver rejects admin roles, table-wide mutation,
protected-schema creation and execution of the other role's function. Column-only
privileges and membership that permits SET ROLE can evade that check. A trusted
operator also needs to verify both role enrollments before starting a listener,
without a test mutation or publishing execution authority.

Add one shared runtime catalog check and a separate native --check-database mode.
The existing --check remains offline. This increment does not change frozen wire
records, configuration fields, SQL functions or their migration. It tightens the
supported bounded deployment to standalone function-only execution/query roles.

## Authority and contract

For each fixed login, require session/current user to match its configured role;
LOGIN with no superuser, bypass-RLS, role/database creation or replication flag;
no membership in another role, including NOINHERIT/SET-only membership; no database
ownership or CREATE privilege; no protected-schema creation or protected-table read/mutation
privileges, including column SELECT/INSERT/UPDATE/REFERENCES; no execution of the
opposite role's function; USAGE plus EXECUTE for its own protected function; and
no schema/function grant option that can delegate those privileges.

Check both resource and attempt tables. Reject owned/inherited privileges and
PUBLIC grants through PostgreSQL's effective privilege functions. No repair,
revoke, role switch or permissive connection fallback is allowed. Use the same
check on every newly opened runtime operation connection, before any effect/query.
Catalog changes after a check remain an administrator-trust/TOCTOU boundary;
preflight is an observation, not a lock or permanent certification.

The operator CLI validates local configuration/TLS/material, contacts only the
configured database as each fixed role, reads catalogs and emits a bounded local
JSON report. It never starts a listener, invokes apply/lookup, accesses reservations,
migrates, enrolls, or tests dispatch. --check and --check-database conflict.
Missing database/function/permission, excessive role rights or unavailable socket
returns nonzero. Error messages do not print keys, tokens or database values.

## Qualification

Disposable PostgreSQL tests must demonstrate actual forbidden capabilities before
calling the guard: column UPDATE/INSERT, column historical SELECT, NOINHERIT role
membership with SET ROLE access, role/database flags, database ownership/CREATE,
PUBLIC privileges, actual schema/function GRANT OPTION delegation, and
accidentally missing/crossed function grants. Refused
preflight and runtime operations must leave the target row and retained attempts
unchanged. Clean standalone roles, including configured mixed-case names, pass preflight; absent database remains
valid for offline --check but fails active --check-database. Remove excessive
fixture enrollment and verify subsequent new connections can operate normally.

Concurrent fixture tests use distinct temporary roles/objects, never alter the
common execution/query roles used by other tests. Preserve earlier evidence and
retain source-pinned required SQL/etcd/SDK regression plus local quality checks.

The [operator guide](../POSTGRES_ENROLLMENT.md) documents the stricter enrollment
and check modes. [Source-pinned verification](../../results/verification/rfc-m6-enrollment-2026-10-13/README.md)
retains the three new isolated groups, native CLI checks and full regression.

## Deployment and remaining gates

Provide protected-owner role grants and Unix peer-map examples separately from
migration. Runtime function-role checks cannot establish socket/OS account custody,
pg_hba/peer-map correctness, secret access, approved provider identities, deployed
agent/descendant bypass denial, owner authorization, function-body custody,
backup independence, retention, or budgets. Never enroll an agent as either target
login. Database/function owners and separately administered break-glass writers
remain trusted and outside this profile's guard.

M6d2 must qualify OS/socket/peer custody and deployed bypass paths. M6d3 must
prepare retention/restore, operational budgets and owner acceptance on an approved
isolated target, with M5c provider acceptance tracked independently.

## References

PostgreSQL's [effective table/column and role privilege functions](https://www.postgresql.org/docs/18/functions-info.html)
separate table rights, column rights and membership/SET access. Its
[peer authentication](https://www.postgresql.org/docs/18/auth-peer.html) binds local
connections to kernel-reported OS identities; a database path alone is not proof
of that configuration or independent service identities.
