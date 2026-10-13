# PostgreSQL enrollment preflight (M6d1)

[RFC 0027](rfcs/0027-postgres-enrollment.md) strengthens the native SQL driver's
function-role boundary and adds an explicit operator database check. Runtime
checks and preflight share the same fixed catalog query. This is a deployment
prerequisite; it does not approve an enterprise pilot.

## Supported enrollment

Use two distinct standalone LOGIN roles. Each has protected-schema USAGE and only
its own resource function: execution gets `kf_reservation.apply(jsonb)`; query gets
`kf_reservation.lookup(text,text)`. Neither role owns the database or has database
CREATE, protected-schema CREATE, protected-table/column read or mutation, opposite
function execution, admin/replication attributes, or membership in another role.
Schema/function GRANT OPTION is also refused, so the target login cannot delegate
those privileges. The profile conservatively rejects all memberships, even those with INHERIT/SET
currently disabled. It covers effective rights, including PUBLIC grants.

Column grants are separate from table grants. NOINHERIT can also leave a role with
SET ROLE access while its current effective table privileges appear narrow.
[PostgreSQL's effective privilege functions](https://www.postgresql.org/docs/18/functions-info.html)
provide the checks used here. Direct table SELECT is also refused: historical
resource disclosure must use the enrolled query service/function boundary.

A protected non-agent administrator applies the unchanged RFC 0023 migration and
creates new roles explicitly. This example assumes the target database already
exists and its owner independently protects function/schema custody:

```sql
BEGIN;
CREATE ROLE kf_executor LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE kf_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE kedgeflow TO kf_executor, kf_reader;
GRANT USAGE ON SCHEMA kf_reservation TO kf_executor, kf_reader;
GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO kf_executor;
GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO kf_reader;
COMMIT;
```

The migration revokes PUBLIC schema/table/function privileges. The example fails
if roles already exist; it does not reconcile or widen existing enrollment. Audit
existing roles with the protected owner and make any changes through that owner's
approved administration process. No migration or automatic revoke/repair is added.

Never allow agents or descendants to authenticate as either target login, the
schema/database owner or an equivalent writer. Protect the Unix socket and use
separate administered OS accounts and exact authentication maps.
[Peer authentication](https://www.postgresql.org/docs/18/auth-peer.html) uses the
kernel-reported OS user; the configured directory and a successful role check do
not prove peer-map or OS-account isolation. M6d2 must qualify those paths.

## Operator sequence

1. Pin the target's resource/incarnation/action/CTD/keys and covered writer set;
   retain protected owner, database authentication, function and configuration
   custody references. Start from the existing target configuration example.
2. Run offline `--check` to validate local configuration/TLS/keys/token. It does
   not contact the database and can succeed with an absent database socket.
3. Run active `--check-database` against the approved fixed database. It opens
   two bounded connections as the exact execution/query logins, reads only
   enrollment catalogs and exits. It starts no listener, invokes neither resource
   function, reads no reservations, and authorizes no probe mutation.
4. Retain the local JSON observation with the configuration/source pins and time.
   Start the service only through the intended protected deployment. Existing
   fresh leaf and witnessed recovery procedures remain unchanged.

```sh
kf-postgres-target --config /etc/kedgeflow/sql-target.json --check
kf-postgres-target --config /etc/kedgeflow/sql-target.json --check-database
```

The flags conflict. Active check returns nonzero for an unavailable database,
missing/overbroad role rights or invalid local material. A successful observation
has this local format:

```json
{"profile":"KF-POSTGRES-ENROLLMENT-0.1-draft","operation":"check_database","database":"kedgeflow","executor_user":"kf_executor","query_user":"kf_reader","status":"passed"}
```

The report contains no keys, tokens, reservation data or owner decision. It records
both roles' catalog checks at that time; it is not a permanent lock, a signed
approval or a claim about actual authentication/custody. Trusted administrators
can change privileges/functions after a check. Runtime reconnects repeat the
check before each operation, but a concurrent administrative change remains a
trust/TOCTOU boundary.

## Qualification and remaining work

The [M6d1 verification](../results/verification/rfc-m6-enrollment-2026-10-13/README.md)
adds three isolated-database test groups within a required 263-test Rust regression.
Actual target logins demonstrate column UPDATE/INSERT/SELECT/REFERENCES and
NOINHERIT direct/transitive SET ROLE capabilities, then preflight/runtime refuse.
Valid mixed-case standalone logins retain exact role identity. Admin/replication
flags, database ownership/CREATE, protected-schema CREATE,
PUBLIC table/column grants, actual schema/function GRANT OPTION delegation, and
crossed/missing function and USAGE grants also refuse.
The original row/fence/attempts stay unchanged; removing the fixture's excess
rights permits a subsequent normal commit and lookup. Private databases/roles
keep these negative tests independent of other integration cases.

Shipping CLI tests show offline check accepts an absent socket, active check
rejects it, both flags conflict, an admin query role refuses, and clean preflight
succeeds while the configured listener port is already occupied. No attempt or
mutation is created. All six existing native SQL cases and eleven M6c failure
cases remain covered by the full required regression.

This is disposable trust-authenticated SQL, not peer/OS containment qualification.
Enrollment failure after an execution has consumed authority cannot justify
remint, resend, replacement or refund; preserve the original attempt and use
query-only recovery/incident handling. M6d2 must qualify protected OS/socket/peer
and secret custody plus deployed bypass attempts. Physical/stale SQL restore,
retention, budgets, approved providers and owner acceptance remain separate
[M6d/M5c enterprise gates](ENTERPRISE_QUALIFICATION.md).
