# PostgreSQL reservation foundation (M6a)

[RFC 0023](rfcs/0023-postgres-reservation.md) starts the real-target milestone with
one row's conditional reservation update and retained target outcome. The Rust
record module and SQL migration are implemented. [RFC 0024](rfcs/0024-postgres-target-http.md) adds the native SQL service;
[RFC 0025](rfcs/0025-postgres-leaf-binding.md) adds the explicit named SQL action
through fresh admission, issuance, gateway, native broker and Node agent. This is not an accepted enterprise pilot.

## Protected database setup

Use a new approved database namespace and a dedicated protected migration owner.
Apply [migration 0001](../migrations/postgres/0001-reservation.sql) once. It creates
`kf_reservation.resource` and `attempt`, validates closed internal dispatch records,
and provides `apply(jsonb)` and `lookup(text,text)`. PUBLIC schema, table and
function permissions are revoked transactionally.

The operator must enroll the resource's tenant/conflict domain, ID/incarnation,
initial version, last covered fence and reservation. Bootstrap authority fence
allocation above the target floor while writers are stopped. Preserve the floor
on deletion/recreation; never delete retained attempts to resume authority.
Keep owner/superuser access outside agent and target execution roles.

Grant only schema USAGE and `apply(jsonb)` EXECUTE to the protected target service
role; grant only schema USAGE and `lookup(text,text)` EXECUTE to its independently
authenticated query role. Neither gets direct table mutation or schema creation.
These roles are not agent credentials. The functions do not verify grants or
tokens; the future target service must verify the original signed grant, actual
credential, gateway identity, exact registered action/resource/parameters and
tenant before constructing the internal request. Tenant arguments are not ACLs.

Only return terminal outcomes after COMMIT acknowledgement. On ambiguous commit,
query the original attempt; missing lookup can precede an in-flight commit and
does not permit resend. A committed outcome binds the original request and exact
post-version. Neither an unsigned JSON record nor its shape authenticates a target.

## Disposable real-database verification

The standalone suite requires PostgreSQL **18.3** server and client binaries, plus
Python 3.11 or newer. It creates and removes its own temporary database, accepts
local fixture identities over a Unix socket and disables TCP listening. It never
uses an existing deployment. PostgreSQL requires local shared-memory permissions.

```sh
python scripts/test-postgres.py --bindir /absolute/path/to/postgresql-18.3/bin
cargo test --locked -p kedgeflow --test postgres_action
```

The source used for local verification is the [official 18.3 archive](https://www.postgresql.org/ftp/source/v18.3/),
with [published SHA-256](https://ftp.postgresql.org/pub/source/v18.3/postgresql-18.3.tar.bz2.sha256)
`d95663fbbf3a80f81a9d98d895266bdcb74ba274bcc04ef6d76630a72dee016f`.
The CI SQL job builds this pin in its temporary directory. This source/version pin
is a test environment, not a recommendation for an enterprise deployment version.
The [M6a verification record](../results/verification/rfc-m6-postgres-2026-10-12/README.md)
retains the SQL cases, complete Rust regression and tested source pins.

## Native service and remaining integration

[M6b1 / RFC 0024](POSTGRES_TARGET_SERVICE.md) now implements the independently
verified native target/query, local Unix-socket driver, exact reference credential
enforcement and fixed adapter client. M6b2 supplies CTD-driven
admission/issuer/gateway/agent mapping and the fresh broker/ledger/SQL execution
and M4 query recovery path. Frozen contracts remain unchanged.

Then qualify actual target partitions, process/storage loss, delayed credentials
and stale target restore alongside authority consumption. Approved provider and
resource contracts, production identity/RBAC/bypass, complete writer coverage,
retention/migration/restore, workload/incident/cost budgets and owner decisions
remain [enterprise gates](ENTERPRISE_QUALIFICATION.md).
