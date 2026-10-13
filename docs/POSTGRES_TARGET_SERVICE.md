# Run the draft PostgreSQL target (M6b1)

[RFC 0024](rfcs/0024-postgres-target-http.md) supplies `kf-postgres-target`, a native
mTLS reservation endpoint and separate authenticated outcome query. The driver
calls the [RFC 0023 storage functions](POSTGRES_RESERVATION.md) over a fixed local
Unix socket and acknowledges COMMIT before returning a terminal result.

Start from [postgres-target.example.json](../config/postgres-target.example.json).
Replace public placeholders with independently approved Grant Authority and target
credential keys (standard base64), exact registered action/resource/contract and
gateway/query SPIFFE identities. Keep private TLS keys and a distinct randomly
generated query token (at least 32 characters) in protected files. The service
loads static pins/token at startup; approved renewal/revocation delivery is later
deployment work. It never accepts an agent's subject token as target authority.

Enroll RFC 0023's schema/functions/resource under a protected non-agent owner.
Use separate database execution and query login roles with schema USAGE and only
their respective `apply(jsonb)` or `lookup(text,text)` EXECUTE permission. Grant
neither table mutation, schema creation nor administrative roles. Configure
protected Unix socket permissions and approved peer-authentication maps; this
service has no remote/TCP database or password-mode configuration. The path itself
cannot certify PostgreSQL authentication, key custody or backup independence.

```sh
cargo build --locked --bin kf-postgres-target
cargo run --locked --bin kf-postgres-target -- --config /etc/kedgeflow/sql-target.json --check
cargo run --locked --bin kf-postgres-target -- --config /etc/kedgeflow/sql-target.json
```

`--check` validates local TLS/keys/registration and closed database configuration.
It performs no database/network operations, enrollment or migration. Active driver
connections validate the fixed function roles, with no permissive fallback.

Dispatch verifies the exact signed grant and actual reference target credential
before constructing a SQL request. The service pins resource/incarnation, action,
parameters, version predicate, adapter contract, tenant, domain, audience/scope and
gateway identity. The mutation role cannot select arbitrary SQL or routing through
this API. The database independently checks version/incarnation/fence and expiry.

Query requires the separate mTLS recovery identity and protected query bearer.
Use the existing `HttpOutcomeQuerier` / recovery `query_url`, query CA/certificate/key
and token file. A missing record remains unavailable/unknown; it is never permission
to resend. Queries work after original execution credentials expire under current
query authorization. Historical incarnation reconfiguration needs explicit retained
query enrollment; this fixed service does not broaden history disclosure.

The fixed `PostgresAdapter` implements the trusted `ResourceAdapter` library port
and verifies target outcomes independently. **The gateway/control CLI and Node
Agent Adapter still bind the mock action.** M6b2 adds explicit registered SQL
parameter mapping and a fresh complete agent/admission/issuer/claim/broker/target/
recovery path. Direct fixture credentials in these tests do not close that gate.

## Verify against an isolated database

```sh
python scripts/test-postgres.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --command cargo test --locked --test postgres_target -- --nocapture --test-threads=1
```

The launcher owns and deletes a disposable Unix-socket cluster, supplies fixture
SQL roles and sets `KF_REQUIRE_POSTGRES=1`; no existing target is contacted. Native
tests use real mTLS and actual database COMMIT with generated preissued authority.
Without the launcher, optional Cargo runs explicitly skip these cases. CI runs a
separate SQL job with the dependency required. Complete combined qualification also
requires the etcd/SDK wrapper inside this launcher; use the retained verification
record's commands when reproducing that run.

Production enrollment/peer maps, actual provider rotation/credential custody,
complete writer/native bypass coverage, fence bootstrap, abrupt database/storage
loss, stale target restore, operational budgets and owner acceptance remain
[enterprise gates](ENTERPRISE_QUALIFICATION.md). The chosen defaults are software
development fixtures, not a production cutover decision.
The [retained M6b1 verification](../results/verification/rfc-m6-target-2026-10-12/README.md)
pins the sources and combined required-mode results.
