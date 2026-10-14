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
connections validate the [RFC 0027 standalone function roles](POSTGRES_ENROLLMENT.md),
including effective column/PUBLIC rights and membership, with no permissive fallback.
Use the distinct `--check-database` flag for an explicit read-only catalog observation
of both roles without a listener, resource query or mutation. The two check flags
conflict; database unavailability fails active preflight. This observation cannot
certify OS/socket/peer custody or future administrative changes.

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
and verifies target outcomes independently. [M6b2 / RFC 0025](rfcs/0025-postgres-leaf-binding.md)
connects the named action `postgres.reservation.set.v1`, CTD version `1.0`, through
fresh admission/issuance, the official Node client, native broker and M4 recovery.
The CTD must pin the exact RFC 0023 Parameters schema. Start the gateway from
[gateway-postgres.example.json](../config/gateway-postgres.example.json), replace
its placeholders and align every action/resource/domain/predicate/contract and
target key/audience/scope with this target and broker registration. The closed
`postgres_adapter` field opts into `KF-POSTGRES-LEAF-0.1-draft`; missing/mismatched
configuration and mixed mock/SQL tools refuse. `kf-proxy --check` constructs the
SQL client without contacting SQL or other services. No generic SQL read is exposed.

The full-path tests obtain fresh signed certificates/grants under installed and
acknowledged control state. Generated signed subject/actor identities drive the
native one-shot broker, and the real SQL function commits. Discarding its reply
leaves the original attempt unknown until authenticated M4 query recovery.
A separate Node process resolves it after expiry/revocation without another mint
or SQL dispatch. Evidence remains a fixed signed software fixture, not a live
enterprise provider; target/identity deployment acceptance remains separate.
The current leaf binds the baseline to the registered CTD's exact version_eq clause;
a subsequent row version requires an updated registered descriptor. Automated
version-template/descriptor rollover remains unqualified.

## Verify against an isolated database

```sh
python scripts/test-postgres.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --command cargo test --locked --test postgres_target -- --nocapture --test-threads=1
```

The launcher owns and deletes a disposable Unix-socket cluster, supplies fixture
SQL roles and sets `KF_REQUIRE_POSTGRES=1`; no existing target is contacted. Native
tests use real mTLS and actual database COMMIT with generated preissued authority.
Without the launcher, optional Cargo runs explicitly skip these cases. CI runs a
separate SQL job with SQL, etcd and the official SDK required for the fresh leaf path. Complete combined qualification also
requires the etcd/SDK wrapper inside this launcher; use the retained verification
record's commands when reproducing that run.

Production enrollment/peer maps, actual provider rotation/credential custody,
complete writer/native bypass coverage, fence bootstrap, abrupt database/storage
loss, stale target restore, operational budgets and owner acceptance remain
[enterprise gates](ENTERPRISE_QUALIFICATION.md). The chosen defaults are software
development fixtures, not a production cutover decision.
The [retained M6b1 verification](../results/verification/rfc-m6-target-2026-10-12/README.md)
pins the sources and combined required-mode results.

The [M6b2 verification](../results/verification/rfc-m6-leaf-2026-10-13/README.md)
retains the clean 249-test required regression and fresh SQL composition cases.
The gateway ID prefix fix prevents randomly generated attempt IDs from violating
the frozen receipt and SQL label schemas. Earlier incomplete runs remain historical
evidence; they do not qualify the final source. Existing consumed attempts are never
renamed or refunded automatically.

[M6c / RFC 0026](SQL_FAILURE_QUALIFICATION.md) adds eleven fresh SQL process-kill,
witnessed logical-restore refusal and incident/collector cases. The retained
[260-test required regression](../results/verification/rfc-m6-failure-2026-10-13/README.md)
keeps earlier evidence intact. Physical/stale SQL restore, independent collector
storage and enterprise custody remain unqualified.

For explicit file protection, select [RFC 0028 custody mode](POSTGRES_CUSTODY.md)
with `--custody-root`; `--check-custody` consumes verified descriptor bytes without
a listener or database call. Legacy loading remains unqualified. The new required
SQL fixture uses actual peer maps while retaining one OS UID; separate-account
bypass/custody and production authentication remain open.
