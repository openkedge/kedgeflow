# RFC 0024: Native PostgreSQL target dispatch and authenticated retained query

- Status: Draft
- Profile: `KF-POSTGRES-TARGET-HTTP-0.1-draft`
- Milestone: M6b1 target/service prerequisite; M6b2 live action mapping remains open
- Baseline: `6dcbe9a`; RFCs 0021 and 0023, unchanged frozen KF-JSON-0.2
- Owners/reviewers: unassigned; resource, security, deployment and SRE owners

## Problem and scope

Connect the PostgreSQL reservation function to a protected native target and an
independently authenticated outcome query. Choose a fixed single-row update and
local Unix-socket database as the bounded default. The target's client-facing
transport is HTTPS/mTLS. It supports neither caller-selected SQL nor remote database
connection strings. Schema/functions/rows must already be enrolled under RFC 0023.

The shipping `kf-postgres-target` and trusted `PostgresAdapter` library implement
this binding. The gateway/control services and Node Agent Adapter still bind the
mock action. M6b2 must add explicit CTD-driven SQL parameter mapping and a fresh
admission → issuance → claim → broker → SQL → recovery path. Independently tested
broker contracts and generated target credentials do not prove that composition.

## Authority and trust

Trust configuration independently pins the grant audience/issuer role keys,
reference target-token issuer/role keys, exact registered action/digest/resource/
incarnation/conflict domain/adapter contract/predicate, tenant, target audience/
scope, gateway SPIFFE identity and a distinct query SPIFFE identity. Grant and
target credential keys must be different. Request headers cannot select workload;
the native TLS listener verifies the certificate chain and derives one SPIFFE ID.

Keep protected query token, TLS keys, database socket/peer maps, schema owner and
database role enrollment outside agents. Only the configured gateway identity can
dispatch; only the query identity with its distinct opaque bearer can query.
Possessing a query credential does not authorize SQL mutation. Native bypass and
production enrollment remain deployment acceptance requirements.

## Closed carriage and endpoint binding

The [HTTP schema](../../spec/drafts/postgres-target-http-v0.1.schema.json) closes
dispatch and query payloads. Fixed endpoints share one authority and have distinct
paths; require exact Host/path, POST and one `application/json` Content-Type. Refuse
browser Origin, query/authority aliases, unknown/missing/duplicate fields and
noninteger numeric carriage. Bound request bodies to 2 MiB within five seconds,
bearers to 16 KiB, 32 concurrent operations and ten seconds of operation time.
Native transport remains TLS 1.3/HTTP 1.1 under the existing listener's bounds.
All replies are noncacheable and errors are redacted.

`Dispatch` contains exactly profile, `operation: dispatch`, `signed_grant` as
canonical unpadded base64url of the exact original signed bytes, `attempt_id` and
RFC 0023 parameters. Parameters are resource ID, expected version and reservation;
they cannot select SQL, tenant, routing, fence, root or authenticated identity.

The target independently verifies current signed-grant validity and checks exact
registered action, resource/incarnation, conflict domain, parameters digest,
adapter contract and version predicate. It verifies the actual RFC 0021 target
token signature/issuer/audience/scope/time and original grant/root/attempt/gateway
binding. Expected values come from those independent pins and verified grant,
never from copying token claims. A token alone cannot substitute altered parameters.

The internal RFC 0023 request uses the pinned tenant/workload, grant-owned fence
and actual credential expiry bounded by grant expiry. SQL checks expiry again
after obtaining the row lock, using the database clock. Target/database clocks,
fence bootstrap, resource lifecycle and covered writers remain trusted deployment
inputs. Target credentials authorize the already claimed attempt through the
independently trusted broker; this target does not create/reopen an etcd claim.

## Database driver and COMMIT

The driver accepts only an absolute Unix socket directory, fixed port/database
and distinct execution/query usernames. It does not use environment-selected
hosts, TCP, passwords, arbitrary statements, migrations or a fallback database.
Production needs independently approved protected socket and peer-authentication
maps; a path alone does not prove peer enrollment. Local tests explicitly use trust
authentication. Remote PostgreSQL TLS is outside this binding.

Each operation opens one fixed-role connection with a safe catalog search path,
two-second connect timeout, three-second statement/idle-transaction timeout and
two-second lock timeout. Reject owner/superuser/bypass/role/database-administration
privileges, schema creation, direct resource/attempt mutation and execution of the
opposite role's function. Probe errors refuse; there is no permissive fallback.
Administrative changes after these checks remain trusted; this is not a complete
database-administrator compromise or deployment custody proof.

Dispatch uses a READ COMMITTED read/write transaction and fixed parameterized
`SELECT kf_reservation.apply($1::jsonb)`. Verify the returned complete request and
post-version before explicit COMMIT, then wait for COMMIT acknowledgement before
returning a terminal outcome. Any statement/commit/transport timeout or lost reply
keeps the possible effect unknown; never reconnect and retry mutation. Connection
tasks are closed on completion/cancellation. A disconnected HTTP client does not
cancel the owned bounded service task; original outcome/deduplication survive.

## Query and recovery

The query request reuses `KF-OUTCOME-RECOVERY-0.1-draft` with `operation: query`
and original attempt ID, restricted to the SQL profile's 128-character identifier.
Current query authorization is separate from original grant/token lifetime. The
driver uses only `lookup(tenant, attempt)` under its fixed query role. It validates
stored shape, original attempt and current fixed tenant/resource/incarnation/
domain/workload before disclosure. Reconfigured incarnation/history needs a
separately approved historical query registration; broad tenant arguments are not
exposed to requesters.

Committed observations retain original root/grant/attempt and a fixed target
reference. Guard rejection returns the existing `fenced_no_effect` observation;
the M4 worker remains conservative and resolves possible-send state only from
correlated commit. Missing lookup returns HTTP 404 `unknown_outcome`; outages or
invalid observations return unavailable. Neither absence nor a malformed reply
authorizes dispatch, refund or new authority.

The existing pinned `HttpOutcomeQuerier` can query this endpoint. The new fixed
`PostgresAdapter` client independently checks the signed grant and target credential
and verifies exact terminal correlation. It forwards neither caller subject
credentials nor MCP metadata, and has no generic read operation or mutation retry.
It is available to trusted integrators; gateway CLI activation is M6b2 work.

## Compatibility, rollout and acceptance

This is a new draft HTTP profile; RFC 0023 SQL storage and frozen records remain
unchanged. [Configuration](../../config/postgres-target.example.json) contains
placeholders. `--check` validates local material/pins without contacting PostgreSQL,
listening, enrolling roles/rows or authorizing an effect. Active service uses the
already installed protected database. Never switch the legacy mock CTD silently.

Implementation: `postgres_target`, `postgres_store`, `postgres_adapter`,
`postgres_config` and `bin/kf-postgres-target`. Native SQL tests require the
disposable cluster from `scripts/test-postgres.py`; required mode refuses missing
SQL setup. Cases use actual SQL/mTLS, generated keys and synthetic preissued
grants/permits. They cover commit, concurrent exact replay, separate query,
wrong/missing workload certificates, credential issuer/audience/scope/root/expiry,
parameter/attempt substitution, owner-role refusal, dropped HTTP reply, material-only
check and shipping process kill/restart with retained original commit.

M6b2 CTD-driven service/agent integration and actual broker/ledger composition,
real AS/SVID provisioning, peer/owner custody, production writer/bypass/restore
qualification, target storage failure and full M6 pilot acceptance remain open.
The target process restart test does not establish PostgreSQL power/storage-loss
or stale-backup behavior. Minimum toolchains and Linux CI execution still require
observed qualification. Owners retain approval of action, resource, rollout and
operational budgets.

See the [M6b1 verification record](../../results/verification/rfc-m6-target-2026-10-12/README.md)
for the tested sources, combined required-mode run and remaining acceptance limits.
