# RFC 0025: PostgreSQL reservation leaf binding

- Status: Draft
- Profile/version: KF-POSTGRES-LEAF-0.1-draft
- Milestone: M6b2
- Baseline: 61ea3ce; frozen v0.9 / KF-JSON-0.2 unchanged
- Owners/reviewers: unassigned

## Problem and scope

Connect fresh admission and issuance to the RFC 0023 reservation action through
RFC 0001 MCP, the RFC 0021 broker, RFC 0024 SQL target and RFC 0010 recovery.
The named CTD action `postgres.reservation.set.v1`, version `1.0`, explicitly selects
this binding. Other action names retain their existing mock leaf binding.
Only one resource, version_eq, dispatch_bound and Level_A/FencingToken are supported.

## Authority and trust

The operator pins the signed CTD digest, resource incarnation, domain, application
schema, policy and evidence requirements. Admission re-verifies that chain;
issuance allocates the root and fence. The broker verifies subject and actor
signatures and the original durable claim before its single permit CAS and mint.
The gateway's protected `postgres_adapter` configuration selects the SQL client
and independently pins the target token issuer/key and RFC 0024 registration.
The agent cannot supply endpoint, database role, fence, attempt or grant metadata.

## Contract

The signed CTD parameter_schema must equal RFC 0023 `$defs/Parameters`: the closed
object `{resource_id, expected_version, reservation}`. Its existing digest and
rendering pins must verify. `resource_id` equals the sole grant resource ID;
expected_version equals the baseline and signed version_eq clause. Reservation
is covered by the proposal/certificate/grant parameter digest. Strings use the
RFC 0023 bounded label grammar; integers use its safe bounds.

MCP discovery advertises `io.kedgeflow/postgres-leaf` with this profile and tools/list
advertises the exact parameter schema. The Node adapter verifies the signed CTD
schema/digest, named version and discovery before sending application arguments.
No fields are added to frozen Proposal, CTD, certificate or grant records.

The optional closed gateway configuration requires this profile, one SQL tool,
matching RFC 0024 registration, separate target verification keys, issuer and
existing fixed HTTPS target URL. Missing configuration, mixed tool types,
unrecognized profile, registration mismatch and mock fallback refuse. Generic
SQL reads are not enabled. The SQL adapter returns the existing terminal receipt
fields plus the authenticated correlated SQL outcome; the grant bytes and token
retain RFC 0024 carriage. Recovery retains the original attempt and parameters.

## Failure and retry

Invalid SQL arguments refuse before remediation/claim. Changed reservation,
version, resource, CTD schema, token binding or adapter configuration refuses.
A possible target send with no correlated reply holds the consumed authority.
RFC 0010 queries the original SQL attempt; commit evidence can resolve it.
Absent/no-effect observations after a possible send remain unknown. Neither
recovery nor Node restart retries mutation, exchanges a second token, renews a
grant or refunds authority. Original target replay remains RFC 0023 behavior.

## Compatibility and rollout

This draft supplements frozen semantics with a new named application action;
existing mock actions and configuration remain compatible. Admission, gateway,
broker registration, Node and SQL target must agree on the new CTD digest/schema.
Unsupported peers refuse. Disable issuance/drain before changing action bindings.
Rollback preserves journal and SQL outcomes and queries consumed attempts.

Generated attempt/remediation IDs now prefix the existing 144 random bits with
`kf-`. Raw base64url can begin with `-` or `_`, which the frozen receipt Id and
SQL label schemas reject. The prefix preserves entropy and makes every generated
ID valid. Existing retained attempts keep their original IDs and consumed state;
nonconforming historical IDs require operator follow-up, not automatic rename or
refund. No frozen schema is broadened to accommodate invalid IDs.

## Implementation and acceptance

Implementation: leaf_action, admission, gateway/config, postgres_adapter, Node
adapter and a fresh native SQL workflow using actual etcd, PostgreSQL and the
pinned official SDK. Acceptance requires normal commit and lost target reply
recovery, process restart status, parameter/schema refusal and legacy regressions.
The [M6b2 verification record](../../results/verification/rfc-m6-leaf-2026-10-13/README.md)
retains 249 passing Rust tests with all SQL/etcd/SDK dependencies required, eleven
SQL storage groups, 32 Python tests and source pins. All 256 leading entropy bytes
are checked against the frozen Id and SQL schemas, including negative controls for
the old invalid prefixes. Earlier failed runs and diagnostic results are retained
separately from final-source qualification. The normal
flow and discarded SQL commit reply both preserve one root/fence, one broker mint,
one SQL update and original-attempt resolution after expired/revoked Node restart.
The evidence source and subject/actor enrollment remain generated fixtures.

## Open decisions

Enterprise owner acceptance, approved provider/peer enrollment, writer coverage,
restore controls and production cutover remain M5/M6 gates. A disposable local
SQL/evidence fixture qualifies software composition, not those operational gates.
