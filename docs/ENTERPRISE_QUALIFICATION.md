# Remaining enterprise and release milestones

[RFCs 0029–0033](MILESTONE_PREREQUISITES.md) add pinned SQL transport, a Linux
account harness, stale logical restore/storage budgets, canonical review and
hierarchical reservation libraries, and a required conformance runner. These do
not close the gates below. M7 native HITL/lease and M8 native grant/claim/A2A/saga/
drain integration remain unfinished; Linux account/MSRV execution is unobserved locally.

M4c3, M5a, M5b, M5c1, M5c2 and M5c3 deliver bounded software contracts and retained verification.
They do not close the original enterprise acceptance gates. This document makes
the next work explicit; the [roadmap](IMPLEMENTATION_ROADMAP.md) remains the scope
and the [claim inventory](WHITEPAPER_IMPLEMENTATION.md) remains the claims baseline.

## M5c — Approved identity and credential providers

Required inputs: approved isolated authorization-server issuer/token/introspection
or JWT contract, client registration, audience/algorithm/key-rotation policy;
workload trust domain, SVID provisioning/rotation and revocation contract;
protected gateway/broker/issuer/recovery identities; approved test configuration
paths and target credential scope/audience/lifetime contract. Supply references
to protected configuration, not secrets in documentation or chat.

The [RFC 0020 verifier](EXCHANGE_IDENTITIES.md) supplies pinned subject/actor
signatures and bounded trust refresh; actual provisioning, protected update
delivery and enterprise mint/target integration remain unqualified.
[RFC 0021](BROKER_TOKEN_SERVICE.md) supplies a native endpoint and custom reference
target credential; this does not qualify an approved enterprise provider or target.
[RFC 0022](IDENTITY_REFRESH.md) adds authenticated snapshot refresh and exact
protected-head checks. Approved publisher administration and rollback-resistant
independent head/floor custody, replica delivery and provider acceptance remain open.

Integrate the approved `ExchangeIdentityProvider` from these contracts, preserving
the same admission delegation digest. Bind the one-shot broker authorization
check to exactly one mint invocation. Qualify target token effective scope and
expiry using the actual provider verification/introspection contract.
A provider with different subject-token or actor semantics needs an explicit
compatible profile before integration.

Evidence: controlled issuer-key rollover and stale/unapproved key refusal;
SVID rotation and revoked-workload refusal; independent replica/restart replay;
provider outage and delay; overbroad/exhausted token refusal; broker permit reply
loss; separate least-privilege etcd roles; combined restore-gated deployment.
Run native egress/socket/file/shell/SDK bypass attempts from the deployed agent
and descendants against the isolated target. Record scope, denied paths and any
separately administered break-glass writers. Accept this gate with the identity,
deployment and security owners. There is no approved provider configuration in
the repository baseline; generic software JWT fixtures cannot supply these facts.

## M6 — PostgreSQL action and isolated enterprise pilot

Required inputs: isolated PostgreSQL target/version and approved protected test
configuration; resource owner's closed reservation/update action, parameter
schema, incarnation/version/fence allocation and complete writer coverage.
The plan selects PostgreSQL reservation/update before physical drain; it does not
authorize arbitrary SQL or turn the mock node action into physical completion.

Draft the target-specific RFC/CTD and map only registered parameters. Implement
one atomic SQL transaction that checks incarnation/version/fence, applies the
effect and retains original attempt/grant/result correlation; provide independently
authenticated authoritative query. Define the schema migration, bootstrap and
privileged-writer boundaries. Establish target-side attempt retention and guards
before exercising the ledger/target boundary.

Evidence: concurrent covered writers, changed/deleted/recreated resource, stale
fence, lost commit reply, delayed exchange, partitions, target restart and stale
restore; independent query confirms actual commit. Deploy bypass tests and a
rehearsed abort/upgrade/restore/exit that preserves consumption and key histories.
Capture agreed workload budgets and end-to-end latency/refusal/unresolved-age
populations. Resource, security, deployment and SRE owners accept the pilot,
retention, costs, incident routing and on-call coverage.

[M6a](POSTGRES_RESERVATION.md) now supplies a real PostgreSQL 18.3 storage
prerequisite, tested in a disposable Unix-socket cluster. This is a local software
fixture, not an approved enterprise target. [M6b1](POSTGRES_TARGET_SERVICE.md) adds authenticated native target/query and a
fixed COMMIT-bound driver under generated preissued authority. [M6b2 / RFC 0025](rfcs/0025-postgres-leaf-binding.md) now connects fresh signed
admission/issuance, the official Node client, native one-shot broker, real SQL
commit and query-only lost-target-reply recovery. These generated identity and
evidence fixtures do not qualify enterprise providers. [M6c / RFC 0026](rfcs/0026-sql-failure-qualification.md)
now composes eleven disposable SQL process-failure, witnessed logical restore and
incident/collector cases. This uses shared retained collector receipts and leaves
pending-witness repair and physical/stale SQL restore unqualified. M6d must supply
protected target/provider custody, deployed writer/bypass/restore coverage, budgets
and owner acceptance; those gates remain open.

[M6d1 / RFC 0027](rfcs/0027-postgres-enrollment.md) now adds effective SQL table/column
and role-membership checks plus a native read-only enrollment preflight. Actual
isolated-database bypass probes and shared runtime refusal are software evidence;
they do not establish approved peer authentication, OS/secret custody, writer
coverage or operator acceptance. M6d2 should qualify those deployed boundaries;
M6d3 retains restore/retention, budgets and owner acceptance.

[M6d2a / RFC 0028](rfcs/0028-postgres-custody.md) now supplies explicit SQL-target
file descriptor/mode custody and actual PostgreSQL peer mapping in the disposable
same-UID fixture. It does not qualify independent service accounts, deployed
agent/descendant denial, ACL/mount/socket/launcher administration or rotation.
Other service loaders remain unqualified. Those are M6d2b prerequisites; M6d3/M5c
restore/retention, budgets, approved providers and owner acceptance remain open.

## M7 — Canonical human review and admission leases

Required inputs: approved reviewer enrollment/attestation provenance, physical
authenticator/hardware and backup policy, browser RP/origin/rendering configuration,
reviewer revocation and operation owners. A no-review leaf pilot must say so.

[RFC 0034](NATIVE_REVIEW.md) now supplies native software reviewed evidence,
canonical rendering and durable challenge/counter/enrollment comparisons. It does
not qualify a protected human display, browser ceremony or physical enrollment.
Draft the non-authorizing lease contract and qualify the actual ceremony. Reuse only exact-proposal static evidence under current
membership/policy/descriptor/delegation; acquire fresh JIT witnesses.

Evidence: a real enrolled-authenticator ceremony plus wrong RP/origin/rendering,
substitution, missing UV, replay/expiry/revocation, hardware/backup-policy negatives,
one challenge across replicas/restart and expired underlying evidence despite
a retained lease. Synthetic signatures do not close hardware-bound review.

## M8 — Reservations, delegation and drain

Required inputs: the accepted resource/action and writer boundaries from M6;
parent/child budget and conflict-domain definitions; actual A2A peer registration;
separately approved Kubernetes drain target, narrowly scoped controller identity
and declared scheduler/autoscaler/human writers.

Draft atomic reservation and delegation conservation, compensation applicability
and late-effect barriers. Implement admitted-operation/child deduplication,
parent/child conservation and authenticated AgentCard/root-reference activation.
Integrate durable query-first orchestration with stable identities.
Implement drain as a separate asynchronous action with observed completion and
truthful physical limits. Do not infer restored workloads from uncordon.

Evidence: last-slot contention, nested/parallel delegation, task-ID replay,
scope widening refusal, crash/late effects/partial or failed compensation, and
authoritative drain observation. Unknown effects remain consumed without retry,
inverse execution or timer refund. Cross-cluster transfer needs a further profile.

## M9 — Independent release conformance

Required inputs: an independently implemented controller/peer, a second actual
runtime and target binding, actual intermediary routes and a second implementer
who can reproduce evidence. Reconfiguring this Rust implementation is insufficient.

Publish the proposed release/profile matrix, schemas, key/migration/retention
rules and conformance runner/corpus. Exchange install/admission/issuance/status/
outcome with the independent peer, including stale install/revocation and
lost-response negatives. Qualify MCP/reference carriage through declared
intermediaries and A2A peers, and upgrade/rotation/export/restore preservation.

Evidence: independent positive/negative exchange and reproduced release logs
with source/tool/dependency pins and explicit unsupported variants. Owners make
the release decision. Performance comparison additionally needs an equivalently
isolated hardened PDP/PEP baseline; existing contention results do not substitute.

## Completion rule

Advance code/RFC work that has independently approved inputs. Keep each acceptance
gate open until its required observations and owner decisions are retained.
Record new evidence separately; never relabel earlier fixture evidence as real
provider, target, hardware or interoperability qualification.
