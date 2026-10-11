# KedgeFlow code and protocol implementation milestones

Planning baseline: **10 October 2026**, runtime `769c0a8`, proposed white paper v0.9. This plan follows the [implementation review](IMPLEMENTATION_REVIEW_2026_10_10.md). M1 now has [four RFC drafts](rfcs/README.md), a template, profile index and separate draft carriage schema. M2 has verified certificate-constrained issuance and begun independently verified input-chain implementation. Neither milestone's full exit gate is complete; later milestones remain proposed.

## Execution status — 11 October 2026

| Increment | Delivered | Remaining gate |
| --- | --- | --- |
| M0 profile clarity | Active profile index; legacy v0.1 guide labelled; required etcd/SDK runtime rerun | Minimum Rust version and separate paper reproduction qualification |
| M1 RFC structure | RFCs 0001–0004 and draft admission/issuance/status carriage | Owners, review decisions, control/outcome wire schemas and acceptance |
| M2a library prerequisite | Typed certificate constraints; pinned local schemas; role/tenant checks; atomic operation-wide issuance; real-etcd concurrency, rebinding, consumption and stale-policy tests | Library verification complete; service permissions still require M2b/M2c |
| M2b input verification | Signed proposal/CTD/manifest/evidence chain; schema/identity/state/freshness/predicate checks; opaque inputs bound to certificate/grant; real-etcd issue/claim test | Cedar; authenticated services; installed-control ingestion; issuer-owned IDs and target fence allocation |
| M2c control implementation | Not started | Authorized registry/policy/install/revoke APIs and race tests |

The trusted legacy issuance API remains available for the existing fixture path.
M2a does not turn it into a certificate-gated service. See
[the 11 October verification record](../results/verification/rfc-m2-2026-10-11/README.md)
for fresh results. The earlier disk block is resolved. M3 starts after the service path
can produce live certificates/grants; a replay/status fix alone cannot satisfy
that milestone.

Deliver a complete single-action path, qualify one recoverable enterprise deployment, then demonstrate independently implemented protocol peers and coordinated workflows. Preserve fail-closed authority, consumed unknown attempts and truthful target guarantees throughout.

## Scope and estimates

Use the current one-resource mock profile to prove live admission/issuance. The first real target should be a **PostgreSQL-backed conditional reservation/update**, owned by a protected target service. This aligns with the white paper's reservation step and offers a verifiable transaction and durable operation lookup. Physical Kubernetes drain follows as a separately qualified asynchronous action.

The first SQL action should have a defined single-resource predicate. If policy depends on a shared capacity budget or other writers, M8's reservation and complete-predicate coverage become prerequisites for that deployment. A database alone does not create adapter fencing/outcome semantics.

Co-locate compatible policy/registry/admission/issuance/evidence roles in one control-plane deployment, with a protected gateway/adapter and shared ledger. Preserve distinct administrator, provider, issuer, agent and executor permissions and signing keys. Nine roles need not become nine microservices.

Estimates are **focused engineer-weeks**, including implementation and acceptance evidence. They assume existing identity infrastructure, a target owner, CI and an isolated environment. A plausible team is two Rust/backend engineers, one platform/integration engineer and part-time security/resource/application owners. These are planning ranges, not measured commitments; re-estimate after M0. Enrollment, hardware and procurement can dominate calendar time.

## Milestone overview

| Milestone | Concrete outcome | Dependencies | Effort | Accountable owner |
| --- | --- | --- | --- | --- |
| M0 | Claim inventory, active profile index and reproducible baseline | This review | 1–2 | Technical lead |
| M1 | Versioned service/wire contracts, especially Enforcement Control | M0 | 2–3 | Protocol lead + security |
| M2 | Rust policy/registry/admission and atomic independent issuer | M1 | 5–8 | Control-plane lead |
| M3 | Real Agent Adapter; fresh admission-to-mock execution; stable status/replay | M2 | 3–5 | Application integration lead |
| M4 | Crash recovery, outcome worker, signed receipts and verifiable trace | M1; integrate with M3 | 4–6 | Runtime/SRE lead |
| M5 | Enterprise identity, credential lifecycle and deployment custody | M1; integrate with M3 | 4–6 | Security/platform lead |
| M6 | Real SQL target and accepted enterprise pilot/cutover | M3, M4, M5 | 5–8 | Resource + deployment owners |
| M7 | Policy-required canonical human review and admission leases | M2, M4, M5 | 3–5 | Evidence/security lead |
| M8 | Shared reservations, delegation, saga recovery and governed drain | M6; M7 when review required | 7–12 | Authority/workflow lead |
| M9 | Independent exchange, second runtime/target and release conformance | M6 leaf profile; M8 coordination profile | 4–7 | Protocol/release lead |

M0–M6 total **24–38 engineer-weeks**; all milestones total **38–62 engineer-weeks**. M4/M5 can proceed alongside M2/M3 after contract agreement. Extra staffing does not divide the critical path linearly.

```mermaid
flowchart LR
  M0[M0 Baseline] --> M1[M1 Protocol contracts]
  M1 --> M2[M2 Admission and issuer]
  M2 --> M3[M3 Live agent path]
  M1 --> M4[M4 Recovery and receipts]
  M1 --> M5[M5 Enterprise trust]
  M3 --> M6[M6 Real-target pilot]
  M4 --> M6
  M5 --> M6
  M2 --> M7[M7 Review and leases]
  M4 --> M7
  M5 --> M7
  M6 --> M8[M8 Coordination and drain]
  M7 -. when required .-> M8
  M6 --> M9[M9 Independent conformance]
  M8 -. coordination profile .-> M9
```

## M0 — Reproducible baseline and claim inventory

**Code/evidence:** provision a pinned Rust toolchain and run the active workspace with real three-member etcd and required official MCP SDK. Reproduce paper tests separately without overwriting published results. Add supported toolchain/OS checks, including the declared Rust minimum or revise it with evidence. Record source/tool versions, dependency hashes, commands, skips and raw logs.

**Protocol/documentation:** label `docs/protocol.md` as the legacy Python v0.1 guide. Publish an active profile index with accepted record, transport, guard and completion variants. Map every manuscript capability to an owner, code, acceptance case and milestone; keep frozen/current/historical evidence distinct.

**Exit:** another developer reproduces the declared baseline without accidental optional skips. Every claim has a pinned source and scope. Retained Rust results remain clearly identified as retained.

## M1 — Implementable contracts for all six interfaces

**Code:** introduce typed service requests/responses, validators and role/scoped trust administration. Separate execution, administrative and evidence permissions. Define durable operation/attempt lookup types without exposing issuer/publication methods to agents.

**Protocol:** specify machine-readable HTTP/RPC bindings for Governance, Runtime Admission, Enforcement Control, Evidence, Execution status and Outcome. Fix caller permissions, version negotiation, closed payloads, signing domains, key history, errors, expected versions, idempotency, clock uncertainty, cancellation and unknown states. Specify the custom RFC 8693 grant/digest/attempt fields, server-side claimed-attempt validation and subject/workload downscoping.

Prioritize **Enforcement Control**: authenticated `install`, expected installed version, policy/descriptor/key/grant/revocation scope, acknowledgements of actual installed version/coverage and stale-state refusal. Retain shared authoritative etcd as the first claim/revocation substrate. Installed caches never authorize local redemption when quorum is unavailable; an acknowledgement cannot cancel an already dispatched effect.

Freeze the supported methods, authentication and transport for the pinned MCP revision. Specify status usable after grant expiry under current caller authorization. Define optional reference-store publication/retrieval ACLs and retention.

**Exit:** positive/negative vectors and authorization tests cover every leaf-profile operation; wrong-scope/rollback installs refuse and acknowledgement coverage is truthful. New records or changed signed meanings require a new proposed version/supplement. Preserve frozen v0.9 bytes and do not reuse a schema ID for changed semantics.

## M2 — Rust admission and independent atomic issuance

**Code:** implement Policy Authority/Resource Registry functions for one action, then Admission Controller and Grant Authority services. Co-location is allowed with distinct permissions/keys. Add typed semantic validation for signed proposals, CTDs, manifests, evidence and certificates against pinned local schemas. Verify signer roles, identity/delegation, action/incarnation, descriptor/parameter digests, current policy/ownership and approved constraints.

Use satisfied/violated/unknown obligations. Emit a certificate only when required evidence is satisfied and policy permits. Integrate one engine first, preferably Cedar to reuse paper behavior; use server-constructed verified inputs and deny on diagnostics. Qualify OPA as a later interchangeable implementation.

The issuer verifies the complete proposal/certificate/constraint chain and intersects audience, guard, completion, lifetime and evidence validity. Atomically deduplicate one admitted operation/budget using an independently derived issuance key. Repeated valid requests return the persisted issuance; conflicting bindings refuse. New caller request/root IDs cannot multiply allowance. Retain deduplication through the replay/outcome horizon. Only the authority service chooses/publishes roots, generations, nonces and fences.

**Protocol:** implement authorized publish/register/revoke and install/acknowledgement. Explicit grant/root/scope revocation should not require fabricated grant-shaped policy updates. Define retryable issuance responses without reopening authority.

**Exit:** live services produce schema-valid signed certificates/grants. Missing, expired, unknown or contradictory required evidence cannot admit. Wrong-role signatures, broadened constraints, old descriptors and evaluation diagnostics refuse. Concurrent issuer replicas receiving one admission with different request/root IDs produce one persisted allowance. Revocation races issuance/claim/final dispatch obey the declared serialization contract.

## M3 — Live Agent Adapter and correct replay/status correlation

**Code:** integrate one actual supported harness/client workflow. Authenticate workload/delegated subject; freeze proposals; validate negotiated remediation and trusted admission endpoints; obtain fresh evidence, certificate and grant; retry the unchanged action with fresh DPoP proofs. Preserve stable operation identity and expose denied, missing-evidence, pending and unknown states faithfully.

Correct the `NonceConsumed` path to return or resolve the original persisted attempt. Resolve ambiguous claim replies similarly. Expose scope-authorized query-only status by operation/grant/attempt identity without requiring a still-executable grant. Current authorization controls disclosure; status never dispatches. New RPC IDs do not create authority.

**Protocol:** finalize remediation expiry, changed-action/new-admission behavior, status result/error types, cancellation and safe retry rules under M1's binding.

**Exit — first release gate:** a real client performs discovery → remediation → fresh evidence → admission → issuance → exact call → mock receipt without fixture grants. Identity/parameter changes require new admission. Lost-response retry resolves the original attempt. Repeated status and expired-grant status cause **zero additional claims, credential exchanges or target mutations**. Unsupported clients cannot bypass the pilot target.

## M4 — Crash recovery, signed outcomes and independent reconstruction

**Code:** persist signed authorization links, adapter/version, identity/correlation context, dispatch intent, target operation references and observations. Replace an overwritten status-only outbox with retained transition/report records where required. Add a supervised worker that discovers stranded `claimed` and unknown attempts, with atomic transitions and safe multi-worker ownership.

Distinguish provably undispatched work from possible sends using durable facts and the adapter's contract. Query authoritative status; insufficient evidence remains consumed unknown. Time, cancellation, missing status or process death cannot prove no effect. Do not implicitly redispatch/refund.

Produce signed KF-JSON Receipts; implement idempotent Outcome reporting/acknowledgement, target queriers, contradictory-evidence retention, bounded polling and owned escalation deadlines. Preserve actual target evidence: gateway signatures do not become target-signed commit proof. Add an offline verifier for proposal → evidence → certificate → grant → claim/dispatch → outcome, with missing links explicit.

**Protocol:** specify recovery transitions, report identity/order, terminal/pending/unknown semantics, retention/key history and late-effect/no-effect barriers. Define authority-preserving quiesce/restore. Initially, consumed allowance can remain held indefinitely; safe restoration/compensation needs additional proven contracts.

**Exit:** kill/restart before/after claim, dispatch authorization, target commit and receipt persistence. Duplicate workers/reports do not duplicate effects. Lost commit replies resolve authoritatively or remain consumed unknown with an incident. Stale backups are fenced/quarantined before execution resumes. A separate verifier reconstructs retained lineage.

## M5 — Enterprise identity, credential lifecycle and custody

**Code:** integrate one real authorization server with controlled issuer/audience/algorithm policy, key rollover and subject-to-workload authorization. Integrate SPIFFE/SPIRE or equivalent administered SVID provisioning/rotation. Add shared atomic DPoP replay/nonce state with bounded retention and fail-closed outages. Keep process-local replay only for its declared profile.

Implement broker-side grant/attempt validation and one real target credential binding. Verify effective target scope/audience/lifetime through the provider's actual token/introspection contract where applicable, retaining final validity checks. Separate issuer/gateway/recovery identities and least-privilege ledger roles so the gateway cannot self-issue. Support secret/certificate/etcd-token renewal and operational key custody.

If reference carriage is needed, implement authorized immutable publication/retrieval, ACLs, rate/concurrency caps, retention and audit. Otherwise keep it disabled for the pilot.

**Deployment/protocol:** supply a supported isolation package, protected service identity/configuration, fixed egress/target access and native shell/file/socket/SDK bypass tests. Declare separately administered break-glass writers. Document rotation, clock uncertainty, TLS termination and actual intermediary/header budgets.

**Exit:** real identity/broker services work end to end. Rotation, revoked workload, cross-replica/restart proof replay, provider outage, overbroad token and exhausted validity refuse unsafe dispatch. Agents/descendants cannot obtain equivalent target credentials, access privileged sockets, tamper with the gateway or invoke alternate mutation paths. Production etcd TLS/RBAC is tested.

## M6 — Real SQL adapter and accepted enterprise pilot

**Code:** replace mock parameter binding with closed CTD-driven action validation/mapping. Supply adapter `describe`, `dispatch` and authoritative `query`. Use fixed target/query/executable definitions rather than caller-controlled SQL or routing.

Implement a PostgreSQL transaction checking declared incarnation/version/fence, applying the effect and retaining attempt/grant/result correlation atomically. Define fence allocation for the covered writer set. Target-side attempt deduplication/retention are resource guarantees, not consequences of an etcd claim. Qualify the ledger/target transaction boundary with M4.

**Protocol:** freeze action, parameter schema, guard, completion, idempotency and outcome contracts with truthful Level A scope. Apply versioning rules when parameters/contracts change. Define actual writer coverage, revocation behavior and evidence. Report only reservation/update completion until physical drain is implemented.

**Exit — enterprise pilot gate:** validate concurrent writers, state changes, deletion/recreation, lost responses, delayed exchange, partitions, target restart and stale restore on a real isolated target. Independent query confirms actual commit. Deployed bypass tests pass. If shared-budget policy applies, M8 is also required.

Deployment/security/SRE/resource owners accept scope, writer coverage, trust, retention, incident deadlines, on-call and cost records. Set workload budgets before measuring admission/issuance/claim/exchange/target/query latency, human queue time, false refusals, unresolved age and support effort.

Use observe → isolated governed pilot → accepted privilege cutover. Production cutover requires rehearsed abort/upgrade/restore/exit preserving consumed roots and key histories. Observation alone makes no enforcement claim.

## M7 — Policy-required canonical review and non-authorizing leases

**Code:** port WebAuthn review into the Rust service path, binding proposal/parameters, policy, template/rendered bytes, reviewer/verdict, nonce and expiry. Provide protected rendering, actual browser ceremony, trusted enrollment/attestation provenance, reviewer revocation and durable atomic challenge/counter consumption. Software fixtures remain test-only.

Implement exact-proposal AdmissionLease reuse for valid static obligations; invalidate on membership, policy, descriptor, delegation or evidence changes. Acquire fresh JIT witnesses before final admission. Leases confer no execution nonce, credential or allowance.

**Exit:** physical enrolled-authenticator ceremony works; wrong RP/origin/rendering, substitution, missing UV, replay, expiry, revoked enrollment and unsupported hardware/backup policy refuse. Replicas/restarts permit one challenge consumption. Expired underlying evidence blocks admission despite a present lease.

This milestone is required before any pilot claims hardware-bound review. A no-human-review leaf profile may ship after M6 with that scope explicit.

## M8 — Shared reservations, A2A delegation and saga/drain recovery

**Code:** add atomic conflict-domain reservations and admitted-operation/child-allocation deduplication. Conserve free, allocated, consumed, unresolved and compensation allowances under one parent generation. Composite parents cannot execute/spend child allocations; transfer/replacement cannot reopen unresolved authority. Qualify multiple-resource/predicate profiles before accepting them.

Implement A2A AgentCard extension advertisement/activation and authenticated root-reference resolution. Task IDs/references are correlation, not authority; each child needs a narrower admitted grant. Demonstrate scope narrowing and refusal of widening.

Integrate durable orchestration, optionally Temporal, with stable operation identities and query-first recovery. Reserve compensation budget before forward execution. Registered inverses require known outcomes, fresh admission, accepted applicability and late-effect barriers where needed.

Implement the paper's **separate Kubernetes drain** action: narrowly scoped credential, durable controller operation, cordon/eviction and authoritative observed completion. Declare Level C physical limits instead of inheriting SQL Level A. Account for schedulers, autoscalers, humans and other writers before broader availability claims. Uncordon does not restore evicted workloads.

**Exit:** last-slot competitors cannot both spend capacity under the complete declared writer/predicate boundary. Nested/parallel delegation conserves budgets. New A2A task IDs cannot duplicate child allocation. Crash, late effect, partial compensation and compensation failure remain explicit. Unknown forward effects never trigger blind retry, inverse execution or timer refunds.

Cross-cluster ownership/reservations require a further coordination/transfer profile; prefixes, regions and separate local transactions do not establish atomic global allocation.

## M9 — Independent interoperability and release conformance

**Code:** publish a conformance runner, negative/fault corpus and trace verifier. Add a second actual runtime adapter and target/credential binding. An independently implemented controller must exchange install/admission/issuance/status/outcome with Rust; another configuration of the same implementation is insufficient proof of independence.

**Protocol:** publish a proposed release with capability matrix, schemas, migration/key rules, security/operations assumptions and reproducible evidence. Test governed MCP/reference carriage through actual intermediaries and A2A peers for the coordination profile. List unsupported variants explicitly.

**Exit:** independent peers pass positive/negative wire exchange, stale install/revocation and lost-response tests. Upgrade/rotation/export/restore retain consumption and original signed history. Another implementer reproduces release evidence. Claims name exact runtimes, targets and protocol variants.

Comparative efficacy/performance requires a separately specified hardened PDP/PEP baseline with equivalent isolation, evidence, exact binding, coordination, guards and recovery. Report attempted, claimed, dispatched, committed, refused and unresolved populations separately. The retained contention matrix is not enterprise mutation-throughput evidence.

## First implementation backlog

1. M0 toolchain/required-mode reproduction and active/legacy protocol index.
2. M1 leaf service contract and operation/authorization model, prioritizing Enforcement Control and status.
3. Typed proposal/CTD/evidence/certificate validation and durable admitted-operation issuance key.
4. Independently authorized admission/issuer/control endpoints with scoped revocation and version acknowledgement.
5. Replay correlation fix and status lookup; test that losing the first response still resolves the original persisted attempt.
6. Replace preissued-grant client retry with live admission/issuance.
7. Recovery context/process-kill matrix alongside real identity/broker integration.

Each accepted gate updates the claim inventory with actual results, source/profile versions and owners. An incomplete gate leaves that capability unsupported; continue refusing inputs whose invariants have not been implemented.
