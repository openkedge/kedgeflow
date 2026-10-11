# KedgeFlow implementation versus white paper — 10 October 2026

This is the 10 October review baseline. Subsequent code, RFCs and remaining
gates are tracked in the [milestone plan](IMPLEMENTATION_ROADMAP.md).

KedgeFlow implements a substantial, deliberately narrow Rust execution boundary. It does **not yet implement the white paper's complete control plane, flagship controller-to-gateway wire protocol, or enterprise deployment**. The white paper itself discloses these limits. Finish the missing service and operational contracts before widening the accepted execution profile.

The next release should demonstrate one freshly admitted action from a real Agent Adapter through an independent issuer, durable claim, target credential acquisition, a real conditional target mutation, and recoverable outcome reporting. The [milestone plan](IMPLEMENTATION_ROADMAP.md) sequences that work.

## Baseline and method

- Runtime repository: `main`, `769c0a8fc47ac27d35184cc2b4c4210ffd6b7d6f`, committed 9 October. A read-only remote `git ls-remote` confirmed the same `origin/main` head during this review. The initial checkout was clean.
- Primary runtime: Rust crate `0.9.0-alpha.1`, `kf-proxy`. There are no changes to active runtime, configuration, schemas, tests, scripts, Cargo manifests or CI between `21d5efe` and this head. The latest commit publishes a separate research snapshot and additional paper tests.
- Normative baseline: [frozen white paper v0.9](whitepaper/v0.9/README.md), 6 October; proposed `KF-JSON-0.2`, `KF-MCP-0.1` and `KF-GRANT-REF-0.1`.
- Latest manuscript: assurance repository head `54fb5cf`; v0.9 editorial positioning at `66ccf26` / `e859672`. Reviewed `acp/whitepaper/03-component-map.tex`, `04-interfaces.tex`, `05-execution.tex`, `06-implementation.tex`, adoption chapters and `07-acceptance.tex`. Later positioning makes Enforcement Control the flagship interface; it does not turn examples into implemented services.
- Reviewed active Rust modules, executable wiring, integration tests, schema tooling, preserved Python demo, Go admission/review documentation and the short-paper snapshot/tests/results. Consulted primary protocol documentation linked below.

This is a source/contract review with fresh specification and compatibility checks. It is not a fresh Rust execution run, independent security audit or production qualification. Missing capabilities are blockers for the corresponding deployment claim, not evidence of an exploit in the declared mock profile.

## Implemented scope

The accepted grant has one nondelegated resource, one `version_eq` predicate, `Level_A` / `FencingToken`, and `dispatch_bound` completion. Unsupported delegation, saga budgets, multiple resources, other guards and `commit_bound` completion are rejected in [contracts.rs](../crates/kedgeflow/src/contracts.rs).

The code includes strict safe-integer JSON, UTF-16 canonical key ordering, domain-separated digests, Ed25519 signatures, verified TLS workload certificates, pinned subject access tokens and DPoP proofs. The gateway binds identity, parameters, action, resource incarnation, audience and adapter contract before claim. Credentials are acquired after claim, followed by final validity and ledger checks before dispatch. Inline and referenced grants share consumption state.

The etcd ledger atomically publishes policy/ownership, issues/replaces roots, claims nonces, authorizes dispatch and updates attempt/outbox state. Consumption survives completion, credential refusal and unknown outcomes. Preserve these foundations.

## Six-interface comparison

“Partial” means executable mechanics exist for a bounded subset. A library trait, configuration field or fixture does not establish a service protocol.

| White-paper interface | Current evidence | Assessment and missing contract | Plan |
| --- | --- | --- | --- |
| Governance: publish, revoke, register with expected versions | Trusted `publish_policy`; monotonic policy/ownership checks; static tool registration | **Partial library support.** No authorized governance/registry service, descriptor lifecycle or explicit scoped revocation API. Epoch updates do not implement every promised revocation operation. | M1, M2 |
| Runtime Admission: discover, propose, discharge evidence, certificate, grant | Tool discovery/remediation; signed fixtures; trusted `issue` method | **Incomplete service path.** No Rust admission endpoint, certificate producer/consumer, evidence acquisition or grant issuer endpoint. SDK tests inject preissued grants. | M2, M3 |
| Enforcement Control: install policy/keys/grants/revocations; acknowledge version/coverage | Shared etcd authority reads; startup keys/tool configuration | **Wire protocol absent.** No authenticated install request, versioned acknowledgement, coverage response, freshness contract or independent controller peer. Shared store checks do not implement the flagship interface. | M1, M2 |
| Execution: execute exact action; query status | Governed MCP discovery/list/call, exact binding, claim/dispatch | **Partial.** No client status method, stable replay lookup or signed KF-JSON Receipt response. Transport/method/version coverage is deliberately narrow. | M3, M4 |
| Evidence: evaluate obligations; ingest scoped observations | Envelope verification and signed vectors; separate Go capacity/WebAuthn experiment | **Rust services absent.** No deployed provider lifecycle, observation ingestion, canonical review ceremony or admission-time evidence evaluation. | M2, M7 |
| Outcome: durable reports/acks, lineage, reconciliation tickets | Attempts/outbox; `OutcomeQuerier` trait; explicit unknown-to-committed reconciliation | **Partial library support.** No worker, report/status service, crash discovery, real target querier, full receipt retention or incident deadlines. | M4, M6 |

Of the nine roles, Execution Gateway is strongest; Grant Authority, Resource Adapter and Outcome Service have bounded foundations; Policy Authority and Resource Registry have configuration/library support. Rust Admission Controller, production Agent Adapter and Evidence Provider remain to be built. Co-location can reduce service count while preserving permissions and signer ownership.

## Findings, ordered by delivery risk

### F1 — P1 code defect: replay returns an unrelated attempt reference

In [gateway.rs](../crates/kedgeflow/src/gateway.rs), lines 424–437, every invocation generates a new attempt ID before claim. On `NonceConsumed`, the response returns that new ID although the refused claim did not persist it. In [ledger.rs](../crates/kedgeflow/src/ledger.rs), claim's failure branch reads the existing nonce-to-attempt mapping but discards its value when returning the unit error.

If the original response is lost, retrying gives the client an ID for which no attempt exists. `Gateway::handle` accepts only `tools/call`, `tools/list` and `server/discover` (lines 280–282); ledger status has no client wire binding. The paper requires `NONCE_CONSUMED` to lead to the **existing** operation. Tests assert replay refusal but do not check the returned ID against the original durable attempt.

Return or resolve the persisted grant/root/nonce attempt and expose authenticated, scope-authorized query-only status. Resolve ambiguous claim replies through the same lookup. Status must remain usable after grant expiry under current caller authorization and never re-execute. **M3.**

### F2 — Release blocker: authenticated records do not form admission/issuance services

[contracts.rs](../crates/kedgeflow/src/contracts.rs), lines 391–415, limits `verify_envelope` to envelope authentication. It does not validate every payload schema, signer role, evidence freshness or proposal/certificate/constraint chain. Grant verification implements the narrow execution profile; an independent issuer must verify admission semantics before signing.

[tests/sdk/interop.mjs](../tests/sdk/interop.mjs), lines 52–54, injects the already-issued grant where evidence acquisition, admission and issuance would occur. The Go service uses a separate `capacity.reserve` profile; Rust accepts mock `{node, expected_version}` arguments. Connecting URLs does not reconcile action/descriptor/constraint semantics. **M2, M3.**

### F3 — Release blocker: same-root safety does not deduplicate admission across roots

[ledger.rs](../crates/kedgeflow/src/ledger.rs), lines 306–330, creates an independent root/grant after policy/ownership comparison. It has no stable admitted-operation issuance key, certificate-consumption record or shared reservation debit. A different root ID can create another allowance through this trusted port.

The new `paper_duplicate_issuance` test races the **same grant/root** 32 times. It proves uniqueness for that root, not deduplication when issuer replicas assign fresh roots to one admitted operation. This is a missing issuer invariant, not a bypass exposed by the execution endpoint. Implement deduplication before publishing an issuer; add reservations before claiming shared capacity safety. **M2, M8.**

### F4 — Release blocker: crash recovery misses possible dispatched effects

[ledger.rs](../crates/kedgeflow/src/ledger.rs), lines 484–505, reconciles only attempts explicitly marked `unknown`. A crash after claim or dispatch authorization can leave `claimed` with outbox state `claimed_not_dispatched` or `dispatch_authorized`. The attempt retains only ID, grant digest, root, status and claim time; recovery also needs action/descriptor/identity and target correlation context.

Held consumption is correct. A worker must discover stranded records, conservatively classify uncertainty, query the actual target and escalate unresolved work. The artifact's fresh-client recovery test first explicitly marks an attempt unknown; it is not a process-kill recovery demonstration. **M4.**

### F5 — Enterprise gap: identity lifecycle and replay are external dependencies

[auth.rs](../crates/kedgeflow/src/auth.rs), lines 130–137 and 359–374, has one pinned issuer key and a process-local bounded replay map. Another replica or a restarted process does not share proof consumption. Certificate verification is implemented; Workload API enrollment/rotation, subject-to-workload authorization and federation operations are not.

[config.rs](../crates/kedgeflow/src/config.rs) wires a single actor assertion binding, one target/broker and static trust. A real authorization server must validate custom grant/digest/attempt fields and subject/actor permissions; the client cannot supply that policy. Complete rotation, shared replay, separated ledger permissions and an actual provider integration before a replica-based pilot. **M5.**

### F6 — Enterprise gap: target/outcome contracts remain mock-specific

[gateway.rs](../crates/kedgeflow/src/gateway.rs) binds exactly two mock parameters. [adapter.rs](../crates/kedgeflow/src/adapter.rs), lines 129–181, expects a fenced mock terminal receipt over pinned TLS, not a produced signed KF-JSON Receipt. `finish` stores status and overwrites outbox state rather than retaining full authorization-to-target evidence.

There is no PostgreSQL, Kubernetes, AWS or SaaS adapter. SQL reservation and physical Kubernetes drain in the paper are distinct operations with different guarantees; mock `drained: true` proves neither. Build typed target mappings, retained signed traces and writer-specific qualification. **M4, M6, M8.**

### F7 — Enterprise/protocol gap: deployment and portability remain unqualified

SDK exchange and cross-language signature vectors are useful, but there is no independent KedgeFlow controller/gateway exchange, A2A authority path, Rust Cedar/OPA or Temporal integration, deployed hardware review, workstation sandbox, production grant store or full restore/upgrade rehearsal. A Dockerfile or CI workflow does not establish a launched/accepted deployment.

The native server deliberately restricts HTTP transport, methods, streaming and protocol revision. Qualify that surface against actual harnesses; one SDK test does not establish broad MCP compatibility or native-tool interception. **M5–M9.**

### F8 — P2 documentation defect: the protocol entry page points to v0.1

[docs/protocol.md](protocol.md) calls the Python v0.1 profile the formal normative specification and describes broad guards/immutable receipts without current v0.9 qualification. This can lead implementers to incompatible records or unsupported guarantees. Label it as the preserved demo and provide an active profile index. **M0.**

## Enterprise integration claim map

| Technology / manuscript claim | Implemented or evidenced | Remaining work |
| --- | --- | --- |
| MCP governed calls | Pinned SDK discovery/remediation/fixture retry; negotiated grant headers | Real Agent Adapter, fresh admission/issuance/status; second harness; deployed header/transport tests |
| OAuth/DPoP and SPIFFE | Pinned token/proof and mTLS checks | Provider enrollment/rollover, workload authorization, shared replay, SVID lifecycle/revocation |
| RFC 8693 and target credentials | Exchange client with KedgeFlow extension; synthetic test broker | Real server-side extension, target scope/audience/lifetime verification; provider-specific AWS/database/SaaS bindings |
| Cedar / OPA | Separate Go Cedar experiment | Rust typed verified policy inputs, version/digest and fail-closed diagnostics; one engine first |
| WebAuthn hardware approval | Signed witnesses; Go assertion checks with software keys | Rust service, trusted rendering, durable replay state, physical ceremony and trusted enrollment/attestation |
| etcd distributed authority | Real single-host cluster evidence; atomic per-root mechanics | Admission deduplication, reservations, production TLS/RBAC, recovery and stale-restore exclusion |
| SQL / Kubernetes drain | Worked trace and fenced mock | Real reservation transaction; separately governed async drain; authoritative queries and writer coverage |
| Temporal / sagas | Schemas/design mapping | Conserved child/recovery budgets, stable workflow identities, query-first recovery and admitted compensation |
| A2A delegation | Structured root-reference fixture/schema checks | Card/extension negotiation, authorized resolution, child allocation and independent peers |
| Local/enterprise rollout | Protected HTTPS endpoint/configuration | Enforced OS/network/credential custody, native bypass tests, operations/retention/incident controls and accepted cutover |

Primary documentation supports these distinctions. [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) leaves deployment token trust details to profiles; [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) describes proof replay protection. [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/) distinguishes identities from provisioning. [Cedar authorization](https://docs.cedarpolicy.com/auth/authorization.html) documents diagnostics requiring safe wrapper handling. [etcd gateway authentication](https://etcd.io/docs/v3.6/dev-guide/api_grpc_gateway/#authentication) explains why certificate CN alone cannot authorize this JSON gateway. [Kubernetes API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/) describe conditional object updates, not fleet-wide transactions. [MCP's pinned specification](https://modelcontextprotocol.io/specification/2026-07-28) and [A2A specification](https://a2a-protocol.org/latest/specification/) supply transport contracts; KedgeFlow conservation is a separate proposed extension.

## Verification and limits

Fresh logs: [results/verification/review-2026-10-10](../results/verification/review-2026-10-10/).

| Check performed during this review | Result |
| --- | --- |
| Remote main comparison | `769c0a8`, same as local HEAD |
| Python compatibility/specification/freeze tests | **32 passed**, Python 3.13 |
| Specification validator | Draft 2020-12 schema, 13 signed envelopes, declared fixture bindings, OAuth/DPoP vectors, CTD YAML and A2A reference passed |
| Freeze verifier | **58 files and 24 contract pins matched** |
| Artifact integrity verifier | **77 original snapshot files**, retained logs/totals, added test copies and pinned Git objects matched |
| Rust rebuild/integration rerun | **Not performed:** no compiler/Cargo toolchain available |

The retained artifact reports **58 Rust tests**, 12 deterministic adversarial scenarios and a 6,560-attempt direct-ledger matrix: 82 claims, 6,478 refusals. Those runs used pinned `21d5efe`, single-host etcd and a fenced mock target. Integrity verification checks retained bytes/consistency; it does not rerun experiments or establish production/throughput claims. Six paper tests live in the snapshot, not the active root test directory.

Initial Python attempts encountered missing specification dependencies. Installing them in an isolated temporary directory allowed fresh tests/validation to pass; no dependency manifest or runtime changed. No deployment or external target was modified.
