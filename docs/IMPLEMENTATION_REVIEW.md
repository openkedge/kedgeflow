# Initial implementation completeness review — 6 October 2026

Reviewed code baseline: `e3f4afd91f9d2c6de0045d0a90909e0fd0e7d06a`.
Specification: frozen KedgeFlow whitepaper v0.9.

This review records the 6 October baseline. Current increments and remaining
gates are tracked in the [implementation plan](IMPLEMENTATION_ROADMAP.md),
including the [draft admission/issuer service](CONTROL_SERVICE.md).

The repository is ready to publish as a bounded research reference gateway. It
does not yet implement a complete KedgeFlow control plane or a production rollout.
The review found no publication blocker within its declared execution profile.
The findings below are implementation gaps, not completed services inferred from
schemas or fixtures. This is a source/contract review and local execution check,
not an independent security audit.

## Coverage and boundaries

| Boundary | Executable coverage | Missing pieces |
|---|---|---|
| Agent Adapter / Runtime Admission | Official Model Context Protocol (MCP) client discovery, remediation and preissued signed-grant retry | Actual proposal freezing, evidence acquisition and fresh admission/issuance within an agent workflow |
| Policy Authority / Governance | Trusted monotonic policy/ownership publication and epoch checks in etcd | Policy lifecycle service, signer/provider trust administration, rollout/revocation operations |
| Resource Registry / Governance | Closed operator tool registration, fixed action/resource/adapter/predicate binding | Registry service, enrollment, descriptor lifecycle and production parameter schemas |
| Admission Controller / Runtime Admission | Signed proposal/certificate fixtures and generic envelope authentication | Rust proposal/descriptor/certificate semantic validation, policy evaluation, fresh obligation discharge and certificate producer |
| Grant Authority / Enforcement Control | Trusted atomic one-root issuance/replacement, active generation/fence, nonce claim, one-time dispatch authorization | Public authenticated issuer, admission-certificate consumption/deduplication, cross-root conflict reservations, delegated allowance and saga budgets |
| Execution Gateway / Execution | Native mutually authenticated TLS listener, pinned subject token/proof, exact call binding, durable claim, postclaim credential exchange, grant-reference retrieval | Enterprise enrollment/rotation, replica-wide proof replay state, broader transport profiles and operational hardening |
| Resource Adapter / Execution and Outcome | Fixed HTTPS fenced mock transaction, exact version predicate, correlated terminal receipt and uncertain-response handling | SQL/Kubernetes/SaaS adapters, resource-specific writer coverage and truthful target contracts |
| Outcome Service / Outcome | Durable attempts/outbox; query-only reconciliation of explicitly `unknown` attempts | Crash recovery worker, target query clients, escalation deadlines, retention and compensation coordination |
| Evidence Provider / Evidence | Signed vectors and cryptographic primitives | Rust witness providers, canonical human review, enrollment/attestation and durable review/replay services |

Rust grant verification accepts one nondelegated resource, one `version_eq`
predicate, `Level_A` / `FencingToken`, and `dispatch_bound` completion. Unsupported
profiles are refused. The preserved Python code is a v0.1 demonstration; the
supplementary Go services use a separate capacity/review profile. Neither fills
the missing Rust services.

## Findings for the next implementation milestones

1. **Admission and issuance are not an end-to-end service path.** The executable
   does not expose an admission or issuer endpoint. `verify_envelope` checks the
   authenticated envelope, not every record's payload schema and cross-record
   authorization semantics. A Rust Admission Controller and Grant Authority must
   validate these semantics under separately administered trust before producing
   and consuming a certificate. Existing SDK tests use a preissued grant.
2. **Single-root conservation is not domain-wide allocation.** `EtcdLedger::issue`
   creates an independent root; it does not deduplicate an admitted operation
   across fresh roots or reserve a shared capacity budget across them. An issuer
   must add those atomic constraints for any profile claiming them. Version/fence
   checks at the mock target do not establish the paper's Kubernetes maintenance
   capacity invariant or saga allocation rules.
3. **Crash recovery is incomplete.** A process can stop after claim or dispatch
   authorization while its durable attempt still says `claimed`. Reconciliation
   currently accepts only explicit `unknown` attempts. Consumption remains held,
   which prevents automatic replay, but a recovery worker must inspect the outbox,
   conservatively classify possible dispatch, query authoritative target state
   and escalate unresolved operations. It must never infer no effect from a
   timeout or blindly redispatch.
4. **Mock completion is narrower than full outcome evidence.** The target's
   terminal receipt is a typed object authenticated by the pinned TLS channel.
   It is not the complete signed KF-JSON-0.2 Receipt producer or a durable
   cross-vendor outcome service. Guard refusal relies on the registered mock
   contract and correlated response; a legacy error string cannot establish no
   effect unless its adapter explicitly guarantees that interpretation.
5. **Deployment trust and bypass controls are external.** Pinned keys and a
   process-local bounded proof cache need enrollment, rotation and shared replay
   controls for replicas. The CLI reads independently supplied service credentials;
   it installs no workstation sandbox. Production must deny alternate shell,
   file/socket, credential and equivalent-writer routes. Target adapters and a
   token-exchange authorization server remain real integration dependencies.
6. **Operating and portability evidence is limited.** The checks run on one macOS
   ARM64 host with Rust 1.98.0. Rust 1.88 is declared but was not exercised.
   Multi-host partitions, process kill/restart recovery, restore, rolling upgrades,
   hardware review, container launch and production target coverage remain gates.
   CI runs the full required cluster/client suite on Linux after publication;
   local passing results must not be presented as that remote result.

The first implementation milestone remains a narrow real Agent Adapter → Rust
admission → atomic issuer → gateway → fenced target path. Add certificate
semantics and admitted-operation deduplication before widening execution scope.
Follow with recovery/incident handling and one production Resource Adapter.

## Fresh verification

| Check | Result |
|---|---|
| Rust full workspace/all-target tests | **52 passed**, `KF_REQUIRE_ETCD=1` and `KF_REQUIRE_SDK=1`; no skips |
| Authority infrastructure | Three actual etcd 3.6.5 members with Raft on one loopback host; default WAL sizing; disposable data removed after the run |
| Official MCP client | Pinned client 2.3.0 on Node 25.2.1; synthetic SDK authentication ports, with cryptographic identity/TLS tested separately |
| Rust formatting / clippy | Passed, warnings denied; locked cached dependencies |
| Python compatibility and freeze tests | **32 passed** (24 compatibility/specification tests plus eight freeze-check tests), Python 3.13 |
| Schema/signature/binding validator | Thirteen signed envelopes, canonical digests, identity vectors, descriptor YAML and Agent2Agent reference passed |
| Frozen artifacts | 58 file hashes and 24 mirrored contract pins matched |
| Python lint / types | Ruff passed; mypy passed for 22 source files |

Raw Rust/clippy logs are in
[`results/verification/review-2026-10-06`](../results/verification/review-2026-10-06/).
The initial fresh etcd startup failed to create its temporary WAL; a subsequent
startup succeeded with diagnostic logging and default storage settings. The first
Python invocation lacked the local package import path; `PYTHONPATH=src` corrected
the test environment. Neither setup failure required a runtime change. CI installs
the package through the existing editable-install step.

## Publication and paper references

The [reference index](REFERENCE_INDEX.md) maps the paper's artifact paths to
repository files and pinned URLs. It includes the frozen PDF, schema, fixtures,
Rust source, original verification and supplementary Go source/results. The
historical Go material is separately labeled and is not compiled into the Rust
runtime or included in claims of Rust completeness.
