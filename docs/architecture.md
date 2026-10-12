# KedgeFlow component boundaries

This matrix implements the [frozen v0.9 paper baseline](WHITEPAPER_IMPLEMENTATION.md).
It describes current Rust coverage; supplementary Go services remain separate experiments.

KedgeFlow defines nine proposed roles, not nine required products. Several roles
may share a service if the deployment preserves their permissions and trust boundaries.

| Role | Responsibility | Reference repository coverage |
|---|---|---|
| Policy Authority | Own approved policy, epochs and signer/provider trust | `kf-governance`: authorized signed publication of operator-approved Cedar/rule registration; dynamic enrollment/rotation remains open |
| Resource Registry | Own versioned action schemas, resource incarnations and adapter contracts | `kf-governance`: signed scoped CTD registration; production schemas/targets remain open |
| Admission Controller | Evaluate the exact proposal and discharge evidence obligations | `kf-control`: authenticated signed input verification, pinned Cedar policy, durable certificate/chain production |
| Grant Authority | Issue scoped authority under conserved root allowance | `kf-control`: certificate/chain revalidation, global operation deduplication, generated IDs/resource fences and live installed-state/revocation checks |
| Execution Gateway | Authenticate, verify bindings, atomically claim and obtain target credentials before dispatch | Rust `Gateway`, `kf-proxy`, authentication and credential-exchange client |
| Resource Adapter | Map a typed action to the target guard, effect and correlated result | Fixed HTTPS fenced mock-target adapter; production resource adapters required |
| Outcome Service | Resolve existing attempts using authoritative evidence | Durable attempts/outbox, authorized retained status and query-only reconciliation port; no incident/query daemon |
| Agent Adapter | Freeze proposals, gather remediation evidence and carry grants through the workflow | Node Agent Adapter with actual official client, fresh admission/issuance and durable exact-call/grant state; wider provider/enterprise integration remains open |
| Evidence Provider | Publish trusted, scoped and fresh witnesses | Signed schemas/fixtures; enrollment, human review and provider services external |

The Governance Interface controls policy and registry publication. Runtime
Admission connects the Agent Adapter to admission/issuance. Enforcement Control
distributes authority lifecycle state to gateways. Execution redeems an exact
grant. Evidence conveys observations and verified review. Outcome conveys
correlated effects or explicit uncertainty. A transport adapter or storage engine
is a substrate for these roles, not an additional architectural role.

The etcd ledger conserves execution allowances independently of target mutations.
The [draft control service](CONTROL_SERVICE.md) uses operator-approved descriptor,
provider and policy pins checked against current installed scope/trust,
acknowledgement freshness and revocation state. The
[administrative service](GOVERNANCE_SERVICE.md) supplies signed versioned control;
the native gateway verifies and renews its installed-scope acknowledgement.
The [Node Agent Adapter](AGENT_ADAPTER.md) now drives fresh evidence/admission/issuance
to mock execution. [M3b operation status](rfcs/0009-operation-status.md) resolves
missing local grants and ambiguous issuer/provider replies without repeated
execution. Wider provider/persistence deployment qualification remains open.
An atomic claim does not make a target effect atomic. A target supplies `Level_A`
only for its declared check-and-commit scope; deadlines required at acceptance or
commit must be enforced there.

The earlier Python modules under `src/kedgeflow` implement the v0.1 local demo.
Their controller, in-memory state and HMAC enforcer do not satisfy the independent
v0.9 trust and target boundaries. They remain covered by compatibility tests.

[M4a recovery](RECOVERY_SERVICE.md) retains exact signed execution context and
claim/dispatch/terminal history. Its separate worker uses CAS to seal only
pre-dispatch work, queries possible sends without dispatch, preserves consumption
and signs linked outcome reports. The offline verifier authenticates grant/receipt
chains and explicitly identifies missing full-admission/target-proof links.

[M4b1 delivery](OUTCOME_REPORT_SERVICE.md) separates the native collector from
execution. It authenticates the current reporter, checks immutable retained
receipts/evidence and stores ordered signed acknowledgements. Delivery/lookup
changes no attempt/root/nonce or target state. The tenant label assigns a dedicated
operator namespace. [M4b2 signed lineage](ADMISSION_LINEAGE.md) now binds
proposal/CTD tenancy through historical admission, grant and receipt records.
Independent-store restore and installation/key-history qualification remain open.

[M4b3 governance history](CONTROL_HISTORY.md) appends immutable control events in
each native mutation transaction and binds a separately signed observer checkpoint
to historical lineage. Approved old/new issuer membership and acknowledgements
are verified offline. Operation-bound control/revocation CAS evidence, distributed
clock/observer trust and production custody remain open.
