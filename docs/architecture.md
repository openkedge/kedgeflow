# KedgeFlow component boundaries

This matrix implements the [frozen v0.9 paper baseline](WHITEPAPER_IMPLEMENTATION.md).
It describes current Rust coverage; supplementary Go services remain separate experiments.

KedgeFlow defines nine proposed roles, not nine required products. Several roles
may share a service if the deployment preserves their permissions and trust boundaries.

| Role | Responsibility | Reference repository coverage |
|---|---|---|
| Policy Authority | Own approved policy, epochs and signer/provider trust | Trusted ledger publication port; no policy-management service |
| Resource Registry | Own versioned action schemas, resource incarnations and adapter contracts | Closed operator tool registration; no registry service |
| Admission Controller | Evaluate the exact proposal and discharge evidence obligations | `kf-control`: authenticated signed input verification, pinned Cedar policy, durable certificate/chain production |
| Grant Authority | Issue scoped authority under conserved root allowance | `kf-control`: authenticated certificate/chain revalidation, global operation deduplication, generated IDs and durable resource fences; control lifecycle remains open |
| Execution Gateway | Authenticate, verify bindings, atomically claim and obtain target credentials before dispatch | Rust `Gateway`, `kf-proxy`, authentication and credential-exchange client |
| Resource Adapter | Map a typed action to the target guard, effect and correlated result | Fixed HTTPS fenced mock-target adapter; production resource adapters required |
| Outcome Service | Resolve existing attempts using authoritative evidence | Durable attempts/outbox and query-only reconciliation port; no incident/query daemon |
| Agent Adapter | Freeze proposals, gather remediation evidence and carry grants through the workflow | Official MCP client compatibility harness; production integration required |
| Evidence Provider | Publish trusted, scoped and fresh witnesses | Signed schemas/fixtures; enrollment, human review and provider services external |

The Governance Interface controls policy and registry publication. Runtime
Admission connects the Agent Adapter to admission/issuance. Enforcement Control
distributes authority lifecycle state to gateways. Execution redeems an exact
grant. Evidence conveys observations and verified review. Outcome conveys
correlated effects or explicit uncertainty. A transport adapter or storage engine
is a substrate for these roles, not an additional architectural role.

The etcd ledger conserves execution allowances independently of target mutations.
The [draft control service](CONTROL_SERVICE.md) uses static operator descriptor,
provider and policy pins checked against current ledger policy/ownership.
Authorized publication/installation/revocation and live control ingestion remain
M2c. A full client admission-to-gateway workflow remains M3.
An atomic claim does not make a target effect atomic. A target supplies `Level_A`
only for its declared check-and-commit scope; deadlines required at acceptance or
commit must be enforced there.

The earlier Python modules under `src/kedgeflow` implement the v0.1 local demo.
Their controller, in-memory state and HMAC enforcer do not satisfy the independent
v0.9 trust and target boundaries. They remain covered by compatibility tests.
