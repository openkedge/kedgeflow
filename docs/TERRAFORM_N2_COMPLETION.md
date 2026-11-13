# N2 software completion and deployment handoff

The delivered scope is a protected local saved-plan runner for one ConfigMap
annotation update, plus a separately admitted two-ConfigMap action. Both are
explicit Level C profiles. N2a–N2i supply the software and local qualification
for that scope. Production deployment acceptance remains open.

| Required software observation | Implementation and evidence |
| --- | --- |
| Exact enforceable apply gate and immutable input inventory | [Saved-plan inspection](TERRAFORM_PLAN.md), [native apply](TERRAFORM_APPLY.md); pinned binary plan, derived inspection, provider/tool/configuration and original state identity |
| Fresh proposal, admission, grant, original claim and broker permit | [Shipping gateway and official SDK](TERRAFORM_GATEWAY.md); exact action/manifest/effect/incarnation binding |
| Fixed saved-plan apply and independent target read | Native apply and shipping gateway qualification; no agent shell, replan, force-unlock or apply retry |
| Policy withdrawal, drift, suspension/expiry and lost publications | [Failure qualification](TERRAFORM_FAILURE_QUALIFICATION.md); original query-only recovery |
| Native local-backend locking and stale serial/lineage refusal | [Backend qualification](TERRAFORM_BACKEND_QUALIFICATION.md) |
| Audited partial apply and lost result | [Pair gateway](TERRAFORM_PAIR_GATEWAY.md); per-member partial observations and held unknown aggregate |
| Active provider/Terraform death and queued late effects | [Active-child](TERRAFORM_ACTIVE_CHILD_QUALIFICATION.md) and [whole-gateway death](TERRAFORM_GATEWAY_DEATH_QUALIFICATION.md) records |
| Linux service containment and separate SDK credential custody | [Systemd qualification](TERRAFORM_SYSTEMD_QUALIFICATION.md); actual kernel/systemd observations and cold original queries |
| Deployable opt-in extension and bounded offline replay | [Linux deployment](TERRAFORM_LINUX_DEPLOYMENT.md), pinned closed bundle and local replay verifier |

The supported action has no external dependency predicate. Metadata checks and
local backend locking do not atomically guard arbitrary target writers. A wider
action with dependency or commit-time invariants must be refused until a
separately admitted profile supplies sufficient coverage. A stock provider and
its code remain trusted. Killing all local descendants cannot retract a request
already queued remotely; unresolved original authority stays held.

The local fixture's writer inventory is explicit:

| Path or principal | Qualified boundary and limit |
| --- | --- |
| SDK agent and descendants | Separate UID, no service/Docker supplementary groups; cannot read writer, protected plan, service key, process environment or Docker socket |
| Gateway and stock provider | Trusted service UID; fixed approved inputs; read-only configuration/plan/secret mounts; writable private staging/backend; empty capabilities and no cgroup delegation |
| Kubernetes runner credential | Resource-scoped fixture writer retained by the service; broader than an exact mutation, so the runner enforces exact action binding |
| Observer credential | Separate read-only target observation; does not authorize mutation |
| Planning/fixture administrator | Trusted test controller provisions the disposable target, RBAC and immutable snapshots; excluded from agent isolation claims |
| Other administrators, existing target writers and credential providers | Require deployment-owner inventory, withdrawal policy and acceptance; same-host fixtures do not prove their absence or independence |
| Other local backend users | Native lock/contention qualification covers cooperating users; no disabled locking or automatic force-unlock |

Deployment owners must now supply concrete acceptance evidence for actual
identity/delegation and credential lifecycle, complete writer/bypass inventory,
independent authority/restore storage and audit custody, supported runtime and
provider pins, recovery/incident ownership, SLOs and independent reproduction.
Record those decisions against [production readiness](PRODUCTION_READINESS.md).
No production credential, independent sign-off or external provider access is
created by this software record. N1 broader deployment, N3 external identity/
Vault interoperability, N4 operational-context experiments and M9 independent
peers remain separately scoped work in the [roadmap](IMPLEMENTATION_ROADMAP.md).

The [deployment acceptance checker](TERRAFORM_DEPLOYMENT_ACCEPTANCE.md) now binds
externally approved owner trust, the exact release/configuration/scope and
retained deployed observations. Preparation emits unknown checks and empty
approvals; verification refuses any missing gate. This closes the executable
acceptance-record gap. Actual production references, deployed measurements and
independent owner decisions remain required.
