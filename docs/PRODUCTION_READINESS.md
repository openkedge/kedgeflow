# Production readiness for the self-hosted MLP

The first deployment target is **Linux with systemd and separate service
accounts**, using self-hosted Keycloak and SPIRE. The initial action is the
registered PostgreSQL reservation/update path. This is a release worklist; the
repository's alpha version and bounded fixture results do not establish
production readiness. The [roadmap](IMPLEMENTATION_ROADMAP.md),
[M8 acceptance](M8_ACCEPTANCE.md) and [enterprise gates](ENTERPRISE_QUALIFICATION.md)
continue to define the protocol and acceptance requirements.

## Deployment boundaries

Run the gateway, admission/issuer, broker, SQL target, database and recovery
client under distinct non-root accounts. The agent and its descendants must have
no access to service private keys, authority signing keys, SQL writer sockets,
administration credentials or deployment configuration. Independently administer
the identity publisher and retained head/floor, restore witness and receipt
collector; a broker restore must not restore their authority state.

Use production provider storage rather than Keycloak's disposable development
H2 setup. Define service certificate issuance and rotation separately from the
SPIRE JWT/X.509 issuer rollover already exercised. A new trust bundle must reach
each actual client/server before old credentials retire. Account separation,
filesystem modes and systemd restrictions must be exercised together on the
selected deployment, including agent child processes.

## Release gates

Each gate needs an exact source/configuration reference, reproducible commands,
positive and refusal observations, and its remaining limitations. A passing
local test closes only the behavior it measures.

| Gate | Existing basis | Required production exit |
| --- | --- | --- |
| Configuration and key custody | [Protected service reads](SERVICE_CUSTODY.md), including operational/recovery/collector loaders and rotating delivery token/proof source | Qualify the deployed secret, socket, writer, publisher and administrative paths; other optional operator/physical profiles remain outside this package |
| Installation and lifecycle | Nine Linux executables, eight accounts and systemd units; native UID preflight and bounded installed lifecycle/sandbox smoke | Full approved topology, live managed-authority workflows, complete bypass/egress and upgrade/rollback/uninstall rehearsal that preserve consumed authority |
| Service credential lifecycle | Protected live receipt-delivery token/proof renewal and primary/witness ledger token reload; bounded real-etcd expiry/RBAC and lost-reply checks | Deployed credential-publisher renewal, service certificate/CA rollout and issuer-pin changes for all long-running roles |
| Identity and service PKI | Real Keycloak/SPIRE SQL, lifecycle, cold-copy restore and issuer rollover fixtures | Production provider databases/key stores; protected publisher delivery; fresh and existing connection rotation/revocation behavior; separate service CA rollout and replica restart evidence |
| Ledger, target and witness custody | Managed controls, SQL enrollment, kernel peer checks and restore gates | Separate least-privilege etcd roles, complete target writer coverage, independently retained witness/head/floor and protected collector/recovery access |
| Failure and storage recovery | SQL process faults, original-attempt recovery, bounded stale logical restore and cold provider copies | Physical backup/restore and stale restore refusal in the selected storage topology; all ambiguous results retain original attempts; no extra claim, mint or dispatch during recovery |
| Operations and capacity | Bounded requests, retained outcome/incident mechanisms and [opt-in monitored readiness](SERVICE_OPERATIONS.md) for control/broker/governance/collector | Complete gateway/SQL/recovery readiness and deployed monitoring; metrics/alerts; workload-specific capacity and latency budgets; retention sizing; rehearsed incident, abort and on-call procedures |
| Release quality and interoperability | Frozen software evidence, conformance runner, CI definitions | Declared MSRV/platform jobs observed on release source, dependency/license/security review, independent implementation and reproduction, signed/versioned release artifacts and supported-upgrade policy |
| Acceptance | Named owner inputs in the protected pilot runbook | Resource, identity/security, deployment and SRE owners accept exact boundaries, workload budgets, break-glass writers, retention and operational responsibility |

The [core service custody record](../results/verification/service-custody-2026-10-31/README.md)
retains source and bounded same-host observations for the first gate's runtime
basis. Deployment and independent custody remain open.

The Linux core increment additionally builds actual ARM64 release executables,
verifies the bundle, parses the five systemd units and exercises protected
preflight under distinct kernel UIDs. Those preflight-only processes do not
establish installed systemd lifecycle, sandbox enforcement, live authority or
full deployed bypass coverage.
The [Linux core package record](../results/verification/linux-core-package-2026-11-01/README.md)
retains the actual release build, bundle manifest and 44 native preflight / 56
file-access observations, with their precise limits.

The [operational services record](../results/verification/linux-operational-services-2026-11-01/README.md)
extends this to nine executables and eight accounts, 108 native preflight and
72 file-access cases, and 36 observations from installing the exact ARM64 bundle
under systemd. Five services completed start/restart/stop and sandbox probes;
unavailable-authority refusals remain distinct from application readiness.

The [ledger credential renewal record](../results/verification/ledger-credential-renewal-2026-11-01/README.md)
adds protected per-transaction token reload for primary and witness clients.
Isolated real-etcd expiry/RBAC and accepted-write/lost-reply cases preserve the
original consumed authority. This is source/test evidence; the prior installed
Linux bundle predates this change and does not qualify its deployed renewal.

The [monitored readiness record](../results/verification/service-readiness-2026-11-01/README.md)
retains native read-only control/receipt observations, real mTLS monitor
boundaries and shipping collector liveness-versus-readiness behavior. Gateway,
SQL target, recovery and installed Linux monitoring remain open; the new
endpoint does not close the complete operations gate.

## Implementation order

1. Define and implement application readiness and operational reporting for each
   managed role. A listening control/broker process and an active systemd target
   do not prove backend authority availability. Preserve query-only recovery
   when execution control stops or expires.
2. Qualify ledger/service credential renewal and an approved full Linux topology:
   live managed-authority workflows, service PKI, actual SQL peer/writer coverage,
   agent/descendant bypass and egress, and retained state across upgrades.
   Local lifecycle/sandbox smoke with unavailable authorities is bounded evidence.
3. Qualify service PKI rotation, provider production storage, least-privilege
   ledger access and independent witness/head/floor/collector administration.
4. Exercise physical recovery, upgrades and realistic workload budgets; add
   operational reporting and rehearsed runbooks around the observed behavior.
5. Complete the release, independent reproduction and owner acceptance gates.

The [protected pilot runbook](PROTECTED_PILOT.md) lists the deployment references
needed from owners. Keep credential values outside the repository and evidence.
Outstanding owner decisions do not prevent implementation of the shared runtime,
packaging and operational controls above.
