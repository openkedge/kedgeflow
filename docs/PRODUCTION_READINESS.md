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
| Installation and lifecycle | Ten Linux executables, eight core accounts and optional credential-publisher management; native UID preflight and bounded installed lifecycle/sandbox smoke | Full approved topology, live managed-authority workflows, complete bypass/egress and upgrade/rollback/uninstall rehearsal that preserve consumed authority |
| Service credential lifecycle | Protected live receipt-delivery token/proof renewal, primary/witness ledger token reload and optional audited etcd token publisher; bounded real-etcd expiry/RBAC and lost-reply checks | Full-topology publisher renewal, service certificate/CA rollout and issuer-pin changes for all long-running roles |
| Identity and service PKI | Real Keycloak/SPIRE SQL, lifecycle, cold-copy restore and issuer rollover fixtures | Production provider databases/key stores; protected publisher delivery; fresh and existing connection rotation/revocation behavior; separate service CA rollout and replica restart evidence |
| Ledger, target and witness custody | Managed controls, SQL enrollment, kernel peer checks and restore gates | Separate least-privilege etcd roles, complete target writer coverage, independently retained witness/head/floor and protected collector/recovery access |
| Failure and storage recovery | SQL process faults, original-attempt recovery, bounded stale logical restore and cold provider copies | Physical backup/restore and stale restore refusal in the selected storage topology; all ambiguous results retain original attempts; no extra claim, mint or dispatch during recovery |
| Operations and capacity | Bounded requests, retained outcome/incident mechanisms and [opt-in monitored readiness](SERVICE_OPERATIONS.md), including gateway upstreams, SQL role separation and query-only workers | Deployed monitoring; metrics/alerts; workload-specific capacity and latency budgets; retention sizing; rehearsed incident, abort and on-call procedures |
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
boundaries and shipping collector liveness-versus-readiness behavior.
The [remaining role readiness record](../results/verification/service-readiness-roles-2026-11-01/README.md)
adds gateway upstreams, SQL role catalogs, recovery/supervision listeners and
shutdown refusal on existing connections. Installed Linux monitoring, metrics,
capacity and owner acceptance remain open.

The [Linux readiness package record](../results/verification/linux-readiness-package-2026-11-01/README.md)
retains a rebuilt nine-executable ARM64 bundle with those changes, 108 monitored
native preflight and 72 file-access cases, and 61 installed-systemd observations.
Five services returned typed unready reports under their separate accounts;
agent monitor access refused. All nine local material preflights passed before
unavailable-prerequisite failures were classified. This does not establish a live
Linux authority/SQL workflow, deployed credential renewal or production acceptance.

The [live systemd SQL record](../results/verification/linux-systemd-sql-2026-11-01/README.md)
adds an actual COMMIT and original-attempt query using that exact release's SQL
target under the shipping sandbox, PostgreSQL 18.3 and six separate kernel UIDs.
The same retained result survives response-body loss, replay, target restart and
execution expiry. Executor withdrawal makes readiness unavailable while original
queries continue; query-role withdrawal also makes readiness unavailable. These
are target-component observations with generated grants and target credentials.
Live broker/control authority, provider integration and recovery-worker delivery
under systemd remain open.

The [managed systemd provider record](../results/verification/managed-systemd-authority-2026-11-01/README.md)
adds real Keycloak/SPIRE credentials through the shipping admission/issuer,
broker, gateway and SQL target, each with protected material and strict managed
launch under its own systemd account. The official SDK agent uses a separate UID
and verifies its groups; other service/agent accounts refuse direct SQL login.
Normal and lost-SDK-reply cases retain one broker permit and SQL attempt through
gateway restart, domain revocation and actual grant expiry. Governance, evidence
and TLS ledger relays remain fixture administration. This does not establish
least-privilege etcd access, independent storage administration, production
provider storage, operational worker delivery or complete bypass/egress coverage.

## Implementation order

The [ledger publisher record](../results/verification/linux-ledger-publisher-2026-11-02/README.md)
adds a rebuilt ten-executable v3 bundle and an optional non-root etcd authenticator
with a separate constrained local installer. Real signed-token expiry and renewal,
READ/READWRITE permission audits, credential access refusals and stale/link failure
paths pass under systemd. The rebuilt core also passes its 108 protected native
preflights and 72 file-access cases. This component qualification does not establish
full-topology service renewal, all-role least privilege or service CA rotation.

1. Qualify all managed-role readiness on the installed Linux topology; add
   operational metrics, refusal/unresolved-age alerts and capacity budgets.
   Process/target activity does not establish readiness. Preserve query-only
   recovery when execution control stops or expires.
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
