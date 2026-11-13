# SQL pilot release contract

Profile **cura**, planning date **12 November 2026**. Normative prerequisites remain
[protected pilot](PROTECTED_PILOT.md), [production readiness](PRODUCTION_READINESS.md)
and [enterprise qualification](ENTERPRISE_QUALIFICATION.md).

| Milestone | Completion boundary | Current state |
| --- | --- | --- |
| A — Reproducible Pilot Infrastructure | Reviewed infrastructure, packaging, protected local preflight, disposable Linux/SQL/identity/bypass and physical recovery harnesses, operational/evidence templates, reproducible required CI | Local implementation and verification in progress; hosted green source not established |
| B — Enterprise Pilot Acceptance | Actual isolated deployment, independently administered custody, all-writer/descendant denial, physical recovery/cutover, measured budgets and seven signed owner decisions | **BLOCKED_EXTERNAL_INPUT** |

Codex implements software; it is not an independent reviewer or acceptance owner.
No AWS resources may be created until the nonproduction account, permissions,
credentials and budget have been explicitly supplied and approved. `cura` is the
requested AWS CLI profile; its presence is not provisioning approval.

## Supported semantics

| Integration | Guarantee | Pilot status |
| --- | --- | --- |
| `KF-POSTGRES-LEAF-0.1-draft`, `postgres.reservation.set.v1` version `1.0` | Level A / FencingToken for the actual conditional reservation transaction and retained outcome COMMIT; exact incarnation, version and fence | Selected; isolated single organization, one resource/action, no delegation or hardware review |
| Terraform single/pair saved-plan | Level C, `target_atomic:false`, retained unknown/partial results | Existing experimental profiles; expansion deferred |
| Managed Kubernetes drain | Level C controller acceptance; physical outcome requires authoritative observation | Existing experimental profile; expansion deferred |
| Physical capacity/scheduling, arbitrary SQL, external target writers, multitenancy, multi-region, dynamic delegation | No guarantee under this contract | Unsupported |

The SQL parameters are the closed `{resource_id, expected_version, reservation}`
schema from [RFC 0023](rfcs/0023-postgres-reservation.md); all components must pin
its registered CTD/schema and [RFC 0025](rfcs/0025-postgres-leaf-binding.md).
An unsupported name, binding, actor, guard or protocol must refuse through the
existing native loaders and discovery checks. The administrative acceptance
checker also rejects out-of-scope pilot declarations. It does not enforce a
running deployment or convert an unsupported runtime into a supported one.

PostgreSQL and its target must share a host: the shipping driver uses a local
Unix socket and kernel peer UID checks. The target cannot use RDS or a remote
PostgreSQL instance under this profile. Run database and target as distinct
non-root users, with no application TCP listener or agent-accessible socket.
Admission and issuance are currently one `kf-control` service/account; splitting
those duties into separately credentialed processes and kernel identities remains
required Milestone A implementation work for the requested reference profile.
An owner signature cannot substitute for that missing implementation.

## Infrastructure and installation

[Versioned manifest](../deploy/pilot/cura/manifest.json) records absent inputs;
[CloudFormation source](../scripts/pilot-infrastructure.py) deterministically
renders [infrastructure v1](../deploy/pilot/cura/infrastructure-v1.json).
It proposes us-west-2, three private subnets, nine bounded ARM64 hosts, separate
agent/identity/SQL/witness/audit hosts, three ledger members and retained encrypted
data disks. Services use separate shipping systemd identities on their service
host. The template has no public IPs, internet/NAT/peering route, SSH ingress,
database TCP ingress, application secrets or service enrollment. SSM instance
roles can operate node channels only, not fetch secrets or administer AWS.

An operator-approved Ubuntu 24.04 ARM64 AMI, pinned image/package inventory,
customer KMS key, source/package/configuration pins, budget and account are
mandatory inputs. Supply preinstalled SSM and pinned runtime dependencies in the
approved AMI. There is no public repository download route from these hosts.
Data volumes are attached, **not formatted or mounted**; storage owners must
bind the exact volume IDs/mounts and test reboot/restore before service startup.
No user-data script silently enrolls or starts authority. Budget notifications
are alerts, not a guaranteed hard spending cap; fixed host/disk counts also bound
resource size. An owner-approved abort/cost-control procedure is still required.

Validate without contacting AWS:

```sh
python scripts/pilot-infrastructure.py --output /tmp/cura-infrastructure.json
cfn-lint deploy/pilot/cura/infrastructure-v1.json
```

The deployment operator must first review a change set against approved inputs;
no provisioning wrapper is provided that bypasses that approval. Same-account
cloud administrators can access all hosts; separate hosts/roles do not themselves
prove independent witness, storage or audit administration. SSM administration,
DNS/resolver access, metadata, root and emergency routes belong in writer/bypass
inventories. The optional [agent unit](../deploy/pilot/cura/kedgeflow-agent.service)
is an unenrolled template for an owner-supplied workflow. Its cgroup IP filters
must be enforced and probed on the selected kernel; missing eBPF support cannot
be treated as effective denial.

Build and stage the core bundle using [Linux deployment](LINUX_DEPLOYMENT.md):

```sh
python scripts/package-linux.py --output dist/linux
python scripts/stage-pilot-release.py --package /approved/bundle.tar.gz \
  --sha256 EXPECTED_APPROVED_SHA256 --output /new/private/staged-release
python scripts/release-provenance.py --package /approved/bundle.tar.gz \
  --sha256 EXPECTED_APPROVED_SHA256 --output /new/private/provenance
sudo python scripts/preflight-sql-pilot.py --binary-dir /opt/kedgeflow/current/bin \
  --configuration-root /etc/kedgeflow --postgres-peer-uid APPROVED_DATABASE_UID
```

Staging authenticates the supplied digest and verified archive bytes before
extraction, refuses replacement and starts no services. The provenance output is
an unsigned draft CycloneDX inventory of locked Rust/Node dependencies; OS packages,
vulnerability/license review, publisher signature and independent source-to-binary
reproduction remain required. Native preflight runs each loader under its actual
kernel identity and makes no enrollment or authority write. Run it on each host
for that host's roles; use `--roles` for an explicit subset. It cannot establish
live readiness or actual isolation by itself.

## Exact evidence and seven-owner acceptance

Use `KF-SQL-PILOT-ACCEPTANCE-0.1-draft`, the [closed schema](../spec/drafts/sql-pilot-acceptance-v0.1.schema.json)
and [record implementation](../scripts/pilot-acceptance-records.mjs).
The deployment binds exact source commit, release bundle, protected configuration,
writer inventory, capabilities manifest, resource/incarnation, action/CTD/schema,
Level A guard and a finite validity interval. Retain inventory and capabilities
bytes at `artifacts/<sha256>` alongside every check's bounded evidence bytes.

```sh
node scripts/prepare-pilot-acceptance.mjs --deployment /approved/deployment.json \
  --output /new/private/owner-request
node scripts/verify-pilot-acceptance.mjs --directory /approved/evidence \
  --trust /independently/approved/trust.json --trust-sha256 APPROVED_TRUST_SHA256 \
  --deployment-digest APPROVED_DEPLOYMENT_DIGEST
```

The request generator creates no keys, signatures, observations or approvals.
The verifier reuses the tested bounded regular-file/signature machinery from the
existing Terraform acceptance checker while preserving that profile's wire bytes
and signature context. SQL has a distinct signature context and closed scope.
It requires all checks to pass with fresh deployed observations and current,
role-bound Ed25519 owner records. Deployment, storage, audit and independent
reproduction must declare different administration domains and all seven owner
principals/keys must differ. Declared domains and signatures do not establish real
independence; owner trust enrollment and factual review remain external duties.

For `required_ci_same_source_no_skips`, retain a JSON artifact `{ "run": <GitHub
run REST response>, "jobs": <complete jobs REST response> }` for the exact commit
and run attempt. The checker checks all eleven mandatory job names, required step
names, complete pagination, source/run binding and success, refusing skipped or
omitted qualification. Only GitHub post-cache cleanup may be skipped. Fetch the
records from GitHub and retain authenticated provenance; fabricated JSON is not CI
proof. The independent reproducer signs the exact observation containing its hash.
No verifier report grants execution or asserts `production_qualified:true`.

## Owner and input register

| Role | Assignment | Gate |
| --- | --- | --- |
| deployment | OpenKedge infrastructure operator, provisional | Exact installed package/configuration, UIDs, sockets/egress, upgrade |
| identity_security | Unassigned | **BLOCKED_EXTERNAL_INPUT**: production Keycloak/SPIRE, PKI, publisher, rotation/revocation |
| resource | PostgreSQL/database owner, provisional | Exact resource/incarnation, all writers and break-glass, guard/query/commit |
| storage | Independent custodian, unassigned | **BLOCKED_EXTERNAL_INPUT**: independent witness/head/floor, physical backup/restore and retention |
| audit | Independent custodian, unassigned | **BLOCKED_EXTERNAL_INPUT**: collector custody and retained effect correlation |
| sre | Pilot on-call owner, provisional | **BLOCKED_EXTERNAL_INPUT**: actual assignment, measured budgets, alerts and abort |
| independent_reproducer | External engineer/reviewer, unassigned | **BLOCKED_EXTERNAL_INPUT**: green source, signed release/SBOM and reproduction |

Cloud account/permissions/AMI/KMS/budget, deployed resources, security approvals,
independent custody, actual SRE ownership and all deployed acceptance evidence are
**BLOCKED_EXTERNAL_INPUT**. These do not prevent further Milestone A work.

The [dependency security work](DEPENDENCY_SECURITY.md) adds patched locks, source-bound
Cedar triage and explicit private fixture execution. Its source still requires a
complete passing hosted qualification run before Milestone A is closed.
The [CI stabilization record](CI_STABILIZATION.md) distinguishes reproduced
failures, corrected fixture build settings and remaining hosted observations.
