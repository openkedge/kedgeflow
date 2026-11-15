# SQL pilot Milestone A implementation verification

Software source **4876d119c3f0d0de785b37d98d1a41c9b8db0eac** passes all
**11 required hosted jobs** in [run 43414116443](https://github.com/openkedge/kedgeflow/actions/runs/43414116443).
The authentic retained REST responses pass `verifyCI` with no missing job/step,
unexpected result, source mismatch or pagination gap. Hosted qualification includes
real managed Keycloak/SPIRE, five separate shipping systemd service identities
(admission, issuer, broker, gateway and SQL target), separate agent/database UIDs,
SDK recovery, cold/stale restore and the existing Kubernetes regression gate.

The separately built ARM64 release uses Rust 1.98.0, Ubuntu 24.04/systemd and
PostgreSQL 18.3. Its 397 compiled/package inputs match the source archive. The
exact bundle passes **79 installed Cura lifecycle/custody/sandbox observations**
and **10 live SQL case groups**, including guarded COMMIT and original-attempt
query. Cleanup reports are retained. The bundle SHA-256 is
`7486a94f1da208f3ae2b359a3577eebe93d352f825ede8dbd7c39d30729b3707`.
The bundle is retained locally outside Git; it is unsigned and not independently
reproduced. This record does not approve OS packages, licenses or security triage.

Local Python passes 152 tests and six subtests. The retained focused native logs
cover 34 control cases and 38 admission/supervision cases; these runs preceded
the final record and are supporting subsets, while exact-source hosted CI is
the complete release gate. Native observation tests preserve retained ledger
bytes and make no target/collector calls. Failure, stale clock, corrupt progress
and truncated-page handling cannot publish a healthy empty unknown queue.

An earlier local real-provider attempt failed during disposable `useradd` setup
with exit 16, before application execution. Standalone creation of that same
name passed; its transient cause remains unproven. The hosted exact-source full
managed workflow subsequently passed. Neither failed setup nor debug packaging
is presented as a passing release workflow.

**Milestone A — Reproducible Pilot Infrastructure: implementation verified.**
This means software, packaging, infrastructure, local isolation, recovery and
acceptance tooling are reviewable and reproducibly qualified for the selected
pilot. It is not an independent architecture/security approval or an enterprise
release. This documentation record does not change the qualified software revision.

**Milestone B — Enterprise Pilot Acceptance: BLOCKED_EXTERNAL_INPUT.**
Approved account/access/budget, actual isolated cloud resources, production
provider storage, independent identity/storage/audit custody, SRE ownership,
measured budgets, complete deployed writer/descendant probes and seven genuine
owner decisions remain absent. No AWS resources, acceptance signatures or owner
approvals were generated. `production_qualified` and `execution_authority` stay
false. Terraform, Kubernetes pilot and durable-capacity expansion remain deferred.
