# Implementation priorities — 2 November 2026

Status: planning update, based on runtime `92169c5` and the supplied 2 November
cloud-operations brief. This updates the forward queue in the
[roadmap](IMPLEMENTATION_ROADMAP.md); historical milestone results remain scoped
to their recorded source. It introduces no executable profile or implementation
claim. Owners below name responsibilities; individual assignments remain open.

## Decision and scope

Make a Terraform-backed, independently verifiable infrastructure mutation the
next integration milestone. KedgeFlow supplies portable mutation admission and
execution enforcement above existing infrastructure workflows. Terraform retains
planning, its own policy checks, locking and apply semantics; identity providers,
Vault and operational platforms retain their existing responsibilities.

Keep the current Linux/systemd PostgreSQL pilot and its production gates. The
bounded M8 software catalog, real SQL/Kubernetes cases, Keycloak/SPIRE identity
work and installed Linux observations already exist. Extend those foundations
rather than reopening delivered software milestones. Production acceptance and
independent M9 interoperability remain open.

## Revised delivery order

| Order | Work and accountable roles | Deliverable and exit |
| --- | --- | --- |
| N1 — now | Deployment/security/SRE: finish the next Linux readiness, credential-renewal and custody increments; resource/test owners: add controlled state-change cases | Source-pinned deployed observations and the fault matrix below, extending existing SQL/managed-drain tests; no premature production sign-off |
| N2 — next integration | Resource/gateway/policy owners: qualify Terraform's admission insertion point and one narrow action | Versioned draft contract, trusted runner/adapter, real disposable target, independent outcome verifier and fault evidence; implement only the qualified scope |
| N3 — provider interoperability | Identity/security/broker owners: define external identity mapping and prototype Vault credential delivery | Verified subject/workload/delegation mapping, original-claim-bound credential issuance and substitution/refusal tests; IBM Verify integration requires actual provider access |
| N4 — operational-context experiment | Evidence/resource owners: consume a capacity recommendation | Availability, cost and placement obligations from independently sourced evidence; start with recorded inputs, then a live connector when qualified |
| Continuing release gates | Deployment/resource/SRE owners and independent implementer | Production storage/PKI/writers/recovery/SLO acceptance plus M9 independent peer, second binding and reproduced release evidence |

N2 interface research and disposable fixtures can proceed alongside N1; they do
not require production sign-off. Protected execution still requires the actual
runner/target boundary to pass its custody and bypass checks. N3 discovery can
also proceed independently; neither commercial-provider access nor preview MCP
features block N1/N2. No calendar estimate substitutes for an exit observation.

The first N1 increment is [controlled SQL target-change qualification](SQL_ENVIRONMENT_QUALIFICATION.md):
six fresh-authority/shipping-process cases, including an unchanged control,
version/incarnation/fence/active changes and lost guard-rejection delivery.
This is bounded software evidence; the broader N1 deployment and dependency
matrix remains open.

## N2: Terraform integration contract and demonstration

The first prerequisite is implemented as [N2a saved-plan inspection](TERRAFORM_PLAN.md)
under [RFC 0059](rfcs/0059-terraform-saved-plan.md). Its protected CLI derives JSON
from pinned binary-plan/tool snapshots and accepts only one annotation update;
it returns candidate evidence with execution disabled. The apply authority,
runner, live guards and outcome/recovery integration below remain N2b work.

First produce a short interface decision record covering CLI saved-plan apply,
HCP Terraform run/apply APIs, policy hooks and the Remote Terraform MCP surface.
For each, identify the exact enforceable apply gate, agent permissions, locking,
run/plan identity, cancellation and retained query semantics. Select the local
saved-plan path first unless investigation establishes a better non-bypassable
gate. Preview-only services remain optional. A policy hook or MCP wrapper alone
does not establish gateway-exclusive apply authority.

Start with one metadata-only ConfigMap update in a disposable Kubernetes
namespace, subject to provider qualification. This is a proposed low-risk target,
not an implemented adapter or an availability/capacity demonstration. If its
provider cannot meet the declared enforcement/recovery requirements, stop at
that gate and select another narrow action; do not substitute a no-op or shell
provisioner and call it a real protected infrastructure mutation.

1. **Freeze the executable inputs.** A protected planning service produces the
   saved binary plan and derives its JSON inspection from those exact bytes.
   Bind plan digest, inspection digest, Terraform/provider versions and binary
   checksums, dependency lock file, immutable configuration/modules, backend and
   workspace identity, state lineage/serial, target incarnation, allowed effects
   and dependency read set. Reject unknown values that affect authorization,
   unapproved providers, provisioners, external executable hooks and unbounded
   effects. Protect plan/state artifacts and inspection output as potentially
   secret material; publish only appropriately sanitized evidence.
2. **Admit an exact registered action.** Evaluate Terraform's applicable policy
   and KedgeFlow's authority, evidence, state and consequence obligations. Bind
   their versions/results to the existing proposal → certificate → grant chain.
   A plan digest supplements that chain; it does not replace exact parameters,
   state predicates, budget, audience, lifetime or completion mode. Specify any
   new bindings in a separately versioned draft and compatibility analysis;
   frozen v0.9 records and current accepted profiles remain unchanged.
3. **Claim before privilege.** The protected runner verifies the full binding,
   current managed control/identity and original claim, then obtains credentials
   through the existing broker authorization boundary. Recheck expiry, policy,
   revocation and ownership at required dispatch points. A materially changed
   plan, dependency or authorization requires fresh admission where permitted;
   an unknown original effect first requires authoritative resolution/barriers.
4. **Apply only the saved plan.** A fixed runner invokes Terraform without an
   agent-controlled shell, mutable executable search path or credential fallback.
   It verifies immutable artifacts immediately before use and preserves native
   backend locking. No `-lock=false`, unattended force-unlock, automatic replan
   or retry by invoking apply again. Lock timeout or stale state is a recorded
   refusal. Replanning creates a new proposal subject to the original authority
   and unresolved-attempt constraints.
5. **Qualify target semantics.** Record Level A/B/C per action and predicate.
   Terraform state locking coordinates supported backend users, not arbitrary
   direct target writers. Pre-apply freshness checks alone leave a commit race.
   Claim Level A only for demonstrated target-atomic predicates or equivalent
   coordination covering all relevant writers and dependency state. Otherwise
   use an explicitly implemented weaker profile with disclosed limits, or refuse
   actions that require stronger invariants. The existing SQL Level A evidence
   does not transfer to Terraform or Kubernetes. A policy revoke after dispatch
   is subject to the declared dispatch/commit boundary, not assumed retroactive.
6. **Verify the effect independently.** Retain original operation/run/provider
   correlation, claim, broker permit, dispatch and Terraform status. A separate
   read-only observer queries target UID/version/fields and relevant dependencies;
   it checks permitted changes and postconditions against archived evidence.
   Terraform exit success, its state file or an agent narrative is insufficient
   by itself. Maintain original-attempt query after expiry/revocation/restart.
7. **Exercise failure.** Add a separately admitted, bounded two-resource fixture
   for partial apply: one effect completes before the other fails. Keep per-effect
   outcomes and partial/unknown aggregate status. Lost apply responses and runner
   death never authorize another apply. Absence of a result is not no-effect
   proof. Any compensation needs its own applicability/barrier evidence, fresh
   admission and reserved authority; it is not an automatic Terraform rollback.

N2 exits with a replayable normal real-target mutation, all applicable fault
cases, a writer/credential coverage inventory, and a capability/limitation
record. Broad resource permissions in a stock provider are not an exact-action
token: keep them in the trusted runner and prove the agent cannot invoke it with
arbitrary inputs. Trusted provider code is a declared compromise assumption;
signing a plan does not make a compromised provider safe. Reuse the existing
control, broker, outcome and verifier foundations; add the resource-specific
runner and adapter rather than a second orchestration/control plane.

## N1/N2 fault matrix and independent evidence

Inspired by [EnvOS](https://arxiv.org/abs/2610.40246), certify each injected change
actually happened at the intended execution boundary and that the oracle can
distinguish valid, invalid and unresolved outcomes. Its computer-use experiments
motivate this method; they establish no KedgeFlow or infrastructure result.

| Injection | Required observation |
| --- | --- |
| Target changes after admission and after the final external read | Target guard refuses stale effect, or the weaker profile's limitation is explicit; a required invariant without sufficient enforcement prevents enabling that action |
| Dependency changes while target version stays constant | Dependency-specific guard/reservation blocks invalid commit, or action is refused for insufficient coverage; a target version alone is insufficient |
| Policy/delegation/key/ownership changes after issuance | Refusal at the profile's required check points, with ordering relative to dispatch/commit retained; already dispatched effects are reconciled |
| Agent/runner suspends, then resumes past evidence/token/grant lifetime | New initiation refuses expired authority; original-attempt query remains available under current query authorization |
| Successful result is lost; client retries or gateway/runner restarts | Original operation/run/attempt is recovered; no extra issuance, permit, mutation dispatch or committed effect |
| Terraform state lock contention or stale saved-plan state | Native refusal retained; no disabled locking, forced unlock or implicit replan |
| First resource commits and later apply fails | Partial effect set verified from target evidence; unresolved effects and held authority persist; no blind reapply/inverse |
| Tool/plugin is compromised | Direct API/SQL/CLI calls, credential/metadata/socket access and gateway/config/provider substitution are denied from agent and descendants |
| Valid credential or plan is substituted into another operation | Exact target/action/plan/attempt binding rejects substitution, including after broker mint but before dispatch |

Extend existing SQL/control/managed-drain cases and label reused versus newly
executed evidence. Use deterministic pause/release boundaries and target-side
records rather than timing sleeps or agent self-reports. Retain source/tool pins,
injection evidence, policy/dependency snapshots, target observations and verifier
outputs. Independent replay code and a separate observer are useful software
evidence; independent administration and another implementer's reproduction
remain separate deployment/M9 gates.

Report attempted, admitted, claimed, dispatched, committed, refused, partial and
unresolved populations with explicit denominators. The primary failure count is
unauthorized or invariant-violating **committed effects**, including duplicates,
not agent recognition of stale state. Include oracle uncertainty and missing
evidence; unknown cannot count as safe or successful. Require zero violations
in the exercised in-scope corpus without claiming a universal production rate.
Report admission/claim/exchange/apply/verification latency and unresolved age
separately, against workload-specific budgets.

## N3: external identity and Vault

Keep Keycloak/SPIRE as the working pilot. Map an external provider's verified
human subject, workload, delegation chain, issuer/audience, proof binding,
expiry and withdrawal semantics into existing admission and broker verification.
Never accept an unverified delegation-reference string as evidence. Add
provider-specific claim mapping and trust-refresh configuration; any wire change
requires a separate draft profile. IBM Verify is a potential provider, not an
assumed compatible implementation.

Prototype Vault behind the broker only after the original durable claim/permit.
The gateway/runner owns target credentials and lease correlation. Test mint
failure, lost mint reply, expiry, revocation races and operation substitution;
retain consumed authority when mint outcome is ambiguous. TTL/resource scope
alone does not bind a credential to one mutation. Either the target enforces the
exact operation, or an independently protected, non-bypassable runner does so.
Document residual use of any already-issued credential after withdrawal; Vault
lease revocation is not proof that no effect occurred. Do not claim native
operation-bound IBM/Vault support until it is tested against the actual service.

## N4 and deferred scope

Treat Concert/other optimizers as recommendation and evidence sources. Register
one proposed optimization with separate availability, cost and placement
obligations, provenance/freshness and relevant dependency/writer coverage. Use a
recorded recommendation first; qualify a live connector when available. Planned
MCP/Terraform integrations do not become release dependencies. OpenTelemetry can
carry correlation, but traces alone establish neither authorization nor outcome.

Deprioritize a general dashboard, new sandbox product, generic credential broker
and extra prompt filters. Existing broker/custody/isolation and necessary
operational readiness/metrics work continue. Compromised coding extensions,
agent helpers and stolen agent-accessible credentials are explicit adversaries;
production issuer, runner/provider and independent observer compromise remain
declared trust limits, not mitigations supplied by prompting.

## Source and availability checks — 2 November 2026

- [IBM Terraform announcement](https://www.ibm.com/new/announcements/terraform-advances-infrastructure-lifecycle-management-for-the-agentic-era), published 26 October: policy GA; Developer Portal and Remote MCP public preview; Z/LinuxONE workflows private preview; Infragraph integration described. Use actual callable contracts, not announcement diagrams, for the insertion decision.
- [IBM Agent Identity announcement](https://www.ibm.com/new/announcements/ibm-agent-identity-is-now-generally-available-building-trust-for-the-agentic-era), published 26 October: identity GA and Verify/Vault delegation/JIT credential architecture. Exact-operation token enforcement is not established by this announcement; the brief's specific Vault/OpenShell version claims are not prerequisites here.
- [IBM Concert announcement](https://www.ibm.com/new/announcements/ibm-concert-platform-advances-the-path-to-cross-domain-agentic-it-operations): Q4 MCP and Terraform configuration features are planned, with timing subject to change.
- [EnvOS abstract/version](https://arxiv.org/abs/2610.40246v1), submitted 29 October: controlled environment changes and archived-evidence outcome rechecking; computer-use scope differs from this infrastructure corpus.
- [Microsoft investigation](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/), 30 October: malicious Cursor-marketplace package attempted host/SSH persistence; host privileges affected success. It motivates the compromised-tool cases, not a claim that all installations lost cloud secrets.
- HashiCorp CLI semantics: [saved-plan apply](https://developer.hashicorp.com/terraform/cli/commands/apply), [backend locking](https://developer.hashicorp.com/terraform/language/state/locking), [plan artifacts](https://developer.hashicorp.com/terraform/cli/commands/plan) and [JSON inspection](https://developer.hashicorp.com/terraform/cli/commands/show). These support the artifact/locking/confidentiality requirements, not a target-atomic guarantee.
