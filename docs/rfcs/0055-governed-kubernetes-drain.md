# RFC 0055 — Governed Kubernetes drain and original physical outcomes

- Status: Draft; explicit bounded M8e1 native implementation; wider qualification remains open
- Milestone: M8e; follows bounded M8d3f native multi-contract saga
- Explicit profile: `KF-KUBE-DRAIN-0.1-draft`
- Named action: `kubernetes.node.drain`, version `1.0`
- Prerequisites: RFCs 0025, 0038–0039, 0044, 0052, 0054

## Separate authority and physical facts

The frozen whitepaper describes one Level A SQL reservation child and a distinct
Level C physical child. Kubernetes cordon and individual policy/v1 evictions are
separate requests. An eviction response, an original pod deletion timestamp, and
observed replacement availability are different facts. No ledger transaction
makes Kubernetes availability atomic. The software must not borrow SQL fencing
claims or interpret uncordon as workload restoration.

Keep the frozen KF-JSON-0.2 schema and fixtures unchanged. The new named CTD uses
`Level_C`, `guard_primitive: None`, `fence_parameter: null`, `guard_scope: []` and
`dispatch_bound`. Its native issuance fence remains an internal monotone ledger
identity only; it is not a Kubernetes fencing primitive. `expected_version`
identifies the protected controller contract generation, not Kubernetes opaque
resourceVersion, live capacity, or a physical SLO version. Exact proposal,
resource incarnation, descriptor/schema and policy digest pins select the profile.
Unselected mock/SQL/inverse mappings continue refusing this Level C action.

A protected deployment must explicitly configure the named native admission,
issuer, gateway/broker, target controller and separate physical observer. No
caller-supplied API endpoint, namespace, credential, node set or observation trust
may broaden those registrations. Each child still requires fresh independent
admission, its original grant/claim and one-shot broker credential exchange. The
physical child requires the actual signed SQL predecessor commit and all fresh
protected evidence. A task reference, reservation witness or root identifier is
not sufficient authority.

## Fixed protected scope

Pin TLS CA, API origin and realm identity (`kube-system` UID), exact target node
name/UID, fixed availability node UIDs, approved namespaces, workload
Deployment/ReplicaSet UIDs and deployment generation, required available replicas,
PDB UID/generation/minAvailable policy and bounded options. Pin allowed DaemonSet/mirror exclusions
explicitly. Reject arbitrary unmanaged, static or newly appeared workload pods.
Inventory at most 32 original nonexcluded pod UIDs. Workload replicas created by
the same approved ReplicaSet can satisfy observed availability; a rollout to a
new ReplicaSet or changed workload generation requires fresh protected enrollment.
Responses have byte/item bounds, no pagination ambiguity, no redirects or ambient
HTTP proxy, and fixed finite request deadlines. Do not follow kubeconfig exec
plugins or inherit an operator's default context.

The mutation service holds a limited private service account. The separate
observer holds read-only credentials. Agents hold neither. RBAC permits reading
fixed required nodes and realm identity, bounded cluster-wide pod metadata
inventory filtered to the target node, patching the named target node, and
creating pod eviction subresources in approved namespaces. Cluster-wide pod reads
are an explicit disclosure permission needed to detect unapproved namespaces on
the target; approved-namespace reads alone cannot prove a complete inventory. It does not grant
arbitrary node patches, direct pod delete, secrets, role changes, exec, bindings
or force deletion. Actual authorization tests must establish the effective
subresource/name restrictions rather than assuming them from YAML.

## Original operation and bounded deferred work

The controller independently verifies the original signed grant, exact parameters,
reference target token, native original issuance/claim and consumed dispatch.
Acceptance atomically creates a durable operation bound to grant/attempt,
controller contract, original node/pod identities, reservation predecessor and
protected derived deferred deadline. Duplicate acceptance is query-only. A
changed operation or grant never replaces a consumed attempt. Native grant
validity bounds first acceptance; the fixed maximum deferred duration bounds
subsequent steps. Neither window can be extended by polling, restart or token
refresh.

Before each mutation, compare the original operation revision, current protected
control/root/family generation, permanent global phase, native write epoch,
retained original dispatch and deferred deadline. Persist exactly one Pending
step in that same native CAS before sending a single API request. Capture fresh
original UID/resourceVersion preconditions for the specific request. Any root
stop, quiesce or competing write must defeat a paused final CAS. A request already
authorized before stop may still arrive later; stop does not claim cancellation.

Use a JSON Patch for cordon that tests exact node UID and resourceVersion and
writes unschedulable plus a unique original-operation annotation. Never claim an
unrelated preexisting cordon as ours. Evict only via policy/v1 with exact original
pod UID/resourceVersion delete preconditions and fixed grace-period policy.
A 429 means blocked (PDB or rate limit), not completion. There is no automatic
force/delete fallback or resubmission of an ambiguous Pending request.

After crash/restart, a Pending substep is query-only forever unless a positive
original response or explicitly qualified late-acceptance barrier resolves it.
Missing target state, a new pod with the same name, an unrelated cordon or elapsed
time alone cannot prove no physical effect. Recreated UID prevents a late old-UID
request from deleting the replacement; it does not prove whether the original
request caused the original pod's disappearance.

## Versioned physical evidence and saga integration

Do not alter frozen receipt statuses or relabel controller acceptance as completed
drain. Retain separate closed versioned physical evidence: protected contract
and original operation digest, complete ordered original Pending/results,
current closed gate, native phase/control comparisons, independent observer
identity/time and normalized node/pod/workload observations. The observer signs
an observation interval, not a claim of atomic cross-resource Kubernetes state.
Native accepted dispatch remains consumed; complete API evidence is required
before classifying the physical child.

Physical states include accepted, pending/unknown, blocked, partial, failed,
observed_completed, no_physical_dispatch and no_physical_effect. Completion
requires our original cordon annotation, exact target/node realm identities,
original pod UIDs absent, no unapproved new pods on the target, the pinned workload
and generation with enough observed available replicas, and required remaining
nodes Ready. A valid signed historical completion does not assert present SLO.
There is no supported physical inverse in this first profile.

Global saga snapshots must carry complete original physical evidence for every
selected Level C member. A native receipt for controller acceptance alone keeps
its effective forward state unknown. Only independently verified observed
physical completion can mark that irreversible member committed; it then blocks
SQL compensation. Unknown, pending, partial or failed physical work also keeps
reservation capacity held. A missing physical member cannot be omitted from a
completed aggregate.

NoPhysicalDispatch requires a signed closed-boundary proof atomically comparing
permanent quiesce/root closure and original operation absence. Any late acceptance
must compare that same marker/phase and fail. Accepted operations with no
authorized mutation can close their step gate atomically and produce
NoPhysicalEffect; call them accepted-with-no-effect, not not-accepted. Once a
mutation is Pending, current-state absence alone never qualifies no effect.
Any broader late-acceptance barrier needs its own explicit request semantics and
positive evidence. Only a positively verified closed physical no-effect boundary
may enable a fresh independently admitted SQL inverse. Unknown is never refunded.

## Required native qualification

Use an isolated real three-node cluster and real API requests, not a simulated
Kubernetes server as milestone closure. Bootstrap/cleanup admin credentials are
separate from the actual controller and observer identities. Qualify actual RBAC
refusals, realm/UID changes, PDB refusal, original UID preconditions, observed
workload availability, real API reply loss after effect, process SIGKILL with a
Pending request, query-only restart, permanent root/phase stop races, deadline
refusal and duplicate acceptance. Couple the drain to an actual committed SQL
reservation under fresh native family authority. Exercise unknown/partial states
and a positively closed pre-physical no-effect path permitting the original SQL
inverse. Retain public normalized API observations, exact target/process counts,
original IDs, native signed aggregate and separate shipping offline replay.

Same-host container nodes establish software mechanics only. Production workload
SLO, physical node failure, alternate maintenance writers, administrators,
autoscalers/schedulers, SA custody and independently administered acceptance stay
explicit deployment gates. Never mark M8 complete based on fixture pod readiness.

## Current implementation boundary

M8e1 implements the closed native controller/observer and bounded real
SQL-to-drain/PDB and accepted-with-no-effect SQL inverse cases. The complete
qualification matrix above remains required work. The [implementation boundary](../KUBERNETES_DRAIN.md)
names the remaining M8e2 process/failure and M8e3 deployed physical acceptance
milestones. A compiled shipping command is not a qualified deployed process.

## Primary references

- https://kubernetes.io/docs/concepts/scheduling-eviction/api-eviction/
- https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- https://raw.githubusercontent.com/kubernetes/apimachinery/v0.37.0/pkg/apis/meta/v1/types.go
  defines UID/resourceVersion delete preconditions; resourceVersion stays opaque.
- The exact policy/v1 eviction endpoint and deleteOptions behavior must be
  exercised against the pinned real API server, including recreated-UID refusal.

## Binding the protected controller contract without frozen-schema changes

Use an acyclic closed `Contract` for cluster/node/workload scope and bounded
options, with no descriptor digest inside it. The named parameter schema carries
its canonical contract digest in a fixed `$comment` string (JSON Schema annotation),
and constrains node and controller generation. The registered CTD signs that
entire schema and its digest; native action pins therefore bind the exact
controller contract. Target registration independently verifies the schema,
contract digest and descriptor/action pin. The annotation is never treated as a
remote URL or source of trust.

A named action-aware validator may accept only this exact Level C contract.
Legacy generic `validate_adapter_contract` remains Level A. Protected native
config must select the named action and explicit physical adapter; the default
HTTP mock and SQL adapters must independently refuse the named physical action.
Do not add unrelated nullable fields to legacy serialized trust records merely
to select this profile. Existing public trust/descriptor digests already provide
the protected opt-in when every relevant call site checks it.

If the frozen native receipt commits controller acceptance, its commit_point
must say so. That receipt is not observed physical completion. The family
aggregate must require the separate physical layer before effective forward
commit/no-effect classification, and the SDK's physical workflow must expose
accepted/native-committed separately from actual physical completion. A generic
MCP result or native committed status alone cannot complete the drain milestone.
