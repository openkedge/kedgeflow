# Governed Kubernetes drain — native, process and SDK boundaries

[RFC 0055](rfcs/0055-governed-kubernetes-drain.md) adds the explicit named
`KF-KUBE-DRAIN-0.1-draft` action to a fresh native family namespace. One actual
SQL reservation is its prerequisite. This is Level C: native ledger authority
does not make Kubernetes cordon, eviction or availability atomic.

The protected controller pins the API origin/CA, realm UID, target and remaining
node UIDs, Deployment/ReplicaSet identities and generation, PDB UID/generation,
minimum availability, exclusions, request count and deferred deadline. The signed
CTD's exact parameter schema binds the contract digest. `expected_version` is the
controller generation; it is neither Kubernetes resourceVersion nor an SLO.
Legacy mock and SQL mappings refuse this named Level C action. The frozen paper,
schema, fixtures and existing SQL migrations remain unchanged.

The original freshly admitted grant, claim, consumed broker permit and native
dispatch must all exist before durable acceptance. The idempotency key is the
protected transport `attempt_id`, independently bound by the reference token;
it is not an extra agent argument. Each cordon/eviction requires
another current control/family/phase/epoch CAS that persists its exact Pending
request first. JSON Patch tests the node UID and opaque resourceVersion; eviction
uses policy/v1 and the original pod UID/resourceVersion preconditions. A known
429 can be tried again under fresh current authority and the original fixed
bounds. Pending, transport ambiguity and other failures are never automatically
resent. There is no direct pod-delete or force fallback.

Native committed means **durable controller acceptance**. A separate observer,
with read-only Kubernetes credentials and its own signing key, supplies complete
original physical evidence. Acceptance alone leaves effective forward state
unknown. Observed completion requires our original cordon annotation, original
nonexcluded pods absent, the protected workload still available, and remaining
nodes Ready. A retained historical completion is not a present availability claim.

An irreversible observed drain blocks the SQL inverse. Unknown, blocked, failed
or partial physical work holds the reservation. A permanent quiesce/root closure
can close an accepted operation with zero Pending steps as `no_physical_effect`.
Only this positive closed boundary (or a qualified no-dispatch barrier) can permit
fresh independent SQL inverse admission. Costs stay held, including after the
actual restore. Uncordon is administrator fixture cleanup, never compensation.

## Implemented entry points

- `kf-kube-drain --material-root PATH --config FILE` supplies protected
  `check`, `state`, `serve`, `advance`, `close-unstarted` and `close-absent` commands.
  The mTLS accept endpoint checks the original one-shot reference token; a
  separate query endpoint only reports original controller acceptance.
- The explicit gateway adapter and selected family child independently pin the
  physical contract. The ordinary HTTP adapter refuses the named action.
- `kf-family-saga verify --bundle FILE --trust FILE` verifies serialized physical
  aggregates offline, including the original native authorization, complete
  control/budget/phase prefixes, controller journal and observer signatures.

The [M8e1 record](../results/verification/rfc-m8-governed-kubernetes-drain-2026-10-23-final/README.md)
qualifies the original native host paths. The
[M8e2a record](../results/verification/rfc-m8-kubernetes-process-boundaries-2026-10-23/README.md)
adds actual shipping controller processes, mTLS acceptance/query roles, CLI
closure and process/fault boundaries. Native grant/broker, SQL and owner orchestration
remain host fixture calls in that record. The
[SDK/query record](../results/verification/rfc-m8-kubernetes-sdk-2026-10-23/README.md)
adds actual official SDK/native gateway/broker execution and shipping recovery.
The [Agent Adapter guide](KUBERNETES_DRAIN_AGENT.md) specifies exact discovery,
client selection and acceptance-versus-physical status. Independent deployment
and the operating/current-reservation boundaries remain open.

## Required local qualification

Use only an explicitly owned disposable three-node kind cluster and private
kubeconfig. `scripts/kube-drain-fixture.py` creates fixed pause-pod fixtures and
separate least-privilege mutation/observation service accounts. The administrator
readiness gate models fixture availability, not application health or an SLO.
`scripts/kube-drain-owned.py` changes those gates and cleans only pinned owned
fixtures. Neither script belongs in an agent or controller deployment.

Set these explicit test inputs before `scripts/conformance.py`:

```text
KF_KUBE_FIXTURE=<fresh fixture directory>
KF_KUBE_TEST_KUBECTL=<absolute kubectl path>
KF_KUBE_TEST_KUBECONFIG=<private owned kubeconfig path>
KF_KUBE_TEST_CONTEXT=kind-kf8-<owned cluster>
KF_KUBE_TEST_PYTHON=<absolute Python path>
```

The runner requires actual service-account RBAC tests and a separate real
PostgreSQL/etcd/Kubernetes batch. Its exact Rust case manifest must match the
combined three batches once; missing cluster inputs fail. Within the Kubernetes
batch, `scripts/test-kube-drain.py` gives each Rust case a fresh owned namespace,
workload and service-account pair. It removes the bootstrap fixture only after
verifying its pinned realm/node/ownership. Every case repeats seven actual RBAC
checks. Its public index pins the exact case population and each contract,
fixture identity and RBAC result; conformance checks those hashes. Private
credentials stay in temporary files. Administrator fault injection and cleanup
remain separate from controller permissions. Public fixture
identities, the protected contract, RBAC outcomes, normalized signed controller
and observer evidence and complete aggregates are retained without SA tokens,
private keys or kubeconfig. Separate shipping offline CLI invocations replay both
completed and closed-no-effect aggregates.

The bounded native cases establish:

1. Missing initial observation or SQL predecessor commit refuses physical
   issuance. Actual SQL commits first; native acceptance remains unresolved.
2. Actual JSON Patch cordon and policy/v1 eviction succeed using the limited
   mutator. Real PDB 429 leaves both costs held and the physical child unknown;
   restored fixture availability allows another freshly authorized eviction.
3. Independent observed drain completion is committed in the aggregate and
   blocks SQL compensation. Re-signed aggregate omission/epoch substitution and
   altered controller evidence refuse verification.
4. Before any Pending mutation, quiesce defeats advance; positive closure proves
   accepted-with-no-effect. A fresh native SQL inverse restores version 243/free,
   reports compensated, and keeps the original 2 forward/1 compensation costs.
5. The observer cannot patch/evict. The mutator cannot patch another node, delete
   a pod directly or read secrets. Its allowed node patch is checked with dry run.

## M8e2a process and boundary qualification

The required real-cluster cases additionally establish:

- A protected shipping `kf-kube-drain serve` process accepts the original grant
  through mTLS. Gateway and outcome-query identities cannot exchange roles.
  SIGKILL after real etcd has durably stored Pending, before returning that CAS
  result, leaves the original operation unknown. A new process after root stop
  only queries that operation; Pending cannot authorize a replacement request.
- A selected pinned TLS fault relay forwards exactly one original cordon to
  the actual Kubernetes API. The API returns 200 and independent reads observe
  our cordon, but the relay withholds the response beyond the unchanged
  five-second client deadline. Transport ambiguity stays unknown. Root stop
  and process restart produce zero additional mutation requests and no SQL
  release. This relay changes transport, not the actual API or SA permissions.
- Permanent quiesce and root stop each defeat a paused final Pending CAS.
  Shipping CLI closure then proves accepted-with-no-effect, with zero Pending
  steps. A separate paused original acceptance loses to permanent quiesce plus
  `close-absent`; its real CAS fails and the positive no-dispatch barrier permits
  fresh original SQL inverse admission and actual version 243/free restoration.
- A separately enrolled one-millisecond deferred bound expires before the first
  mutation. Shipping `advance` refuses, retains the original state and holds all
  costs. The production bound, original grant and transport windows are unchanged.
- Actual policy/v1 eviction rejects stale resourceVersion and recreated pod UID
  with 409. The same-name replacement remains undeleted. These are target
  primitive probes using the limited mutator; administrator recreation is fault
  injection, not controller recovery or proof of the original operation's effect.

Each physical aggregate is also replayed by a separate shipping offline verifier.
Current-state absence, elapsed time and a committed acceptance receipt never
suffice for no-effect or completed-drain classification.

## Remaining M8e milestones

M8e2b now supplies the [named Node/native gateway/broker path and selected
shipping recovery](KUBERNETES_DRAIN_AGENT.md). Native commit is locally projected
as accepted/unresolved, and complete independent physical evidence remains
required. The two additional required SDK cases keep original identities and
costs across reply loss and process restart. Wider adversarial physical evidence,
physical HITL/static-lease combinations and historical-versus-current availability
cases remain open.

Before deployment qualification, an explicit protected Level C operating record
must bind accountable ownership/on-call, reconciliation deadlines and owned
incident escalation. Native committed acceptance must not conceal unresolved
physical work. The present predecessor check proves the original native SQL
commit and blocks the registered inverse during live/unknown physical work;
it does not prove a current exclusive SQL reservation against external writers
or restored storage. Protected current reservation/fence evidence and a declared
writer/storage boundary remain required work. These are whitepaper claim gaps,
not capabilities established by the local process tests.

M8e3 requires independently administered custody and writer coverage, production
workload/maintenance acceptance, physical node failure and accepted SLO evidence.
Container nodes sharing one local VM do not establish those claims. Independent
saga/authority peers, owner CLI deployment and other roadmap release gates also
remain open. **M8 is incomplete.**
