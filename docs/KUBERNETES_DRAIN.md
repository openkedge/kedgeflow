# Governed Kubernetes drain — bounded M8e1

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

These entry points compile as shipping software. The qualification below uses
co-located Rust native/controller tasks and host owner/forward/inverse calls;
it does not qualify shipping controller CLI deployment or an SDK drain workflow.
The [required frozen-source record](../results/verification/rfc-m8-governed-kubernetes-drain-2026-10-23-final/README.md)
pins the accepted implementation, complete case population and public evidence.

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
combined three batches once; missing cluster inputs fail. Public fixture
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

## Remaining M8e milestones

M8e2 must qualify the shipping protected controller process and gateway/SDK path,
actual API effect followed by reply loss, SIGKILL after durable Pending,
query-only restart, positive absent-operation closure versus late acceptance,
paused final-CAS stop races, deferred expiry, and actual recreated-UID refusal.
These remain unqualified even though the draft controller contains fail-closed
paths for them. Wider adversarial physical evidence and historical-versus-current
availability cases also remain open.

M8e3 requires independently administered custody and writer coverage, production
workload/maintenance acceptance, physical node failure and accepted SLO evidence.
Container nodes sharing one local VM do not establish those claims. Independent
saga/authority peers, owner CLI deployment and other roadmap release gates also
remain open. **M8 is incomplete.**
