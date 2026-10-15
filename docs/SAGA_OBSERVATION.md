# Durable query-first saga observation (M8d1)

[RFC 0043](rfcs/0043-durable-saga-observation.md) adds the non-authorizing
`KF-SAGA-OBSERVATION-0.1-draft` prerequisite. A protected DAG and stable operation
identities survive process restart. The observer reconciles original native
admission/grant/binding/attempt/receipt records into a durable bounded journal.
It records compensation intent while every inverse remains blocked.

Native dependency enforcement, fresh compensation admission and inverse execution
remain M8d2/M8d3. Existing executable grants still reject saga fields. This is a
query-only observer, not a forward runner or complete saga implementation.

## Approve and enroll the plan

Use a dedicated, newly enrolled [audited static hierarchy](HIERARCHICAL_HISTORY.md).
The protected plan contains a stable saga ID, exact reservation registration
digest, at most eight nodes, original admitted-operation keys, approved
subject/workload assignments, dependency edges and optional inverse intent.
Operation keys come from the verified signed proposal identity; never substitute
A2A/task/request IDs or create a new operation after an ambiguous reply.

The [public example](../config/saga-observation-plan.example.json) references the
[public hierarchy example](../config/hierarchical-history.example.json). Its
operation key, inverse action, semantic/applicability/barrier digests and all
example deployment/key/time pins are illustrative. Replace them with independently
approved material. An inverse intent pins its full proposed scope on the same
resource/incarnation and conflict domain, plus the intended semantics,
applicability, late-effect barrier and units within the fixed held compensation
allowance. A digest is a reference; it does not implement or prove that barrier.

Prepare a protected operator JSON file with:

- `plan`: the approved plan object;
- `trust`: the same complete public trust shape used by the
  [hierarchical history verifier](HIERARCHICAL_HISTORY.md), including independently
  approved namespace/registration, all subjects and historical policy/role pins;
- `etcd_endpoint`, `etcd_ca`, `etcd_certificate`, `etcd_private_key`,
  `etcd_token_file`: fixed HTTPS origin, pinned mTLS and protected credentials;
- optional `restore_gate`: the existing independently retained witness configuration.

No target URL/credential, signing key, admission client or mutation adapter is
loaded. Etcd ACLs must restrict this operator's writes to its observation records
and identity markers. Querying retained native authority needs appropriate reads.
Service file custody and a complete deployment/writer boundary remain unqualified.

```sh
kf-saga --config /etc/kedgeflow/saga.json --check
kf-saga --config /etc/kedgeflow/saga.json --enroll
kf-saga --config /etc/kedgeflow/saga.json --once
kf-saga --config /etc/kedgeflow/saga.json --status
kf-saga --config /etc/kedgeflow/saga.json --history
kf-saga --config /etc/kedgeflow/saga.json --request-compensation
```

`--check` validates local configuration/TLS material without contacting etcd.
Enrollment requires an active root containing only its original static skeleton;
previously issued children cannot be adopted. Admission preparation alone may
precede enrollment. Plan, genesis/head/state and permanent root/operation ownership
markers share one transaction. The markers also pin the complete approved
historical trust: policy, evidence/review/lease definitions, subjects/workload/scope,
all signer keys, source and observer identity. Changed trust cannot reuse even
status; key/policy rotation needs a separate migration design. Exact reenrollment
returns original state; changed
plans, new saga IDs on the same root or reused operations refuse.

The plan checks hypothetical whole-DAG capacity but reserves no new execution
capacity and cannot exclude other native callers from the root. Native leaf
issuance still holds both fixed allowances before claim. An unplanned leaf on this
dedicated root blocks reconciliation. M8d2 must add native plan/dependency gates.

## Reconcile original outcomes

Run `--once` after restart and after each existing recovery-worker poll. It queries
retained native records only. If target effects are uncertain, the separate
[`kf-recover`](RESERVED_HISTORY.md) worker performs its authenticated query-only
resolution. The observer itself never contacts the target.

- `planned`: no retained issuance observed. This supplies no permission to issue,
  mint, retry or dispatch.
- `issued`: original independently admitted grant and parent binding retained;
  no consumed attempt observed.
- `unknown`: original attempt consumed, with no verified known receipt/budget
  refinement. Unsigned gateway success stays unknown. Dispatched pending,
  not-found and no-effect wording also stay unknown.
- `committed` / `proven_no_effect`: the original signed native receipt chain and
  audited budget classification agree. Both allowances stay held.
- `failed`: a verified native failed receipt remains held and needs operator
  handling. Failure supplies no inverse authority.

Every observed grant/attempt is immutable. Terminal classifications cannot reverse;
a previously observed receipt must remain in the original predecessor chain.
Proof blobs retain original authorization, parent binding, claim/context and any
signed outcome chain. Reconciliation compares current native snapshot/history /
composites/bindings, exact issuance, attempt/outbox/context/receipt head and the
prior observation head/state. A raced receipt invalidates the transaction even
when the budget is still unknown. No local fallback or automatic mutation retry.

Snapshots always report `execution_authority: false` and
`dependency_order_enforced: false`. Current unmet dependencies are diagnostic.
An already-issued node observed before its predecessors commit retains a sticky
violation and requires operator attention. Native execution is not blocked by
this observation profile; observing later satisfaction cannot erase a recorded
violation or prove unobserved historical ordering.

`--request-compensation` records one-way operator intent, with no native authority
mutation. Unknown forward effects yield `blocked_forward_unknown`; no known
committed effect yields `blocked_not_committed`. A registered inverse after a known
commit yields `requires_fresh_admission_and_barrier`. This state is deliberately
nonexecutable. The observer does not verify inverse applicability, establish a
late-effect barrier, produce fresh admission or spend compensation capacity.

## Retention and remaining work

Plans/snapshots/proof blobs are bounded to 64 KiB, events to 128 KiB and the journal
to 128 events. Transactions deduplicate identical comparisons and refuse beyond
96 comparisons, 32 operations or 1 MiB. Combined bounds can refuse an otherwise
valid larger graph. Changed observations at exhaustion refuse; unchanged status
and reconciliation remain readable. No truncation, reset, refund or replacement.

Status validates the retained head/latest event and referenced proof blobs. Complete
history refuses missing older events/proofs and inconsistent identity transitions.
These records depend on ledger custody and have no new observer signature or
independent saga replay/consensus claim. Physical effects, runtime authentication
transcripts, key/control lifecycle and enterprise acceptance remain open.

[Required verification](../results/verification/rfc-m8-saga-observation-2026-10-14/README.md)
covers real-etcd restart/concurrency, partial/unknown/no-effect outcomes, blocked
inverse intent, dependency diagnostics, signed-input/identity validation, raced
receipt heads, missing/tampered/exhausted history and shipping mTLS CLI processes.

M8d2 next needs an explicit executable saga/compensation profile with native DAG
and fresh inverse admission/issuance/claim/dispatch comparisons. M8d3 must qualify
an actual inverse target, accepted applicability/late-effect barriers, partial or
failed compensation, process loss and complete independent saga evidence.
Unknown forward effects never trigger inverse execution. M8e governed drain and
M9 independent release acceptance remain open.
