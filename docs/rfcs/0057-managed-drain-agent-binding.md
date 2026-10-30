# RFC 0057 — Named managed drain gateway and agent binding

- Status: Draft; acceptance verifier, separate adapter/configuration, discovery and
  SDK/family-runner binding implemented in development; fresh isolated native-service
  workflows and shipping gateway/controller/source/supervisor/recovery pass;
  isolated protected control/broker/gateway service binaries exercised;
  required complete O4 qualification recorded in the M8 completion checklist;
  independent protocol/deployment acceptance remains open
- Milestone: RFC 0056 O4 / M8e2b bounded software exit
- Depends on: RFC 0055 mechanical drain, RFC 0056 managed operating/source records

Current software exit and independent acceptance are tracked in the
[M8 completion checklist](../M8_ACCEPTANCE.md). Its frozen qualification record
supersedes the incremental software-status notes below; draft protocol and
independent deployment acceptance are not inferred from local test results.

## Purpose and boundary

Bind `kubernetes.node.drain.managed` version `1.1` explicitly to the protected
`KF-MANAGED-KUBE-DRAIN-0.2-draft` enrollment. The gateway must independently verify
complete acceptance sources before recording a successful controller reply. A
signed controller response alone is not complete source evidence. Native commit
continues to mean durable controller acceptance; physical completion requires the
separate complete operating/physical audit.

The legacy action, adapter, discovery, configuration and SDK registration keep
their original semantics. Managed discovery must remain refused until the named
adapter and independent source integration are selected and validated together.
Neither Level C nor a nullable legacy switch selects this action.

## Protected selection

The separate `managed_drain_adapter` configuration pins the complete
family/child selection, managed profile, gateway workload, broker token issuer
and broker verification keys. The selection supplies the physical contract,
enrollment, target audience/scope, action/schema and source/owner trust. The
runtime's family, reservation, gateway audience, target URL/scope and single
registered managed tool must match that selection exactly. The broker actor
assertion must identify the selected native admission trust's original proposal
workload. The gateway authenticates separately using its own outgoing workload
certificate. Conflating those identities would make the shipping broker client
refuse the original agent's exchange. The managed adapter cannot
coexist with a legacy drain, generic SQL or inverse adapter selection.

The gateway uses its independently configured native ledger transport and its own
workload credentials. It does not obtain the controller47, physical49,
operating91, SQL provider94 or storage-owner95 private keys. Incoming/outgoing
workload and source/signing-key roles remain distinct. Agent arguments cannot
choose a source, enrollment, native namespace, target or proof trust root.

## Versioned acceptance-source record

The new closed wrapper is `KF-MANAGED-DRAIN-ACCEPTANCE-0.1-draft`. It does not
change existing version-0.2 controller/source statements or version-0.1 mechanical
signatures. Its required fields are:

| Field | Meaning |
| --- | --- |
| `profile` | Exact wrapper profile above |
| `enrollment_digest` | Independently protected managed enrollment digest |
| `authorization` | Complete original native admission/issuance packet and any explicitly selected lease authority |
| `acceptance` | Existing managed response: original origin, event prefix, initial signed mechanical state and signed Accepted control proof |
| `sources` | Complete original acceptance prefix: origin/events, control proof, native source claims, preflight claim chain and signed exact-proposal SQL admission evidence |

The wrapper has a two-MiB encoded bound. Embedded source-prefix bounds remain
unchanged: event/claim/control limits and the existing 512-KiB source-proof bound.
It ends exactly at `ControllerAccepted`, before Pending/send, closure, physical
observation or incident resolution. A later independently read snapshot may
supply this historical prefix, but later events/claims must not be presented as
part of the acceptance prefix or omitted while claiming a complete current view.

The verifier must:

1. Use independently selected protected context and native role-scoped keys.
2. Replay original admission/issuance signatures, inputs, Cedar decision,
   original proposal/grant/operation and explicit lease authority.
3. Match the exact source admission evidence against the actual authorization
   packet; validate its proposal, preflight chain, original SQL grant/attempt,
   provider/storage signatures and declared storage boundary at historical times.
4. Replay every acceptance-prefix transition and referenced control/source claim.
   Verify source-claim slot/context/correlation, query budget and original bounds.
5. Verify the original controller signature and reconstruct the mechanical
   acceptance state. Require exact origin/grant/attempt/enrollment, Accepted proof
   and event head, with no Pending/send/closed state or substituted proof body.
6. Refuse missing/extra/reordered sources, wrong profile/roles/trust, null/unknown
   fields, malformed signatures and excessive input size.

The serialized wrapper alone verifies signatures and historical correlation. It
is not an etcd consensus proof, a physical observation, current authority or
proof that the caller read native storage. Its report must state
`native_history_verified: false`, `execution_authority: false`,
`physical_status: unresolved` and the explicit acceptance-prefix scope.

## Gateway integration

After the original target reply, the adapter independently reads bounded actual
native source bodies and original authorization under the protected selected
ledger. It verifies the record above and compares the exact retained native
origin/head/control/claim/admission values before retaining success. Repeated
proof work may reuse only immutable complete-input validation; live reads,
comparisons, clocks and current authority must not be cached.

A native read/head change or unavailable proof after the target reply is
ambiguous. It cannot trigger another target request, claim, token mint, grant or
inverse. Bounded retries may repeat only read-only original status/proof work.
After one known guarded-read/head race, the adapter may recapture once within
the original grant deadline. Its final native comparison remains after proof
verification. Reuse is limited to successful immutable historical replay keyed by
the entire canonical proof and all protected selection, physical and enrollment
pins, in an eight-entry cache under the existing byte budget. Fresh native values
and comparisons are never reused. Missing/changed bodies or pins force replay;
standalone acceptance verification always independently replays. Query-only
recovery retains the original attempt and acceptance semantics.

Each native guarded range transaction may capture fresh guards at most three
times within one five-second budget when a comparison refuses the snapshot.
Multi-batch proof reads retain the existing outer capture deadline. This does
not consume another source query or repeat a mutation. Malformed responses and
transport errors refuse immediately; retry exhaustion remains unavailable. Every
authority-changing caller must still compare its complete returned source bytes
in the final native transaction.

The result preserves the mechanical state in `kedgeflow_drain_acceptance` for the
existing physical collector, and carries the new wrapper separately in
`kedgeflow_managed_drain_acceptance`. Its commit point is
`controller_acceptance` and physical status is `unresolved`. Independent complete
operating/physical replay remains required to resolve the episode.

## Discovery and official agents

Managed MCP discovery must publish only the protected named action/version,
complete generated enrollment schema, contract/enrollment/policy/context binding
and explicit managed extension. Unknown/missing metadata or a legacy descriptor,
schema, adapter or SDK registration must refuse. Existing generic Level C tools
must not inherit the managed binding.

The official MCP/A2A client path must use a separate explicit managed
registration and validate exact descriptor/schema/arguments/grant/result
correlation. Its native `committed` view maps to `accepted` with unresolved
physical state. A completed A2A coordination task conveys no execution or
physical-completion authority. Resume/status cannot remint, redispatch, refund or
compensate unknown work.

## Implementation milestones and exit evidence

| Increment | Deliverable | Required evidence |
| --- | --- | --- |
| A | Closed acceptance wrapper, complete historical prefix verifier and independently reading adapter | Prior actual source vectors; missing/extra/reordered/forged source and wrong-context refusals; old complete managed audit still verifies |
| B | Explicit protected runtime selection and managed discovery/official SDK | No legacy fallback; exact schema/metadata/role/endpoint binding; named managed action and accepted/unresolved semantics |
| C | Combined shipping agent/admission/issuer/broker/gateway/controller/source/supervisor | Actual SQL/etcd/Kubernetes, original reply loss/SIGKILL/query-only restart, no extra claim/exchange/dispatch, complete independent physical/operating audit |
| D | Frozen-source qualification and state documentation | Full existing corpus plus new cases and standalone replay; unchanged historical results, paper/schema/fixtures and migrations |

Original five-second grant/source/transport, ten-second ACK, sixty-second family,
thirty-second inverse and one-second maximum managed send bounds remain fixed.
Neither a new profile nor a faster fixture can silently enlarge them. Wider
concurrent/paused-send/stop/deadline and native admission/material exhaustion are
still RFC 0056 requirements. Durable head/floor publication, declared writer/
restore coverage, independent custody, production maintenance, physical failures,
accepted SLOs and independent whole-saga/authority-peer acceptance remain open.
This draft and its development vectors do not close M8 or the current phase.

## Development validation and next gate

The implementation includes historical replay of a previously qualified actual
SQL/etcd/Kubernetes acceptance prefix, standalone binary refusals for missing or
altered sources, protected configuration and discovery vectors, and separate
Node managed registration, metadata, grant/result and original-status vectors.
The family runner compares the complete selected family/child registration.
Fresh isolated development runs also cover actual native services and shipping
managed controller/source/supervisor/recovery binaries with the official SDK.
They do not establish whole-saga deployment qualification.

The gateway's final native comparison includes the retained admission packet,
certificate/issuance records, selected lease bindings (or their absence), complete
preflight head/events, original origin/head, controls, claims and admission source.
No successful current read comparison is cached.

Increment C has fresh actual SQL/native/Kubernetes completion and original-reply
loss/restart cases, complete sources and independent operating/physical replay.
Additional cases now start actual protected control, broker and gateway binaries
with separate role credentials. They cover healthy completion and one real
controller HTTP acceptance reply lost before gateway verification, stopped-root
SIGKILL/restart and query-only original recovery. The lost-HTTP case reconstructs
the historical proof from the independently verified complete native aggregate;
it cannot claim that the original SDK received a full proof. Increment D freezes
the exact source and qualifies the whole existing and new corpus.

## Complete-source native reference carriage

The first combined live prototype produced a 556,129-byte aggregate, exceeding
its unchanged 524,288-byte limit. The full SDK acceptance record duplicated
original authorization and acceptance-prefix source bodies already carried in
the independent member capture. Increasing the bound or omitting those sources
would invalidate the qualification.

The explicit `KF-MANAGED-DRAIN-ACCEPTANCE-REFERENCE-0.1-draft` native outcome record
has exactly `profile`, `kind: managed_drain_acceptance`, `enrollment_digest` and
`proof_digest`. The digest domain is `managed-drain-complete-acceptance-proof` and
covers the entire canonical full acceptance wrapper. The MCP reply still carries
the complete wrapper. The native receipt binds this reference as outcome evidence.

Independent member verification must reconstruct the exact full wrapper from
co-carried original admission/issuance, the complete original source history and
claims/preflight/admission, the original Accepted control proof, and the original
mechanical accepted body and signed header. It then replays all signatures and
transitions and compares the full proof digest. Missing source bodies, a changed
authorization/control/claim, wrong enrollment/digest/profile, unknown fields,
missing dispatch or a reference on a legacy/non-managed member must refuse.
The reference alone proves nothing. This is structural sharing of complete
source bodies; it does not make a current-state, physical or consensus assertion.
The original whole-snapshot, source-prefix, event, material and time bounds remain
unchanged. Fresh isolated combined workflow checks pass; the qualification record
defines the exact frozen corpus. All-service configuration deployment remains open.

## Fresh local workflow evidence

Development runs now exercise official MCP client/AgentAdapter/FamilySagaRunner,
actual native admission/issuer/broker/gateway services, and shipping managed
controller, SQL source, supervisor and recovery binaries against real SQL, etcd
and Kubernetes. A completed case retains one broker mint/dispatch, four SQL read
claims, five controller proofs and two successful physical requests. The separate
loss case proves exactly one fully verified original adapter reply is discarded,
then stops the root, restarts the controller, recovers the original acceptance
with `kf-recover`, and resumes the SDK through query-only status. It retains zero
physical Pending/sends and the original grant/attempt. Both preserve held costs
of two forward and one compensation unit, and both complete independent source
and operating/physical replay. The healthy aggregate is approximately 278 KiB;
the original 512-KiB limit is unchanged.

The official SDK first-response assertion exposed missing MCP `content` arrays
in native structured adapters. Those responses now include the required array;
status fallback cannot qualify a first-response proof. Independent native reads
in the controller run concurrently but retain every exact final CAS comparison;
the checked dispatch journal is reused only within its original snapshot. The
protected-clock control check remains last. A bounded cache retains only pinned
Cedar parsing/strict-validation artifacts; every decision still evaluates fresh
context and time. No grant/source/token/ACK/deadline/send bound is extended.

The supervisor waits for the original recorded in-flight source-slot expiry
before a fresh observation; it cannot steal, refund or replay that slot. All
complete source bodies remain necessary for the reference reconstruction.

An additional case runs the actual protected `kf-proxy` configuration and binary,
with separate gateway transport credentials and per-endpoint SDK CA pins. Its
bounded five-second startup hook verifies the installed complete family history
before listening. The separate managed controller performs the same read-only
preparation before its listener starts. Actual control and broker service binaries
also prepare selected complete family history under the same five-second bound;
closed/stopped history can still support
query-only startup. Immutable history replay may be reused only under all original
pins and source bytes; every execution rereads and checks current native values.
Check-only configuration performs no remote preparation. Startup is not authority.

Guarded read epoch races during query-only recovery may trigger at most three
sweeps within one fifteen-second bound; all attempts and diagnostics are retained.
Other errors refuse. This does not repeat a physical request or mint authority.

The original typed native-service cases remain as regressions. Additional cases
use actual protected control/broker binaries, exact per-endpoint SDK CA pins and
the identical original native credential permit before/after recovery. Actual
broker diagnostics count decoded requests and issued responses; the unused typed
minter is zero and cannot establish a binary mint invocation count. These are
generated co-located identities. Independent custody, production writers/restore/
SLOs and authority peers remain external gates. Full source-frozen conformance
and the wider RFC 0056 native race/exhaustion matrix remain required.

The unchanged four pre-admission SQL claims now have a shipping-source/native
boundary case: SIGKILL after actual claim commit, replay refusal while the
original remains live, one winner among last-slot competitors, unchanged cached
successful reply, and refusal of a fifth claim. It retains every claim and
successful signed statement and proves no drain origin/grant was issued. It does
not substitute for the wider material and physical-send race matrix.
