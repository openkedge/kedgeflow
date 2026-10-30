# Managed Kubernetes drain — implementation and current SQL source

[RFC 0056](rfcs/0056-physical-operating-records.md) and the separate
[RFC 0057 gateway/SDK binding](rfcs/0057-managed-drain-agent-binding.md) implement
protected controller/current-SQL/supervisor/recovery processes, named admission,
broker and gateway services, official SDK composition and complete offline audit.
The [M8 completion checklist](M8_ACCEPTANCE.md) defines the bounded software exit
and the independent deployment gates. Its linked frozen record determines which
checks passed. Existing RFC 0055 records retain their original mechanical semantics.
Local software qualification does not complete independent M8 release acceptance.

## Explicit contract

The new named action is `kubernetes.node.drain.managed`, version `1.1`, profile
`KF-MANAGED-KUBE-DRAIN-0.2-draft`. Its parameter schema binds both the full managed
enrollment digest and original mechanical contract digest in its exact `$comment`.
Its adapter commit point names the managed profile. It cannot use the original
action's descriptor, adapter or schema.

The closed enrollment pins the family namespace, selected child and operation,
original mechanical contract, operating policy, target URL/scope, three separate
controller/supervisor/evidence-assembler workload identities, operating observer,
current SQL registration, clock uncertainty and authorization-to-send bound.
Explicit null cannot normalize into absent legacy `operating` trust. Managed trust
requires its named current SQL admission obligation and separated signer roles.
The current SQL provider may discharge that evidence obligation; it is not
repurposed as a physical, operating or native authority signer.

The proposed current SQL registration pins the original forward SQL child,
operation/reservation root/resource incarnation, compensation contract, fixed query and
evidence endpoints, provider, storage owner/generation, restore protocol digest,
declared coordinated/external writers, maximum age and request timeout. The
witness types check exact original grant/attempt, parameter digest, fence,
post-version and signed storage head. A signed historical forward outcome alone
cannot serve as this witness. The reservation root identifies allocation, while the original signed grant
supplies its distinct execution root. Both appear in version-2 evidence. The
provider checks actual SQL; storage-head publication and writer/restore custody
remain protected external responsibilities.

## Native and controller source paths

The native dispatch path prepares the original managed anchor and initial event
in the same transaction as `dispatch_authorized`. The deadline derives from that
native dispatch time, including when acceptance has no reply. Predecessor records
are read and compared in the SQL child's paired forward ledger scope.

The new native store replays retained origin, ordered hash-linked events, exact
head and all referenced material before preparing an expected-head CAS. Query
reservation is durable before a controller inventory/current-SQL cycle. Accept,
advance and supervisor observation share the finite budget; a lost slot stays
consumed and can be marked interrupted only after its expiry. Pre-acceptance
supervisor observation waits until the original grant expires so it cannot steal
the five-second acceptance opportunity. Query slots also end at the applicable
grant/deadline/final-observation boundary. The event/source limits are 640 events,
512 retained material records and 32 MiB per native source range.

`Controller::new_managed` requires a separately supplied current SQL querier.
The legacy constructor refuses managed trust. The managed source path retains:

1. Current SQL witness and signed operating proof in the mechanical acceptance CAS.
2. A fresh witness and operating proof in every newly authorized mechanical
   Pending CAS, alongside existing root/control/family checks.
3. A second native authority/stop CAS before the original API send, followed by
   protected-clock, policy, SQL/storage-head freshness and send-interval checks.

Each native authority check reads a fresh reservation gate. Its checked history
head and last event already bind the current reservation state and are compared
as exact native bytes in the final CAS. The controller uses that checked head
digest directly instead of rereading the complete prefix just to recover the
same digest. Complete prefix export and independent replay are unchanged; no
successful live authority or clock decision is cached across calls. Independent
reservation marker/state/domain/plan values and controller marker/state values
are read together through guarded native transactions, with their original byte
bounds and exact final comparisons. Grouping reads does not renew authority.

The controller never resends a retained Pending request. Losing the final send
check keeps the original Pending unknown; it cannot imply no effect. Closed
unstarted/absent mechanical proofs share their CAS with the operating closure.
Complete signed original physical aggregates remain necessary to classify the
operating outcome. Native committed acceptance cannot resolve it.

The shipping controller loop has a separate managed deadline task so inventory
or mutation I/O cannot hold that task. `kf-managed-kube-drain` selects the explicit
managed loader. `kf-kube-drain` retains its legacy loader and refuses managed
enrollment. The separate RFC 0057 managed gateway/SDK binding still requires
fresh all-shipping workflow qualification.

## Protected managed controller process

`kf-managed-kube-drain --material-root ROOT --config FILE` provides `check`,
`state`, `advance`, `close-unstarted`, `close-absent` and `serve`. `serve` reuses
fixed mTLS acceptance/query endpoints and the independent deadline/mutation loops.
`check` reads and validates configuration/material without dispatching. A native
query reports original controller acceptance; its `committed` status is not a
physical completion statement.

The closed top-level configuration requires exactly three fields:

| Field | Protected value |
| --- | --- |
| `profile` | `KF-MANAGED-KUBE-DRAIN-0.2-draft` |
| `controller` | The closed controller object defined by `kube_drain_config::Config`, with a complete managed family registration, selected child, API/native/restore/server files, controller signer, broker keys and fixed incoming roles/endpoints |
| `current_sql` | Exactly `ca_file`, `certificate_file`, `private_key_file`, `token_file`; each is a file path inside `controller.material_root` |

The current SQL URL is selected exclusively by the enrollment; no second URL or
caller-selected source endpoint is accepted. The selected managed child, complete
schema/action, target audience/scope and separate controller/supervisor/evidence
roles are validated together. Both outgoing native and source certificates must
name the enrolled controller workload. Restore credentials also use the protected
root and controller workload. Broker verification keys cannot double as physical,
operating, sink, source or storage-owner keys. Source and incoming outcome-query
credentials are distinct. The loader requires the controller signing key and query
credentials; it requires no source, storage-owner or operating signing key.

All API/native/source/restore/server material is loaded under one protected root.
Null/unknown fields, legacy/prototype enrollment, substituted roles/endpoints,
root escape and widened secret permissions refuse. Local file/SAN checks are
configuration sanity checks; remote authentication and deployed custody/RBAC still
require their own enforcement. The original grant, source and transport windows,
query budgets, deadline and maximum one-second authorization-to-send bound are
unchanged. Losing a mutation authorization comparison leaves Pending unknown.

`close-absent --signed-grant FILE --attempt ORIGINAL` reads the public original
grant under the same protected root. Both closure commands require the actual
permanently closed family/phase boundary. Closing accepted work additionally
requires that no Pending mutation was ever authorized. Signed closure shares the
native operating CAS and must be carried by a complete independent physical audit.
Neither absence of a reply nor expiry alone is a closure proof.

## Stop and incident source paths

At or after the original deadline, the native state machine requires permanent
stop and one owned incident outbox before another transition. This does not
require source availability or successful sink delivery. Query-only observation
has its own finite count and final deadline.

The delivery worker reserves an attempt before sink I/O, sends to a fixed HTTPS
endpoint through a protected mTLS client, and bounds the response and request
lifetime. The report body derives from the original outbox, so lost replies and
restart retain its incident/event identity. Sink acknowledgement is independently
signed and matched to the exact outbox; it changes delivery state only. It
cannot resolve physical unknown, refund allocation, reopen mutation or authorize
SQL inverse. The protected shipping supervisor has separate timer, observation and delivery
loops. Its incident protocol is exercised with an acknowledgement withheld after
sink retention, SIGKILL and restart; the same signed report and original incident
remain held until a bounded later attempt recovers the sink acknowledgement.

The CAS compares retained state, not the etcd server's wall clock. Clock checks
and an enrolled send interval do not establish a hard real-time physical cutoff.
A pause after the final local check or a delayed original request can cause a
late original effect. SQL-to-Kubernetes is not atomic. Neither property grants
permission to repeat a request or compensate unknown work.

## Current SQL source integration

The current source protocol is `KF-CURRENT-SQL-RESERVATION-0.2-draft`.
`kf-current-reservation` has protected configuration and separate fixed mTLS
query/evidence endpoints and credentials. The selected original SQL barrier runs
under its standalone peer-authenticated role. It checks database name/OID and
postmaster start time against the enrolled lifetime before and after the locked
query. Database recreation or postmaster restart requires fresh protected
enrollment. This is deliberately conservative and does not detect every possible
same-process administrator rollback or replace declared writer/restore custody.

A signed storage head plus current digest/minimum sequence are read from protected
files outside SQL. In-process head regression or same-sequence substitution
refuses; maintaining the durable latest floor on service restart remains the
external storage owner's responsibility. Native source claims are one-use before
SQL I/O, and their exact retained bodies are required by controller operating
proofs. Cumulative retained material bytes/counts are checked before new material
CAS, keeping an exhausted observation from making the existing history unreadable.

Admission has a separate preflight protocol because no physical grant/origin
exists yet. At most four native claims per enrolled child bind exact signed
proposals and the actual original committed SQL predecessor. A source outage or
crash consumes its claim. A fresh retained successful result can be returned on
reply loss without another SQL read or later expiry. Source statements are
retained before the standard evidence reply, and native dispatch compares the
actual retained admission source statement/claim with the exact grant/proposal
and SQL original in its anchor transaction.

The standard evidence state fields bind the physical proposal's declared
contract baseline. SQL current facts and the retained source statement digest are
explicit result fields under the registered version-2 question/result schema.
The SQL provider does not assert current Kubernetes inventory; that still needs
the separate actual physical provider and complete admission manifest.

The six focused source tests include actual peer SQL, row/role/ACL drift,
identical-row database recreation, actual postmaster restart, expiry without
another effect, protected head/floor and explicit prototype version refusal.
The live shipping service case additionally exercises actual peer SQL, etcd
original dispatch/source claims, separate mTLS roles and credentials, wrong
proposal/tenant refusal without budget consumption, unchanged cached evidence,
concurrent one-use reads and live-slot restart replay refusal. Before/after SQL
resources, outcomes and snapshots must remain identical.

`kf-verify-current-reservation --bundle BUNDLE --trust TRUST` independently checks
source/storage signatures, exact original SQL grant and proposal evidence against
the retained signed admission/issuance authorization at historical times. Its
output explicitly reports `native_history_verified: false` and
`managed_physical_qualification: false`. The external protected trust enrollment
must be selected independently; a bundle cannot enroll its own keys. This narrow
source replay does not replace the complete managed aggregate. The [current SQL source verification record](../results/verification/rfc-m8-current-sql-source-2026-10-25/README.md)
records the exact unchanged-source corpus and its limits. The foundation record linked below covers the earlier 0.1
prototype source, not qualification of these new 0.2 source paths. Archived
prototype statements and the legacy/O1 records are not reinterpreted as the new
version.

## Verification and remaining work

The pure tests exercise closed enrollment/schema/action separation, shared slots,
restart accounting, original deadlines, stop/outbox ordering, lost Pending,
backoff/budgets, finite observation windows, incident identity/ack semantics,
complete event links and signed current-SQL correlation/freshness negatives.
These tests use synthetic records and are not native concurrency or physical
qualification. The [foundation regression record](../results/verification/rfc-m8-managed-drain-foundation-2026-10-24/README.md)
separately states its exact tested source and scope.

The following increment notes record the earlier O2–O4 gates. The current
[M8 completion checklist](M8_ACCEPTANCE.md) and frozen record supersede their
software-status statements:

- Independently maintained storage-head/floor and declared writer/restore rules
  for the implemented protected current SQL query/admission service.
- Wider native concurrent-worker, paused-mutation-versus-stop and exact material
  exhaustion cases. The protected managed controller loader is implemented. The
  shipping supervisor, bounded complete captures and lost-sink-reply/SIGKILL
  recovery are implemented; this is still local reference qualification.
- Named managed gateway/SDK integration and combined shipping qualification
  using the implemented complete operating audit. Broader closure races,
  paused send/stop and wider exhaustion paths still need live coverage.
- Combined actual peer SQL/etcd/Kubernetes qualification under the unchanged
  five-second grant/transport and existing family/inverse windows.

Independent custody, all writers, production maintenance, physical node failure,
accepted workload SLO and independent whole-saga/authority-peer acceptance remain
separate deployment gates even after those software tasks pass.

## Controller process qualification

The [controller verification record](../results/verification/rfc-m8-managed-controller-2026-10-27/README.md)
retains the exact-source corpus and public process/audit artifacts. The completion
case uses the shipping managed controller, current SQL source and read-only
supervisor with real peer SQL, etcd and Kubernetes. A test-owned transport barrier
holds the first Pending transaction before the actual native CAS. After SIGKILL,
the held transaction returns a transport failure without forwarding a write. Its
original SQL claim/query remains consumed until interrupted expiry. Restart uses
the same original acceptance with fresh checks, then performs two actual requests.
Supervision observes completion after mutation. This completion case does not
qualify simultaneous observation versus send; that remains a separate race gate.

Complete independent replay requires five controller proofs, four native SQL
source claims and the interrupted original query. Native committed query reports
acceptance only. Source/physical work leaves SQL rows unchanged. Two further cases
exercise shipping positive `close-unstarted` and `close-absent` commands against
the actual permanent family/phase boundary, with complete no-effect/no-dispatch
audits. Original receipt absence remains explicit. Local tests and file/SAN checks
do not establish independent custody, deployed writer coverage or physical SLOs.

## Shipping read-only supervisor and complete audit

The [verification record](../results/verification/rfc-m8-managed-supervision-2026-10-26/README.md)
pins the tested source, complete corpus and public local runtime evidence.

`kf-managed-drain-supervisor --material-root ROOT --config FILE` provides
`check`, `status`, `tick`, `observe`, `deliver`, `export` and `run`. Its closed
configuration pins one managed child, the complete family/member observer catalog,
the physical read-only API files, operating signer and fixed sink TLS/credential
files. Every file is read through the protected root; selected local client SPIFFE
metadata must match the enrolled supervisor workload. Actual remote authentication
still requires the pinned mTLS handshake. `check` validates configuration and
material; it does not establish independent OS custody or deployed RBAC.

The process holds observer/signing credentials and a read-only Kubernetes client,
with no controller, broker, grant issuer or inverse target. Its 250 ms deadline
loop is separate from complete aggregate collection and incident delivery. Each
observation reserves a shared native slot before any source I/O; the entire cycle
is bounded by its original slot. Managed physical captures have a ten-second
whole-cycle bound, in addition to existing response and serialized limits. Lost
or failed work consumes the slot. A final clock sample and native expected-head
comparison precede observation retention. No timer or polling loop renews policy,
grant, family, inverse or transport windows.
Retained-byte decoding and pure replay run in a blocking worker with bounded
caching and one verifier per identical input. Timer, source I/O and incident
transport remain asynchronous; every invocation still reads the native store.
A received signed sink acknowledgement can retry its native retention comparison
at most three times inside the same original five-second delivery slot. This
performs no additional sink request or delivery reservation. A protected clock is
sampled after each read and before CAS; failed retention leaves the original slot
consumed until expiry. The live restart case forces a real native epoch conflict
and requires the same acknowledgement without a third sink request.

A managed observation explicitly distinguishes `native: {"state":"missing"}`
from a retained signed receipt. Missing or ambiguous acceptance stays unresolved
and cannot postpone the original dispatch-derived deadline. The legacy O1 record
format continues to require its actual receipt; no placeholder receipt/digest is
created. Native committed acceptance also stays unresolved until complete physical
evidence resolves the original operation.

An original dispatch without a receipt uses the separate closed
`KF-MANAGED-PENDING-LINEAGE-0.1-draft` supplement, with explicit pending
outcomes and reserved/control wrappers in
[`spec/drafts`](../spec/drafts/managed-pending-lineage-v0.1.schema.json).
It retains the actual signed managed grant and correlated original journal,
requires an empty receipt/evidence chain, and reports only `pending`. Its native
observer rechecks the exact journal, context, original nonce and receipt-head
absence at the enclosing checkpoint. Existing receipt-based schemas are
unchanged. A pending journal cannot establish no effect, completion or inverse
authority; receipt absence remains an observer/storage assertion.

Physical captures now carry a separately signed native control prefix, original
preflight evidence/claims and source-read claims. The verifier reconstructs every
acceptance/Pending/send/closure mechanical signature prefix and checks original
SQL evidence, reservation/control history and family/phase authority views,
including the final send checks. This observer-attested native prefix is not a
consensus proof. Prior aggregate views and acknowledgements are replayed from the
outer operating audit instead of being recursively embedded in each capture.

`kf-verify-managed-drain --bundle BUNDLE --trust TRUST` replays the complete bounded
operating event/material history with independently selected enrollment, all
referenced aggregate and acknowledgement bodies, original admission evidence and
all mechanical/control/source prefixes. Export serializes retained evidence and
never performs an extra physical query outside the budget. A later control or
closure cannot be hidden behind an older physical capture; missing source bodies
refuse. The output separately reports the operating checkpoint time and physical
observation time and conveys no current execution authority.

The controller carries forward the fully verified Pending prefix only after its
native CAS succeeds. The final send CAS compares that exact expected prefix and
fresh native authority. After a successful send CAS, the controller compares the
head, mechanical Pending, source claim and original native authority values again
before I/O. Bounded replay caching includes every retained source byte and
protected trust pin. These paths reuse immutable verification results, never a
successful live comparison. The final protected-clock check retains the original one-second
maximum enrolled authorization-to-send interval. A changed stop/head/source/control
refuses the original send and retains Pending as unknown. A pause after the last
check still cannot establish a hard real-time physical cutoff.

The initial O2 cases use actual SQL/native/Kubernetes and the shipping source/supervisor.
Their controller uses its explicit library constructor. Completed cordon and
eviction produce five retained control proofs and three SQL read claims; a native
committed receipt is separately observed as unresolved before physical work. The
unknown case covers original missing acceptance, deadline escalation, sink retention
before SIGKILL, finite delivery restart, stable incident identity and acknowledgement
without resolving unknown. These cases do not qualify the shipping managed
controller configuration or SDK/gateway, all native races/exhaustion, independent
storage/writers/custody, production maintenance, physical failure or workload SLO.
M8 and the current phase remain incomplete.

## Managed gateway and agent binding in development

[RFC 0057](rfcs/0057-managed-drain-agent-binding.md) adds an explicit
`managed_drain_adapter` selection to the gateway configuration. Its fields are
`profile`, the complete protected family/child `selection`, `token_issuer`,
`target_keys` and `gateway_workload`. It must match the actual selected native
ledger, reservation, namespace, named action/version, resource, predicate,
gateway/target audience, target scope and gateway certificate identity. The broker
actor assertion instead pins the original proposal workload from native admission
trust, as required by RFC 8693 exchange. Mixed legacy, SQL or inverse
adapter selections refuse. The gateway uses its own protected native transport;
controller, observer, source and storage-owner signing keys are not gateway inputs.

The adapter independently reads complete original acceptance sources and
admission/issuance, replays signatures and historical transitions, and compares
the retained native values after verification, before recording acceptance. One
known guarded-read/head race permits one read-only recapture within the original
grant deadline. Successful historical replay can be reused only for identical
complete proof bytes and all protected context pins; native reads/comparisons
remain fresh. Acceptance, token exchange and physical requests are never repeated
by this recapture. It returns the mechanical
controller state plus `kedgeflow_managed_drain_acceptance`. The new wrapper has
profile `KF-MANAGED-DRAIN-ACCEPTANCE-0.1-draft` and a separate
[structural schema](../spec/drafts/managed-drain-acceptance-v0.1.schema.json).
Nested original records retain their strict Rust decoders and semantic verifiers.

Each native guarded range transaction (at most 32 keys) may capture a snapshot
at most three times within one original five-second transaction budget. Multi-batch
proof reads retain the existing outer capture deadline. Each
attempt reads fresh guards, and authority-changing callers still compare the
returned bytes in their final CAS. Exhaustion remains unavailable. Malformed
responses, transport errors and mutations are not retried by this helper.

`kf-verify-managed-drain-acceptance --proof FILE --trust FILE` independently
replays the historical acceptance prefix against a protected managed trust file.
Its report states `native_history_verified: false`, `execution_authority: false`
and `physical_status: unresolved`. It does not verify current authority or
physical completion. The complete operating/physical verifier remains separate.

The Node `managedDrainRegistration(selection)` helper and `managedDrain` agent
configuration are explicit managed opt-ins. Discovery requires the managed
extension and exact enrollment/policy/family/operation/schema metadata. Native
`committed` maps to `accepted` with unresolved physical status. The family runner
requires the same complete protected selection; original status remains query-only.

Historical source replay and configuration/discovery vectors are supplemented by
fresh official SDK/native-service completion and reply-loss/root-stop cases with
the shipping controller, SQL source, supervisor and recovery worker. The native
outcome uses an explicit acceptance reference; independent audit reconstructs and
verifies the entire proof from complete co-carried member sources. MCP still
returns the full proof, and snapshot/material/time bounds remain unchanged.

The original completion/loss cases host native control/broker/gateway as typed instances.
A separate case starts the actual `kf-proxy` binary with protected managed
configuration, its own native/broker/controller gateway credentials, and exact
per-endpoint SDK CA pins. Two further cases start actual protected `kf-control`
and `kf-broker` binaries too. Control holds admission/issuer keys 6/5; broker holds
target key 29; each has its own TLS/native credentials and private process root.
None receives controller47, physical49, operating91, provider94 or storage-owner95
signing keys. The availability/manifest frontend remains an authenticated fixture
that reads actual Kubernetes availability and the shipping SQL source.

Before listening, the managed gateway, control, broker and separate managed controller
replay installed complete family history and compare native values, each within
five seconds.
Only immutable replay results can be reused; execution rereads sources and
performs all fresh authority/epoch CAS checks. `--check` remains local and does
not perform this remote preparation. Closed/stopped histories remain valid for
query-only startup; an active authority decision is never retained for execution. No source/grant/token/ACK/send bound changes.

Query-only recovery may poll again, within fifteen seconds and at most three
sweeps, when a guarded reservation/proof read loses its epoch. Every failed sweep
and diagnostic is retained; other errors refuse. No execution request, broker
exchange or source claim is repeated by that recovery worker.

The [gateway qualification record](../results/verification/rfc-m8-managed-gateway-2026-10-29/README.md)
defines the exact frozen-source corpus. The additional transport-loss case forwards
one real acceptance to the shipping controller, validates its signed reply, then
discards that reply. It requires one acceptance request, one discarded reply, zero
physical sends, original stopped-root recovery and the identical native credential
permit. Its full historical acceptance proof is reconstructed from the separately
verified complete operating/physical aggregate; the first SDK result stays unknown.
The healthy case requires the complete proof in the first SDK reply.

Actual broker process diagnostics count decoded exchange requests and issued
responses. The unused typed minter stays at zero; an internal binary mint-provider
invocation count is explicitly unobserved. Generated same-host roles do not
establish independent custody or production native ACLs. Independent deployment,
wider races/exhaustion and complete O4 qualification remain open. M8 is incomplete.

The native pre-admission boundary case exercises the unchanged four-claim limit
against the shipping SQL source. It kills the source after an actual claim CAS,
restarts it, and requires replay refusal while the original claim and proposal
are still valid. Two competitors for the fourth slot produce one retained signed
observation. A fifth request refuses, successful reply replay remains unchanged,
and the interrupted claim stays consumed. All four actual claim bodies and three
successful source statements are retained. SQL rows stay unchanged; no drain
origin or execution grant is created. This source-only evidence does not qualify
physical execution or the wider native material/send race matrix.

The full conformance runner creates its private task-owned Kubernetes bootstrap
immediately before the RBAC stage. It does not reuse a caller's pre-issued
bootstrap credentials after a paused continuation. The existing one-hour service
account lifetime stays unchanged, and every drain case still has a separate fresh
namespace. Cleanup checks the exact cluster/node/namespace ownership; only public
contract and fixture metadata enter the retained record. Protocol grant/source/
token and physical timing limits are unchanged.

## Combined software exit

The [completion checklist](M8_ACCEPTANCE.md) maps the finite O4 software checks to
required cases. It adds actual Pending/Send stop/deadline CAS losers, complete-proof
epoch-race/corrupt-source faults, native material/wire bounds and the all-service
unknown-at-deadline incident/ACK case to the existing completion and positive
closure evidence. Earlier increment descriptions above remain historical scope
notes; the final frozen record is the evidence of combined qualification.
Independent deployment, custody/writers, physical restore/failure/SLO and peer/owner
acceptance remain required. No limits or supported profiles are broadened.

Managed SDK acceptance qualification holds the first advance-query transaction
before its native CAS while collecting the initial acceptance proof. The held
query is uncommitted and is not counted as consumed. A live controller can
legitimately defeat both bounded proof reads and produce unknown; the dedicated
proof-race cases exercise that refusal. Separate controller crash and Pending/Send
cases qualify consumed-query and mutation boundaries. No retry count, deadline or
protocol profile is changed to force the healthy fixture's first proof to pass.
