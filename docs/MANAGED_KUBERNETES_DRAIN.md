# Managed Kubernetes drain — implementation and current SQL source

[RFC 0056](rfcs/0056-physical-operating-records.md) now has a proposed-profile
implementation foundation. **Managed drain is not enabled or qualified.** The
shipping managed controller configuration, gateway/SDK adapter, operating
supervisor and complete independent managed aggregate still require integration
and actual managed physical SQL/etcd/Kubernetes tests. The separate current SQL
source has live read-only integration coverage. Existing RFC 0055 records keep their original
mechanical semantics. M8 remains incomplete.

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

The controller never resends a retained Pending request. Losing the final send
check keeps the original Pending unknown; it cannot imply no effect. Closed
unstarted/absent mechanical proofs share their CAS with the operating closure.
Complete signed original physical aggregates remain necessary to classify the
operating outcome. Native committed acceptance cannot resolve it.

The shipping controller loop has a separate managed deadline task so inventory
or mutation I/O cannot hold that task. The existing protected configuration still
constructs the legacy controller and therefore refuses managed enrollment. This
source path is not an operational enablement switch.

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
SQL inverse. Protected supervisor configuration and shipping delivery/crash tests
remain required.

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

Before O2–O4 can be completed, implement and verify:

- Independently maintained storage-head/floor and declared writer/restore rules
  for the implemented protected current SQL query/admission service.
- Explicit shipping managed controller/supervisor configuration, bounded physical
  captures and incident delivery with real native concurrent-worker/restart,
  paused-mutation-versus-stop and lost-sink-reply tests.
- Named managed gateway/SDK integration and complete independent managed
  aggregate replay, including every acceptance/Pending/send/closure proof and
  its actual native authority and mechanical signature prefix.
- Combined actual peer SQL/etcd/Kubernetes qualification under the unchanged
  five-second grant/transport and existing family/inverse windows.

Independent custody, all writers, production maintenance, physical node failure,
accepted workload SLO and independent whole-saga/authority-peer acceptance remain
separate deployment gates even after those software tasks pass.
