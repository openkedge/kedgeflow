# Managed Kubernetes drain — implementation foundation

[RFC 0056](rfcs/0056-physical-operating-records.md) now has a proposed-profile
implementation foundation. **Managed drain is not enabled or qualified.** The
shipping configuration, gateway/SDK adapter, current SQL provider, operating
supervisor and complete independent managed aggregate still require integration
and actual SQL/etcd/Kubernetes tests. Existing RFC 0055 records keep their original
mechanical semantics. M8 remains incomplete.

## Explicit contract

The new named action is `kubernetes.node.drain.managed`, version `1.0`, profile
`KF-MANAGED-KUBE-DRAIN-0.1-draft`. Its parameter schema binds both the full managed
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
operation/root/resource incarnation, compensation contract, fixed query and
evidence endpoints, provider, storage owner/generation, restore protocol digest,
declared coordinated/external writers, maximum age and request timeout. The
witness types check exact original grant/attempt, parameter digest, fence,
post-version and signed storage head. A signed historical forward outcome alone
cannot serve as this witness. The actual provider and protected storage-head
publication/restore enforcement are not delivered by these types or the client.

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

## Verification and remaining work

The pure tests exercise closed enrollment/schema/action separation, shared slots,
restart accounting, original deadlines, stop/outbox ordering, lost Pending,
backoff/budgets, finite observation windows, incident identity/ack semantics,
complete event links and signed current-SQL correlation/freshness negatives.
These tests use synthetic records and are not native concurrency or physical
qualification. The [foundation regression record](../results/verification/rfc-m8-managed-drain-foundation-2026-10-24/README.md)
separately states its exact tested source and scope.

Before O2–O4 can be completed, implement and verify:

- Protected current SQL query and exact-proposal admission evidence service,
  independently maintained storage-head/floor and declared writer/restore rules.
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
