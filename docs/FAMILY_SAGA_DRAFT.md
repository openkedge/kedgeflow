# Multi-contract family saga proposal

[RFC 0054](rfcs/0054-multi-contract-family-saga.md) specifies
`KF-FAMILY-SAGA-0.1-draft`. This profile is **not enabled for execution**.
`Family::new` and native `Selection::attach` reject it before retaining state or
selecting a service. Legacy RFC 0052 registration bytes and digests retain their
original meaning. A legacy registration cannot select a composition plan, and
explicit null cannot erase a required plan.

The current Rust proposal validators cover:

- Exact coverage of the protected catalog by at most eight distinct native
  forward operations, each with one planned leaf; unique operation keys, a
  bounded acyclic dependency graph, held allowance costs and validity windows.
- Existing public native trust validators, exact namespace and paired topology /
  contract pins, identical paired forward trust, and separate family and aggregate
  observer keys. The owner cannot substitute admission, issuer or outcome keys.
- Closed, domain-separated signed owner intents with permanent operation key,
  family digest, expected phase head, short validity and exact proof digest.
  Historical observation can be validated after family expiry; an intent that
  would enable compensation cannot. Validation neither retains a command nor
  supplies execution authority.
- Complete member inventories, including fully unissued members. Reuse native
  reservation-history and authorization replay; a claimed original requires
  complete reserved lineage and a signed original outcome. A paired claimed
  forward also requires complete compound evidence. Missing records never
  become no-effect results.
- Successive inventories retain prior native history, original authorizations,
  grant/attempt identity, qualifications and inverse bindings. Known terminal
  effects cannot revert or disappear. A real SQL fixture exercises an original
  inverse progressing from absent through unknown to committed.

These are unsigned proposed snapshots. The validators check carriage, native
signatures and historical continuity. They do **not** establish the current storage
epoch, qualify negative inventory or prove that separate member exports came
from one atomic observation. Two separate native fixtures test complete catalog
coverage; they are not a multi-contract execution qualification. The one-member
SQL case qualifies evidence validation, not the proposed global protocol.

Implementation still required before enabling this profile:

1. Atomic fresh composition genesis and mandatory nonrepeating native-write epoch
   across every mutating native transaction, including auth/control and recovery.
2. Native global phase and dependency checks, permanent quiescing, consistent
   all-member collection and one-CAS entry to compensation with complete proof
   retention and fresh original applicability/barrier checks.
3. A global original inverse claim slot in the native claim/spend CAS, reverse DAG
   order and complete original evidence before clearing the slot.
4. Shipping protected runner and complete signed aggregate export/offline replay;
   real two-contract SQL, concurrency, lost-response, restart, partial/unknown and
   malicious aggregate qualification.
5. Separately governed Level C drain and actual disposable Kubernetes qualification.

Independent authority peers, deployed writer coverage, physical restore/cutover,
observer custody and independent acceptance remain release gates after this
software work. The [milestone plan](IMPLEMENTATION_ROADMAP.md) keeps M8 open.

The existing family runtime additionally reserves both serialized state and etcd
transaction capacity for permanent root stop. Non-root-stop commands refuse before
using that reserve. Identical family comparisons are deduplicated while conflicting
comparisons remain present; existing inverse transaction bounds stay in force.

The required frozen-source qualification is retained in the
[18 October verification record](../results/verification/rfc-m8-family-saga-draft-2026-10-18/README.md).
