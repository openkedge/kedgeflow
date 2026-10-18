# RFC 0052 — Shared family capacity and live narrowed delegation

- Status: Draft; local native qualification, no release or deployment acceptance
- Milestone: M8c4; shared-capacity prerequisite for multi-contract M8d3
- Profile: `KF-FAMILY-AUTHORITY-0.1-draft`
- Depends on: RFCs 0032, 0038–0039, 0041–0042; 0044–0049 for inverse children
- Schema: [signed commands](../../spec/drafts/family-authority-command-v0.1.schema.json)
- Implementation: `family`, native control/ledger integration and `kf-family`

## Problem and scope

Static native hierarchies cover one protected leaf contract. Independent roots
cannot assert a common capacity budget merely because a planner groups them.
Runtime delegation also needs live ancestor checks, without turning a composite
or a task reference into an execution grant.

Enroll one protected family in a **fresh authority namespace**. Its catalog pins
at most eight distinct native child contracts, their exact audited registration,
optional paired topology and optional inverse contract. Physical conflict domains,
resource IDs and local budget-root IDs must be distinct. One etcd namespace and
transaction domain is required. Every child retains its own admission, native
issuance, budget history, original claim, dispatch and outcome controls.

Hold each child's **whole enrollment allowance**, including its compensation
allowance, in the family before enrolling that child's native reservation. Local
issuance can spend only within that preallocated allowance. This is conservative
preallocation, without per-leaf transfers or returning unused capacity. A family
is never a native execution grant and cannot execute a child action itself.

## Protected registration

`Registration` is a closed typed record: profile, exact authority namespace, family ID, tenant, root owner,
preapproved principal set, maximum action/resource scope, separate integer forward
and compensation budgets, validity interval, signer ID/public-key/principal pins
and child catalog. Configuration, public audit trust and signed commands are
separate inputs. The signed registration digest includes the exact namespace;
manager and child selection reject another prefix, so a signed command cannot
be replayed into a copied fresh namespace. Commands cannot supply endpoints, trust keys, credentials or
new catalog entries. Root owner and delegated owners must have approved signing
keys. Delegation keys must differ from catalog issuer, composite, outcome,
acknowledgement, barrier and applicability keys. Native service construction also
checks supplied admission, evidence and administration roles against family keys.

Existing native registration, hierarchy, saga and inverse execution validation
remains required. Pinning an inverse lane without its compound execution profile
permits governance and historical queries only. It cannot admit, issue, claim or
dispatch an inverse. No frozen Grant or SQL migration changes are introduced.

Family enrollment compares the whole namespace empty, excluding only the exact
existing restore-gate marker. An enrolled witness must still be configured and
checked. Install all catalog paired topology markers, the immutable required
family marker and genesis state in that same transaction. Refuse legacy adoption,
re-enrollment or partial migration. Child enrollment and control installation
follow explicit signed attachment. A plain or differently selected ledger cannot
operate around the namespace's required marker.

## Signed operations and conservation

`Command` contains profile, approved key ID, payload and Ed25519 signature. The
payload pins family-registration digest, stable 64-hex operation key, expected
family head, issued/expires timestamps and one operation. Signature input is
`KedgeFlow:KF-FAMILY-AUTHORITY-0.1-draft:command\0` followed by canonical JSON of
profile, key ID and payload. The command window is at most 60 seconds and lies
inside the family lifetime. Parsing rejects duplicate/unknown fields, unsafe
integers, unknown operations and malformed signatures before signature/semantic
verification. Server time and approved key custody remain trusted.

- `delegate(parent, branch)`: only the selected parent owner may create a new
  branch. Branch ID is the command operation key. Owner, principals, scope, both
  budgets and lifetime must narrow the live ancestor chain. The new owner must
  have a preapproved family signer. The branch is a nonexecuting composite
  allocation. Root and every ancestor count toward depth eight.
- `attach(parent, child_id)`: only the live parent owner can attach a catalog child,
  once. Its scope and native principal assignments must fit that parent. Hold the
  child's full forward/compensation allowance as a leaf allocation. Ancestors'
  allocations include, rather than add to, their descendants' costs.
- `stop(branch_id)`: the selected owner or root owner can permanently stop that
  branch. Root stop closes the whole family. Stop changes no allowance, child
  registration, original operation, claim, outcome or dispatch already authorized.

All commands compare the exact retained old state/head and write the full new
state in one CAS. Concurrent commands may refuse; callers must query and decide
what to do next. There is no automatic command rewrite or blind retry. Exact
original-command replay returns current retained state without mutation, including
after expiry or stop. Changing a replayed command refuses. New operation/task IDs
cannot attach an already attached child or obtain another allowance.

Retain all signed commands, application times, hash-linked heads, branch states,
attachments and the independently replayable reservation snapshot. Bound history
to 64 events, branches to 16, registration to 128 KiB, commands to 16 KiB and state
to 512 KiB. Reserve the last event slot for root stop. Size/history exhaustion
refuses; it cannot release a reservation or reopen authority.

## Mandatory native transaction checks

Every normal native transaction observes family marker/state and compares those
exact values in its final transaction. An absent marker is also compared absent,
closing family enrollment versus legacy writes. Configured children require the
exact family, retained attachment, catalog digest and matching native lane/context.
Missing/corrupt state or removed selection refuses, including historical export.

Admission, fence allocation, issuance, claim and dispatch additionally require a
live selected parent and every ancestor. Their original comparisons remain in the
final CAS, so a stop between preparation and commit makes the transaction refuse.
Final historical/query transactions preserve attachment and context checks without
requiring a live branch. Already authorized effects can remain in flight after
stop; their original outcome must be queried. No cancellation, refund, replacement
claim or automatic compensation follows from family stop.

## Historical evidence

The family verifier independently reconstructs genesis and every signed command,
checks owner/scope/time/conservation, and compares the entire resulting state.
`kf-family --export` makes a final native state CAS and signs a checkpoint with a
separately pinned observer: observer/key IDs, namespace, captured time and state
digest. Observer keys must differ from delegation and known catalog role keys.
The verifier accepts separately supplied public trust and performs no network I/O.

This proves the bounded retained **family allocation/delegation history** under
its observer/ledger assumptions. It does not itself prove a child target effect,
complete cross-contract execution lineage, latest wall-clock head, consensus
commit, independent custody or whole-saga acceptance. Existing child lineage and
inverse proofs remain separately required. Offline history has no authority.

## Qualification and open M8 work

Native tests cover competing last-slot child attachment, two actual independently
admitted child contracts, delegated/nested ownership, scope/cost/principal/time
widening refusals, replay, expiry, stopped replacement, bounded history with a
reserved root-stop slot, corruption/missing state, context substitution, cross-namespace command replay, legacy
refusal and separate-observer replay. An etcd relay races root stop against native
fence allocation, issuance, claim and dispatch. Paired inverse qualification,
fresh compound issuance and original recovery remain functional after family stop
with unchanged held costs. Shipping CLI tests use real mTLS relay traffic and
create-only enrollment, signed apply/replay, export and offline verification.

This is one-host disposable software qualification. A core/independent A2A task
peer, multi-contract real-SQL inverse runner and aggregate execution evidence,
wider failure composition, physical restore/cutover, enterprise writer/custody
acceptance and the separate actual Level C Kubernetes drain remain open. This
RFC does **not** close M8. [Operator guide](../FAMILY_AUTHORITY.md).
