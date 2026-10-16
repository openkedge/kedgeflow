# RFC 0050: Bounded inverse process loss and witnessed authority restore

- Status: Draft
- Milestone: M8d3d
- Prerequisites: RFCs 0023, 0046–0049
- Owners/reviewers: unassigned

## Scope and invariants

Qualify one actual conditional PostgreSQL inverse through fresh native admission,
original claim, one-shot broker authorization and the shipping inverse target.
Process death and missing replies must preserve the same original attempt and
held compensation cost. Recovery queries original results; it never mints,
resends, refunds or infers no effect from a missing SQL result. Permanent shared
stop and expiry do not prevent historical reconciliation.

Use existing wire profiles, signed compound binding, common resource fence,
query-only recovery and independent write-ahead restore gate. This RFC adds no
execution profile, schema, production failure hook or migration. Paired forward
and inverse services must use the same pre-enrolled restore witness for their
shared namespace. Existing namespaces cannot be silently re-enrolled.

## Process boundaries

Before effect: an independent owner session holds the actual protected resource
row lock. Observe the inverse executor waiting on that lock, kill the shipping
process with SIGKILL, release the lock and wait for the dead SQL session to exit.
Restart using identical protected configuration. Confirm no inverse result,
unchanged forward version/fence/value and an unknown original attempt/cost.
Absence of a result does not certify no effect or free capacity.

After effect: a test-owned mTLS relay forwards the original dispatch, receives its
committed response and holds delivery to the gateway. Kill the target with SIGKILL
and restart it before returning an unavailable reply. Confirm the actual restored
row and original retained SQL outcome. After actual expiry and permanent root
stop, query-only recovery signs the original committed receipt. Repeat recovery
must return that same receipt, with one original dispatch and unchanged held cost.

The relay verifies separate gateway and recovery identities and preserves the
pinned public Host/audience when forwarding to the private target listener.
Generated identities and one host UID qualify local software behavior only.
The fixture uses a 15-second inverse policy and 60-second acknowledgement to
accommodate debug-build witness checks, retains the five-second broker credential
ceiling, and waits for actual grant expiry. Production settings are unchanged.

## Stopped authority restore

Enroll a separate disposable witness process before any paired topology write.
Capture the complete local namespace before inverse issuance and after committed
recovery. Stop native authority servers and drain their completed operations;
privileged test tooling may then replace the local prefix with its old values.
Keep the independent witness and actual SQL target state intact.

The stale local copy must refuse witness checks, recovery, original/replacement
claims, audit export and attempts to remove the gate. Independent target query
must still return the original commit. Replace the prefix with its exact latest
values; verify the original receipt, held spend and complete historical evidence.
No replacement authority or automatic service resume follows restoration.

## Evidence and remaining gates

Required native tests cover the three boundaries, real SQL row/version/fence,
original attempt/root/grant correlation, stop/expiry, retained spend, repeated
receipt and complete independently pinned offline lineage verification. Retain
source/tool/log pins from the full required conformance runner.

This is a stopped logical **authority-prefix** rollback against a separate local
witness, not physical database backup/restore, an independent failure domain,
accepted writer coverage or independent implementation acceptance. Inverse SQL
storage rollback/restore, wider gateway/broker/witness crash matrices,
multi-contract families, partial multi-inverse workflows, dynamic delegation,
full A2A peers, independent saga acceptance and actual Kubernetes drain remain
separate milestones. M8 remains incomplete.
