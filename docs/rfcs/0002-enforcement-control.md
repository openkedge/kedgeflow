# RFC 0002: Enforcement Control installation and revocation

- Status: **Draft**, 10 October 2026
- Profile: `KF-ENFORCEMENT-CONTROL-0.1-draft` binding in RFC 0007
- Milestone: M1 → M2
- Owners/reviewers: unassigned

## Problem and scope

The original `publish_policy` takes a grant-shaped argument and installs only policy
and ownership tuples. It does not implement an authorized control protocol,
registry lifecycle or acknowledgement. This draft defines those operations
without treating data publication as proof of enforcement installation.

## Authorization and operations

| Semantic operation | Authorized caller | Durable result |
| --- | --- | --- |
| publish policy | Policy Authority | Versioned policy/obligation digest and epoch |
| register descriptor | Resource Registry | Signed CTD, incarnation, ownership epoch |
| install control | Authorized control coordinator | Exact installation revision |
| acknowledge install | Enrolled gateway/adapter | Signed installed revision and supported scope |
| revoke | Policy/Grant/Resource authority within assigned scope | Monotonic grant/root/scope revocation |
| query installation | Authorized operator/issuer | Installed revision and acknowledgements |

Publication verifies signer role, schema, digest, tenant/action scope and
monotonic epochs. Equal epochs with different content refuse; exact repetitions
are idempotent. Registration includes adapter version, guard scope, conflict
domain, resource incarnation and declared coordinated/uncoordinated writers.
An installation identifies exact policy, descriptor, obligation and trust-set
digests. Acknowledgements name the component and exact revision; they never
claim a guard or writer coverage absent from the deployed adapter.

The first deployment must use fixed trusted endpoints and signed records over
mTLS. Agent keys cannot perform these operations. Authorization belongs at the
service boundary and the backing store; TLS alone is insufficient.

## Serialization and revocation

Policy, ownership, installation and revocation state live in the same authority
serialization domain used by issuance, claim and dispatch authorization. Each
transition atomically compares the relevant installed tuples and revocation
state. A publication acknowledgement follows its durable transaction. A cached
descriptor cannot override newer ownership or revocation state.

Explicit grant/root/scope revocation requires its own typed record, revision,
issuer and reason reference. It cannot be emulated by an agent supplying a grant
with a fabricated policy. Revocation before issuance/claim/dispatch authorization
causes refusal at that transition. If dispatch authorization linearizes first,
revocation does not retract an already possible send. Stronger immediate fencing
requires target participation and must have a separate adapter contract.

Unacknowledged or unsupported required installations block issuance. A
partitioned control store blocks new authority and dispatch authorization.
Acknowledgement expiry/heartbeat behavior and the minimum required component
set must be configured explicitly; mere process availability is not installation.

## Failure, rollback and acceptance

Lost publication replies resolve by reading the exact revision. An older backup
or lower epoch never becomes current through restart. A restored control store
is quarantined until target fencing and retained consumption records are reconciled.
Rollback publishes a new revision describing older behavior; it never decreases
policy/ownership/installation counters or restores spent allowances.

Implementation: replace grant-shaped publication with typed operations in
`ledger.rs`; add authority service authorization and registry persistence;
compare installed/revocation tuples in issuance, claim and final dispatch.
Existing tuple comparisons are a starting point only. No install/revoke endpoint
was implemented by this RFC's initial library increment. The
[RFC 0007 supplement](0007-enforcement-control-http.md) now implements a bounded
signed service, one enrolled gateway acknowledgement/renewal and installed-state/
revocation comparisons. Legacy publication/issuance/replacement ports refuse
managed domains. Target coverage, migration/restore and broader enrollment remain
deployment gates; this semantic contract remains a draft.

Acceptance: duplicate/reordered installs, old ownership, conflicting same-epoch
content, unauthorized writers, missing acknowledgement, partition and revoke
races all preserve the declared ordering; stale restoration cannot reopen authority.

## Open decisions

- Owner acceptance of the new signed schema/binding and actual deployment ACLs.
- Multiple required acknowledgers, adapter coverage and retention/restore policy.
- Target fence allocation and break-glass writer coordination for a real adapter.
