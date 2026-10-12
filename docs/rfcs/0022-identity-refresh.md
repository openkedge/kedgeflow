# RFC 0022: Signed broker identity refresh and retained head checks

- Status: Draft
- Milestone: M5c3 software lifecycle prerequisite
- Baseline: `3c428b9`; RFCs 0020 and 0021
- Owners/reviewers: unassigned; identity, broker and security owners
- Profile: `KF-IDENTITY-REFRESH-0.1-draft`

## Scope and trust

Replace restart-only trust loading with authenticated snapshot publication and
fresh protected-head checks. The native broker does not publish snapshots, write
heads or mint workload identities. An independently administered refresh authority
signs RFC 0020 snapshots. A separately protected head file retains the current
epoch and exact snapshot digest outside the restorable broker/snapshot storage.
Both source paths and authority/issuer/audience pins are operator configuration.
Agents must have no write access to these sources, key material or configuration.

This is a bounded file binding and trusted source API, not an authenticated remote
publication service, a proof of physical storage independence or enterprise AS/SVID
provisioning. Simultaneously restoring the broker and the head/floor breaks the
assumption; rollback-resistant custody remains an acceptance requirement.

## Closed records and signatures

A head contains `profile`, `kind: head`, `authority_id`, `realm_digest`, `epoch`,
`snapshot_digest`. A signed snapshot contains those fields with `kind: snapshot`,
plus `snapshot`, `key_id`, `signature`. The embedded snapshot is RFC 0020 without
changed semantics. The explicit record epoch equals the embedded epoch. Digests
use `identity-realm` over exact issuer/subject audience/actor audience and
`identity-snapshot` over the complete embedded snapshot. Both are canonical
KedgeFlow domain-separated digests, not token or execution authority.

Sign the canonical unsigned snapshot record, including `key_id`, with Ed25519
over `KF-IDENTITY-REFRESH-0.1-draft` followed by a zero byte and the canonical JSON.
The signature is canonical base64url without padding. Only independently pinned
refresh keys select trust. Snapshot issuer/audiences must equal configured realm
pins. Reject unknown/duplicate fields, invalid schema/keys/signature/digests,
wrong authority/realm, epoch below the independently retained floor, and overlap
of refresh/subject/grant/target keys. Snapshot validity still lasts at most five
minutes and every identity verification must satisfy RFC 0020 time/registration.

## Verification and publication ordering

For every exchange: read the bounded regular head file; validate trusted pins and
observe its epoch/digest; read and cryptographically verify the signed snapshot;
require exact head/snapshot correlation; verify the actual subject/actor tokens;
read the head again and require the same semantic record. Observe the second head
before deciding whether it changed, so an advancing head remains remembered even
when verification refuses. There is no cached snapshot fallback or lease extension
on failed reads, bad signatures, missing files, expiry or inconsistent publication.

A process-shared high-water mark refuses a lower observed epoch or different
snapshot digest at the same epoch. A valid higher protected head is remembered
before loading the snapshot, including when its publication is missing/invalid.
This prevents a subsequent observed rollback from restoring earlier trust in the
same process. A retained floor and independent head are still required on restart.
Clones share the high-water mark; other replicas sample the head independently.
The final head read is the verification freshness boundary. A head change after
that boundary does not revoke an already verified identity, permit or target token.

Publish a fully signed snapshot atomically, then independently advance the head
and retained floor through protected administration. During mismatched publication,
exchange refuses. Use a greater epoch for renewal, rollover or withdrawal; editing
an existing epoch is forbidden. The broker never updates its own rollback floor.
File replacement must be atomic under the approved filesystem/storage contract.
Source read/verification is bounded by RFC 0019's five-second provider deadline.
No remote request may choose a source path, head or refresh key.

## Configuration and compatibility

`identity_refresh` selects the signed mode with authority ID, issuer, enrolled
refresh keys, signed snapshot/head paths and an independent minimum-epoch file.
Legacy `identity_snapshot_file`/`identity_epoch_floor_file` remain the static mode.
Require exactly one complete mode; mixing modes or incomplete configuration refuses.
The shipped binary verifies signed material at startup/`--check` without writing
or accessing remote authority. Each token exchange reloads the signed sources;
rotation does not require a native broker restart. Invalid signed mode never
falls back to static mode. No frozen record or token-exchange wire field changes.

## Implementation, acceptance and limits

`identity_refresh` supplies closed signing/head helpers, source binding and an
`ExchangeIdentityProvider` implementation. Tests cover signatures/realm/role
substitution, exact digest/epoch, per-request renewal, withdrawal/key retirement,
source failure/expiry, remembered rollback after a missing higher snapshot,
same-epoch split heads, restart with retained floor, concurrent/changed heads and
closed bounds. The shipping broker must rotate actor trust from signed files
without restarting: old assertions refuse before mint, a fresh assertion for the
same registered workload can redeem the original undispatched claim once.

Generated software keys, ordinary protected-file fixtures and loopback etcd qualify
software behavior. Approved publisher authentication, independently retained
floor/head custody and availability, atomic file publication, cross-replica delivery
budgets, revocation/clock guarantees, production RBAC/isolation and real target
acceptance remain [enterprise gates](../ENTERPRISE_QUALIFICATION.md).
