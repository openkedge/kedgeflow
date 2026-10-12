# Signed identity refresh (M5c3)

[RFC 0022](rfcs/0022-identity-refresh.md) adds an opt-in signed source to the
[native broker](BROKER_TOKEN_SERVICE.md). Every exchange reloads the current
protected head and signed snapshot. Actor/subject keys, registrations and token
withdrawals can change without restarting `kf-broker`. Failure refuses; there is
no cached trust fallback or automatic extension of a five-minute snapshot.

## Enrollment

Use [the signed-mode example](../config/broker-refresh.example.json). Remove the
legacy `identity_snapshot_file` and `identity_epoch_floor_file` fields and supply
`identity_refresh`: authority ID, exact issuer, independent public authority keys,
signed snapshot/head files and a separately retained minimum-epoch file. The
subject audience remains `delegation_audience`; the actor audience is the exact
broker URL. The execution-grant `gateway_audience` is a separate pin.

Select exactly one complete mode. Mixed/incomplete configuration refuses. The
old static mode remains supported and requires protected restart for refresh.
Signed mode never falls back to the static files. Authority verification keys use
standard base64 in configuration; record signatures use base64url without padding.
Do not reuse subject, Grant Authority or target credential keys for refresh. The
broker configuration and source directories must be inaccessible to agents.

`identity_refresh::sign_snapshot` produces a signed record and its matching
`RefreshHead` from a validated RFC 0020 snapshot and an independently held Ed25519
signing key. It is an authority-side library helper. The broker has only public
refresh pins and does not sign/publish identity updates or write the head/floor.
An external approved publisher must retain the signing key and implement its
protected administration and atomic publication procedure.

## Renewal, rollover and withdrawal

Publish a fully signed snapshot atomically, then advance the matching protected
head and retained floor through independent administration. Every renewal or
change uses a greater epoch. Same-epoch edits are forbidden. The head pins exact
realm and complete snapshot digest, so inconsistent partial publication refuses.
The digest binds the exact embedded canonical JSON before typed scope-set
normalization; array order is not silently rewritten. Freshness, subject/workload
registration and scope checks remain RFC 0020 checks.

For key overlap, publish both keys, rotate issuance, then remove the old key in a
higher epoch. Workload or token withdrawal similarly changes the signed snapshot.
A valid higher head is remembered even if its matching snapshot is absent or
invalid. Restoring a previously seen lower head cannot reinstate old trust in the
same process. A different digest at the same observed epoch refuses. Clones share
this high-water mark; separate replicas independently reload the protected head.

Each successful verification reads the head before loading/verifying the snapshot
and actual subject/actor tokens, then reads it again. A changed head refuses and
remains observed. The second read is the freshness boundary. Changes after that
boundary do not revoke an identity already returned, a permit or a target token;
final dispatch and target enforcement remain independent.

`minimum_epoch_file` is sampled at startup. It must survive independently of the
broker and snapshot. The protected current head must also survive independently;
file path names alone do not establish storage independence. On restart, an older
head/snapshot below the retained floor refuses. The process-local high-water mark
alone cannot prevent simultaneous rollback of the process, head and floor.

## Operation and verification

The source reads bounded regular files; missing/oversized/malformed files,
unknown/duplicate fields, bad signatures, role/authority/realm changes, digest or
epoch mismatch, rollback and expiry refuse. `--check` validates signed material
and exact head/floor correlation without network authority or writes. It does
not verify live token freshness or qualify publisher custody. No watching thread,
network JWKS discovery or writer endpoint is introduced. RFC 0019's existing
provider timeout bounds source acquisition and token verification.

[Fresh verification](../results/verification/rfc-m5-refresh-2026-10-12/README.md)
includes generated-key signing/head tests, concurrent replicas, renewed validity,
withdrawal, stale restart floor, changed/split heads and missing source. The actual
shipping broker rotates actor trust from signed files without restarting: the old
assertion refuses, rollback remains refused, and a new assertion for the same
registered workload redeems the original undispatched claim once. Material-only
checks reject mixed modes, bad heads, overlapping roles and stale floors.

Tests use ordinary atomic file replacements, generated software keys and native
loopback etcd. They do not establish production publisher authentication,
rollback-resistant external head/floor storage, cross-replica delivery budgets,
clock/power-loss/atomic-filesystem guarantees, workload provisioning, deployed
RBAC/bypass or actual target effects. Those [enterprise gates](ENTERPRISE_QUALIFICATION.md)
remain open. Frozen grants, token-exchange carriage and prior evidence are unchanged.
