# Shared authentication prerequisite (M5a)

[RFC 0018](rfcs/0018-shared-authentication.md) adds optional
`KF-SHARED-AUTH-0.1-draft` state to the existing pinned Ed25519 dual identity
profile. Independent replicas and restarted services consume one proof using
etcd CAS; process-local cache state is insufficient for that claim.

Merge [the sample member](../config/shared-auth.example.json) into the
`shared_auth` property of gateway, control or collector configuration. Governance
uses `control.shared_auth`. Replace all registrations with operator-approved
subjects, validated SPIFFE workloads and permitted token scopes. Every scope in
a token must be allowed. These checks complement existing application permissions.

All replicas serving the same issuer/audience/external URI must share the exact
namespace, capacity and registration. The realm partitions URI contexts; a
different registration refuses against its existing record. Do not change
namespace or delete the record to rotate identities: migration, key rollover,
workload revocation and safe reset need an approved follow-up contract.
Unconfigured services continue the local-cache profile. Neither sample identity
values nor software certificates constitute production enrollment.

`--check` loads configuration/key/TLS material without a remote replay transaction.
It cannot certify etcd permissions, availability, deployment clock trust or full
replica coverage. Shipping gateway, control, governance administration and
collector DPoP routes await the shared path when configured. The synchronous
`authenticate_at` helper refuses for a shared authenticator.

The protected record stores hashed key-thumbprint/proof-ID correlation, expiry,
registration digest and a monotone verifier-time watermark. It retains no raw
token, secret or proof ID. Capacity is 1..4096 live entries; four CAS attempts
bound contention. Saturation, corrupt state, replay, clock regression, store outage,
restore quarantine and uncertain mutation replies refuse with no local fallback.
Successful consumption can precede an application refusal. Retry with a fresh
DPoP proof and the same operation identity; proof consumption never grants an
execution allowance.

Expiry is proof creation time plus 66 seconds. Cleanup and watermark advancement
are part of the same CAS. No lease expiry or wall-clock rollback can silently
reopen a retained proof. A clock ahead of peers can cause availability refusals;
trusted service time must be independently operated. Namespace-wide replay
serialization and bounded record rewriting are reference mechanics whose
production throughput remains unqualified.

All reads/writes use the optional restore gate. Require independently retained
gate configuration for stale-backup protection. Without enrollment, shared replay
retention assumes the store survives restart and is not rolled back or bypassed
by raw/older writers. Prefix sharing does not establish independent custody.

Fresh [verification](../results/verification/rfc-m5-auth-2026-10-12/README.md)
covers concurrent independent verifiers, service recreation, future skew/capacity,
registration substitutions, clock regression, corruption, outage, lost successful
write reply, restore-marker refusal and native collector/admission routes.
Existing required SDK/native process tests also run. Real authorization-server
and SVID lifecycle, broker validation, production RBAC/custody and deployed
bypass acceptance remain M5 gates.
