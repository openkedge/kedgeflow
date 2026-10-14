# Historical lease and membership audit (M7d1)

[RFC 0036](rfcs/0036-leased-authorization-lineage.md) extends the existing
[lineage](ADMISSION_LINEAGE.md), [history](CONTROL_HISTORY.md) and
[control-binding](CONTROL_BINDINGS.md) exports with explicit closed v0.2 profiles.
No frozen records or v0.1 schemas change. Audit verification returns evidence and
creates no executable authority.

## Retained authority snapshots

A lease-enabled authority now retains one original membership/cache snapshot in
the transaction creating a certificate, and another in the transaction creating
its grant. Each snapshot carries phase, signed authority digest, check time and
the exact active membership generation/registration compared. For a leased packet
it also retains the exact signed lease and static-only input cache. Exact retries
keep original snapshots. Fence allocation and duplicate lookup continue comparing
live membership/cache; they create no extra audit snapshot.

Configured leases require membership even when an ordinary full-evidence request
omits a lease. Those operations export v0.2 with membership snapshots and null
caches. Unconfigured legacy operations export v0.1 with unchanged serialization.

`EtcdLedger::export_lineage` reads original retained records. Withdrawal or later
replacement does not rewrite them, and exports remain verifiable after expiry.
Missing one phase refuses export. Missing both phases cannot establish historical
lease membership: leased packets refuse export; an independent verifier refuses
legacy carriage under lease-enabled trust. Earlier operations are not upgraded
from current membership. Old grants use normal explicit execution revocation;
lease withdrawal does not retroactively invalidate them.

## Export and independent verification

Use the existing privileged export APIs and `kf-verify-lineage`, `kf-verify-history`
or `kf-verify-control-bindings` CLI commands. Authorization for disclosure remains
operator-managed; no agent-facing export route is added. The decoder selects the
schema by exact profile and rejects unsupported or mixed versions. All old byte
and count bounds remain, with at most two 1 MiB authority snapshots.

Approve historical public registration separately. Its optional `leases` object
has `keys`, `max_lifetime_ms` and `jit_max_age_ms`, matching the original registration
used in obligation/Cedar pins. Lease keys equal admission-role keys. Include the
original static and JIT provider rules and policy. History trust requires those
same rules in its approved historical registration snapshots. Never infer keys,
policy or trust from the exported bundle.

Verification recomputes the static-only verified-input binding at signed lease
issue time, complete member registration binding and cache identity under the
approved signer and original generation. It checks signed lid/discharges, exact
original canonical signed static records, and full static/JIT admission/issuance bindings and freshness.
Phase snapshots must link to the correct signed certificate/grant, with active
membership, ordered check times/generations and checks within authority/input
validity. Harmless JSON formatting variations retain the same signed record
identity and remain verifiable. Altered generation/cache/static packet, wrong phase/digest/time, missing
snapshots, downgrades and cross-version wrappers refuse.

History checkpoints attest the complete lineage, including snapshots, using the
`KF-CONTROL-HISTORY-0.2-draft` signature domain. Control-binding checkpoints use
`KF-CONTROL-BINDINGS-0.2-draft` and retain their existing exact per-phase installed
control/revocation verification. v0.1 checkpoints keep their original domains.

## Evidence and limits

The [required software verification](../results/verification/rfc-m7-leased-lineage-2026-10-14/README.md)
includes real TLS/DPoP/etcd prevalidation/admission/issuance, post-withdrawal exports,
independent tampering/version refusal and all three shipping offline verifiers.
Membership, providers and observer custody in these tests are software fixtures.

Unsigned lineage alone does not prove consensus comparisons. A separately approved
observer attests its ledger observation, under honest runtime/ledger operation,
protected observer custody and clock trust. Membership lifecycle history and
historical review enrollment/challenge consumption remain missing links; review
rules are re-evaluated from signed evidence, without proving original consumption.
Original runtime authentication, target effects and complete writer coverage are
still not established. Physical review and accepted enterprise custody remain
open. [M7d2 Node Agent Adapter](AGENT_STATIC_LEASES.md) now adds lease acquisition;
[M8b1 native fixed-cost leaf reservations](NATIVE_RESERVED_LEAF.md) are now
delivered; versioned reserved history/refinement is the next software increment.
