# RFC 0017: Owned unknown incidents and automatic retained delivery

- Status: Draft
- Milestone: bounded M4c3
- Baseline: `0fdfccb`; RFCs 0010, 0011 and 0016
- Owners/reviewers: unassigned; OutcomeService, collector, resource and SRE owners
- Profile: `KF-OUTCOME-SUPERVISION-0.1-draft` (separate internal storage contract)

## Contract and boundaries

A separately configured `kf-supervise` process composes query-only recovery with
owned escalation and bounded retained outcome delivery. It cannot dispatch, mint
grants, refund consumed allowances, clear restore quarantine or prove no effect.
It uses current OutcomeService/reporter credentials and independently approved
collector keys. Delivery continues using RFC 0011; frozen signed records do not
change. An incident is protected operator state, not a target-signed assertion or
an external page/email/ticket. Its owner is an operator-enrolled team/service ID,
not a temporary worker lease or proof that a human responded.

## Durable incident contract

The first retained `unknown` journal transition anchors `unknown_since`.
`deadline = unknown_since + unknown_after_ms`; the duration is operator configured
in 1..604800000 ms. Owner ID and policy digest are fixed at creation and MUST NOT
change on restart. New owner/duration registrations that conflict with a retained
incident refuse; transfer and policy migration require a future explicit contract.
A trusted clock supplies current time; clock regression refuses state advancement.

Verify the signed current receipt and retained evidence against the configured grant
and outcome pins before advancing incidents. Full receipt-chain export is required
for delivery only; exceeding its bound must not suppress owned escalation.

An immutable event chain and a CAS head under the original attempt retain at most
three transitions: `open`, `escalated`, `resolved`. Open is retained when unknown
history exists, including late discovery after resolution. Escalation occurs only
while current authority state remains unknown and time reaches the original
deadline. Resolution requires the current retained committed outcome; it does not
restore execution allowance. Repeated/concurrent workers reuse the same event,
owner, origin and deadline. Every event compares the current attempt/receipt head,
original nonce/root/grant, retained execution/index and first unknown journal.
A raced resolution cannot be overwritten with a stale escalation.

## Ordered automatic delivery

After recovery, verify the complete retained signed receipt/evidence chain with
independently configured grant and outcome keys. Export is bounded to 64 receipts
and 16 MiB. Walk oldest first; skip only exact locally retained acknowledgements
that pass signature/correlation verification. A pass handles at most the configured
1..64 previously unrecorded receipts per attempt; the page has 1..64 attempts.
Each missing local receipt first performs an authenticated exact-receipt lookup.
Only an explicit missing acknowledgement permits reporting that same retained
receipt. Unavailable, invalid or uncorrelated lookup/reply ends that attempt's
pass. Later passes resume from verified durable progress with fresh DPoP proofs.

A signed acknowledgement can be persisted locally only with exact receipt and
evidence retention, original consumed nonce and execution binding, and verified
local predecessor progress for that collector. The local record is immutable;
concurrent duplicate workers reuse the same bytes. A collector acceptance followed
by a lost reply or worker death leaves local progress absent; restart resolves it
through lookup without reordering or generating replacement receipts. Collector
identity/URL bindings partition progress; trust pins remain independently supplied.

No exclusive network-delivery lease is claimed: concurrent workers can submit the
same report, and the existing collector deduplicates it. Local progress records
verified collector acceptance, not independent custody/availability or target
commit proof. Scheduling is bounded sequential polling, with operator-selected
page/poll limits; the cursor is process-local and restart rescans immutable progress.
It is not a hard latency SLO, replicated scheduler or enterprise paging integration.

## Restore, authentication and implementation

All incident/progress reads and writes use the shared ledger gate from RFC 0016.
If recovery or freshness reads refuse, do not deliver from cached state. Restored
consumption/history cannot be used to resume supervision without its independently
pinned ready witness. Material-only `--check` does not certify remote freshness.

The closed supervisor configuration nests the existing recovery config, fixed
collector registration/TLS/token/DPoP key files, incident policy and receipt budget.
The recovery signing key must match the enrolled outcome public key; source,
grant pins/audience and conflict domain must align with the delivery registration.
Tenant remains a dedicated operator namespace assertion because the frozen grant
has no tenant field. Multi-tenant deployment is unqualified.

A bounded `--once` prints page counts and returns nonzero if any entry is
unavailable. Continuous mode resumes scans after bounded polling; each report
lookup/submission has a five-second timeout. Unknown incidents remain owned even
when the collector is unavailable. Delivery errors never imply no effect or reset
the unknown-age origin. Admission, issuance, gateway and collector stay separate.

## Acceptance and remaining qualification

Test real etcd plus native software mTLS/DPoP collector, ordered delivery budgets,
unknown deadlines, owner persistence/config conflict, resolution, concurrent
workers, collector loss/restart, lost acknowledgement replies, local progress
write failure and actual supervisor process restart/termination. Repeated passes
must preserve original attempts, receipt/ack identity and consumption. Assert
invalid/corrupt progress and restore-required state fail before network reporting.

Combined managed execution/restoration, independent production identities and
custody, real incident routing/ownership handoff, token rotation, receipt-chain
pagination, latency/scale and independently implemented peers remain release
gates. M5 begins enterprise identity/credential lifecycle qualification after
this bounded software slice.
