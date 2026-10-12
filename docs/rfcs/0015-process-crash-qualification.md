# RFC 0015: Process termination and retained recovery qualification

- Status: Draft
- Milestone: bounded M4c1
- Baseline: `26dcebe`; RFCs 0008, 0010 and 0014
- Owners/reviewers: unassigned; runtime, resource and SRE owners
- Wire compatibility: no new wire profile or production crash-control API

## Contract and boundaries

Qualify actual `kf-proxy` and `kf-recover` child processes using test-owned mTLS
ledger transport barriers. Block immediately before a selected transaction is
submitted, or after a successful etcd transaction but before its response reaches
the process. Kill the blocked process forcibly and await its termination before
starting a replacement. A before-submit barrier never later forwards that request.
Use unique namespaces, bounded barrier/startup waits and kill-on-drop child cleanup.

The parent hosts an authenticated software broker and an atomic fenced/versioned
mock target with retained attempt/grant observations. A target barrier can block
after its commit but before returning the reply. Ledger terminal-write barriers
distinguish target reply from persisted gateway completion. Recovery barriers
distinguish signed receipt preparation from persisted receipt/head state.

The process-crash matrix uses operator-bootstrapped signed fixture grants and the
gateway's explicit unmanaged fixture configuration. Current managed control checks
are separately qualified by RFC 0014; this matrix does not qualify managed control
renewal under crash, full admission lineage, production broker/identity services,
real enterprise target durability, power loss, host failure or backup restore.

## Required matrix

| Termination boundary | Retained state before recovery | Required behavior |
| --- | --- | --- |
| Before claim submission | Unclaimed, nonce absent | Restarted status stays unclaimed; worker has no attempt to recover |
| Claim persisted, response withheld | Claimed, original nonce/attempt | Recovery seals not-dispatched without target query |
| Before dispatch-authorization submission | Claimed, credential exchange completed | Recovery seals not-dispatched; no additional exchange or dispatch |
| Dispatch authorization persisted, response withheld | Possible send; target not contacted | Authoritative not-found remains consumed unknown; never infer no effect |
| Target commit, response withheld | Dispatch authorized; target committed once | Query resolves original commit, without dispatching again |
| Target reply received, before terminal submission | Dispatch authorized; target committed once | Query resolves original commit, without dispatching again |
| Terminal state persisted, response withheld | Committed with retained gateway evidence | Recovery signs receipt without another target query |
| Before receipt transaction submission | Prior attempt/outcome retained; no receipt | New worker recreates and persists the original correlated result |
| Receipt/head persisted, response withheld | Immutable correlated receipt/head | New worker reuses it; no duplicate report or additional target query |

## Acceptance

At every reached barrier assert the intended etcd writes or mock target commit
have actually occurred (or remain absent), then kill the actual PID. Restart the
same shipping binary and authorize fresh query-only disclosure after grant expiry.
For post-claim cases the nonce must keep the original attempt and replacement or
new claims must refuse. Repeated status and repeated worker restarts must preserve
broker exchange counts, target dispatch/commit counts and receipt identity.
Verify the retained signed grant/receipt/evidence chain offline.

Record each matrix case with its reached boundary, pre/post state, count changes,
process exit and receipt count in test output. Tests must fail when the required
etcd endpoint is absent. No production delay flags, caller-controlled barriers,
blind retries, nonce refunds or automatic allowance restoration are introduced.

## Remaining milestones

M4c2 specifies restore quarantine with an independently retained authority
high-water mark. Restored local state cannot establish its own freshness. M4c3
adds owned incidents and bounded automatic delivery. Managed process-kill coverage,
target-process failure/durable real-resource recovery, production custody/RBAC and
independent-peer acceptance remain enterprise release gates.
