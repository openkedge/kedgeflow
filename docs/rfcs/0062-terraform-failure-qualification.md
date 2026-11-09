# RFC 0062: Terraform failure-boundary qualification

- Status: Draft; test-only supplement to RFC 0060/0061
- Runtime/wire change: none
- Milestone: N2d, six controlled failure/state-change cases

Use a fresh protected v0.2 saved plan per case, real target/backend, shipping
gateway/broker, official SDK, fresh signed admission/issuance and original native
claim/permit/dispatch. Generated same-host identity/evidence/policy roles remain
explicit. An authenticated test relay gates only declared native request/reply
points; it is not a production fault API or fabricated outcome oracle.

Certify SIGKILL after durable intent before reply, after effect before intent
outcome retention, and after applied intent before ordinary publication. Before
native write, a held request must not be forwarded; after commit, retention must
be established independently of reply delivery. Also certify domain revocation
at intent CAS, external target drift after authorization before runner checks,
and observed SIGSTOP/SIGCONT spanning original grant expiry.

Before intervention verify grant validity, target UID/annotation/resourceVersion
and backend hash/lineage/serial. Verify the intended signal, CAS refusal or external
state transition actually occurred. Missing hooks and incidental expiry cannot
count as success.

Read native status, intent and counters independently of agent output. Crashes
retain ordinary `dispatch_authorized` with started/applied intent. Neither target
coincidence nor applied intent alone may promote ordinary status. Revocation/drift
retain unknown without an intent; suspension past expiry retains not_dispatched.

Restart gateway and SDK under current disclosure-only credentials after execution
expiry/domain revocation with broker stopped and writer absent. Assert the same
grant/attempt, no new execution/outcome writes, unchanged intent/backend and no
tools/call retry. Account separately for the external mutation and independently
observe final target state. Verify namespace ownership before cleanup.

See [the guide](../TERRAFORM_FAILURE_QUALIFICATION.md) and its verification record
for measured results, preliminary fixture failures and limits. This does not
qualify active-child termination, general dependency invariants, multi-resource
partial apply, automatic publication repair or production isolation.
