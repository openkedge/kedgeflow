# M8c1 authenticated A2A root views — 14 October 2026

Baseline: aece222. [RFC 0040](../../../docs/rfcs/0040-a2a-root-resolution.md)
and the [operator guide](../../../docs/A2A_ROOT_RESOLUTION.md) add the optional
activated root-reference endpoint, immutable reader ACL, scoped hierarchical
reservation views, independently pinned HTTPS client and shipping control CLI.
This is disclosure only: every successful view declares execution authority and
child-grant support false. The service implements no core A2A messaging/tasks.

The complete required run passed **343 Rust tests across 46 binaries**, **18 SQL
storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips. All **435 source files** remained unchanged
throughout the complete run and match final-source.json. summary.json pins source,
commands, logs and tools. Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3, etcd 3.6.5,
Python 3.13.12, Node 25.2.1 and pinned official MCP client 2.3.0. No new dependency,
frozen record, fixture, whitepaper or SQL migration change was required.

## New observations

Twelve test groups exercise the bounded software contract:

- An actual native TLS/DPoP/etcd resolver and pinned Rust client observe nested
  composite/unknown reservations. Scope narrows the reader and selected parent.
  Different request/task/context IDs return the same snapshot digest and leave
  capacity unchanged. Composite execution and replacement attempts still refuse.
  Stop is visible without reopening the original unknown attempt.
- Correctly signed OAuth tokens for another subject, insufficient scopes and a
  different enrolled TLS workload refuse. Missing auth, replayed DPoP, untrusted
  TLS, wrong roots/delegations/endpoints, widening and missing/wrong parent
  selectors do not disclose a view.
- Missing/wrong/duplicate activation, conflicting extension versions, duplicate
  scope/object keys, legacy/mixed Part discriminators, extra fields, unsupported
  generations/assurance and allocation-bearing saga references refuse. Unrelated
  extension URIs can coexist with the exact activated extension. Browser origins,
  wrong authority, query aliases, methods and content types refuse.
- Withdrawal races a native resolution. A permitted earlier view is still
  non-authorizing; subsequent reads refuse. Recreated clients cannot reenroll or
  replace the logical ACL by changing readers. Configuration drift also refuses
  while the original ACL is active. Capacity remains identical.
- Missing/corrupt ACL, root and domain markers refuse. Duplicate retained scopes
  and over-budget siblings outside the selected reader scope do not produce a
  normalized or partial-success view. Complete conservation is validated.
- The pinned client refuses an unapproved reference destination before any trap
  request. An authenticated redirect does not forward credentials. Forged
  execution flags, scope/correlation/tenant/domain, malformed digests, duplicate
  sets and extra fields in authenticated software responses refuse.
- Unavailable storage returns no library view. An enrolled restore marker without
  its witness blocks the native endpoint and withdrawal; removing the test-owned
  marker leaves the original capacity unchanged. Existing dedicated restore
  qualification remains part of the required regression corpus.
- The shipping `kf-control` process validates protected generated material and
  prints a capability fragment without ACL enrollment. Operator enrollment then
  permits an actual authenticated HTTPS resolution. Permanent withdrawal is
  observed by the running process and after restart. The existing admission route
  retains its authentication boundary. Removing optional A2A configuration makes
  the route absent; malformed/drifting configuration refuses. etcd traffic uses
  actual pinned mTLS forwarding with the fixture operator token/workload checked.
- Native reserved v0.2 issuance and claim produce the original unknown attempt.
  The trusted resolver reads that native state while preserving exact costs,
  attempt identity and history head bytes. Native stop remains visible, and native
  issuance/replacement consumption does not reopen afterward.
- Two shared-auth instances race the same DPoP proof in real etcd; exactly one
  authenticates. A recreated instance refuses the replay. The accepted identity
  may obtain a non-authorizing view with unchanged capacity.

Only the new results directory was created. Previous evidence is unchanged.
Before the complete run, cleaning disposable KedgeFlow package build outputs
reclaimed 2.0 GiB. The complete run passed on its first attempt with fixed sources.

## Limits and next work

The wire conventions are pinned to A2A 1.0.0; the method and extension URI are a
separate KedgeFlow draft. Printing an AgentExtension fragment does not supply or
qualify a complete AgentCard/task server. Native client/server implementations in
this repository are not independent peers. Keys, OAuth issuer, workload CA,
clocks, TLS forwarder and deployment custody are software fixtures.

Views attest neither execution permission nor fresh admission, target commit,
complete signed history or ledger consensus. They contain no sibling allocation
list or free capacity. ACL/configuration and ledger correctness remain trusted.
Registration/messages are bounded to 64 KiB and 64 readers; snapshots retain RFC
0032's 128 KiB/256-allocation/depth-8 bounds. Generation 1 is fixed; ACL rotation,
replacement and reenrollment are unsupported. Withdrawal controls this disclosure
ACL, not the underlying budget or independently issued grants.

M8c2 must implement separately versioned hierarchical executable grants and
conserved child issuance/claim/dispatch. M8c3 must retain/replay complete hierarchy
history. Durable saga/compensation, actual governed Kubernetes drain, accepted
writer/predicate coverage, enterprise/custody/physical qualification and independent
A2A/release acceptance remain open. Linux separate-account and minimum Rust CI
execution were not observed locally.
