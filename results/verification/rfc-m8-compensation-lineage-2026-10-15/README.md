# M8d3c bounded compound saga evidence — 15 October 2026

Baseline: de23051. [RFC 0049](../../../docs/rfcs/0049-compensation-lineage.md)
and the [audit guide](../../../docs/COMPENSATION_LINEAGE.md) add complete historical
forward budget/authorization/outcome, qualification and selected inverse
binding/spend/authorization/outcome carriage, a protected native export and a
separately pinned offline verifier. Every claimed planned forward node must appear.
Complete evidence is distinct from successful compensation or live authority.

The final complete required run passed **436 Rust tests across 52 binaries**,
**26 SQL storage/peer/restore groups**, **32 Python tests**, both Node suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips occurred. All **503 source files** stayed
unchanged through and after the final run; no repairs were made during or after
it. `summary.json` pins commands, tools, source and raw logs; `final-source.json`
pins the same source and new evidence. Shipping commands now number 22.

Six native audit groups compose:

- Actual SQL forward commit, independently signed target barrier/applicability,
  fresh inverse admission/issuance, cryptographically verified native broker
  authorization and actual conditional restoration. Query-only recovery refines
  the original unknown attempt to committed after stop/expiry; historical export
  and the shipping offline CLI preserve both original receipt links and attempt.
- An unclaimed inverse stays allocated; an original pre-send claim can refine to
  proven no-effect. Both retain held costs and the report remains partial. Claimed
  operations with no signed receipt refuse export rather than inventing evidence.
- A registered two-node plan includes one actual SQL forward/inverse and another
  original pre-send no-effect node. Omitting that node, substituting its lineage
  or hiding the complete all-issued-leaf history refuses independent replay.
- Re-signed outer checkpoints, issuer-signed compound substitutions with coherent
  spend digests, recomputed broker permit IDs, changed qualifications/roles/
  attempts/costs, absent permits and unsupported carriage cannot override semantic
  correlation. Wrong namespace, unknown fields and oversized artifacts refuse.
- Actual native export compares all original receipts/evidence/journal and history
  records in its final bounded read transaction. Deleting a receipt between its
  read and that CAS refuses the export. Already captured signed evidence remains
  verifiable; restoring the exact original record permits a new export.
- Allocated authority requires the exact unclaimed native root/grant and unused
  nonce. Missing root/grant, a consumed nonce or a claimed root hidden behind an
  allocated spend refuses. Forward unclaimed authority uses the same comparisons.

The verifier checks independently pinned trust, complete same-head forward
histories, contiguous qualification replay, original inverse Cedar admission,
mandatory compound binding, common fence ordering, original held spend/refinement
and broker registration/claim/dispatch timing. It reports held, no-effect,
unresolved, uncompensated and compensated nodes. It never authorizes execution,
refunds capacity, allocates replacement attempts or contacts target services.

## Verification history and limits

A preliminary full corpus passed before the allocated-authority consistency
hardening. Its original logs/source observations and a source archive are retained
separately in `rfc-m8-compensation-lineage-preliminary-2026-10-15`. The final run
above qualifies the hardened source. Development also corrected test-only early
recovery timing and large async setup futures; production recovery guards remain
unchanged. Earlier committed evidence and frozen records/migrations are untouched.

This is local disposable Darwin software qualification with generated signer
identities, one OS UID and fixture evidence/capacity providers. Historical public
pins are independent of the exported payload; this is the same implementation,
not independent peer acceptance. Observer correctness, ledger custody/consensus,
clock, native authentication and original lineage trust assumptions remain.
Per-transition governance/installed-control and external provider/membership
history are not newly established by this wrapper. Actual target assertions and
complete deployed writer coverage still need accepted custody and operations.

One exact inverse contract is selected per paired service. Multi-contract inverse
families, wider inverse process/crash/storage restore qualification, dynamic
delegation, complete independent A2A/saga acceptance and actual Kubernetes Level C
drain remain open. The included restore rehearsal still covers the original
forward profile. M8 remains incomplete. No global cross-namespace/cluster
atomicity, physical rollback, blind retry or automatic service resume is claimed.
