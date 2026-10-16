# M8d3d bounded inverse failure recovery — 16 October 2026

Baseline: ed80b46. [RFC 0050](../../../docs/rfcs/0050-inverse-failure-recovery.md)
and the [failure guide](../../../docs/COMPENSATION_FAILURE_RECOVERY.md) qualify
shipping inverse target process loss and stopped logical authority rollback.
Existing production protocols, execution limits and SQL migrations are unchanged.

The final complete required run passed **439 Rust tests across 52 binaries**,
**26 SQL storage/peer/restore groups**, **32 Python tests**, both Node suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. There were no
Rust failures, ignored tests or required-mode skips. All **506 source files**
remained unchanged through and after the run. No source repairs occurred during
or after it. `summary.json` pins tools, commands, source and raw logs;
`source-observations.json` retains intermediate/final freeze checks;
`final-source.json` pins the same source and new evidence. Shipping commands
remain 22. Earlier committed evidence and frozen inputs remain untouched.

Three new native cases compose actual SQL forward commit, original-result
barrier and separate applicability, fresh inverse admission/issuance, verified
subject/actor signatures, one-shot native broker authorization, mandatory signed
compound binding, common resource fence and shipping inverse target mTLS:

- SIGKILL while actual inverse SQL waits on an independent owner's protected row
  lock. Release the lock, wait for the dead backend to exit and restart the target.
  No inverse result appears; the original forward row/version/fence stays intact.
  Recovery after actual expiry and shared stop retains the original unknown
  attempt and held cost. Missing lookup never proves no effect or permits retry.
- SIGKILL after actual COMMIT while an external mTLS relay holds the successful
  reply. Restart before returning unavailable. The restored row/version/fence and
  original SQL root/grant/attempt survive. Query-only recovery after expiry/stop
  retains the same committed receipt on repetition, with one target send and
  unchanged cost. No replacement claim, remint, resend or refund is allowed.
- A separate disposable witness protects the paired shared namespace. Capture
  its local prefix before inverse issuance and after committed recovery; stop
  authority servers and replace only local values with the old capture. Witness
  checks, re-enrollment, original/replacement claims, recovery, audit export and
  gate removal refuse. The unconfigured ledger specifically reports the required
  witness quarantine. Independent target query still returns the original commit.
  Restore exact latest key/value pairs and verify the same receipt, spend and
  retained proof records. Fresh observer capture attestations may differ.

Every case independently verifies the complete compound lineage as unresolved
or compensated, including original signed authority, qualifications, broker permit,
held spending and receipts. The test harness now enrolls the witness before paired
writes and checks it when joining the existing namespace. Its explicit 15-second
inverse policy and 60-second acknowledgement allow debug-build witness checks;
the broker credential ceiling stays five seconds and recovery waits for actual
expiry. Production timing defaults are unchanged. Development corrected a SQL
column assertion, short fixture timing and comparison of freshly signed observer
checkpoints. A preliminary full run caught a gate-removal negative missing its
inverse execution profile. Its complete original logs and source archive remain
in `rfc-m8-inverse-failure-preliminary-2026-10-16`; the final run keeps every
execution pin and omits only the witness. All repairs preceded the final freeze.

## Limits and remaining milestones

This is disposable local Darwin software qualification with generated identities,
fixture evidence/capacity providers and one OS UID. The witness is a separate
process, not an accepted independent backup or failure domain. The stopped logical
rollback replaces authority-prefix values while actual SQL and witness remain
intact. It does not qualify inverse SQL storage restore, physical backup/cutover,
all deployed writers, production custody or independent implementations.

One exact inverse contract remains selected per paired service. Multi-contract
inverse families, dynamic delegation, full/independent A2A peers, independent
whole-saga acceptance, inverse SQL storage restore and wider gateway/broker/
witness/partial-failure matrices, actual Kubernetes drain and enterprise/release
acceptance remain open. M8 remains incomplete. No automatic resume, global
atomicity, physical rollback or blind retry is claimed.
