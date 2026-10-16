# RFC 0051: Native inverse authority across stale logical SQL restore

- Status: Draft
- Milestone: M8d3e
- Prerequisites: RFCs 0030, 0046–0050
- Owners/reviewers: unassigned

## Contract

A stale SQL backup can retain the forward commit and protected inverse snapshot
while losing a later inverse commit. Missing lookup on that copy cannot revoke a
retained signed receipt, certify no effect, refund consumed compensation capacity
or authorize another attempt. Keep the native authority ledger, independent
write-ahead witness, original identities and external history outside the SQL
restore. This RFC qualifies those existing invariants; it adds no wire profile,
production restore tool, schema or migration.

Stop mutation services and their completed authority operations before restoring.
Use a fresh disposable database with CONNECTION LIMIT 0. Exercise actual login
refusal for both forward roles and the inverse executor, reader and barrier roles
before and after real pg_restore. Restore without ACLs/ownership adoption; while
still fenced, remove PUBLIC and original application schema/table/function/database
privileges. Rotate the restored resource incarnation. Admit only the original
inverse query role with CONNECT, schema USAGE and its exact lookup function.
Forward, inverse execution and barrier logins remain denied; query-role mutation
and normal target database preflight must refuse. No native service resumes and
no original request is reapplied, even as a negative test.

## Two outcome cases

Capture a real custom-format pg_dump after the original forward commit/barrier
and before fresh inverse authority is claimed. Execute the one inverse through
native admission, one-shot broker authorization, signed compound binding and the
shipping mTLS target. Hold its actual COMMIT reply in an external relay, kill the
target and return unavailable. Preserve the actual committed SQL result outside
the stale backup. Permanently stop the shared root and wait for real grant expiry.

1. **Original native uncertainty:** do not recover against the current SQL source.
   After stale-copy restore, query only that copy for the original attempt. Missing
   lookup leaves a signed unknown receipt, the same original claim/nonce/grant and
   held spend. The test-owner's external commit record is not a trusted receipt
   source and cannot silently promote the native outcome.
2. **Original signed commit:** recover against the original target before stopping
   it for SQL restore. On the stale query-only copy, repeated native recovery must
   retain the exact committed signed receipt without querying or overwriting it.
   Historical complete lineage can remain `compensated`, although the restored
   live row is the earlier forward state. Historical classification supplies no
   execution authority or claim about that restored live state.

In both cases the actual source commit remains independently queryable in the
fixture, the restored lookup stays absent, the restored row/version/fence does
not change during reconciliation and the rotated incarnation stays intact. The
native forward budget and held inverse spend remain unchanged. Original target
sends stay at one; there is no new mint, resend, replacement claim or dispatch.
The same witness enrollment remains checked; no authority prefix is restored.

## Verification and limits

Required native tests use actual pg_dump/pg_restore, shipping inverse execution,
real clock expiry, query-only native recovery, original signed history and public
compound-lineage verification. Pin dump and external-history hashes, retained
receipt identity, connection/role refusals and held costs in the full required
source-pinned conformance evidence.

This is a stopped logical SQL copy in one disposable local cluster with generated
identities, one OS UID and fixture providers. The external record is test-owned
and the witness is a separate local process. It does not establish physical SQL
backup/PITR/cutover, separate storage or credential custody, production retention,
accepted external historical evidence ingestion, complete deployed writers or
independent implementation acceptance. A real restart requires accepted fresh
CTD/contract/target/authority enrollment for the new incarnation and reconciliation
of original history. Old native authority cannot be rebound to the copy. Wider
crash/partial-failure matrices, multi-contract inverse families, dynamic delegation,
full A2A peers, independent saga acceptance and actual Kubernetes drain remain
open. M8 is incomplete.
