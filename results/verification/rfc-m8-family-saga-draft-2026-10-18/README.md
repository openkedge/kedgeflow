# M8 family stop reserve and RFC 0054 proposal validation — 18 October 2026

Baseline: fc54d0e. The [proposal implementation boundary](../../../docs/FAMILY_SAGA_DRAFT.md)
and [RFC 0054](../../../docs/rfcs/0054-multi-contract-family-saga.md) describe
strict multi-contract plan, signed owner-intent and complete native-inventory
validation. The proposed native execution profile remains disabled.

The complete required frozen-source run passed **459 Rust tests across
54 binaries**, **26 SQL storage/peer/restore groups**,
**32 Python tests**, both existing Node vector suites, formatting, Clippy, Ruff,
mypy and frozen schema/whitepaper checks. Required-mode ignored/skipped tests and
failures: zero. All **527 source files** stayed unchanged throughout and
after qualification. Source archive, source/evidence hashes, observations and
command/tool logs retain the exact tested source. Earlier committed evidence,
fixtures, frozen schema/paper and both SQL migrations remain unchanged.

## Qualification

Five new native cases supplement the previous required population:

- A large valid family record reaches a serialized state / encoded etcd wire
  reserve before exhausting branches or history. Further delegation refuses
  without mutation, while permanent root stop and separate observer audit replay
  succeed with the same held allocations. Identical family comparisons are
  deduplicated; conflicting comparisons and inverse-only wire bounds remain.
- A two-member proposed plan rejects missing/duplicate members, unknown/self/
  cyclic dependencies, substituted operations/namespaces, observer/owner role
  collisions and excessive validity. Legacy omitted-plan registration encoding
  remains stable. Both family construction and native service attachment refuse
  the new execution profile before any marker write.
- Owner intents bind the original family, head, permanent operation key and exact
  proof digest. Non-owner signatures, changed signed fields, expired/future
  intent windows, unknown/duplicate fields and missing required proof refuse.
  Historical observation may be validated after root expiry; compensation
  preparation may not. This is validation, never a retained phase transition.
- Complete actual native histories distinguish unissued, issued/unclaimed and
  originally claimed unknown work. Missing planned members, histories,
  authorization or original signed outcome lineage refuse; prior authority and
  event history cannot disappear in a later snapshot. The fixtures are separate
  native namespaces, so this case does not claim atomic multi-member capture.
- Actual SQL forward commit and original inverse authority/target effect exercise
  complete paired evidence from absent inverse through an unknown original
  attempt to committed compensation. Later inventories retain original
  authorization, binding, qualifications, attempts and known receipts; omission
  and rollback refuse. This remains one selected inverse contract, not the
  proposed global runner. Paired forward public trust must be identical, and
  family signing keys cannot also act as native observers.

The first focused attempts are retained byte-for-byte as gzip with original
SHA256 pins. They exposed a private test-helper call, missing initial outcome
receipt, premature recovery before the original execution budget elapsed, and
an actual missing proposal role-separation check. The helper uses retained
fixture records; recovery now advances the fixture clock past the unchanged
production window and retains its original receipt. The role check was fixed.
A nested-if Clippy failure was corrected before freeze. The final focused run
passed all four new proposal cases; required full conformance then passed this
exact frozen source. Production validity, unknown consumption and replay guards
were not relaxed to make the fixtures pass.

The earlier [host-suspension preliminary attempt](../rfc-m8-family-saga-draft-suspension-preliminary-2026-10-18/README.md)
failed across a 162-second clamshell sleep and is retained separately with this
exact source. The required full suite was rerun without source changes or relaxed
production windows.

A second [disk-exhaustion preliminary attempt](../rfc-m8-family-saga-draft-storage-preliminary-2026-10-18/README.md)
failed when etcd could not allocate WAL space. Only rebuildable outputs for this
Cargo package were cleaned to remove stale variants. The accepted build explicitly
pins the existing no-debug/no-incremental defaults; it does not change runtime
guards. The exact build environment is in qualification-build.json.
The final suite uses the same source and unchanged runtime enforcement.

## Meaning and remaining gates

RFC 0054 supplies proposal structures and validators only. Unsigned snapshots do
not authenticate current storage epoch, qualify absence or prove one atomic
multi-member capture. Family::new and Selection::attach deliberately reject this
profile. No new phase/claim/compensation capability is enabled.

Global native phase/epoch enforcement, consistent all-member capture, one-CAS
compensation entry, the global original inverse claim slot, shipping protected
multi-contract runner and complete signed aggregate checkpoint/replay remain
unfinished. Actual separately governed Level C Kubernetes drain, independent
A2A authority implementation, accepted deployment/writer coverage, physical
restore/cutover and independent custody/acceptance remain open. M8 is incomplete.
