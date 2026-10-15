# Retained pre-canonicalization run — 14 October 2026

This first complete software run passed 358 Rust tests / 46 binaries, 18 SQL
storage/peer/restore groups, 32 Python tests, both Node vector suites and all
quality/frozen checks. Its 441 source hashes were stable during the run.

Review then found that the new composite decoder could normalize unique unordered
scope arrays before signature checking. That did not change the represented
permission set, but it did not enforce the draft's exact signed JSON value.
This run is therefore preliminary evidence, not final acceptance of the parser.

The receiver was tightened to reject reordered signed scopes and duplicate signed
fields before normalization, with regression tests and an explicit ascending
UTF-8 byte-order rule. The [final complete run](../rfc-m8-hierarchical-leaf-2026-10-14/README.md)
qualifies those corrected sources. Original logs and summary here were moved
byte-for-byte into this separate directory; this explanatory file was added later.
No old committed evidence was changed.
