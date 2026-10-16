# Preliminary inverse failure run — 16 October 2026

This source-frozen full required run failed one new gate-removal assertion.
The bypass ledger omitted its inverse execution profile, so it refused with
`inverse execution profile required` before reaching the intended witness check.
The target-kill cases and the remaining governance cases passed; this is not a
complete passing conformance record. Original runner logs and `summary.json`
remain byte-identical. `source.zip` preserves all 506 original source files;
`preliminary.json` pins their hashes and the archive.

The correction retains all inverse execution, topology and control pins while
omitting only the gate. The final full record is retained separately in
`rfc-m8-inverse-failure-2026-10-16`. No production behavior was changed.
