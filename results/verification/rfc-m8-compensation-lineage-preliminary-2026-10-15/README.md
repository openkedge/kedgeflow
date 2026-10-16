# Preliminary compound-lineage corpus — 15 October 2026

Baseline de23051. The required corpus passed 435 Rust tests / 52 binaries, 26 SQL
groups, 32 Python tests, both Node suites and all quality/frozen checks. All 503
source files stayed unchanged throughout this run. The original logs and summary
are retained byte-for-byte; source.zip contains the exact source matching their
hashes. This directory was moved from the planned final path after completion.

Additional review identified a missing export consistency check for allocated
authority: compare its exact unclaimed native root/grant and unused nonce, for both
forward and inverse leaves. This preliminary pass is not final qualification for
that hardening. The later final record at
[compound lineage](../rfc-m8-compensation-lineage-2026-10-15/README.md) qualifies the
hardened source and additional native corruption/refusal cases. It does not claim
M8 completion or independent/deployed acceptance. Earlier retained results remain
unchanged.
