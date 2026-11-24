# Chrono maintenance-debt removal

The managed-fixture repair passed all eleven jobs in
[CI run 45287711693](https://github.com/openkedge/kedgeflow/actions/runs/45287711693)
for commit `0b14db20ac7bd0dc694f22d2e2e3a3b03d1f0f09`. Its dependency audit ran
before the existing Chrono exception expired at 16:00 PST on 23 November.
A subsequent live audit correctly blocked on `RUSTSEC-2026-0543`.

The replacement removes Chrono and nine orphaned timezone/platform packages from
the root lockfile, without introducing or upgrading any package version. Direct
UTC clock/formatting calls use the already locked `time` 0.3.55 crate. Timestamp
fractions, extended-year bounds, negative epochs, offsets and leap-second cursor
ordering retain the previous behavior.

The source-pinned Cedar 4.7.1 patch retains its datetime extension and replaces
only calendar construction and epoch conversion. A separate pinned `serde_with`
3.24.0 patch excludes unused Chrono conversions; explicit activation fails
compilation. See `vendor/README.md`, the archive-reproduction script and the exact
upstream/patched file inventory in `vendor/provenance.json`. Both public package
versions remain in advisory scope, and source drift or unknown Cargo patches
block auditing. The expired Chrono exception is removed.

The legacy corpus was captured from the original locked `bdf6fa3` ARM64 source
using `legacy-baseline.rs` as a temporary example, then removed from that source.
It contains 21 formatting cases, 21 parsing/ordering cases and 259 Cedar
expressions. The final replacement source passed this corpus using isolated
native tooling. Full Python regressions, targeted packaging/source-integrity
checks, type/format/lint checks and a fresh live advisory audit also passed.
`local-qualification.json` records their bounded scope and selected source hashes.

These are implementation regressions. Full same-source Linux CI remains a
required release gate; independent review, reproduction and deployed enterprise
acceptance remain `BLOCKED_EXTERNAL_INPUT`. The disposable Linux VM was removed
after host disk pressure caused filesystem I/O errors during a later test link.
That interrupted attempt is not counted as a passing Linux test. The legacy
corpus, prior qualified ARM bundle and earlier CI fixture evidence were retained.

No cloud runtime was started or updated. The earlier URL-patch ARM bundle remains
an older immutable candidate; these source changes do not qualify that bundle as
Chrono-free. A new source-bound ARM release and an approved runtime window are
required for subsequent pilot deployment work.
