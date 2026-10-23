# Preserved required-run lint failure — 23 October 2026

This exact-source conformance attempt passed formatting and Clippy, then stopped
at Ruff. Ruff scanned the immutable previously committed M8e1 evidence finalizer
as current Python source. No required runtime population ran in this attempt;
this is not a conformance pass. source.zip, source-sha256.json, summary.json and
logs preserve the exact pre-repair source and failure before any source edit.

The repair belongs in source lint configuration: verification archives are
historical evidence, not editable source. Previously committed results remain
unchanged. A new complete required run must qualify repaired source.
