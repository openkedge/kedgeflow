# Frozen KedgeFlow whitepaper v0.9

Frozen on 6 October 2026. Copyright (C) 2026 OpenKedge LLC.

This package retains the final source, PDF and protocol files. `FREEZE.json`
records their SHA-256 hashes, the paper source commit, the paper Git tag, the
primary Rust runtime baseline and the contract paths mirrored in the code repository.
The manifest excludes its own hash to avoid a circular dependency.

The paper remains a proposed architecture and interface specification. Freezing
it does not certify a complete control plane or a production deployment. The
primary runtime is the Rust `kedgeflow` crate `0.9.0-alpha.1` at
`0a06d00e2d6f951b7763b85ea01694f31385b159`. Sections 8.4 and 10.4 distinguish
its coverage and recorded checks from the supplementary Go experiments.

The Go proxy and admission/review experiments, along with historical raw results,
remain in the assurance repository at the paper source commit recorded in the
manifest. They were not ported or demonstrated end-to-end with the Rust gateway.
Rust verification logs remain in the implementation repository at the pinned
runtime commit. Runtime development continues independently of this freeze.

Read `output/pdf/kedgeflow-whitepaper.pdf`. To rebuild, copy this package to a
working directory and run `make deliverables` with TeX Live and BibTeX. PDF build
metadata may change on rebuild; the distributed PDF's hash identifies the frozen
artifact. The hash list also retains shared-contract validation tools and prior
results, whose dates and scopes are historical rather than new freeze-time runs.

Do not edit this package in place. Paper or protocol changes need a new version
and freeze manifest; Rust implementation changes may continue against this baseline.
