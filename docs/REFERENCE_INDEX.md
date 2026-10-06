# Whitepaper v0.9 artifact references

Readers of the frozen paper can use this public repository instead of local
`openkedge/code/kedgeflow` paths. Runtime baseline links pin the exact commit named
in Sections 8.4 and 10.4. Frozen-paper links pin the reconciliation commit containing
the final exported package. Implementation development continues on `main`.

| Paper reference | Repository artifact | Pinned public URL |
|---|---|---|
| Primary Rust crate / `kf-proxy` | [`crates/kedgeflow`](../crates/kedgeflow/) | [Runtime baseline 0a06d00](https://github.com/openkedge/kedgeflow/tree/0a06d00e2d6f951b7763b85ea01694f31385b159/crates/kedgeflow) |
| `spec/kedgeflow.schema.json` | [Schema](../spec/kedgeflow.schema.json) | [Baseline schema](https://github.com/openkedge/kedgeflow/blob/0a06d00e2d6f951b7763b85ea01694f31385b159/spec/kedgeflow.schema.json) |
| `fixtures/` | [Signed fixtures and public test keys](../fixtures/) | [Baseline fixtures](https://github.com/openkedge/kedgeflow/tree/0a06d00e2d6f951b7763b85ea01694f31385b159/fixtures) |
| `spec/validate.py` | [Offline validator](../spec/validate.py) | [Baseline validator](https://github.com/openkedge/kedgeflow/blob/0a06d00e2d6f951b7763b85ea01694f31385b159/spec/validate.py) |
| `docs/RUST_VERIFICATION.md` | [Original Rust verification](RUST_VERIFICATION.md) | [Pinned record](https://github.com/openkedge/kedgeflow/blob/0a06d00e2d6f951b7763b85ea01694f31385b159/docs/RUST_VERIFICATION.md) |
| `results/verification/` | [Original Rust results](../results/verification/) | [Pinned logs](https://github.com/openkedge/kedgeflow/tree/0a06d00e2d6f951b7763b85ea01694f31385b159/results/verification) |
| Frozen whitepaper PDF | [PDF](whitepaper/v0.9/output/pdf/kedgeflow-whitepaper.pdf) | [Pinned frozen PDF](https://github.com/openkedge/kedgeflow/blob/e3f4afd91f9d2c6de0045d0a90909e0fd0e7d06a/docs/whitepaper/v0.9/output/pdf/kedgeflow-whitepaper.pdf) |
| Frozen source and `FREEZE.json` | [Source package](whitepaper/v0.9/) | [Pinned frozen source](https://github.com/openkedge/kedgeflow/tree/e3f4afd91f9d2c6de0045d0a90909e0fd0e7d06a/docs/whitepaper/v0.9) |
| KF-GRANT-REF-0.1 | [Grant-reference transport](../spec/GRANT_REFERENCE_PROFILE.md) | [Frozen profile](https://github.com/openkedge/kedgeflow/blob/e3f4afd91f9d2c6de0045d0a90909e0fd0e7d06a/spec/GRANT_REFERENCE_PROFILE.md) |

## Supplementary historical Go artifacts

The paper also reports earlier Go proxy and admission/review experiments. They
are retained separately from the primary Rust runtime:

- [Go proxy raw results](../results/historical-go/prototype/results/), including
  the 6,560-claim matrix, official-client and boundary tests.
- [Go service raw results](../results/historical-go/services/results/).
- [Source archive](../artifacts/whitepaper-v0.9-go-experiments.tar.gz) and
  [SHA-256 inventory](../artifacts/whitepaper-v0.9-go-experiments.json), exported
  byte-for-byte from assurance commit `9ee111e46b32d212bc3d669c86d5dbe96d9d63b2`.

Extract the archive into a separate working directory. It preserves `acp/prototype`,
`acp/services`, `acp/spec` and `acp/docs/V0_9_VERIFICATION.md`, including dependency
locks, artifact READMEs, fixtures and historical results. The verification report's
other assurance-relative document/archive links refer to that original repository;
the frozen paper is supplied above. The experiments were not rerun for this Rust
publication and have not been integrated end-to-end with the Rust gateway.

## Schema identifiers and configured endpoints

The signed records retain `https://kedgeflow.dev/spec/...` as exact schema/profile
identifiers. Validators resolve them through the local published schema; they do
not fetch arbitrary URLs during authorization. This code publication does not
deploy that domain or turn illustrative admission/target URLs into live services.
Use the schema link above (or its GitHub Raw view) to obtain the machine-readable
file. Supply real independently trusted endpoints when configuring a deployment.
