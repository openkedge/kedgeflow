# Pinned dependency patches

`cedar-policy-core` 4.7.1 remains Apache-2.0 software by the Cedar contributors.
Its datetime extension uses the locked `time` 0.3.55 implementation for calendar
construction and UTC epoch conversion. The existing Cedar grammar, extensions,
integer arithmetic and error categories are retained.
Its minimum Rust version is aligned with this project's declared Rust 1.88.

`serde_with` 3.24.0 retains its upstream Apache-2.0/MIT notices. Its unused Chrono
conversion dependency is removed from the manifest so it also leaves the full
lockfile. Explicit activation of the excluded conversion feature fails compilation.
The project uses the other serialization helpers and does not expose this feature.

The original package archives are identified by immutable SHA-256 in
`provenance.json`, with every original and patched file hash. The audit verifies
the exact file inventories and continues querying OSV for both public package
versions. There is no Chrono advisory waiver. Independent security acceptance
remains `BLOCKED_EXTERNAL_INPUT`.

Reproduce into a new directory from the two original public `.crate` files:

```sh
python3 scripts/vendor-cedar-time.py \
  --archive /path/to/cedar-policy-core-4.7.1.crate \
  --serde-archive /path/to/serde_with-3.24.0.crate \
  --output /path/to/new-vendor-directory
```

The generator checks both archive hashes and exact patch contexts. Compare its
output with this directory. Git treats these files as exact bytes; line-ending
normalization would invalidate the source pins.
