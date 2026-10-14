# M7d1 leased authorization lineage — 14 October 2026

Baseline: e7188e4. [RFC 0036](../../../docs/rfcs/0036-leased-authorization-lineage.md)
adds original membership/cache retention in admission and issuance transactions,
closed v0.2 lineage/history/control-binding profiles and independent historical
verification. [Operator guide](../../../docs/LEASED_AUTHORIZATION_LINEAGE.md).

The final required run passed **300 Rust tests across 44 binaries**, **18 SQL
storage/peer/restore groups** and **32 Python tests**, plus formatting, Clippy,
Ruff, mypy, Node vectors, frozen schema and whitepaper checks. No Rust failures,
ignored tests or required-mode skips. All **406 source files** remained unchanged
throughout the final run; summary.json pins commands, sources and raw logs.
Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3, etcd 3.6.5, Node 25.2.1 and Python
3.13.12. final-source.json pins final sources and evidence files.

## New observations

Five new test groups pass in the complete required corpus:

- Actual native TLS/DPoP prevalidation, admission and issuance retain original
  static packet, signed lease, member generation and phase snapshots. Historical
  export and the shipping lineage CLI verify the original chain after withdrawal
  and expected-generation replacement, without changing the exported records.
- Independent verification recomputes static input/registration/cache bindings and
  signed lid under approved signer/member pins. Altered generation, registration,
  active state, static packet/input binding/cache identity/lease, phase, authority
  digest and time, missing snapshots, absent trust and downgraded/unknown profiles
  refuse. Rewriting both phase and cache member generations still fails the signed
  cache identity check.
- Lease-enabled ordinary full-evidence admission also retains membership. Its
  v0.2 audit uses null caches, and a missing phase refuses export rather than
  reconstructing it from current membership.
- Harmless JSON formatting changes in signed proposal, CTD, manifest, lease and
  witnesses pass native admission/issuance and audit. Independent verification
  compares strictly parsed canonical signed records, preserving frozen reference /
  signature semantics while retaining the original raw cache.
- Actual managed governance publication/install/acknowledgement combines with
  leased admission/issuance, original claim and retained not-dispatched outcome.
  All three shipping offline verifiers pass. History verification survives member
  withdrawal. Independently re-signed malformed snapshots, version downgrades and
  mixed wrappers/checkpoints refuse. Old v0.1 schemas reject v0.2 carriage; the
  full legacy runtime/history corpus continues passing with its original domains.

No frozen schema, fixtures, whitepaper files, migration or previous evidence bytes
changed. A [preliminary passing run](../rfc-m7-leased-lineage-preliminary-2026-10-14/README.md)
retains the earlier 299-test candidate. It predates canonical signed-record
comparison and its regression test, so it cannot qualify this final implementation.
The final source received no implementation/schema/test/documentation changes
following the complete passing run; only this new evidence record was finalized.

## Reproduce and remaining gates

Install locked Rust/Node dependencies and Python development dependencies, and
provide PostgreSQL 18.3 and etcd 3.6.5. Select a new output directory:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd \
  python scripts/conformance.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --output results/local/leased-lineage-new
```

Membership, providers, authenticators and observer custody are software fixtures.
Unsigned lineage is not a consensus proof; a protected independent observer
attests its ledger observation, under correct runtime/ledger operation and clock
trust. Membership lifecycle and historical review challenge/enrollment state,
original runtime authentication, target effects and complete writer coverage
remain explicit gaps. This increment does not add membership checks to existing
grant claim/dispatch or make withdrawal retroactively revoke issued grants.

M7d2 Node adapter static-cache/JIT acquisition is next. Protected browser/physical
ceremony, approved enrollment/attestation and provider/custody lifecycle remain
open. Separate Linux account and minimum Rust CI observations remain unobserved
locally. SQL restore/budgets remain disposable same-host logical/storage-only
checks with authority_consumption_tested=false. M8 native reservation/grant/claim,
A2A/saga/compensation/drain and M9 independent peer/reproduction/release acceptance
remain open. This is software qualification, not enterprise or protocol release
acceptance.
