# Historical admission lineage verification

[RFC 0012](rfcs/0012-admission-lineage.md) implements bounded M4b2. A privileged
operator can export the retained signed proposal, CTD, manifest, witnesses,
certificate and issued grant alongside the original execution and outcome chain.
The separate offline verifier checks declared identity/tenant, evidence rules,
pinned Cedar policy, freshness at signed historical times, constraint/discharge
bindings and receipt predecessors. It returns evidence, with remaining gaps
explicit, and never creates executable authority.

## Export and verify

An authorized authority-side caller supplies the original operation key and
candidate to `EtcdLedger::export_lineage(&candidate, &operation_key)`. Authorize
storage/disclosure before using this library API: parameters and provider evidence
may be sensitive. There is no agent-facing export endpoint. The exporter reads
historical retained records, including after expiry or a current policy change.
Missing legacy admission chains or mismatched operations refuse export.

Serialize the returned `LineageBundle`, then run:

```bash
cargo run --locked --bin kf-verify-lineage -- \
  --trust /secure/history/approved-registration.json \
  --bundle /secure/history/lineage.json
```

The [public trust example](../config/lineage-trust.example.json) contains test
public keys, declared subjects, evidence schemas/rules and Cedar source. Replace
it with independently approved historical registration. The bundle cannot choose
trust, and a private key/service configuration is not accepted. There is no
network key/schema retrieval. The CLI emits JSON on success and exits nonzero on
invalid records, metadata, registration or carriage. Limits are 1 MiB for trust
and each signed record, 16 MiB for the bundle and 1–64 witnesses/receipts.

The verifier authenticates certificate/grant signatures before using admitted_at
and issued_at as historical clocks. Inputs are verified at both times, Cedar is
re-evaluated at admission, certificate TTL is bounded by approved policy/input
validity, and the issuer's full constraint/discharge checks run at issuance.
Unsigned retained metadata must agree with recomputed operation/binding/digests
and signed times. Execution parameters and the canonical grant must match.
An expired grant remains refused by the live verifier.

## What the result establishes

The result reports signed tenant, operation/proposal/certificate/grant identities,
historical times, witness/receipt counts and reported outcome. Signed proposal/CTD
tenancy is now transitively bound through the frozen grant's digests. This does
not change RFC 0011's operator-assigned dedicated namespace or qualify mixed
enterprise tenancy. Existing `kf-verify-outcomes` remains the partial verifier.

The export authenticates a retained receipt-chain prefix. It does not prove the
latest head or absence of later reports. Admission/issuance metadata and raw
journal are correlated records, without independent ledger-state signatures.
Journal shape, unique phases and operation bindings are checked; the verifier
requires claim and reported phases plus dispatch authorization for possible sends.
Collector acknowledgements are not included in this supplement.

Five missing links remain in every successful result: original OAuth/DPoP/mTLS
transcript, installed control/revocation/key history, authenticated authority
journal/fence allocation, registered tool-name mapping, and target-signed
commit/no-effect proof with complete writer coverage. OutcomeService attests a
retained observation; provider signatures do not prove factual state or hardware
enrollment. The frozen receipt effect_digest retains its parameters_digest
meaning; resolution_evidence binds the actual observation.

See [fresh verification](../results/verification/rfc-m4-lineage-2026-10-11/README.md).
[M4b3 governance history](CONTROL_HISTORY.md) now adds immutable control records,
a separate observer checkpoint and historical membership verification. Operation-
bound control/revocation CAS evidence remains M4b4.
Automatic delivery/incident handling, gateway/target kill cases, backup/restore
fencing, enterprise custody and independent-peer protocol qualification remain
open. M4 is not a completed deployment gate.
