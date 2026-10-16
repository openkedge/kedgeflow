# Complete bounded saga and compensation evidence

[RFC 0049](rfcs/0049-compensation-lineage.md) defines historical evidence for one
registered fixed forward DAG and its one selected inverse contract. The native
`EtcdLedger::export_compensation_lineage` API requires an explicitly configured
inverse ledger, independent public trust and two protected observer signers.
It neither executes nor queries the target. Missing signed receipts require the
existing query-only recovery worker before export; absent or changing original
records refuse instead of being synthesized.

The compound observer must be distinct from the budget observer and all admitted
input, issuer, outcome, composite, barrier and applicability signers. Export pins
all planned allocations, all issued authorizations, every claimed original
outcome chain, complete budget/qualification histories, original inverse held
spend/binding/seal, unclaimed roots/unused nonces, mode and broker permit in one bounded native read transaction.
Service and ledger custody, observer correctness and clocks remain trusted.

Use protected public trust material to run the shipping verifier offline:

```sh
kf-verify-compensation-lineage --trust approved-compound-trust.json \
  --bundle captured-compound-lineage.json
```

The closed trust object has `forward` (the existing reserved-lineage TrustConfig),
`inverse` (historical LineageTrustConfig including the exact `inverse_contract`),
`topology`, `contract`, `broker` (the exact BrokerRegistration), `observer_id` and
base64 Ed25519 `observer_keys`. It contains no secrets or inferred bundle pins.
The library export API accepts the separately configured budget and compound
HistoryObservers; deployment must protect both signing keys and ledger access.
There is no new agent endpoint or automatic export-service enrollment.

The report verifies complete evidence and separately classifies workflow state:

| State | Meaning |
| --- | --- |
| `forward_only` | Compensation mode was absent at the captured checkpoint |
| `partial` | Compensation mode exists, but one or more committed effects remain uncovered, or inverse work is held/no-effect |
| `unresolved` | At least one forward or inverse original outcome remains unknown |
| `compensated` | The selected inverse is committed and every committed forward node is covered, with no unresolved original outcome |

Each planned node appears as `held`, `no_effect`, `unresolved`, `uncompensated` or
`compensated`. The one-contract implementation cannot report a multi-contract
saga compensated. All costs remain held. A complete report grants no execution,
refund, resend, replacement attempt, automatic service resume or scope expansion.

Reports are capped at eight planned nodes, 32 qualifications, 8 MiB and the native
export comparison budget. Oversized reports refuse; they are never truncated.
Historical stop and expiry preserve original evidence. Verification at original
recorded instants does not establish current execution permission or a new target
barrier. An already captured report remains valid evidence after later record
loss; a new export must refuse that loss.

Local software tests compose actual SQL original/restore state, independent
barrier/evaluator roles, fresh native admission/issuance, real broker identity
verification, original query recovery and offline audit. They exercise missing
receipts, missing/corrupt allocated authority, semantic substitutions even after re-signing the outer observer, wrong
roles, absent permits, bounds and stopped/expired recovery. They are not an
independently implemented peer, inverse crash/storage restore acceptance, deployed
custody/writer qualification or physical Kubernetes Level C acceptance. M8 remains
incomplete until those and the other roadmap gates are accepted.
