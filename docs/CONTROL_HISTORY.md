# Observer-attested governance history

[RFC 0013](rfcs/0013-control-history.md) implements bounded M4b3. Successful
native governance changes now append immutable per-domain history in the same
etcd transaction as their live state. History retains policy/descriptor
publications, installations, gateway acknowledgement renewals and all revocation
targets. Exact retries append nothing; failed changes leave history unchanged.
A missing or corrupt prior head event prevents an append.

## Protected export and offline verification

An authorized operator calls
`EtcdLedger::export_control_history(&candidate, &operation_key, &observer, &clock)`.
Configure `HistoryObserver` with its approved identity and a separately protected
signing key. The observer reads a captured history head and every immutable event
from genesis through that head, then the operation's RFC 0012 lineage. Its signed
checkpoint binds namespace, tenant/domain, history head/count/capture time and the
exact lineage digest. Authorize disclosure/storage: domain history can include
other operations' revocation identifiers and sensitive registration/evidence.
There is no agent-facing export listener or automatic observer signing service.

Verify the serialized `ControlHistoryBundle` with separate public trust:

```bash
cargo run --locked --bin kf-verify-history -- \
  --trust /secure/history/approved-control-registration.json \
  --bundle /secure/history/control-history.json
```

The [public test example](../config/control-history-trust.example.json) contains
operation trust, independently approved historical scope/acknowledger/key snapshots,
four administrative role key sets, observer identity/keys and namespace. Replace
it with approved deployment history. Each snapshot pins exact policy, ownership,
scope, input/admission/issuer trust digest and issuer membership. A new installation
or signing-key set needs independent approval; exported metadata cannot enroll it.
The observer key must differ from all administrative, acknowledgement, admission,
issuer, provider, proposal, registry, manifest and outcome roles. The CLI accepts
no private keys, service secrets or network key/schema retrieval.

Limits are 4 MiB public trust, 1–16 approved historical snapshots, 32 MiB bundle,
1 MiB per signed record and 1–64 complete history events, with RFC 0012's nested
lineage limits retained. Longer histories refuse export; no pagination or pruning
is implemented. Existing managed domains without a retained history genesis also
refuse export and new history mutations. They need an approved migration/restore
contract. Standalone legacy fixture issuance has no managed history claim.

## Result and limits

The verifier authenticates observer and original control signatures, contiguous
sequence/predecessors/head, accepted-time ordering, exact approved registrations,
current publication references at installation, revision/epoch monotonicity,
acknowledger identities/coverage/freshness and immutable revocation targets. It
runs RFC 0012's admission, Cedar, issuer and outcome checks under operation trust.
A matching approved installation and accepted gateway acknowledgement must cover
the signed admission and issuance times. Old issuer membership can remain verifiable
after an approved later installation uses a different issuer key.

The result lists verified events/installations/acknowledgements, matching
installation digests and known revocation targets/sequence/accepted times.
Revocation timing is labelled by recorded clock, with equal milliseconds explicitly
ambiguous. Every successful result states that operation control state is not
attested. It provides no non-revocation or historical execution permission.

The observer attests a protected ledger observation, rather than an etcd consensus
signature. accepted_at samples the authority clock before the successful mutation;
it is not a consensus commit timestamp or independently trusted distributed clock.
The export is a history prefix; an old valid checkpoint cannot establish the latest
head or exclude later revocation. Historical membership and gateway configuration
coverage do not prove operation-bound CAS checks, target/writer coverage, hardware
enrollment, production key custody or correct underlying ledger operation.

Remaining links are original OAuth/DPoP/mTLS transcript, operation-to-control/
revocation CAS sequence and clock trust, authenticated claim/dispatch/fence
allocation, registered tool-name mapping and target-signed proof with full writer
coverage. Native service recreation and externally approved issuer changes are
software qualification, not automatic production key rollover or trust discovery.
[M4b4](CONTROL_BINDINGS.md) now adds a separate operation-bound supplement
retaining actual transition control comparisons. This RFC 0013 format continues
to report the operation-control gap when used alone. Observer
RBAC/custody, pagination, automatic delivery/incidents, hard-crash cases and
stale-backup restore fencing remain open. See
[fresh verification](../results/verification/rfc-m4-history-2026-10-11/README.md).
