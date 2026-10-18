# Shared family authority

[RFC 0052](rfcs/0052-family-authority.md) adds runtime narrowed delegation and a
common held budget across cataloged native contracts. Every child remains an
independently admitted leaf or forward saga; an optional exact inverse still needs
its existing compound execution profile. Use a fresh etcd prefix and independently
approved protected files. This draft has local software qualification only.

The operator configuration contains `registration`, `etcd_endpoint`, `etcd_prefix`,
`etcd_ca`, `etcd_certificate`, `etcd_private_key`, `etcd_token_file` and optional
`restore_gate`. Registration is the exact closed Rust `family::Registration`:
profile/namespace/family/tenant/owner/principals/scope, both maximum budgets, validity times,
approved signer pins and up to eight child records. Each child has `id`, audited
`reservation`, nullable `topology` and nullable `inverse`. Domains, resources and
budget-root IDs must be distinct. Registration namespace must equal the configured
etcd prefix; signed commands cannot be replayed across prefixes. The immutable catalog is approved out of band;
no request can create a new contract or supply credentials.

```sh
kf-family --config /protected/family.json --check
# When a restore gate is configured, enroll it before the empty family:
kf-family --config /protected/family.json --enroll-witness
kf-family --config /protected/family.json --enroll
kf-family --config /protected/family.json --status
kf-family --config /protected/family.json --apply --command /protected/attach.json
```

`--check` loads local protected material and validates pins; it does not probe
remote authority state. `--enroll` is create-only and refuses an occupied prefix.
It also installs any catalog paired topology atomically. Do not run a separate
paired enrollment for that family. An attachment must precede child reservation
and control enrollment. Signing clients use `family::Command::sign` with the exact
current head, a permanent operation key and a short validity window; request data
is constrained by the [closed command schema](../spec/drafts/family-authority-command-v0.1.schema.json).
After an ambiguous reply, query status and resend only the exact original signed
command. An expected-head conflict requires an explicit new decision.

Set `family: {"registration": <same exact registration>, "child_id": "..."}` in
the child's control, governance, gateway, broker, recovery, outcome collector,
review, saga or compensation configuration. Keep its existing `reservation`,
`action_domain`, `inverse_execution` and restore-gate pins as required by that
profile. Forward family selection supplies the exact catalog reservation and
refuses conflicting explicit pins. Inverse governance/query can pin its lane
before execution is selected; fresh inverse authority still requires the native
compound execution configuration. Removing family configuration, selecting another
child/family or deleting family state makes native operations refuse.

The separate action-domain operator config also accepts family selection for
historical status and permanent physical-domain stop. Family enrollment already
created its paired topology. Family root/branch stop uses a signed `stop` command;
there is no resume, transfer or release command. Further commands refuse before they consume the reserved state and transaction space for a permanent root stop. Stop preserves every allowance,
claim and outcome. Query original attempts; do not repeat an uncertain effect.

```sh
kf-family --config /protected/family.json --export \
  --trust /protected/family-audit-trust.json \
  --observer-id approved-observer --observer-key-id observer-key \
  --observer-key /protected/observer-seed > /protected/family-bundle.json
kf-family --config /protected/family.json --verify \
  --trust /protected/family-audit-trust.json --bundle /protected/family-bundle.json
```

Audit trust contains the separately approved `registration`, `namespace`,
`observer_id` and nonempty `observer_keys` map. Public keys and the protected
32-byte Ed25519 observer seed file use standard base64. Export checks the retained
state with a final CAS. Offline verification ignores endpoint/credential files,
replays the signed family history and authenticates the checkpoint. It verifies
allocation history under observer/ledger assumptions, not a complete child saga
or a target effect. Continue verifying each child's existing native lineage.

The profile uses one shared etcd namespace. Child budgets are fully held before
native enrollment, and remain held after unused, failed, unknown, committed or
stopped work. Roots cannot spend as executable parents. Cross-namespace/cluster
coordination, dynamic catalog changes, independent task peers, complete
multi-contract inverse execution/aggregate evidence and Kubernetes drain are
separate remaining M8 work. Physical restore, all-writer coverage and independent
custody/acceptance remain required for a deployment claim.
