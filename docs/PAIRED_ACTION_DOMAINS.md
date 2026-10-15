# Paired action control — M8d2b2a

[RFC 0046](rfcs/0046-paired-action-domain.md) defines the explicit fresh-domain
`KF-PAIRED-ACTION-DOMAIN-0.1-draft` control prerequisite. It gives forward and
inverse actions separate exact installations over the same physical conflict
domain and resource/incarnation. The shared native operation indices and resource
fence allocator remain unchanged. Installing the inverse lane alone does **not** enable inverse admission, spending
or execution. [RFC 0047](NATIVE_COMPENSATION_AUTHORITY.md) separately opts into
fresh inverse authority.

## Approve and enroll a fresh domain

Start with [the protected configuration example](../config/action-domain.example.json).
Replace its public demonstration keys, illustrative digests, identities and scopes
with independently approved material. In particular, the example's obligation and
trust digests are placeholders; they must equal the digests computed by each
lane's actual control configuration before a service can start. The example is a
shape reference, not an approved deployment.

The `topology` contains exactly `profile`, `forward` and `inverse`. Each lane is a
complete control registration: tenant, action/resource/domain/audience/adapter /
predicate scope, policy, ownership epoch, obligation and trust digests, issuer keys
and acknowledger. Control-registration public keys use hexadecimal encoding;
service key-file configuration retains its existing base64 encoding. Both lanes
must share tenant, physical domain, resource/incarnation and ownership epoch and
have different action IDs. Each governance service still verifies its independent
full role/trust configuration and registry-signed CTD.

Use a new authority domain with no legacy policy, ownership, reservation or
governance state. Enrollment cannot adopt existing roots or add an inverse to a
classic installation. The operator uses fixed HTTPS/mTLS etcd configuration and a
protected namespace-scoped token. A restore witness, when required by the
deployment, covers topology enrollment and lane writes in the original namespace.

```sh
kf-action-domain --config /etc/kedgeflow/paired-domain.json --check
kf-action-domain --config /etc/kedgeflow/paired-domain.json --enroll
kf-action-domain --config /etc/kedgeflow/paired-domain.json --status
```

`--check` validates protected material without reading credentials or contacting
etcd. Enrollment retains an immutable topology and an unknown-profile sentinel at
the legacy domain's `control-required` key in one transaction. An exact retry
returns the original enrollment. Changed pins, preexisting legacy state and a
stopped domain refuse. Neither a task nor a request supplies lane selection.

## Configure each service explicitly

Set `require_control:true` on control and gateway configurations and add:

```json
{
  "action_domain": {
    "topology": "replace with the complete approved topology object",
    "lane": "forward"
  }
}
```

The quoted placeholder above must be replaced by the actual object. The inverse
governance service selects `inverse`; all forward control, gateway, broker, review,
outcome collection and recovery,
query-only saga and compensation qualification services select `forward` with the
same complete topology. Governance uses `control.action_domain`. Omitting the field
preserves classic paths; a classic service in an enrolled paired domain refuses
the sentinel. Explicit null and unknown fields refuse.

Publish, register, install and acknowledge each lane through its existing signed
governance interface. Registrations must exactly match their protected lane.
Pairing does not relax CTD signatures, Cedar admission, acknowledgements,
revocations, admission identities, nonce consumption or original-attempt recovery.
Control/root/history state lives below the physical domain's `paired/forward` or
`paired/inverse` path. Admission, issuance, fence-allocation and the
tenant/resource/incarnation fence counter remain global within the original
authority namespace. Raw unsigned policy publication is disabled on selected
paired ledgers.

An RFC 0044 forward reservation must match the lane's tenant, exact scope, policy,
ownership and issuer keys in either configuration attachment order. The inverse
lane cannot enroll another reservation to manufacture compensation capacity.
RFC 0045 qualification additionally requires the topology's inverse scope and
policy to match the approved inverse contract. Its permanent marker binds the
topology digest. Qualification remains nonauthorizing.

## Stop and recover

```sh
kf-action-domain --config /etc/kedgeflow/paired-domain.json --stop
```

Stop is permanent for both lanes. The create-only marker cannot be cleared by
restart, acknowledgement refresh or enrollment. It blocks new admission,
issuance/reuse, fence allocation, claim and dispatch, including a race with their
actual etcd CAS. It does not refund allowances or reset counters. Historical
original-attempt status and signed query-only recovery remain available. A corrupt
stop marker refuses; the operator cannot overwrite it to conceal corruption.

Every selected-ledger transaction compares the exact original topology and legacy
sentinel. Missing/changed topology refuses even historical reads; this is a custody
failure requiring operator investigation, not permission to reconstruct authority.
Historical single-action lineage can still be exported and verified under its
original profile. It attests neither the paired topology nor complete inverse /
saga execution; complete paired saga evidence needs the later compound wrapper.

## Qualification and remaining M8 work

[The source-pinned verification](../results/verification/rfc-m8-paired-control-2026-10-15/README.md)
covers closed/bounded material, legacy and conflicting enrollment, independent
signed lane controls, shared retained resource counters, configuration omission /
substitution, permanent stop, an actual claim/stop CAS race, recovery after stop,
original committed saga-proof qualification and shipping mTLS CLI restart/replay.

This delivers the control prerequisite. [RFC 0047](NATIVE_COMPENSATION_AUTHORITY.md)
adds fresh inverse admission, signed binding and atomic held compensation spending
through native claim/dispatch/recovery. M8d3 requires an actual registered inverse /
barrier and crash, late-effect, partial/failure/unknown evidence. M8e requires an
actual separately accepted Kubernetes drain controller with Level C physical
limits. Dynamic delegation and independent A2A/enterprise/writer acceptance also
remain open. M8 is not complete.
