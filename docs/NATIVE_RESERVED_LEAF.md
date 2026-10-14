# Native fixed-cost leaf reservations (M8b1)

[RFC 0038](rfcs/0038-native-reserved-leaf.md) connects the RFC 0032 capacity
snapshot to native admission/issuance, claims and dispatch. The opt-in profile is
`KF-RESERVED-LEAF-0.1-draft`. Frozen leaf grants, HTTP operations and Agent Adapter
records are unchanged. This increment delivers a root-level, single-resource,
fixed-cost leaf. Composite grants, saga/compensation execution, A2A and actual
Kubernetes drain remain open.

## Independently approved enrollment

Add the **same** `reservation` registration to the control and gateway protected
configurations, with `require_control: true`. The control admission trust and
issuer key must match; the gateway requires one consequential tool and the exact
action/resource/incarnation/audience/adapter/predicate identity and issuer role.
Managed installation and gateway acknowledgement remain required independently.

[Example fragment](../config/reserved-leaf.example.json) is illustrative: its
repeated descriptor/policy digests and public fixture key are not deployment pins.
Replace them from independently accepted service/tool/policy material before use.
Pin the complete predicate, including its expected resource version. A changed
predicate or incarnation requires a separately reviewed profile/migration.
The approved budget root is separate from the issuer-generated execution root.
Root generation is one; operation costs are fixed positive forward units and
optional compensation units. Both totals remain conserved.

The registration digest covers every field, including costs and role keys. All
services must approve identical material. Changing keys, costs, policy or scope
cannot silently replace an existing enrollment. Subject/workload admission,
current policy/ownership, review and lease checks retain their existing behavior.

Use the protected control configuration and shipping CLI:

```sh
kf-control --config /etc/kedgeflow/control.json --check
kf-control --config /etc/kedgeflow/control.json --enroll-reservation
kf-control --config /etc/kedgeflow/control.json --stop-reservation
```

`--check` validates local material without probing/installing authority state.
Enrollment atomically creates the budget snapshot, tenant/domain marker and native
required marker. It is create-only; repeats refuse rather than reset capacity.
Stopping is permanent and preserves allocations and both budgets. No enrollment,
stop or budget-selection HTTP field is available to agents. These commands require
operator custody and authorized etcd credentials; the tests use generated files
and a TLS forwarding fixture, not accepted production custody.

## Authority and retry behavior

1. The native issuer independently re-verifies complete admitted inputs. In one
   etcd transaction, it reserves the fixed budget units under the stable operation
   key and allocates the resource fence. Capacity lost after this boundary stays
   held; there is no automatic refund.
2. The issuer signs a reservation binding to the operation, budget root/generation,
   approved registration, immutable allocation and exact grant/certificate digests.
   Grant/root/issuance creation retains this binding and an operation seal together.
   Recreated issuers reuse the original allocation, fence and signed grant.
3. Claim verifies the retained signed binding and both markers, then changes the
   allocation to `unknown` with the original attempt in the nonce/root/context
   transaction. Competing claims cannot consume twice. Dispatch compares the
   active root, binding and original unknown attempt again before authorization.
4. A stopped root blocks new claims and dispatch. A stop raced against either
   authority transaction fails its comparison. Status remains query-only after
   expiry/stop and resolves the original attempt. Stop cannot undo an already
   authorized external send.

Omitted native configuration cannot bypass an enrolled domain: ordinary authority
paths compare absence of its required marker. Missing/corrupt binding indexes or
seals refuse. Sealed allocations cannot become composite parents, be consumed,
or have their outcomes refined through the older state-only coordination ports.
No replacement/generation bump or synthesized allocation for a prior fence is
supported. Legacy unenrolled domains retain their current wire behavior.

The budget currently stays `unknown` after native known outcomes. Both allowances
remain held even for proven no effect. Native outcome refinement and versioned
budget history are the next software increment; compensation is reserved capacity,
not an executable inverse or compensation grant.

## Historical verification and evidence

An authorized operator can disclose a binding through
`EtcdLedger::retained_reservation_binding`. With an independently approved public
registration and the original signed grant, the shipping offline verifier checks
closed carriage, signatures, exact scope and digests:

```sh
kf-verify-reservation --registration approved-registration.json \
  --grant signed-grant.json --binding reservation-binding.json
```

The result explicitly reports `execution_authority: false` and
`live_budget_verified: false`. It proves an issuer statement, not current capacity,
ledger consensus, complete admission lineage or an actual target effect. Reserved
operations refuse existing lineage export until versioned budget carriage exists.

[Required run](../results/verification/rfc-m8-reserved-leaf-2026-10-14/README.md)
qualifies native managed control/etcd producer and consumer transitions, last-slot
and claim contention, issuer recreation, stop races at four authority boundaries,
configuration omission/pin changes, retained index/seal corruption, library bypass
and offline signature/carriage substitutions. Shipping operator/verification CLIs
and an official Node SDK workflow exercise actual TLS/DPoP and query-only recovery
in a separate process, including lost issuer and execution replies. Evidence provider, broker and guarded effect are software
fixtures. Accepted writers/predicate coverage, physical failures, production
custody and enterprise acceptance remain open.
