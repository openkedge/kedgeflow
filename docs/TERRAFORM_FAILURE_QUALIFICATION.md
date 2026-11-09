# Terraform failure-boundary qualification (N2d)

This qualifies the existing [Terraform gateway](TERRAFORM_GATEWAY.md) at certified
process/native-storage boundaries and controlled target changes. It adds fixtures
and evidence, with no runtime fault API, wire change or automatic outcome repair.
See [RFC 0062](rfcs/0062-terraform-failure-qualification.md) and the
[verification record](../results/verification/terraform-failure-2026-11-09/README.md).

Every case uses a fresh real saved plan, shipping gateway/broker, official SDK,
fresh Cedar admission/issuance, native etcd and an owned Kubernetes target. A
test-only authenticated relay gates the declared native request or reply.
Independent target reads, backend lineage/serial/hashes, native write counters,
grant time bounds and OS process signals certify the intervention. Missing
checkpoints or accidental pre-intervention expiry fail the experiment.

| Intervention | Target at cold recovery | Intent | Ordinary native state |
| --- | --- | --- | --- |
| SIGKILL after intent commit with reply withheld | Original state | started | dispatch_authorized |
| SIGKILL after effect/backend progress, before intent outcome reaches etcd | Desired annotation | started | dispatch_authorized |
| SIGKILL after applied intent, before ordinary outcome reaches etcd | Desired annotation | applied | dispatch_authorized |
| Domain revocation before forwarding the intent CAS | Original state | absent | unknown |
| External target annotation change after dispatch authorization, before runner checks | External annotation | absent | unknown |
| Observed SIGSTOP after dispatch authorization; SIGCONT after grant expiry | Original state | absent | not_dispatched |

For crashes, `dispatch_authorized` is the retained nonterminal phase, not a
committed-effect verdict. The first SDK process may report unavailable while
the gateway is dead or paused; the cold process reports the original native phase.
Matching target/backend or an applied intent does not silently promote ordinary
status. The intent and ordinary outcome remain separate histories until an
explicitly qualified repair mechanism exists.

All cold checks restart the gateway and SDK with current disclosure-only
credentials after grant expiry/revocation, broker shutdown and writer removal.
Repeated SDK execution performs status queries only. Grant/attempt, backend,
intent and native write counters stay unchanged. Authority is not renewed or
released. Normal committed and unknown workflows retain their separate tests.

The external mutation is accounted for separately: UID/data/labels remain fixed,
and its annotation/resourceVersion certify injection. The independent oracle
expects that external value, not the plan's desired value. This option belongs
only to the owned loopback kind qualification script and grants no apply power.

The suspension fixture's five-second TLS transport can time out before resume.
Its immediate SDK availability is recorded separately from the native outcome;
the fixture waits only for existing outcome publication, without repairing it.

The relay records native commit/forwarding state before client cancellation can
discard a reply. Lost replies are not proof that a native write failed. SIGKILL
is verified on the actual gateway child; SIGSTOP is observed in OS process state,
and continuation occurs only after the original grant expires. The revocation
case also requires the held native CAS to fail.

These are same-host Darwin fixtures with generated roles and an allow policy.
Crashes are before apply starts or after the Terraform child has completed.
Active Terraform/provider child termination, systemd/cgroup behavior, multi-resource
partial apply, HCP/remote backends, target-incarnation races after the last check,
arbitrary dependency changes and independent production custody remain open.
The adapter remains Level C; these cases do not close the full N2 exit.
