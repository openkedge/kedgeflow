# N2i: Linux service containment and N2 software handoff

Qualification date: 12 November 2026, America/Los_Angeles. Baseline `f9981e8`;
implementation `4628109`, replay correction `0c0e081`. [RFC 0069](../../../docs/rfcs/0069-terraform-systemd-containment.md),
the [service guide](../../../docs/TERRAFORM_SYSTEMD_QUALIFICATION.md) and
[N2 software handoff](../../../docs/TERRAFORM_N2_COMPLETION.md) describe the
bounded software exit. Independent production acceptance remains open.

| Final case | Real target behavior | Retained original outcome |
| --- | --- | --- |
| normal | One approved ConfigMap annotation mutation through the official SDK and shipping gateway/broker | applied intent / committed |
| cgroup-drop | SIGKILL main gateway while provider PATCH held; systemd terminates old gateway, Terraform, provider and detached SIGTERM-ignoring child; original request dropped after expiry | started intent / dispatch_authorized |
| cgroup-late | Same verified cgroup drain and automatic restart; captured original PATCH forwarded after expiry and committed, with matching target observation and audit | started intent / dispatch_authorized |
| partial | First approved member changes, second fails; writer permissions restored before recovery queries | per-member partial observation / unknown aggregate |

All four workflows use fresh authority, the shipping Linux gateway/broker,
official MCP client 2.3.0, Terraform 1.17.1, Kubernetes provider 2.38.0, a private
three-member etcd 3.6.5 fixture and an owned audited Kubernetes 1.37.0 kind
cluster. Linux ARM64 runs systemd 255 as PID 1. Pinned builder, tool/binary
hashes, kernel and bundle identity are in [summary.json](summary.json),
[host.json](host.json), [tool pins](tool-pins.json) and [bundle.json](bundle.json).
Runtime source, SDK, accepted schemas and existing fixtures match the baseline.
The test adapter now accounts for actual executed nested restore transactions.

The optional unit keeps `--require-managed`, shared authentication, authenticated
native storage, installation acknowledgement and restore protection. It uses a
dedicated service UID, read-only protected inputs, private writable backend/
staging, `KillMode=control-group`, a five-second stop bound, no cgroup delegation,
no capabilities and no new privileges. The official SDK runs under a separate
UID with no privileged supplementary groups. Eight actual service starts retain
kernel/systemd snapshots and five EACCES probes each: writer, plan, service key,
process environment and a real Docker socket connection. Three probes per start
enter the actual service mount namespace without privileges and require EROFS
when attempting to change the plan, writer material or configuration.

The detached test child has its own process group and ignores SIGTERM. It remains
in the service cgroup. Both fault cases record real signal-9 gateway exits,
old-process disappearance and systemd automatic restarts. No fixture process-group
kill supplies containment. The shipping binaries have no test escape/fault hook.
The root helper and temporary helper-only sudo rule are fixture infrastructure
and are excluded from the extension bundle; the SDK UID cannot use that rule.

Draining local processes does not retract a remotely queued request. The late
case demonstrates a real post-expiry target commit after cgroup cleanup. Both
fault cases retain one claim/permit/dispatch/started intent and zero native
intent outcomes or ordinary terminal publications. Repeated cold gateway/SDK
queries after expiry, revocation, broker shutdown and writer removal keep the
original phase and attempt. They change neither backend/intent bytes, counters
nor target-write audit events. No automatic reapply, no-effect promotion,
release, force-unlock, refund or inverse is introduced.

The final denominator is **104 native Rust test runs**: 99 core, four actual
service workflows and one nested-transaction evidence-accounting regression.
There are zero qualified failures, ignored tests or skips. Seven SDK vector
suites pass, including 46 single-resource and 67 pair checks. Three package
semantic tests cover deterministic archives, external digest pins and unsafe
member rejection; their synthetic ELF headers provide no runtime credit.
The real ARM64 ELF bundle rebuilds byte-for-byte and verifies using its externally
pinned SHA-256. It always declares `production_qualified: false`; the verified
archive remains in the local workspace at the path recorded in bundle.json.

Read-only replay validates the actual custody, cgroup, original authority,
late-effect and pair records. Twelve altered public records must refuse:
wrong KillMode, cgroup delegation, same agent UID, readable writer, unproven
read-only mount, surviving old cgroup or detached child, fixture group kill,
pre-expiry alleged late effect, false publication, repeated dispatch and a
mutating cold query.

```sh
node scripts/verify-terraform-systemd.mjs results/verification/terraform-systemd-2026-11-12
node scripts/test-terraform-systemd-replay.mjs results/verification/terraform-systemd-2026-11-12
```

[Preliminary diagnostics](preliminary/diagnostics.json) explicitly exclude setup,
helper, audit and fixture-selection failures from the final denominator. A prior
guest disk-full event left one malformed audit line. The entire owned cluster
was replaced before the successful cohorts; malformed events were not skipped.
The final cohort additionally requires actual EACCES and Docker connect refusal.
Repeated successful development cohorts are not added to the final population.

The fixture controller, identity/evidence roles, restore transport/namespace,
audit policy and Kubernetes administration share one host administrator and
storage failure domain. These are local software observations, not independent
attestation, production writer coverage, physically separate restore storage or
a universal provider escape guarantee. Trusted stock provider code and root
administration remain explicit assumptions. The scope is one/two fixed
ConfigMap annotation actions with a local backend, at Level C. Remote backends,
other providers and larger graphs require separately admitted qualification.

[Source hashes](source-hashes.json), [source patch](source.patch),
[prior evidence hashes](prior-evidence-hashes.json), [checks](checks.log) and
[artifact hashes](artifact-hashes.json) preserve the reviewable chain. The
[cleanup log](cleanup.log) records removal of owned namespaces, temporary
units/users/sudo rules, private work mounts/credentials, task-labelled build
containers/volumes and the owned kind cluster, then stops only the tf9 VM.
No production deployment or push is performed.
