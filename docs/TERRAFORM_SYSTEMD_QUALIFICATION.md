# Linux Terraform service containment (N2i)

The [verification record](../results/verification/terraform-systemd-2026-11-12/README.md)
qualifies the optional [Linux service](TERRAFORM_LINUX_DEPLOYMENT.md) on an owned
ARM64 Linux VM with systemd as PID 1. The core eight-role package is unchanged.
The extension ships five existing binaries and a dedicated, hardened service
unit, sysusers/tmpfiles assets and deployment instructions. Its manifest always
records `production_qualified: false`.

The normal single-resource and partial pair workflows use shipping gateway/
broker processes and the official SDK, fresh authority, authenticated native
storage, shared proof consumption, managed acknowledgement and restore protection.
The SDK runs under a separate unprivileged UID. Root fixture probes verify
explicit EACCES on credential/plan/key/process-environment reads and an actual
Docker socket connection, plus actual
EROFS write refusals inside the service's mount namespace. These probes do not
represent independent production administration.

Two fault cases hold a real provider mutation request, then SIGKILL only the
unit's main gateway. A test-only detached child has escaped Terraform's process
group and ignores SIGTERM; it remains in the service cgroup. Actual systemd
exit status and kernel process snapshots establish that the old gateway,
Terraform, provider and detached child terminate before an on-failure restart.
The fixture does not kill their process group. The restart prepares the service
without dispatching another apply.

The gate then either drops the captured original request or forwards it after
the original grant expires. The forwarded request can still commit. Both cases
retain a started native intent and `dispatch_authorized` phase, with no intent
outcome or ordinary terminal publication. Cold gateway/SDK queries after
expiry, revocation, broker shutdown and writer removal preserve the original
attempt, backend and intent without reapply. Cgroup containment is qualified;
a target-side late-effect barrier is not supplied.

The root adapter is fixture infrastructure and is excluded from the runtime
bundle. Its controller UID is trusted and has a temporary helper-only sudo
rule; the actual SDK UID has no such access. The fixture restore witness uses a
separate namespace/transport under the same host administration and storage
failure domain. This is local software evidence, not independent storage,
attestation or production acceptance. Provider compromise and arbitrary root
administration remain outside the declared boundary.

Replay public records without executing any mutation:

```sh
node scripts/verify-terraform-systemd.mjs results/verification/terraform-systemd-2026-11-12
```

The live root orchestrator `scripts/qualify-terraform-systemd.py` requires an
explicit disposable systemd host, pinned Linux tools/binaries, private kubeconfig
and an owned disk-backed work directory. It creates separate temporary UIDs,
retains public outputs and removes its units/users/sudo rule. Fixture target/VM
cleanup remains the invoking administrator's responsibility. See
[RFC 0069](rfcs/0069-terraform-systemd-containment.md) and the
[N2 handoff](TERRAFORM_N2_COMPLETION.md) for scope and remaining owner gates.
