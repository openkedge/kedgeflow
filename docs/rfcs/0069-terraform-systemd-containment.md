# RFC 0069: Optional Linux Terraform containment

Status: draft; N2i deployment/software qualification; no wire or grant change.

Add an opt-in extension to the existing Linux release rather than broadening
its core role inventory. Run the existing saved-plan gateway under a dedicated
UID with managed startup required, read-only protected inputs, writable private
backend/staging, no new privilege and `KillMode=control-group`. Keep cgroup
mounts protected and delegation disabled. A detached process group must remain
in that service's cgroup and terminate during whole-gateway death cleanup.

Qualify actual systemd/kernel behavior separately from Rust process-group
cleanup. Run the official SDK under a different UID and test credential and
configuration boundaries. Managed native transactions remain restore-protected;
fixture counters must follow the executed nested transaction branch.

Qualify both a dropped original request and an original request committed after
expiry despite verified cgroup cleanup. Retain original unresolved authority;
restart and status never imply retry, no-effect proof, release or inverse.
No runtime test hooks or root helper are shipped. Bundle verification is
externally digest-pinned, closed, deterministic and always non-production-qualified.

See the [qualification guide](../TERRAFORM_SYSTEMD_QUALIFICATION.md) and
[N2 completion/handoff](../TERRAFORM_N2_COMPLETION.md). Independent production
identity, custody, storage/writer/audit/operations acceptance and peer reproduction
remain separate gates.
