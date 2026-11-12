# Protected Linux Terraform gateway

This optional extension supplies the existing saved-plan runner under a dedicated
systemd service. It does not enable a generic Terraform shell or change the
single/pair action profiles. Independent production enrollment and acceptance
remain required; an archive is never marked production-qualified.

Verify the externally pinned archive SHA-256 before installation:

```sh
python3 scripts/package-terraform-linux.py --verify ARCHIVE --sha256 EXPECTED_SHA256
```

As the deployment owner, install the verified payload into a root-owned immutable
release directory under `/opt/kedgeflow-terraform/releases`, and select it with
`/opt/kedgeflow-terraform/current`. Install its optional sysusers/tmpfiles assets
and service unit using the normal administrative process. The core control,
identity, broker, native ledger, restore witness and role enrollments are the
existing KedgeFlow services; this package does not replace them or mint authority.
Do not enable the service until the following inputs are provisioned and checked.
The recorded ARM64 software qualification and scope are in the
[systemd guide](TERRAFORM_SYSTEMD_QUALIFICATION.md); production acceptance is
tracked in the [N2 handoff](TERRAFORM_N2_COMPLETION.md).

- Use dedicated `kf-terraform-gateway`; give agent/SDK runtimes separate UIDs,
  no supplementary service/Docker groups, sudo, cgroup delegation or writable
  service configuration. Keep the service account noninteractive.
- Keep `/etc/kedgeflow/terraform-gateway` and its configuration, approved plan/
  provider/tool snapshots, service identity and writer/observer credentials under
  administrative custody. Private blobs must be readable only by the service
  UID, mode 0400/0600, under non-writable parent directories. The unit mounts
  that configuration tree read-only even to the service. Protect producer
  snapshots before enrollment, including binary plan/state and inspection hashes.
- Put the local backend under `/var/lib/kedgeflow/terraform-gateway`; use an
  explicitly pinned child backend directory. Preserve original lineage/serial
  and file privacy. The service's private staging is inside that writable state
  root; child execution clears inherited environment and uses approved snapshots.
- Use a separate observer credential with get-only access to exact targets.
  Confine the stock provider's broader writer credential to the trusted service.
  Source/rotate credentials through the deployment's approved provider. A stock
  resource token is not a mutation-specific capability.
- Configure the explicit single or pair adapter with its exact protected plan,
  schema, resource/incarnation, scope and trusted token/grant keys. Install current
  control, shared authentication, restore gate and acknowledgement enrollment.
  The shipped unit runs `--require-managed --check` before listening. A valid
  file shape is not evidence that remote dependencies or authority are ready.
- Preserve `KillMode=control-group`, `SendSIGKILL=yes`, `TimeoutStopSec=5s`, no
  cgroup delegation, protected cgroup mounts, empty capabilities, no new privileges,
  namespace restrictions and strict filesystem protection. systemd drains the
  old cgroup before an on-failure restart; a detached process group remains in
  the service cgroup. Restart only prepares the runner; it never initiates apply.

A killed service can leave a request already accepted elsewhere. Even verified
cgroup emptiness cannot prove no late target effect. Keep original unresolved
allowance held. Query the original attempt after restart; matching target state
or backend progress cannot promote history, release authority or authorize
another apply. Do not force-unlock, replan, refund or compensate automatically.

The supported software scope is fixed single/two-ConfigMap annotation updates,
local backend and approved tool/provider versions. Other providers, HCP/remote
backends and wider dependency graphs require separately admitted profiles and
qualification. This remains Level C, not target-atomic enforcement.

Deployment acceptance must be signed off by the owners of identity/delegation,
credential custody, all relevant writers, independent restore storage, audit,
operations/SLOs and incident response. Same-host generated fixture identities,
root-administered tests and replay checks cannot supply those independent
signoffs. A deployment must fail closed on missing enrollment or required
invariant coverage; no placeholder/private key in an example is production trust.
