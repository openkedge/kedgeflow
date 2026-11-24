# Cura admission and issuance custody

The selected SQL pilot uses separate admission and issuer processes, private
signing keys, TLS identities, authority credentials, protected roots and non-root
kernel UIDs. These software controls do not enroll or approve a deployment.
Milestone B remains **BLOCKED_EXTERNAL_INPUT**.

The bundle includes additional accounts and units under `share/pilot/cura`.
After authenticated staging, an approved operator installs the core account and
directory declarations, then Cura’s `accounts/sysusers.conf` and
`accounts/tmpfiles.conf`. Install the core service units and Cura’s systemd files;
select `kedgeflow-cura.target`. Do not enable `kedgeflow.target` or the combined
`kedgeflow-control.service` in this profile. The Cura target conflicts with them
and propagates shutdown to its service/timer members. Provision protected files
before enabling anything; templates contain no provider enrollment or secrets.

| Property | Admission | Issuer |
| --- | --- | --- |
| Account/root | `kf-admission`, `/etc/kedgeflow/admission` | `kf-issuer`, `/etc/kedgeflow/issuer` |
| Executable | `kf-control --runtime-role admission --require-managed` | `kf-control --runtime-role issuer --require-managed` |
| JSON `runtime_role` | `admission` | `issuer` |
| Private signer field | `admission_signing_key_file` | `issuer_signing_key_file` |
| Peer private signer field | Omit entirely | Omit entirely |
| Registered application port | 9443 | 9448 |

Both configurations must pin `admission_verification_key_base64` and
`issuer_verification_key_base64` as standard Base64 Ed25519 public keys, use
distinct nonempty key IDs and the identical registered policy/trust scope. Each
own private key must match its public pin. Use approved generated keys, never the
fixed disposable fixture seeds. Present-null, foreign private-key fields, missing
public pins, role/CLI mismatch, unprotected launch and single-role operator
enrollment flags refuse. Single-role mode excludes leases and A2A. Privileged
enrollment uses the independently protected governance/operator workflow.

`admission_url` and `issuance_url` identify the separate HTTPS origins in both
configs. Each `status_url` and optional `/ops/ready` URL uses that process’s own
origin. The inactive authority route is unavailable before JWT/DPoP handling.
Public verification objects contain no placeholder private signer. AgentAdapter
already pins admission and issuer origins independently; use discovery with the
same exact endpoints. Key rotation changes both public trust configurations and
the managed trust registration through the approved process; never silently
regenerate a signer or reopen an old consumed attempt.

Roots are root-owned `0750` with only that service’s group; private files are
role-owned `0400`. Give each process its separately registered TLS identity and
least-privilege authority token. Do not copy one service’s directory into another.
The production secret publisher, PKI renewal, etcd RBAC grants and independent
storage/security administration still require real owner-approved inputs.

The reference CloudFormation permits agent access to gateway 8443, read-only
evidence 8444, admission 9443 and issuer 9448. It grants no direct agent path to
broker, SQL, governance, ledger, witness or collector. Supply approved endpoint
addresses/certificates and the evidence provider contract before deployment;
security-group reachability is not application authorization. Exercise cgroup
egress and metadata denial on the actual agent kernel and every descendant.

Disposable qualification:

```sh
sudo python3 scripts/qualify-systemd-services.py --ephemeral-host \
  --accept-test-install --split-control --package /fixture/runtime.tar.gz \
  --sha256 EXACT_BUNDLE_SHA256
```

This installs and cleans its own test accounts/units, refuses preexisting paths,
checks each role’s native material loader, cross-role private reads, mTLS monitor
boundaries, effective sandbox, restart and shutdown. Authority endpoints are
deliberately unavailable; its typed unready responses are not live acceptance.
The separate managed-provider workflow runs real Keycloak/SPIRE, SDK and SQL
through five shipping systemd roles plus independent agent/database UIDs. Its
administration, evidence and TLS ledger relays remain disposable fixtures.
