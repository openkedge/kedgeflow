# Cura AWS pilot bootstrap

The maintainer approved the concrete Cura account, us-west-2 deployment proposal,
budget and bounded image/key bootstrap on 17 November 2026. The subsequent request
to provision acceptance duties authorizes IAM scaffolding; it supplies no human
identities, signatures or independent acceptance. Detailed account, billing route,
change sets and observations belong in the operator's protected execution packet,
not the public repository. The parameterized [manifest](../deploy/pilot/cura/manifest.json)
is an input template, not a live account inventory.

This work advances Milestone B infrastructure. Its remaining gates are
**BLOCKED_EXTERNAL_INPUT**: real role principals and independently approved trust,
provider/resource/writer contracts, independent storage/audit administration,
actual on-call and acceptance decisions. Infrastructure observations cannot close
the [enterprise acceptance contract](SQL_PILOT_RELEASE.md).

## Reproducible provisioning

Render the approved layers into a new private directory. Each renderer refuses
replacement and makes no AWS calls:

```sh
umask 077
packet=$(mktemp -d)
python3 scripts/pilot-bootstrap.py --output "$packet/bootstrap.json"
python3 scripts/pilot-image-builder.py --output "$packet/builder.json"
python3 scripts/pilot-custody.py --output "$packet/custody.json"
python3 scripts/pilot-infrastructure.py --existing-budget --output "$packet/fleet.json"
python3 scripts/validate-pilot-templates.py
```

The bootstrap creates a rotating retained KMS key, private versioned encrypted
artifact bucket and a separate pilot budget. Its billing email parameter is
`NoEcho`; use the approved protected alert route. Preserve unrelated account
budgets. The live budget is an account-total alert at $312/month, conservatively
including unrelated spend; it is not a hard limit or a claim that excluded
charges fit the core estimate.

The image builder is a separate two-hour disposable host with no ingress,
HTTPS-only outbound traffic, encrypted root disk and an exact-instance termination
schedule. Its temporary public package-download network is absent from the
runtime fleet. Its IAM role can read only the public runtime input prefix, write
only build reports, use the corresponding S3-scoped encryption key and operate
SSM node channels. Keep credentials and enrolled authority out of build inputs.

Verify the public-source allowlist, exact native bundle, vendor checksums and SSM
package signature before upload. `install-cura-image.sh` verifies input bytes,
records exact signed-repository package versions, installs dependencies and the
qualified bundle, and executes binaries under non-root accounts. Only the public
software trees receive public read/traversal permissions; protected configuration
and build evidence retain their private modes. Install all units disabled.
The [17 November direct-package lock](../deploy/pilot/cura/image-packages-ubuntu24-arm64-20261117.txt)
records the actual initial build versions. Include it as `apt-package-lock.txt`
in the hash-verified image inputs for subsequent builds. Initial candidate
resolution requires the explicit `--resolve-package-lock` option; unavailable
locked versions must fail, never silently select a replacement. Also retain the
full dpkg inventory: direct package pins alone do not freeze transitive repository
contents or establish bit-for-bit image reproduction.

Run `finalize-cura-image.sh` through an independent delayed systemd job, since it
uninstalls its controlling SSM agent. It refuses enrolled application material,
uninstalls the old management agent before purging this disposable builder's
registration, installs the verified fresh package without starting it, removes
host keys, resets cloud-init/machine identity, writes a non-secret finalization
report and shuts down. This is an image-builder procedure, never a runtime
recovery or authority-reset procedure. Require the exact builder to be stopped,
the finalization report to pass and its manifest hash to match before AMI capture.
After capture, verify the AMI is private, ARM64 and KMS encrypted.

Verify the real bootstrap budget exists before using the fleet's
`--existing-budget` variant. Review an exact CloudFormation change set with
`ApprovedAccountId`, pinned runtime AMI, dedicated KMS ARN, `ExistingBudgetName`
and a future `PilotStopUTC`; always pass `--profile cura --region us-west-2`.
The initial fleet window is 24 hours. Its schedule can stop only the nine exact
fleet instances; it cannot delete authority/storage or restart compute. Retained
volumes, interface endpoints, image snapshots, DNS and keys keep billing after
compute stops. Retention and teardown require deliberate ownership.

The fleet has nine private hosts across three AZs, eight separately retained
unformatted data volumes, three interface endpoint services across the AZs,
private DNS and no public IP, internet/NAT route, peering, SSH ingress or database
TCP ingress. No user data enrolls or starts application authority. Node IAM roles
have only SSM node-channel actions, without secret, S3, KMS, EC2 or IAM access.
The approved management principal remains a privileged writer and must appear in
the eventual writer inventory.

Inspect each newly booted unenrolled host with
`python3 scripts/inspect-cura-host.py` over the approved SSM management path. It
checks all installed bundle hashes/modes, distinct non-root accounts, actual
non-root binary execution, disabled application/SSH units, absent application
configuration and public runtime versions. It emits no configuration or credential
contents. Retain invocation metadata and inspect actual EC2 routes, groups,
metadata settings, disks, IAM policies and the stop schedule independently.
`probe-cura-agent-boundary.py` additionally probes the shipping agent unit's
network restrictions in a disposable transient service, including a child
process. A successful same-UID unconfined loopback control must precede confined
loopback, metadata TCP and public TCP denial. It never requests metadata tokens
or exercises an application action; these limited negatives do not establish
complete writer coverage or enrolled private-key custody.
Delete the temporary builder stack only after the replacement AMI and private
hosts are verified; preserve the selected image and its encrypted snapshot.

## Administrative duty scaffolding

`pilot-custody.py` creates seven named duty roles: deployment, identity-security,
resource, storage, audit, SRE and independent-reproducer. All initially have an
explicit deny trust policy: **none is an enrolled owner**. They create no users,
passwords, access keys, signatures or approvals. Real approved principal enrollment
requires a deliberate trust-policy change. Permissions are limited to each duty;
SRE can stop Cura-tagged instances, never delete them. These roles do not receive
protocol signing authority.

Storage and audit use different retained rotating keys and different private,
versioned encrypted buckets, with HTTPS enforced and object/version deletes
denied. They remain under the same account/root administration: this is neither
cross-account independence nor immutable WORM custody. The approved account is
not enrolled in AWS Organizations; no organization or additional account was
created. Independent administration cannot be fabricated through resource names.

Before runtime enrollment, obtain real owner/trust references and the exact
identity, registered resource/incarnation, writer, retained storage and operational
contracts in [protected pilot](PROTECTED_PILOT.md). Mount only explicitly identified
fresh volumes, protect provider/service keys, register only the reservation action
and run deployed writer/agent/descendant, rotation/revocation and physical stale
restore qualification. Recovery keeps original attempt/consumption history and
independent head/floor; it never resets authority or resends an uncertain action.
Seven real owner decisions remain mandatory for Milestone B acceptance.
