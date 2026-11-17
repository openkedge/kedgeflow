# Cura AWS foundation observations — 17 November 2026

The maintainer approved the concrete Cura account/us-west-2 proposal and bounded
image/key bootstrap, then requested provisioning of the acceptance duties.
[Observations](observations.json) record actual AWS infrastructure and actual Linux
host probes. This is **not** a signed enterprise acceptance record. Milestone B
remains **BLOCKED_EXTERNAL_INPUT** for real principals/trust, approved runtime
contracts, independent administration, complete deployed qualification and owner
acceptance. No owners, signatures or approval records were fabricated.

The approved account now has a private nine-host, three-AZ foundation, three
interface endpoint services across those AZs, 17 dedicated-key encrypted volumes
totalling 472 GiB, private DNS, SSM-only node policies and an exact nine-instance
stop schedule. Actual route/group checks found no public IP, internet/NAT route,
SSH or PostgreSQL TCP ingress. CPU credits are Standard. Seven duty roles exist
with explicit deny trust pending real principal enrollment. Audit and backup
have separate rotating keys and private versioned stores with object/version
deletes denied; both remain under the same account/root administration.

All nine hosts passed the shipping bundle's 44 file hash/mode checks, non-root
binary execution, 20 distinct service UID checks and explicit disabled/inactive
application, timer, target and SSH checks. Machine identities differ across all
nine. All eight 32 GiB data disks remain unformatted and unmounted. An initial
inspector incorrectly treated systemd's zero exit code for **static** helpers as
enabled; the corrected inspector records actual state names and separately
checks their activating timers/targets. Full SSM invocation output was retained;
the list API's truncated output was not used as JSON evidence.

The actual Agent host also exercised the versioned optional agent unit's
restrictions in a transient service. An unconfined same-UID loopback control
succeeded. The confined process could reach a disposable empty TCP listener on
the private Services host, while loopback, metadata TCP and public TCP failed;
a child process also failed the loopback attempt. No metadata token/credential
was requested and no application/SQL action was invoked. The listener stopped.
These limited transport probes do not qualify the enrolled workflow, all writers,
private-key custody, authentication or target effects.

The runtime AMI contains the original qualified native bundle from `4876d11`,
checksum-pinned providers and PostgreSQL 18.3, with no application configuration
or enrollment. The image build manifest and its postflight correction are retained
privately: an unused first image exposed a public-directory traversal problem
from the installer's private umask; only public software permissions were fixed,
all binaries were tested as non-root users, and management identity sanitization
was repeated before the selected image capture. No claim is made that this image
was built by the later revised installer without that recorded correction.

Temporary builder resources and the unused image/snapshot were removed. The nine
idle fleet hosts were normally stopped after verification; root/data disks and
keys remain intact. The original **18 November 2026, 23:16:43 UTC** stop-only
schedule remains enabled. Budget alerts are $312/month, not a hard cap. Retained
disks, endpoints, DNS, keys and the selected image continue billing after compute
stops. No budget or lifetime extension is inferred for later operation.

The live dependency refresh patches Python OpenTelemetry to 1.45.2 and separately
reports the Chrono maintenance notice, with a seven-day source/lock/classification
bound ending **24 November UTC**. It grants no independent security approval.
See [dependency security](../../../docs/DEPENDENCY_SECURITY.md). The original
Milestone A record and its CI source remain frozen; new hosted CI observations
are retained separately in the protected execution packet.

The [bootstrap runbook](../../../docs/CURA_AWS_BOOTSTRAP.md) describes reproduction.
Full account IDs, AMI/KMS/volume/role references, billing route, API responses,
SSM invocations and failed-attempt history remain in the private operator packet
`.cache/milestone-b-2026-11-17/`; its relevant file hashes are recorded here. Those
hashes permit later comparison, not independent authentication of provenance.
Local verification passed 162 Python tests and six subtests, all five full-schema
CloudFormation variants, Ruff, mypy and frozen protocol checks.

Remaining deployed work requires protected provider/service enrollment, the exact
registered SQL resource/incarnation and closed writer inventory, independent
witness/head/floor and audit administration, actual operational ownership, live
guarded commit/query and bypass qualification, rotation/revocation, physical stale
restore/cutover and seven real owner decisions. Empty cloud resources and local
fixtures do not close those gates. No new AWS organization/account was created.
