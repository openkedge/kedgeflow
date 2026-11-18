# Cura operator runtime enrollment

The [18 November deployed observations](../results/verification/sql-pilot-aws-enrollment-2026-11-18/README.md)
cover retained storage, real identity providers, workload issuance, the SQL database
and authenticated authority/witness stores. They are bounded technical evidence.
Milestone B enterprise acceptance remains pending independent custody, security
approval, actual SRE ownership and all seven real owner decisions. The seven
provisioned IAM duty roles do not supply those people or their signatures.

Continue authorized technical implementation without waiting for these independent
assignments. Use the [protected pilot](PROTECTED_PILOT.md),
[production readiness](PRODUCTION_READINESS.md) and
[enterprise qualification](ENTERPRISE_QUALIFICATION.md) contracts. Run only with
`--profile cura --region us-west-2`, within the approved account and existing pilot
window. This increment creates no additional compute/network infrastructure and
does not extend the original stop deadline. Stopped compute leaves retained disks,
endpoints, DNS and keys billing.

## Persistent host and provider enrollment

`scripts/enroll-cura-storage.py` accepts an explicit exact-instance/new-volume
manifest. It validates the EBS serial, blank 32 GiB layout and declared filesystem
UUID before first initialization. An existing filesystem must have that UUID and
the original host enrollment. There is no force erase or authority-reset path.
Retained per-role directories stay owner-only; shared traversal ancestors receive
explicit modes independent of the operator's private umask.

`scripts/setup-cura-identity.py --operator-bootstrap --realm-template ...` installs
the persistent PostgreSQL/Keycloak and SPIRE provider units on the already enrolled
Identity host. Secrets are created once in protected on-host storage; unit
credentials supply passwords without secret arguments. Read-only configuration
binds preserve real paths for protected loading. This is a technical service
administrator, not an independent identity/security owner. Re-running bootstrap
must not rotate keys or replace an enrolled database. Use
`scripts/probe-cura-provider-restart.py` for the named public-key/enrollment
continuity and private-file refusal checks. Rotation/revocation and physical
provider restore remain separate work.

`scripts/enroll-cura-spire.py` closes the Services and Agent instance/UID/workload
inventory. A separately rendered `pilot-enrollment-bridge.py` stack allows only
two exact short-lived encrypted delivery parameters with individual reader
policies, a KMS encryption-context restriction and explicit expiration. Tokens are
generated on Identity, fetched on the enrolled node, and never exported in command
arguments or output. An expired unused bootstrap can be retried only under the
script's attestation/registration guards; an already attested identity is never
reset. Retain bootstrap alias history and all issuer/node key stores.

After actual UID issuance probes succeed, `--finalize-node` removes the consumed
join file/config directive and checks a retained-identity restart.
`--cleanup-delivery` removes the two delivery parameters after both exact nodes
attest. Delete the auxiliary policy stack and read back the original node IAM
policies. `probe-cura-spire.py` verifies JWT signatures/subject/audience/expiry,
X.509 chain/URI, private-key modes, privileged key denial and cross-host UID
refusal. Repeat after provider restart before enabling the node units. The live
bridge and parameters have already been removed; recreating them is unnecessary
for normal restart or credential renewal.

## SQL and ledger foundation

`scripts/enroll-cura-postgres.py --operator-bootstrap --migration ... --incarnation ...`
requires the enrolled Sql mount, the pinned unchanged migration and an immutable
registered incarnation. First initialization creates a pending record; an ambiguous
partial database is preserved for review, never erased or automatically migrated
again. Completed reruns require the same enrollment/configuration. PostgreSQL uses
a private Unix socket, exact kernel-peer maps and separate execution/query logins
with function-only rights. The helper audits actual rights, checks durability and
restart continuity, then attempts denied direct-role/table/file paths. It starts
no target listener and dispatches no action. The eventual native target must still
pass protected `--check-custody`, `--check-database`, managed launch and its peer UID
pin under `kf-sql-target`.

`scripts/enroll-cura-service-pki.py` prepares fixed-role public CSRs with private
keys on their owning hosts. Only Services signs public requests under its protected
operator transport CA. Installation checks CA signatures, original key bindings,
host/role SANs and custody. Ordinary client leaves have no Common Name; only the
separate protected etcd CLI administrator has the reserved root CN. Public chain
installation starts no service. Leaf lifetimes end at the existing pilot deadline;
these certificates are not an independently administered service PKI or a qualified
rotation mechanism.

`scripts/enroll-cura-etcd.py --operator-bootstrap --host ...` starts only the fixed
three-member primary cluster or separate witness, using the retained original
data identity. It never forces a new cluster. Private host listeners, client/peer
TLS, direct VPC DNS and systemd network restrictions are explicit. Immediately run
`scripts/enroll-cura-ledger-auth.py` on Services before any protocol authority
service starts. It creates individual namespace-scoped users and a read-only
observer, retaining random passwords locally. Existing unexpected principals,
changed membership or broader permissions refuse without automatic repair.
The reserved root ACL is handled explicitly; ordinary roles cannot inherit it.

Authentication checks use actual login, exact role permission audit and positive
namespace reads, together with unauthenticated, outside-namespace, root metadata
and observer-write refusals. Negative writes must leave no key. Run one retained
member restart at a time; require all endpoint health, original cluster/member IDs
and renewed authentication/scope checks before enabling units. Current five-minute
simple tokens require protected renewal and safe refusal after server/token loss.
Namespace permissions do not establish finer per-key isolation, publisher
availability, application failover or independent witness administration.

## Next deployment gates

Protected credential publication/renewal, native empty-namespace restore enrollment
and retained head/floor, fresh evidence and separate application service
configuration remain implementation/deployment work. Then qualify a real guarded
reservation COMMIT, original-attempt recovery, full agent/descendant/writer bypass,
rotation/revocation, physical/stale restore and deployed operational measurements.
Never replace any of these with a successful disposable fixture or reset history
to make a preflight pass.

Keep private logs and credential material on the protected hosts. Export only
allowlisted public metadata, fixed failure categories and explicit booleans. A
failed command's raw stderr or a redacted log is not an approved export mechanism.
Retain invocation/source/configuration references in the private operator packet;
publish bounded observations separately from independently signed owner acceptance.
