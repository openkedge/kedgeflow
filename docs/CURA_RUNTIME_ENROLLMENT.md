# Cura operator runtime enrollment

The [18 November deployed observations](../results/verification/sql-pilot-aws-enrollment-2026-11-18/README.md)
cover retained storage, real identity providers, workload issuance, the SQL database
and authenticated authority/witness stores. They are bounded technical evidence.
The subsequent [credential and native genesis record](../results/verification/sql-pilot-aws-credentials-2026-11-18/README.md)
adds fourteen real service-token publications, authentication-failure/expiry/renewal
and shipping native restore namespace enrollment under the operator UID.
The [SQL observer and identity record](../results/verification/sql-pilot-aws-observer-2026-11-18/README.md)
adds a function-only fixed-row reader, Agent request-key pins and closed Keycloak
scopes. Its checks ran on 18 November; all nine hosts were confirmed stopped on
22 November after the original operating window elapsed.
The [22 November renewed-window record](../results/verification/sql-pilot-aws-recovery-2026-11-22/README.md)
records the user's explicit renewal through **2026-11-23T08:00:00Z**, stop-guard
installation before restart, renewed transport, actual expired-node SPIRE recovery,
retained provider restart and unchanged SQL/native recovery head.
The [live evidence record](../results/verification/sql-pilot-aws-evidence-2026-11-22/README.md)
adds two real isolated Agent requests through the nonroot observation source and
relay, signed fresh records, DPoP replay/input refusals and encrypted subject-token
handoff with cleanup. Its artifacts are historical, not reusable fresh inputs.
The published observer increment's CI failed its disposable
credential-renewal step; a passing prior commit does not qualify the new source.
Milestone B enterprise acceptance remains pending independent custody, security
approval, actual SRE ownership and all seven real owner decisions. The seven
provisioned IAM duty roles do not supply those people or their signatures.

Continue authorized technical implementation without waiting for these independent
assignments. Use the [protected pilot](PROTECTED_PILOT.md),
[production readiness](PRODUCTION_READINESS.md) and
[enterprise qualification](ENTERPRISE_QUALIFICATION.md) contracts. Run only with
`--profile cura --region us-west-2`, within the approved account and existing pilot
window. The original stop record is retained; the separately approved renewed guard
has a fixed new deadline. Only the two reviewed Services-to-Sql observation rules
were added; no additional host, volume or endpoint was created. Stopped compute leaves retained disks,
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

## Protected renewal and native genesis

`scripts/enroll-cura-credential-publisher.py` provisions the isolated optional
publisher account from the verified bundle. After its host-local PKI is enrolled,
it binds only nested role credential directories writable, copies ordinary
namespace passwords locally and checks the shipping native issuer. A separate
source-pinned Python sink includes admission/issuer destinations; it does not
overwrite any original bundle file. Two real issue/install cycles must replace
all fourteen tokens with exact service ownership and foreign-reader refusal
before renewal is enabled. The generic sink/units also include the split-role
extension for subsequent packages.

`scripts/probe-cura-credential-lifecycle.py --action prepare` is a deliberate
pre-application drill; it refuses when application services are active. It
temporarily stops renewal under an automatic recovery watchdog, proves a wrong
publisher password refuses publication without replacing prior tokens, restores
the password and retains old tokens in a root-only on-host record. Run `--action
finish` only after its returned real expiry deadline. It requires explicit old
token unauthentication, resumes publication/timer, verifies fresh positive controls
and removes the private record. `--action recover` restores protected renewal if
the drill is interrupted. Neither credentials nor their hashes leave the host.

`scripts/enroll-cura-restore-gate.py --binary-sha256 ... --enroll-empty` requires
the pinned shipping restore binary, protected operator configuration, fresh
published credentials and observed-empty primary/witness namespaces. It records
intent before the one native enrollment attempt. Reruns query native status only;
missing, pending or mismatched heads stay quarantined. Never delete the intent,
re-enroll a nonempty namespace, replace its witness or reset history to proceed.
The current native genesis is enrolled, and a second status check preserved its
original head. Independent witness administration and broker identity floors
remain separate work.

## Next deployment gates

Fresh signed observation and bounded sender-constrained subject delivery now have
deployed technical checks. Provider identity snapshots/floors, actor delivery and
separate native application service configuration remain implementation/deployment
work. Then qualify a real guarded
reservation COMMIT, original-attempt recovery, full agent/descendant/writer bypass,
rotation/revocation, physical/stale restore and deployed operational measurements.
Never replace any of these with a successful disposable fixture or reset history
to make a preflight pass.

Keep private logs and credential material on the protected hosts. Export only
allowlisted public metadata, fixed failure categories and explicit booleans. A
failed command's raw stderr or a redacted log is not an approved export mechanism.
Retain invocation/source/configuration references in the private operator packet;
publish bounded observations separately from independently signed owner acceptance.

## Resuming an elapsed operating window

The original stop time was **2026-11-18T23:16:43Z**. A later instruction to continue
software work does not silently renew that duration/spending authorization. Keep
the fleet stopped while preparing the exact renewal proposal. Record stale and
expired credentials as unready; successful November 18 fixtures or invocations do
not establish current service health.

`scripts/pilot-run-window.py` renders one new stop-only schedule in the existing
pilot schedule group with its existing exact-fleet stop role. It creates no IAM,
compute or network authority and cannot start instances. Its input validator
requires the approved account, nine distinct exact instances and a future stop
within 24 hours. Review an approved live change set, install/read back the renewed
guard, and only then start the named fleet. Preserve the original schedule record.
Scheduler retries and budget alerts do not establish a guaranteed hard cost cap.

Renew expired transport credentials through explicit protected issuer/certificate
rollover and preserve old material/history and host-local keys. Check SPIRE's
retained node keys, registrations and trust after the offline interval before
deciding whether controlled reattestation is needed. One-time join enrollment is
not an automatic long-offline recovery mechanism. Never clear a key store, remove
restore intent, reset a witness/head, disable TLS verification or re-enroll history
to make recovery pass.

`rollover-cura-transport.py` prepares CSRs from the retained private keys, signs
under an explicit new protected issuer generation, archives old public chains and
installs only public CA/certificate material while consumers are stopped. The
generation's eighteen actual leaf certificates end at the renewed stop deadline.
This operator-controlled issuer is not independent PKI custody.

`recover-cura-spire.py` handles only the explicitly reviewed two expired join-token
nodes, before application startup. Its pinned base source checks the exact closed
instance/UID/workload manifest. Identity retains a protected original inventory;
old token-derived internal node IDs never leave that host. Each node retains a
root-only on-host snapshot before a surgical public CA cache update. The existing
SVID, counters, original enrollment marker and disk directories remain in place;
SPIRE's native expired-node attestation rotates its node key. Do not claim that
the old key bytes or internal node principal stay unchanged. The two current
internal principals use new aliases to the same public node parents and exact
workload entries; both expired principals and all old aliases remain as history.

After actual UID JWT/X.509 probes, finalization removes the consumed delivery file
and configuration directive and repeats retained-identity restart checks. Cleanup
requires exactly two old expired and two current nodes, unchanged workload entries
and retained old history, then removes both encrypted parameters. Delete the three
expiring auxiliary delivery policies and read back the original five-action host
policies. This was completed in the real renewed window. The provider restart probe
can accept this exact history only with an explicit generation, protected original
inventory and both source pins; its original two-node default remains strict.
Repeat both workload probes after provider restart. These bounded recovery checks
do not establish complete issuer revocation, independent custody or enterprise
acceptance.

The SQL observer adds an explicit authentication profile to the original database
bootstrap. Use `enroll-cura-sql-observer.py` for its retained profile checks; the
original base bootstrap deliberately refuses the changed HBA file. It retains
base source pins and uses its read-only audits without replaying base enrollment.
The evidence reader/Services relay now have managed launch and actual signed-response
checks over 8452. They have no writer authority and do not qualify an execution workflow.

## Fixed-row signed observation and bounded subject requests

`cura-sql-evidence.mjs` runs as `kf-observer` on Sql (8452) and Services (8444).
The source executes only `SELECT kf_reservation.observe_cura()` through the existing
kernel-peer login with read-only transaction options. It verifies the exact public
resource/policy/proposal pins, actual Keycloak signature/profile/scopes and DPoP
request binding before issuing evidence. Replay consumption is retained under the
observer's private EBS state and flushed before returning a signed result.
The source accepts only the relay's authenticated mTLS identity. The relay accepts
only the Agent's SPIRE mTLS identity and pins the source's server identity; it
forwards bounded requests and cannot sign evidence. Signing seeds remain on Sql.

`enroll-cura-evidence-api.py` checks the pinned module manifest and Node executable,
protected role configuration, proof-key pins and systemd preflight. Its generated
units use separate hosts, nonroot UID, empty capabilities, read-only code/config,
seccomp, explicit VPC DNS and VPC-only networking. The Node runtime runs without
JIT so the units can retain `MemoryDenyWriteExecute=yes`. Installed generations
are immutable. Configuration mismatches require explicit reconciliation.

`cura-sql-profile.mjs` builds the technical version-one SQL descriptor/policy and
evidence contract. The governance-owned registry key signs it under the real
governance UID. The descriptor passes the frozen schema and official SDK binding
checks. Its runtime-writer listing remains a candidate: privileged database/host
maintenance is explicit, and complete writer qualification and owner review are
pending. No registry signature supplies an independent owner's acceptance.

`probe-cura-subject-provider.py` mints and verifies an ephemeral Identity-local
DPoP probe. On first actual signing, Keycloak initialized its configured Ed25519
key while preserving the two existing RSA keys. A real restart preserved the new
key, and a later Agent request verified its signature. Scope enrollment can record
this one initialization only with an explicit flag, protected source pin, fresh
actual subject verification and archived original scope/RSA history. It refuses
other key replacements, scope changes or later rotations through that path.

`pilot-subject-delivery.py` renders two expiring policies on existing Identity and
Agent roles. Agent can write only the exact encrypted Proof parameter and read
only Token; Identity holds the client secret, verifies the Agent proof, and writes
only a short-lived DPoP-bound token. KMS actions are individually tied to their
parameter encryption contexts. Services receives no grant. This is a bounded
operator delivery harness, not a continuously available token service.

`deliver-cura-subject-request.py` checks exact host/context/source pins and launches
`cura-agent-observation.mjs` under the isolated Agent UID and systemd sandbox.
Each request generation retains a separate protected configuration. Credentials
never enter command text or output. The Agent obtains its own workload X.509
credential, reads fresh baseline state, signs its own proposal and verifies the
returned evidence/manifest with the SDK. Actual replay, arbitrary input, tampering,
metadata, direct observer and database TCP refusals passed twice. Both sets of
parameters, local ephemeral proof/token files and auxiliary policies were removed.

`export-cura-observation.py` collects only provider-signature-verified public
artifacts from the exact registered cohort. It exports no JWT or private log.
Collected records are historical evidence: their short validity has elapsed and
they cannot authorize another request. Obtain new live evidence for each workflow.
Static workload trust, continuous subject/actor renewal, complete issuer
rotation/revocation, operational budgets and independent custody remain separate
qualification work. Current provider keys and TLS material do not establish these.

## Technical governance identity and physical baseline

`enroll-cura-operator-client.py` enrolls the explicitly approved technical
`kf-pilot-operator` Keycloak client on Identity. It has only `kf.publish_policy`,
`kf.register_descriptor`, `kf.install`, `kf.revoke` and `kf.query`, with mandatory
DPoP and a 120-second token lifetime. Browser, implicit and password client flows
are disabled. Its distinct actual service-account subject and protected creation
intent are retained; the client secret never leaves Identity. Existing client or
secret mismatches require reconciliation. The helper verifies that the Agent's
five scopes and issuer keys remain unchanged. This client supplies implementation
operations, not an independent acceptance owner. Actual enrollment succeeded in
the renewed window; native governance publication has not yet run.

`backup-cura-sql.py --before-first-dispatch` takes a bounded cold baseline on the
existing Sql volume only. It requires the original version-1/fence-0 resource,
zero attempts and an inactive native target; it refuses existing or interrupted
backup paths. It stops the observer and database, requires clean shutdown, rejects
links/special files, verifies every copied file, flushes files/directories and
resumes the original database and observer. The manifest and database copy remain
root-protected on Sql; no backup contents leave the host. The actual copy verified
1,285 files (47,992,492 bytes), with about 6.2 seconds of quiescence and unchanged
database state after resumption. It is a baseline for the later physical/stale
restore rehearsal. It does not perform a restore or supply independent storage
custody. The completed backup and manifest must be preserved for that rehearsal.
