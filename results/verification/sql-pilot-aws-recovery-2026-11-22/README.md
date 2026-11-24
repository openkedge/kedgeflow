# Renewed Cura pilot and retained identity recovery

These are bounded observations from the real retained AWS pilot in `cura`,
`us-west-2`, on 22 November 2026. They are not owner signatures or enterprise
acceptance. The original stop deadline and earlier records remain historical.

The user explicitly approved the reviewed renewed window ending
**2026-11-23T08:00:00Z (23 November 00:00 PST)**, existing nine hosts, stop schedule,
two observation rules and protected credential recovery. The stop-only schedule
was installed and read back before starting only those hosts. The main stack added
only Services-to-Sql TCP 8452 ingress/egress; Agent has no Sql path. No new instance,
disk, endpoint, VPC or IAM principal was provisioned. Retained resources continue
billing; the account budget is an alert, not a hard cost cap.

All eighteen transport leaves were renewed to that deadline under a new protected
issuer generation. Host private keys were retained, old public chains archived and
consumers stopped during installation. Both retained etcd cluster identities,
authentication, ordinary-role scope refusals, credential renewal and the original
native recovery enrollment/head at sequence zero passed rechecks. There was no
namespace reset or second genesis enrollment.

Both old SPIRE node SVIDs had expired during the stopped interval. Initial actual
UID issuance failed. The protected recovery helper retained full original inventory
only on Identity and private node snapshots only on their original hosts. It
refreshed public CA trust without clearing the cache or disk stores. Native SPIRE
attestation rotated node keys and created two new internal principals/aliases;
both expired principals and all old aliases remain. The two original public
workload entries and Unix UID selectors were preserved. Internal token-derived
node IDs, join tokens, JWTs, passwords and private keys were not exported.

Both actual registered UIDs passed JWT signature/subject/audience/expiry and X.509
chain/URI checks, cross-host UID refusals and protected node-key denial. Consumed
join material was removed, both nodes restarted from retained state, and probes
passed again. A real PostgreSQL/Keycloak/SPIRE provider restart preserved public
signing keys, all registrations and old/current node IDs; both workload probes
then passed again. Both encrypted delivery parameters are absent, the temporary
three-policy recovery stack is `DELETE_COMPLETE`, and the three original host
roles retain only `ssm-node-only` inline policy names. No duty-role trust changed.

SQL remains the same registered incarnation at version 1. Its function-only reader
audit and five negative paths pass without changing the resource or attempt state.
Keycloak retains the same service-account subject, two public key IDs, confidential
DPoP client and five closed SQL-pilot scopes.

The public JSON records the exact bounded observations and helper source hashes.
Raw command provenance and approval metadata remain in the ignored protected
operator packet. The native Linux release bundle remains unchanged.

The observer/window commit `d7bd71d432359c1a49cc355ac6aa734ba622c4c7` did **not**
pass CI: run `45005194732` failed the disposable systemd credential-renewal step,
and the dependent self-hosted identity job was skipped. Earlier commit `c69f96d`
passed all eleven jobs. Current recovery source needs its own hosted qualification.
The fixture now allows thirty seconds for real token lifetime instead of three,
retains an actual expiry negative, and emits fixed diagnostic phases. Timing is
a suspected cause, not an established root cause; a fresh passing run is required.

The signed observation HTTP API, guarded SQL COMMIT/original-attempt recovery,
full writer/descendant bypass, deployed rotation/revocation, physical/stale restore
and operational measurements remain pending technical work. Independent security
approval, storage/audit custody, actual SRE ownership, independent reproduction and
all seven signed owner decisions remain **BLOCKED_EXTERNAL_INPUT**. Milestone B
enterprise acceptance remains pending.
