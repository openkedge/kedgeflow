# Real signed SQL observation and isolated Agent requests

These bounded deployed checks ran in the approved Cura/us-west-2 window on
22 November 2026. They do not constitute enterprise acceptance. The fixed stop
remains **2026-11-23T08:00:00Z**, with the original stop record retained.

Sql serves a function-only observation source on 8452; Services serves its relay
on 8444. Both are actual systemd processes under UID 971 with zero effective
capabilities, `NoNewPrivileges` and seccomp. The source retains its evidence and
manifest signing keys on Sql. It accepts only the relay's authenticated mTLS
identity; the relay accepts only the Agent's SPIRE identity and verifies the
source's server identity. Agent has no direct Sql security-group path.

First actual Keycloak signing initialized the configured Ed25519 key
`8dckaks_59-XIz0z4IP0R46WMXcbW46TBosoQE-aMdE`. Both existing RSA public keys were
preserved. A real provider/database restart preserved the new key and all retained
SPIRE registrations/node history. Explicit initialization recording archived the
old scope record and retained RSA history; it does not permit arbitrary rotation.
Actual DPoP tokens verified the fixed subject, audience and five scopes. The client
secret remained on Identity.

Two request generations ran under the real Agent UID 969 and systemd isolation.
Encrypted exact-parameter delivery carried its own DPoP proof to Identity and a
120-second sender-constrained subject token back to Agent. No key, client secret,
JWT or credential hash was returned in command output or local operator packets.
Each Agent fetched its real SPIRE X.509 credential, obtained fresh SQL baseline
state, signed its own proposal and verified the real provider signatures and
proposal/policy/state/manifest links. The second generation followed provider
restart and preserved the first generation's configuration/evidence.

Both generations refused proof replay, arbitrary input and a tampered proposal.
The Agent could not connect to instance metadata, Sql's observation port or
PostgreSQL TCP. Temporary Proof/Token parameters and local ephemeral request
credential files were removed after each generation. Both auxiliary policy stacks
are `DELETE_COMPLETE`; the original two host-role inline policies are again only
`ssm-node-only`. No new principal, trust, instance, volume or endpoint was created.

After both requests, the real database audit observed one resource at version 1,
fence 0 and zero attempts. Its five function-only reader bypass checks still pass.
No execution grant, SQL target listener or guarded SQL action was exercised.

The governance-signed descriptor candidate and collected public evidence/manifest
pass the frozen protocol schema and operator-side official SDK signature/binding
verification. The registry candidate is not complete writer qualification; its
privileged maintenance assumptions and pending resource-owner review are explicit.
The collected signed records have expired and are retained only as historical
proof. Obtain fresh responses for any new operation.

Local checks: **224 Python tests plus six subtests, 93 Node tests, all eight
CloudFormation variants, lint/type checks and 58 frozen files/24 contract pins**.
The prior recovery commit's hosted run `45008445140` subsequently failed the same
credential-renewal step, and its identity job was skipped. Increasing the disposable
token lifetime did not resolve that failure. Fixed phase/process-status annotations
and a bounded exact-artifact reproduction workflow now support diagnosis. This
source increment requires its own complete successful hosted run; an earlier green
commit cannot substitute for it.

The ordered credential reproduction and the native Linux packaging job both passed
for `0171e36bc1` (runs `45067533996` and `45067534010`). The root cause was execution
from `/run` after the preceding lifecycle test left that mount `noexec`. The fixture
now keeps executable copies in a separately owned `/opt` directory and leaves the
protected runtime mount intact. The full run still requires its remaining jobs.

The live dependency audit subsequently identified `RUSTSEC-2026-0592` in `url`
2.5.8. Source now requires patched 2.5.9 and its required `form_urlencoded` 1.2.3;
the lock contains only these two package changes. A 2 MiB worker-stack regression
checks a 10,000-level nested blob URL. The live audit reports no unmatched findings.
The existing Chrono maintenance debt still expires at **2026-11-24T00:00:00Z**;
only its reviewed source hashes were refreshed. The retained AWS native release
has not yet been rebuilt or replaced and must not be claimed patched. See
`url-patch-review.json` for the review scope and upstream references.

Native admission/issuance, broker floors and actor delivery, guarded COMMIT and
original-attempt recovery, complete writer/descendant bypass, deployed
rotation/revocation, physical/stale restore and operational measurements remain
pending. Static workload trust and the bounded operator token harness do not
establish continuous production renewal. Independent security review,
storage/audit custody, actual SRE ownership, independent reproduction and all seven
signed owner decisions remain **BLOCKED_EXTERNAL_INPUT**. Milestone B enterprise
acceptance remains pending.
