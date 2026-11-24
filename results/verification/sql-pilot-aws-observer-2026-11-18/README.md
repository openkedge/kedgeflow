# Cura SQL observer and request identity enrollment

[Observations](observations.json) retain actual 18 November 2026 execution,
collected after work resumed on 22 November. They separate those historical
checks from the current stopped fleet. No fresh application or enterprise
acceptance is inferred from old credentials or successful enrollment.

The `kf-observer` UID 971 connects through an exact PostgreSQL peer map and can
execute only a fixed zero-argument reader of the enrolled `slot-a` incarnation.
Its function owner, execution context, effective privileges and original target
roles passed inspection. Direct table read/write, owner impersonation, Agent
observer login and executor access to the observer function refused. Resource and
attempt state were unchanged. Separate protected evidence/manifest keys were
created on Sql; only public pins were returned. No observation API or signed
evidence object has been issued.

The Agent's own proposal and DPoP request keys remain on its host under UID 969.
Root-held public pins detect replacement on rerun. These are request-identity keys,
not grant/service/writer or acceptance keys. Keycloak's existing confidential DPoP
client now binds exactly five SQL-pilot scopes; its actual service-account subject,
disabled browser/password flows and unchanged public issuer keys were verified.
No client secret, private key or administrator token was exported or rotated.

Host-local observer and relay TLS material brought the recorded certificate count
to seventeen. Those leaf certificates expired at the original pilot stop time,
**18 November 23:16:43 UTC**; the recorded service CA expired one hour later.
Read-only AWS inspection on 22 November found all nine hosts stopped. They have
not been restarted and neither expired credential handling nor SPIRE recovery
after this multi-day pause has been qualified.

The proposed infrastructure delta adds only a Services-to-Sql observation path on
8452, one ingress and one egress rule, preserving every existing rule identity.
It is **not deployed**. The Agent gets no direct Sql path. The renewed-window
renderer proposes a stop-only schedule using the existing exact-fleet role/group;
it starts no hosts and requires a separately approved, bounded operating window.

`c69f96d01be1a41a50cd360db35551e46c318346` passed all eleven required hosted jobs
in [CI run 44268632396](https://github.com/openkedge/kedgeflow/actions/runs/44268632396).
The retained REST run/jobs passed the source, step, completeness and no-skip
checks with no gaps. Earlier run 44265485682 failed and is not passing evidence.
This observer/window increment has **211 local tests and six subtests**, seven
schema-checked CloudFormation variants, Ruff/mypy and unchanged 58 frozen files/24
protocol pins; it needs its own hosted run.

Fresh signed observation, application enrollment and a guarded SQL COMMIT/original
attempt query remain unfinished. Complete writer/descendant qualification,
rotation/revocation, physical/stale restore and deployed operational measurements
also remain open. Independent security, storage/audit custody, actual SRE ownership
and seven real owner decisions remain **BLOCKED_EXTERNAL_INPUT**. No enterprise
acceptance or production qualification is asserted.
