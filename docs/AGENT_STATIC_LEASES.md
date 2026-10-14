# Node Agent Adapter static lease workflow (M7d2)

[RFC 0037](rfcs/0037-agent-static-lease-workflow.md) adds opt-in static preparation
and fresh JIT acquisition to the [Node adapter](AGENT_ADAPTER.md). It uses the
existing [native lease endpoint](STATIC_ADMISSION_LEASES.md) and frozen
non-authorizing AdmissionLease record. No MCP discovery or frozen wire profile
changes. Full native admission/issuance still verify raw evidence, Cedar policy
and current membership/cache/review/control state.

## Configure

Add an independently approved `config.leases` object, using
[agent-leases.example.json](../config/agent-leases.example.json) as a fragment.
The example has public software test keys and zero placeholder digests; replace
all pins with the intended approved registration. Match native policy, ownership,
proposal-age, lease/JIT lifetime and obligation rules. Public keys use the existing
SDK unpadded base64url encoding, representing the same native role keys.

The closed fragment contains `url`, `scope`, `policy`, `ownershipEpoch`,
`maxLifetimeMs`, `jitMaxAgeMs`, `maxProposalAgeMs` and `obligations`. Each obligation
pins `stage`, `predicate_digest`, `execution_relevant`, `provider_id`,
`provider_version`, `keys` and `max_age_ms`. Supply both static and JIT stages.
Lease verification uses `config.admissionKeys`, disjoint from input/issuer keys.
The lease URL must be `/leases` on the approved admission origin and distinct
from gateway, admission, issuance and status URLs. Include it in the pinned mTLS
transport's `allowedUrls`. Require `statusUrl` for conservative recovery, the
configured lease scope for preparation/admission, and normal issuance/status scopes.
Do not obtain endpoint, stage assignments or pins from remediation or a lease.

An opt-in evidence source implements:

```js
const evidenceSource = {
  prepareProposal, // existing baseline and exact proposal contract
  collectStatic: async ({proposal, proposal_digest}) => {
    // Return {manifest, witnesses} for exactly the static obligations.
    return approvedStaticProvider.collect({proposal, proposal_digest});
  },
  collectJit: async ({proposal, proposal_digest, staticPacket, lease}) => {
    // Acquire fresh JIT witnesses and assemble the complete signed manifest,
    // retaining the original static witnesses from staticPacket.
    return approvedJitProvider.collect({proposal, proposal_digest, staticPacket, lease});
  }
};
```

These are application provider interfaces, not new public HTTP protocols. Obtain
records from enrolled providers using their approved authentication. Providers do
not receive admission/issuer private keys or target mutation credentials. Client
checks cover role signatures, exact manifest/stage coverage and references,
proposal/policy/provider/state/time bindings, original static records and lease /
certificate links. Native services additionally enforce registered application
schemas/predicates, review facts and full authorization. A client check does not
replace native admission.

## Prepare and execute

The existing `execute` call automatically performs static preparation, lease
acquisition and fresh JIT admission when configured. For preparation in advance:

```js
await agent.connect();
const call = {qid: stableOperationId, arguments: applicationArguments};
const prepared = await agent.prevalidate(call);
// prepared: state, lease_digest, lid, expires_at; no execution authority.
const result = await agent.execute(call);
await agent.close();
```

The protected operation store retains the original proposal/delegation, static
packet and signed lease. `KF-AGENT-LEASE-STATE-0.1-draft` is local state with a
registration digest and `prevalidating`, `ready` or `authority_started` phase;
it is not a grant or a server-negotiated protocol.

A separate adapter process can retry prevalidation after a lost reply using the
same retained static packet, or reuse a ready lease without another baseline /
static collection or prevalidation request. It rechecks original signed records
and validity. Ready-cache reuse does not establish current membership: native
admission and issuance still compare it atomically. Expired caches are not renewed;
changed operation/parameters, configuration or delegation requires a new operation.

JIT acquisition occurs immediately before final admission. Observations must be
at or after lease issue and within both configured and registered maximum ages.
The complete signed manifest must preserve the original canonical static records.
Client validation rejects swapped, duplicate, missing or stale witnesses. The
certificate must bind the exact verified lease, policy/ownership, full discharges
and bounded expiry.

Before sending admission, the adapter durably writes the complete packet and
permanent `authority_started` marker. A lost admission/issuer reply, failed grant
persistence or an unissued/unclaimed status never permits another admission or
dispatch. Subsequent `execute` calls are query-only. Legacy retained operations
remain query-only. Only explicit prevalidating/ready records can resume before
that boundary: a lost JIT reply or failed pre-admission marker write can recollect
JIT because no authority request was sent. No retry refunds allowance or resends
a possibly executed action.

Use `connect({queryOnly:true})` and `status(qid)` with a current status-only
delegation for authorized history after expiry/revocation. Query results provide
no execution permission. Existing file locks remain until explicit owner recovery
after an actual crash; never release them based on elapsed time.

## Qualification and limits

The [source-pinned software evidence](../results/verification/rfc-m7-agent-leases-2026-10-14/README.md)
qualifies the official SDK with real mTLS/DPoP/etcd and installed control. Five
native groups cover automatic/prepared acquisition, separate Node processes,
immutable lost-prevalidation retry, lost JIT/marker-write recovery, lost admission /
issuer/grant-persistence query-only behavior, expiry/withdrawal/replacement /
changed-delegation refusal, one original guarded mock effect and renewed status-only
queries. Independent client vectors cover closed fields, roles, substitutions,
freshness, discharge/JIT coverage, local markers and certificate links.

These are software providers/memberships, a guarded mock target and simulated
reply/write failures with ordinary process recreation. They do not establish
physical power-loss storage, crash-lock recovery, actual hardware review, a leased
SQL enterprise pilot or deployed provider/custody acceptance. The existing SQL
non-lease path remains qualified separately. Native service process-kill evidence
remains in prior records. Frozen artifacts and legacy non-lease behavior remain
unchanged. M7 hardware/ceremony acceptance is open; next software work is M8b
reservation-to-native-grant/claim integration.
