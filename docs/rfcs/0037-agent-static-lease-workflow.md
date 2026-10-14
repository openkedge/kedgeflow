# RFC 0037: Node Agent Adapter static lease preparation

- Status: Draft
- Profiles: existing KF-STATIC-LEASE-HTTP-0.1-draft; local
  KF-AGENT-LEASE-STATE-0.1-draft
- Milestone: M7d2 client integration
- Baseline: e94ffd0; RFCs 0008, 0035, 0036
- Owners/reviewers: unassigned

## Scope and registration

Opt in with independently pinned lease endpoint, scope, policy/ownership,
proposal/lease/JIT lifetime limits and a complete static/JIT obligation map. Pin
provider identities, versions and role keys per obligation, predicate digest,
execution relevance and maximum age. Lease signing uses the existing admission
role. Reject unknown fields, overlapping lease/input/issuer keys, empty or
unbounded registrations, absent static/JIT stages and endpoint aliases.
Do not discover a lease endpoint or obligations from remediation or a lease.
The no-lease adapter keeps its existing wire flow and query-only recovery.

## Preparation and acquisition

`prevalidate({qid, arguments})` freezes the exact proposal and delegation using
existing baseline/remediation checks. Persist a versioned, registration-bound
preparation marker and proposal before acquiring static evidence. `collectStatic`
returns a signed static-only manifest and original witnesses; verify exact
registered coverage, signatures, proposal/policy/provider/freshness and manifest
references before retaining them. Submit unchanged records to native /leases.
Verify the frozen non-authorizing lease signature, closed payload, exact context,
static discharges, pending JIT IDs and original validity bounds before retaining
its original bytes. Return preparation metadata, never an execution grant.

A lost prevalidation reply can retry the original retained static packet; the
server returns its immutable cache. A ready lease can be reused locally across
adapter recreation while original proposal/delegation/static evidence remain
valid. This does not prove current membership; final native admission/issuance
still compare current member/cache/review/control. Never renew an expired cache,
recollect static evidence over a ready lease or move it to another proposal.

## Final admission and ambiguity

`execute` can perform preparation automatically or use an explicitly prepared
operation. `collectJit` receives the original static packet and lease and returns
a complete signed manifest/witness set. Independently verify exact static/JIT
coverage, original canonical static records, all context/signature/ref/age links
and JIT observations at or after lease issue. Certificate lease_digest must equal
the verified retained lease; policy/ownership and expiry must remain bounded.

Persist the complete packet and `authority_started` before sending admission.
That marker is permanent even if admission, issuance or grant persistence fails,
a reply is lost, or status says unissued/unclaimed. Subsequent execution is
query-only. Only prevalidating/ready records with matching approved registration
and unchanged delegation may resume acquisition; a lost JIT reply can recollect
JIT because no authority request has begun. Never infer resumability from missing
grant/certificate, elapsed time or status. Legacy records are always query-only.
A changed registration, identity, proposal, action, parameters or delegation
cannot renew the prepared operation. Keep single-owner durable locking and the
existing no-resend rule for possible execution.

## Qualification and limits

Qualify official SDK with native mTLS/DPoP/etcd and installed control, static-only
preparation/retry, separate Node-process reuse, fresh JIT final admission/issuance,
one original effect, expired/withdrawn cache refusal and lost prevalidation/JIT /
admission/issuer/persistence reply boundaries. Add closed-field, role, discharge,
pending-JIT, static substitution, freshness and certificate-link client negatives.
Retain required software evidence and unchanged frozen artifacts.

This increment uses software provider/membership/custody fixtures. It does not
supply a protected browser, physical ceremony/attestation, approved enterprise
provider lifecycle, independent peer acceptance or a latency/cost claim. Local
store access, atomic durable writes and honest restoration remain assumptions;
crashed file locks require explicit owner recovery, as before. M7 ceremony gates
remain open; M8 native reservation/grant/claim integration is the next software
milestone after this client increment.
