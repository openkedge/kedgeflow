# RFC 0019: Broker authorization before target credential minting

- Status: Draft
- Milestone: M5b software prerequisite
- Baseline: `973a510`; RFCs 0004, 0010, 0016 and 0018
- Owners/reviewers: unassigned; authorization server, gateway, resource and security owners
- Profile: `KF-BROKER-AUTHORIZATION-0.1-draft` (internal library/store contract)

## Purpose and trust

[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1) defines token
exchange carriage; KedgeFlow's grant/digest/attempt fields are a separately named
extension. A token-exchange client cannot prove that the authorization server
checked a durable claimed attempt. This increment supplies that authorization
check for integration into an independently operated broker. It neither starts
an authorization server nor mints a production token. Only the existing closed
one-resource node/version FencingToken leaf binding is accepted here; CTD-driven
SQL action mapping remains M6.

The broker authenticates its gateway connection through independently verified
mTLS and an exact registered gateway workload. The delegated subject and actor
assertion are verified by an operator-approved `ExchangeIdentityProvider`.
That trusted integration MUST verify issuer/key/audience/algorithm/time and
revocation policy, bind the actor to the agent workload, and construct the exact
canonical subject-token delegation digest/confirmation key used at admission.
Returning fields from unverified request data is not an implementation.

The library takes the original subject/actor tokens, exact signed grant/digest,
original AttemptID, and requested audience/scope. It checks bounded closed
inputs. Provider verification has a five-second bound. No raw credentials are
persisted in the permit. A provider failure refuses before permit creation.

## Independent checks

Verify the grant with independently configured Grant Authority keys and live
time. Bind freshly verified subject, workload, confirmation key and delegation
digest to it; require the provider's returned subject token to equal the submitted
token. Subject and actor expiry bound credential validity. Bind retained original
parameters/tool to an operator-pinned ToolDescriptor using the gateway's exact
action/resource/contract/predicate parameter checks. Agent-supplied SQL, endpoints,
target audience or wider scopes do not select a new binding.

A fixed registration supplies gateway workload, target audience/scope and maximum
credential duration in 1000..300000 ms. The target must independently enforce the
declared action/attempt/fence contract. A permit is not target authority, a target
commit proof or a substitute for final dispatch authorization.

Read the original execution snapshot and require the original consumed root,
nonce, grant digest, claimed attempt and `claimed_not_dispatched` outbox.
Validate its retained signed execution record and immutable claim journal.
Require current policy/ownership and managed control/revocation comparisons at
the permit CAS. Any unknown, committed, sealed, dispatched, missing, substituted
or revoked attempt refuses. Recheck grant/provider time after verification/reads
before the write. The broker must not allocate, claim, refund or replace roots.

## One permit and ambiguous failure

An immutable permit under the original attempt binds profile, registration,
grant/root/attempt, authenticated gateway, fixed target audience/scope and
authorization/expiry times. Its domain-separated ID is correlation, not a
signature. Expiry is the smallest of grant, verified subject token, verified actor
assertion and operator duration; at least one full second must remain.

A version-zero permit CAS compares exact execution context, attempt, outbox,
claim journal, root/nonce/grant, policy/ownership and managed control/revocation
state. Only the winning call returns authorization for one mint invocation.
Duplicate/concurrent calls refuse; no second permit or credential renewal is
authorized. An uncertain CAS reply refuses and MUST NOT invoke minting. If a
permit persists before broker death or failed mint, allowance remains consumed
and future authorization refuses. Availability repair requires a future provider
idempotency/custody contract; a timer or missing token is not a refund.

The provider must enforce target audience/scope/attempt and no later expiry
during minting, recheck validity after delays and retain credentials under its
own custody contract. Revocation after a permit does not revoke an already
minted token; the gateway still performs its separate final dispatch CAS.
The library is not an agent-callable endpoint, and permits are not accepted
from remote callers as capabilities. All ledger operations use the configured
restore gate; production RBAC must exclude agents and unauthorized permit writers.

## Verification and enterprise gate

Required native-etcd cases: one concurrent winner; repeated/recreated refusal;
unclaimed/foreign/missing execution; wrong gateway/subject/workload/key/delegation;
target widening; expired provider identity; time exhausted during verification;
current policy/ownership and revocation; dispatch/terminal state; lost successful
CAS reply; unavailable ledger; restore quarantine. Assert original consumption
and no target mutation/mint from refused authorization.

Tests use software provider identities and do not establish actual subject/actor
verification, SPIRE provisioning, server interoperability, target token binding,
broker custody, rotation or production permissions. M5c must integrate and qualify
the approved authorization server, workload provider and target before enterprise
acceptance. No frozen signed record or RFC 8693 wire change is made here.
