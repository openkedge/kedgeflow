# Broker authorization prerequisite (M5b)

[RFC 0019](rfcs/0019-broker-authorization.md) defines the internal
`KF-BROKER-AUTHORIZATION-0.1-draft` contract. The Rust
`broker_authorization::BrokerAuthorizer` is a trusted integration library for an
independently administered broker. It does not start an authorization server,
mint a credential or replace the existing RFC 8693 client. The accepted binding
is the existing closed one-resource node/version FencingToken leaf profile.
CTD-driven SQL mapping remains M6.

Construct it with independently approved grant keys, a fixed target/tool
registration, protected ledger access, trusted service clock and an
`ExchangeIdentityProvider`. The provider must verify the actual subject and actor
tokens and return their verified identity and validity bounds. It must construct
the original canonical delegation digest and confirmation key, rather than trust
caller claims. Provider implementations and token mint/custody behavior require
the approved AS/SVID/target contracts. The software test provider is not a
production implementation.

Pass the exact grant/digest/original AttemptID, subject/actor tokens and fixed
target audience/scope, plus the workload context from the broker's completed
verified-mTLS gateway connection. Agent connections cannot stand in for the
registered gateway. The library verifies the grant and identity, retained
parameters/tool, original consumed root/nonce/claim and undispatched outbox.
Current policy/ownership and managed revocations/install comparisons join the
same permit CAS. No grant allocation or root consumption transition is added.

The winning call retains one immutable permit under the original attempt.
Duplicate/recreated/concurrent calls refuse, as do ambiguous mutation replies.
Provider verification and reads can consume time: grant/provider validity is
rechecked before writing, and permit validity is checked again after the reply.
At least one full second must remain. Failed mint, death after permit persistence
or an expired/lost permit reply leaves allowance held. No renewal, automatic
repair, idempotent token-mint recovery or second permit is authorized.

A permit is unsigned protected broker state, not a remotely accepted capability.
It retains correlation and expiry, with no subject/actor token. The minting
provider must enforce the fixed target scope/audience/attempt and expiry, check
delays, and keep credentials within its custody contract. An already minted token
does not acquire automatic revocation from the permit; final gateway dispatch CAS
and target guard/deduplication remain separate required boundaries.

[Fresh verification](../results/verification/rfc-m5-broker-2026-10-12/README.md)
uses real etcd and software provider identities. It checks one concurrent winner,
recreated refusal, unclaimed/unrecorded state, issuer/key/workload/delegation/tool/
target substitution, expiry, provider failure/delay, policy/ownership/revocation,
dispatch/terminal state, corruption, restore-marker refusal, store outage, lost
successful write reply and a revocation racing the final CAS. These tests do not
claim provider identity verification, real token issuance, target token binding,
production RBAC/custody or a native broker endpoint.

Next is [M5c enterprise qualification](ENTERPRISE_QUALIFICATION.md). Configure the
actual independent provider and credential binding before claiming end-to-end
broker enforcement. Software fixtures cannot close that gate.
