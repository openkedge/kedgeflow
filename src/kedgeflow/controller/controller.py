"""KedgeFlow controller evaluating proposals and issuing bounded authority grants."""

import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field

from kedgeflow.controller.policy import PolicyEngine, RuleBasedPolicyEngine
from kedgeflow.protocol.authority import (
    AuthorityGrant,
    AuthoritySigner,
    HMACAuthoritySigner,
)
from kedgeflow.protocol.proposal import Proposal
from kedgeflow.protocol.state_machine import LifecycleState, ProposalLifecycle
from kedgeflow.storage.memory import GlobalState, StateStore


class DecisionDisposition(str, Enum):
    """The outcome of a proposal admission evaluation."""

    GRANT = "GRANT"
    DENY = "DENY"


class Decision(BaseModel):
    """Admission decision returned by the KedgeFlow Controller."""

    disposition: DecisionDisposition = Field(
        description="Whether the proposal was granted authority or denied."
    )
    authority: AuthorityGrant | None = Field(
        default=None,
        description="Bounded authority grant if disposition is GRANT.",
    )
    reason: str = Field(
        default="",
        description="Explanation or justification for the admission decision.",
    )


class KedgeFlowController:
    """The central control plane component responsible for proposal admission
    and authority issuance.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        state: StateStore | None = None,
        signer: AuthoritySigner | None = None,
    ) -> None:
        self.policy_engine: PolicyEngine = policy_engine or RuleBasedPolicyEngine()
        self.state: StateStore = state or GlobalState()
        self.signer: AuthoritySigner = signer or HMACAuthoritySigner(secrets.token_hex(32))

        # Internal registries for active authority, revocations, and lifecycle tracking
        self._lifecycles: dict[UUID, ProposalLifecycle] = {}
        self._grants: dict[UUID, AuthorityGrant] = {}
        self._revoked_grants: dict[UUID, str] = {}  # authority_id -> reason

    def propose(self, proposal: Proposal) -> Decision:
        """Evaluate an agent's proposal against policy, evidence, and state."""
        # 1. Initialize and advance state machine to PROPOSED
        lifecycle = self._lifecycles.setdefault(
            proposal.proposal_id, ProposalLifecycle(LifecycleState.CREATED)
        )
        if lifecycle.current_state == LifecycleState.CREATED:
            lifecycle.transition_to(LifecycleState.PROPOSED)

        # 2. Evaluate with Policy Engine
        policy_decision = self.policy_engine.evaluate(proposal, self.state)

        # 3. Process DENIED outcome
        if not policy_decision.allowed:
            lifecycle.transition_to(LifecycleState.DENIED)
            return Decision(
                disposition=DecisionDisposition.DENY,
                authority=None,
                reason=policy_decision.reason,
            )

        # 4. Process GRANTED outcome: issue bounded authority grant
        lifecycle.transition_to(LifecycleState.GRANTED)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=policy_decision.ttl_seconds)

        unsigned_grant = AuthorityGrant(
            proposal_id=proposal.proposal_id,
            actor=proposal.actor,
            operation=proposal.operation,
            target=proposal.target,
            parameter_constraints=policy_decision.parameter_constraints,
            guards=policy_decision.guards,
            issued_at=now,
            expires_at=expires_at,
            policy_version=policy_decision.policy_version,
            max_uses=1,
        )

        # 5. Sign the grant with controller's cryptographic authority signer
        signed_grant = self.signer.sign(unsigned_grant)
        self._grants[signed_grant.authority_id] = signed_grant

        return Decision(
            disposition=DecisionDisposition.GRANT,
            authority=signed_grant,
            reason=policy_decision.reason,
        )

    def revoke(self, authority_id: UUID, reason: str = "Revoked by controller") -> None:
        """Revoke an issued authority grant immediately."""
        self._revoked_grants[authority_id] = reason
        if authority_id in self._grants:
            grant = self._grants[authority_id]
            lifecycle = self._lifecycles.get(grant.proposal_id)
            if lifecycle and lifecycle.current_state == LifecycleState.GRANTED:
                lifecycle.transition_to(LifecycleState.REVOKED)

    def is_revoked(self, authority_id: UUID) -> bool:
        """Check if an authority grant has been revoked."""
        return authority_id in self._revoked_grants

    def get_lifecycle_state(self, proposal_id: UUID) -> LifecycleState | None:
        """Retrieve the current lifecycle state of a proposal."""
        lifecycle = self._lifecycles.get(proposal_id)
        return lifecycle.current_state if lifecycle else None

    def transition_proposal(self, proposal_id: UUID, next_state: LifecycleState) -> None:
        """Advance the proposal lifecycle state."""
        lifecycle = self._lifecycles.get(proposal_id)
        if lifecycle:
            lifecycle.transition_to(next_state)
