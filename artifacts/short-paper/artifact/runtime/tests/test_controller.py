"""Tests for KedgeFlowController and policy engine evaluation."""

from kedgeflow.controller.controller import DecisionDisposition, KedgeFlowController
from kedgeflow.controller.policy import PolicyDecision, RuleBasedPolicyEngine
from kedgeflow.protocol.guard import Guard, GuardOperator
from kedgeflow.protocol.proposal import Proposal
from kedgeflow.protocol.state_machine import LifecycleState
from kedgeflow.storage.memory import GlobalState


def test_controller_valid_proposal_grant() -> None:
    state = GlobalState({"production.capacity": 4})
    controller = KedgeFlowController(state=state)

    proposal = Proposal(
        actor="ops-agent",
        intent="remove unhealthy capacity",
        operation="compute.terminate",
        target="instance/i-17",
        evidence=[{"type": "health", "value": "failed"}],
    )

    decision = controller.propose(proposal)
    assert decision.disposition == DecisionDisposition.GRANT
    assert decision.authority is not None
    assert decision.authority.actor == "ops-agent"
    assert decision.authority.operation == "compute.terminate"
    assert decision.authority.target == "instance/i-17"
    assert len(decision.authority.guards) == 1
    assert decision.authority.guards[0].key == "production.capacity"
    assert decision.authority.signature is not None
    assert controller.get_lifecycle_state(proposal.proposal_id) == LifecycleState.GRANTED


def test_controller_invalid_evidence_deny() -> None:
    state = GlobalState({"production.capacity": 4})
    controller = KedgeFlowController(state=state)

    # Missing evidence or healthy instance
    proposal = Proposal(
        actor="ops-agent",
        intent="remove healthy capacity",
        operation="compute.terminate",
        target="instance/i-17",
        evidence=[{"type": "health", "value": "healthy"}],
    )

    decision = controller.propose(proposal)
    assert decision.disposition == DecisionDisposition.DENY
    assert decision.authority is None
    assert "health == failed" in decision.reason
    assert controller.get_lifecycle_state(proposal.proposal_id) == LifecycleState.DENIED


def test_controller_unsupported_operation_default_deny() -> None:
    controller = KedgeFlowController()
    proposal = Proposal(
        actor="unknown-agent",
        intent="arbitrary operation",
        operation="database.drop_all",
        target="db/prod",
    )

    decision = controller.propose(proposal)
    assert decision.disposition == DecisionDisposition.DENY
    assert decision.authority is None
    assert "No matching policy rule" in decision.reason


def test_controller_revocation() -> None:
    controller = KedgeFlowController()
    proposal = Proposal(
        actor="ops-agent",
        intent="remove unhealthy capacity",
        operation="compute.terminate",
        target="instance/i-17",
        evidence=[{"type": "health", "value": "failed"}],
    )

    decision = controller.propose(proposal)
    assert decision.authority is not None
    auth_id = decision.authority.authority_id

    assert controller.is_revoked(auth_id) is False
    controller.revoke(auth_id, reason="Emergency hold")
    assert controller.is_revoked(auth_id) is True
    assert controller.get_lifecycle_state(proposal.proposal_id) == LifecycleState.REVOKED


def test_controller_custom_policy_registration() -> None:
    engine = RuleBasedPolicyEngine()

    def custom_rule(proposal: Proposal, state: GlobalState) -> PolicyDecision | None:
        if proposal.operation == "cache.flush":
            return PolicyDecision(
                allowed=True,
                reason="Cache flush allowed for admins",
                guards=[Guard(key="env", operator=GuardOperator.EQUALS, value="staging")],
            )
        return None

    engine.register("cache.flush", custom_rule)
    controller = KedgeFlowController(policy_engine=engine)

    prop = Proposal(
        actor="dev-agent",
        intent="clear redis",
        operation="cache.flush",
        target="redis/staging",
    )
    decision = controller.propose(prop)
    assert decision.disposition == DecisionDisposition.GRANT
    assert decision.authority is not None
    assert len(decision.authority.guards) == 1
    assert decision.authority.guards[0].value == "staging"
