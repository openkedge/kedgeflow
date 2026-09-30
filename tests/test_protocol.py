"""Tests for protocol objects, guards, tamper-evident signing, and lifecycle state transitions."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from kedgeflow.protocol.authority import (
    AuthorityGrant,
    HMACAuthoritySigner,
    HMACAuthorityVerifier,
)
from kedgeflow.protocol.errors import InvalidLifecycleTransitionError
from kedgeflow.protocol.guard import Guard, GuardOperator
from kedgeflow.protocol.proposal import Proposal
from kedgeflow.protocol.state_machine import (
    LifecycleState,
    ProposalLifecycle,
    validate_transition,
)


def test_guard_evaluation_all_operators() -> None:
    # Equals
    g_eq = Guard(key="env", operator=GuardOperator.EQUALS, value="prod")
    assert g_eq.evaluate("prod") is True
    assert g_eq.evaluate("dev") is False

    # Not Equals
    g_neq = Guard(key="env", operator=GuardOperator.NOT_EQUALS, value="dev")
    assert g_neq.evaluate("prod") is True
    assert g_neq.evaluate("dev") is False

    # Greater Than
    g_gt = Guard(key="capacity", operator=GuardOperator.GREATER_THAN, value=3)
    assert g_gt.evaluate(4) is True
    assert g_gt.evaluate(3) is False
    assert g_gt.evaluate(2) is False

    # Greater Than Or Equal
    g_gte = Guard(key="capacity", operator=GuardOperator.GREATER_THAN_OR_EQUAL, value=3)
    assert g_gte.evaluate(4) is True
    assert g_gte.evaluate(3) is True
    assert g_gte.evaluate(2) is False

    # Less Than
    g_lt = Guard(key="load", operator=GuardOperator.LESS_THAN, value=0.8)
    assert g_lt.evaluate(0.7) is True
    assert g_lt.evaluate(0.8) is False
    assert g_lt.evaluate(0.9) is False

    # Less Than Or Equal
    g_lte = Guard(key="load", operator=GuardOperator.LESS_THAN_OR_EQUAL, value=0.8)
    assert g_lte.evaluate(0.7) is True
    assert g_lte.evaluate(0.8) is True
    assert g_lte.evaluate(0.9) is False

    # Missing value or mismatched type
    assert g_gt.evaluate(None) is False
    assert g_gt.evaluate("invalid_type") is False


def test_proposal_normalization() -> None:
    # Dict evidence normalized
    p1 = Proposal(
        actor="ops",
        intent="test",
        operation="noop",
        target="res/1",
        evidence={"health": "failed"},  # type: ignore[arg-type]
    )
    assert len(p1.evidence) == 1
    assert p1.evidence[0]["type"] == "health"
    assert p1.evidence[0]["value"] == "failed"

    # List evidence
    p2 = Proposal(
        actor="ops",
        intent="test",
        operation="noop",
        target="res/1",
        evidence=[{"type": "metric", "value": 42}],
    )
    assert len(p2.evidence) == 1
    assert p2.evidence[0]["value"] == 42


def test_tamper_evident_authority_signing_and_verification() -> None:
    secret = "test-secret-key-32-bytes-long!!"
    signer = HMACAuthoritySigner(secret)
    verifier = HMACAuthorityVerifier(secret)

    grant = AuthorityGrant(
        proposal_id=uuid4(),
        actor="agent-1",
        operation="compute.terminate",
        target="instance/i-17",
        guards=[Guard(key="capacity", operator=GuardOperator.GREATER_THAN, value=3)],
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        max_uses=1,
    )

    signed_grant = signer.sign(grant)
    assert signed_grant.signature is not None
    assert verifier.verify(signed_grant) is True

    # Tamper test 1: Modify target
    tampered_target = signed_grant.model_copy(update={"target": "instance/i-99"})
    assert verifier.verify(tampered_target) is False

    # Tamper test 2: Modify operation
    tampered_op = signed_grant.model_copy(update={"operation": "compute.reboot"})
    assert verifier.verify(tampered_op) is False

    # Tamper test 3: Modify expiration
    tampered_exp = signed_grant.model_copy(
        update={"expires_at": signed_grant.expires_at + timedelta(hours=1)}
    )
    assert verifier.verify(tampered_exp) is False

    # Tamper test 4: Modify guards
    tampered_guards = signed_grant.model_copy(
        update={"guards": [Guard(key="capacity", operator=GuardOperator.GREATER_THAN, value=0)]}
    )
    assert verifier.verify(tampered_guards) is False

    # Tamper test 5: Modify actor
    tampered_actor = signed_grant.model_copy(update={"actor": "malicious-agent"})
    assert verifier.verify(tampered_actor) is False


def test_lifecycle_state_machine_valid_transitions() -> None:
    lc = ProposalLifecycle(LifecycleState.CREATED)
    assert lc.current_state == LifecycleState.CREATED

    lc.transition_to(LifecycleState.PROPOSED)
    assert lc.current_state == LifecycleState.PROPOSED

    lc.transition_to(LifecycleState.GRANTED)
    assert lc.current_state == LifecycleState.GRANTED

    lc.transition_to(LifecycleState.EXECUTING)
    assert lc.current_state == LifecycleState.EXECUTING

    lc.transition_to(LifecycleState.COMPLETED)
    assert lc.current_state == LifecycleState.COMPLETED
    assert len(lc.history) == 5


def test_lifecycle_state_machine_invalid_transitions() -> None:
    # DENIED -> EXECUTING must be impossible
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_transition(LifecycleState.DENIED, LifecycleState.EXECUTING)

    # EXPIRED -> EXECUTING must be impossible
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_transition(LifecycleState.EXPIRED, LifecycleState.EXECUTING)

    # REVOKED -> EXECUTING must be impossible
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_transition(LifecycleState.REVOKED, LifecycleState.EXECUTING)

    # CREATED -> EXECUTING must be impossible
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_transition(LifecycleState.CREATED, LifecycleState.EXECUTING)

    # COMPLETED is terminal
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_transition(LifecycleState.COMPLETED, LifecycleState.EXECUTING)
