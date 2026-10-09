"""Tests for LocalEnforcer authority verification and live guard enforcement."""

from datetime import datetime, timedelta, timezone

import pytest

from kedgeflow.enforcement.local import LocalEnforcer
from kedgeflow.protocol.authority import (
    AuthorityGrant,
    HMACAuthoritySigner,
    HMACAuthorityVerifier,
)
from kedgeflow.protocol.errors import (
    AuthorityExhaustedError,
    AuthorityExpiredError,
    AuthorityRevokedError,
    ConstraintViolationError,
    GuardFailedError,
    InvalidAuthorityError,
)
from kedgeflow.protocol.guard import Guard, GuardOperator
from kedgeflow.protocol.proposal import Proposal
from kedgeflow.protocol.receipt import ExecutionStatus
from kedgeflow.storage.memory import GlobalState, InMemoryReceiptStore


@pytest.fixture
def test_setup() -> dict:
    secret = "secret-for-testing-enforcer-32b"
    signer = HMACAuthoritySigner(secret)
    verifier = HMACAuthorityVerifier(secret)
    state = GlobalState({"production.capacity": 4, "env": "prod"})
    receipt_store = InMemoryReceiptStore()
    revoked_set: set = set()

    enforcer = LocalEnforcer(
        verifier=verifier,
        state=state,
        receipt_store=receipt_store,
        revocation_checker=lambda auth_id: auth_id in revoked_set,
    )

    proposal = Proposal(
        actor="ops-agent",
        intent="remove unhealthy capacity",
        operation="compute.terminate",
        target="instance/i-17",
        parameters={"force": False},
        evidence=[{"type": "health", "value": "failed"}],
    )

    grant = AuthorityGrant(
        proposal_id=proposal.proposal_id,
        actor=proposal.actor,
        operation=proposal.operation,
        target=proposal.target,
        parameter_constraints={"force": False},
        guards=[Guard(key="production.capacity", operator=GuardOperator.GREATER_THAN, value=3)],
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        max_uses=1,
    )
    signed_grant = signer.sign(grant)

    return {
        "enforcer": enforcer,
        "signer": signer,
        "state": state,
        "proposal": proposal,
        "grant": signed_grant,
        "revoked_set": revoked_set,
        "receipt_store": receipt_store,
    }


def test_enforcer_successful_execution(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    proposal: Proposal = test_setup["proposal"]
    grant: AuthorityGrant = test_setup["grant"]

    tool_called = False

    def dummy_tool(target: str) -> str:
        nonlocal tool_called
        tool_called = True
        return f"terminated {target}"

    receipt = enforcer.execute(proposal, grant, dummy_tool, target=proposal.target)

    assert tool_called is True
    assert receipt.status == ExecutionStatus.COMPLETED
    assert receipt.result == "terminated instance/i-17"
    assert receipt.actor == proposal.actor
    assert receipt.target == proposal.target
    assert len(receipt.observed_guards) == 1
    assert receipt.observed_guards[0]["observed"] == 4
    assert receipt.observed_guards[0]["passed"] is True


def test_enforcer_blocks_wrong_actor(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    proposal: Proposal = test_setup["proposal"]
    grant: AuthorityGrant = test_setup["grant"]

    # Different actor trying to use the grant
    alien_proposal = proposal.model_copy(update={"actor": "imposter-agent"})
    with pytest.raises(InvalidAuthorityError, match="does not match proposal actor"):
        enforcer.execute(alien_proposal, grant, lambda: None)


def test_enforcer_blocks_wrong_operation(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    proposal: Proposal = test_setup["proposal"]
    grant: AuthorityGrant = test_setup["grant"]

    diff_op = proposal.model_copy(update={"operation": "compute.reboot"})
    with pytest.raises(InvalidAuthorityError, match="does not match proposal operation"):
        enforcer.execute(diff_op, grant, lambda: None)


def test_enforcer_blocks_wrong_target(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    proposal: Proposal = test_setup["proposal"]
    grant: AuthorityGrant = test_setup["grant"]

    diff_target = proposal.model_copy(update={"target": "instance/i-999"})
    with pytest.raises(InvalidAuthorityError, match="does not match proposal target"):
        enforcer.execute(diff_target, grant, lambda: None)


def test_enforcer_blocks_expired_authority(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    signer: HMACAuthoritySigner = test_setup["signer"]
    proposal: Proposal = test_setup["proposal"]

    # Expired grant
    expired_grant = AuthorityGrant(
        proposal_id=proposal.proposal_id,
        actor=proposal.actor,
        operation=proposal.operation,
        target=proposal.target,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
        max_uses=1,
    )
    signed_expired = signer.sign(expired_grant)

    with pytest.raises(AuthorityExpiredError, match="expired at"):
        enforcer.execute(proposal, signed_expired, lambda: None)


def test_enforcer_blocks_revoked_authority(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    proposal: Proposal = test_setup["proposal"]
    grant: AuthorityGrant = test_setup["grant"]
    revoked_set: set = test_setup["revoked_set"]

    revoked_set.add(grant.authority_id)

    with pytest.raises(AuthorityRevokedError, match="has been revoked"):
        enforcer.execute(proposal, grant, lambda: None)


def test_enforcer_blocks_max_uses_exceeded(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    proposal: Proposal = test_setup["proposal"]
    grant: AuthorityGrant = test_setup["grant"]

    # First execution succeeds
    enforcer.execute(proposal, grant, lambda: "ok")

    # Second execution using same single-use authority must fail
    with pytest.raises(AuthorityExhaustedError, match="already been used"):
        enforcer.execute(proposal, grant, lambda: "ok")


def test_enforcer_blocks_constraint_violation(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    proposal: Proposal = test_setup["proposal"]
    grant: AuthorityGrant = test_setup["grant"]

    # Proposal has parameter force=True, but grant constrained force=False
    violated_proposal = proposal.model_copy(update={"parameters": {"force": True}})
    with pytest.raises(ConstraintViolationError, match="violates constraint"):
        enforcer.execute(violated_proposal, grant, lambda: None)


def test_enforcer_blocks_failed_live_guard(test_setup: dict) -> None:
    enforcer: LocalEnforcer = test_setup["enforcer"]
    proposal: Proposal = test_setup["proposal"]
    grant: AuthorityGrant = test_setup["grant"]
    state: GlobalState = test_setup["state"]

    # Live guard requires capacity > 3. Change state to 3:
    state.set("production.capacity", 3)

    tool_called = False

    def dummy_tool() -> None:
        nonlocal tool_called
        tool_called = True

    with pytest.raises(GuardFailedError, match="Live guard failed at execution time"):
        enforcer.execute(proposal, grant, dummy_tool)

    assert tool_called is False, "Tool must NOT be invoked when guard fails!"
