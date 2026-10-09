"""End-to-end integration tests for KedgeFlow."""

import pytest

from kedgeflow import KedgeFlow
from kedgeflow.controller.controller import DecisionDisposition
from kedgeflow.protocol.errors import GuardFailedError
from kedgeflow.protocol.receipt import ExecutionStatus


def test_end_to_end_single_agent_flow() -> None:
    kf = KedgeFlow.local(initial_state={"production.capacity": 4})

    # Propose
    proposal = kf.proposal(
        actor="ops-agent",
        intent="remove unhealthy capacity",
        operation="compute.terminate",
        target="instance/i-17",
        evidence={"health": "failed"},
    )

    decision = kf.propose(proposal)
    assert decision.disposition == DecisionDisposition.GRANT
    assert decision.authority is not None

    # Execute
    def tool_terminate(target: str) -> dict[str, str]:
        return {"action": "deleted", "target": target}

    receipt = kf.execute(
        proposal,
        decision.authority,
        tool_terminate,
        target="instance/i-17",
    )

    assert receipt.status == ExecutionStatus.COMPLETED
    assert receipt.result == {"action": "deleted", "target": "instance/i-17"}

    # Verify receipt storage
    retrieved = kf.get_receipt(receipt.receipt_id)
    assert retrieved is not None
    assert retrieved.receipt_id == receipt.receipt_id


def test_end_to_end_guard_blocking_on_dynamic_state() -> None:
    kf = KedgeFlow.local(initial_state={"production.capacity": 4})

    proposal = kf.proposal(
        actor="ops-agent",
        intent="remove unhealthy capacity",
        operation="compute.terminate",
        target="instance/i-17",
        evidence={"health": "failed"},
    )
    decision = kf.propose(proposal)
    assert decision.authority is not None

    # Capacity drops prior to execution
    kf.state.set("production.capacity", 2)

    with pytest.raises(GuardFailedError):
        kf.execute(
            proposal,
            decision.authority,
            lambda target: "executed",
            target="instance/i-17",
        )


def test_end_to_end_multi_agent_conflict() -> None:
    kf = KedgeFlow.local(initial_state={"production.capacity": 4})

    # 1. deployment-agent proposes deployment
    p_deploy = kf.proposal(
        actor="deployment-agent",
        intent="deploy service",
        operation="workload.deploy",
        target="instance/i-17",
        parameters={"workload": "web-svc"},
    )
    d_deploy = kf.propose(p_deploy)
    assert d_deploy.disposition == DecisionDisposition.GRANT

    # 2. ops-agent proposes termination on same target
    p_term = kf.proposal(
        actor="ops-agent",
        intent="terminate node",
        operation="compute.terminate",
        target="instance/i-17",
        evidence={"health": "failed"},
    )
    d_term = kf.propose(p_term)
    assert d_term.disposition == DecisionDisposition.DENY
    assert "Conflicting pending transition" in d_term.reason


def test_end_to_end_controlled_decorator() -> None:
    kf = KedgeFlow.local(initial_state={"production.capacity": 4})

    @kf.controlled(operation="compute.terminate")
    def safe_terminate(instance_id: str) -> str:
        return f"terminated-{instance_id}"

    proposal = kf.proposal(
        actor="ops-agent",
        intent="clean instance",
        operation="compute.terminate",
        target="instance/i-17",
        evidence={"health": "failed"},
    )
    decision = kf.propose(proposal)
    assert decision.authority is not None

    res = safe_terminate(
        "instance/i-17",
        proposal=proposal,
        authority=decision.authority,
    )
    assert res == "terminated-instance/i-17"
