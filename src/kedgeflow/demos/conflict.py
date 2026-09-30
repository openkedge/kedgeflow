"""Conflicting Agents Demo - Multi-Agent Control Plane Conflict Resolution."""

from kedgeflow import KedgeFlow
from kedgeflow.controller.controller import DecisionDisposition


def run_conflict_demo() -> None:
    print("=" * 65)
    print(" KEDGEFLOW DEMO: MULTI-AGENT CONFLICT RESOLUTION")
    print("=" * 65)

    # 1. Initialize KedgeFlow control plane with healthy state
    kf = KedgeFlow.local(initial_state={"production.capacity": 4})

    target_instance = "instance/i-17"

    print("\n--- STEP 1: deployment-agent proposes workload deployment ---")
    deployment_proposal = kf.proposal(
        actor="deployment-agent",
        intent="roll out service update",
        operation="workload.deploy",
        target=target_instance,
        parameters={"workload": "workload-Y"},
    )
    workload = deployment_proposal.parameters["workload"]
    print(
        f"[agent:deployment-agent] Proposing: {deployment_proposal.operation} "
        f"{workload} -> {target_instance}"
    )

    decision_deploy = kf.propose(deployment_proposal)
    print("[controller] Admission evaluated for deployment-agent:")
    print(f"             disposition = {decision_deploy.disposition.value}")
    print(f"             reason      = {decision_deploy.reason}")
    if decision_deploy.authority:
        print(f"             authority   = {decision_deploy.authority.authority_id}")

    # Inspect controller global state
    pending_info = kf.state.get(f"pending:{target_instance}")
    print(f"\n[controller state] pending:{target_instance} = {pending_info!r}")

    print("\n--- STEP 2: ops-agent proposes instance termination ---")
    ops_proposal = kf.proposal(
        actor="ops-agent",
        intent="remediate degrading node",
        operation="compute.terminate",
        target=target_instance,
        parameters={},
        evidence=[{"type": "health", "value": "failed"}],
    )
    print(f"[agent:ops-agent] Proposing: {ops_proposal.operation} -> {target_instance}")
    print("                  (ops-agent has isolated view: node health is reported failed)")

    decision_terminate = kf.propose(ops_proposal)
    print("\n[controller] Admission evaluated for ops-agent:")
    print(f"             disposition = {decision_terminate.disposition.value}")
    print(f"             reason      = {decision_terminate.reason}")

    # Verify outcome
    assert decision_deploy.disposition == DecisionDisposition.GRANT
    assert decision_terminate.disposition == DecisionDisposition.DENY

    print("\n" + "=" * 65)
    print(" DEMO RESULT:")
    print("   deployment proposal  -> GRANT")
    print("   termination proposal -> DENY")
    print("   Reason: conflicting pending transition on instance/i-17")
    print("\n KEY INSIGHT: Local agent view != global control-plane view.")
    print(" KedgeFlow prevents race conditions across decoupled AI agents.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_conflict_demo()
