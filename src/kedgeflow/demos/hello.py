"""Hello KedgeFlow - Working End-to-End Demo."""

import sys

from kedgeflow import KedgeFlow
from kedgeflow.protocol.errors import GuardFailedError


def terminate_instance_tool(target: str) -> dict[str, str]:
    """Simulated infrastructure execution tool."""
    return {"status": "terminated", "target": target}


def run_demo() -> None:
    print("=" * 65)
    print(" KEDGEFLOW DEMO: COGNITION PROPOSES, EXECUTION PROVES")
    print("=" * 65)

    # 1. Initialize local KedgeFlow control plane with initial global state
    kf = KedgeFlow.local(initial_state={"production.capacity": 4})

    print("\n--- PHASE 1: Successful Authorized Execution ---")
    print("[system] Initial global state: production.capacity = 4")

    # 2. Agent creates and submits proposal
    actor = "ops-agent"
    operation = "compute.terminate"
    target = "instance/i-17"

    print(f"\n[agent] proposing {operation} {target}")
    proposal = kf.proposal(
        actor=actor,
        intent="remove unhealthy capacity",
        operation=operation,
        target=target,
        parameters={},
        evidence=[{"type": "health", "value": "failed"}],
    )

    print("[controller] proposal received")
    print("             evaluating evidence: health == failed")

    # 3. Controller evaluates and grants authority
    decision = kf.propose(proposal)
    print("[controller] evidence satisfied")
    print(f"[controller] {decision.disposition.value}")
    assert decision.authority is not None, "Authority must be granted"
    authority = decision.authority

    guard_desc = authority.guards[0].describe() if authority.guards else "none"
    print(f"             authority={authority.authority_id}")
    print(f"             expires={authority.expires_at.isoformat()}")
    print(f"             guard={guard_desc}")

    # 4. Enforcer validates authority & live guard
    print("\n[enforcer] authority verified")
    current_capacity = kf.state.get("production.capacity")
    print(f"[enforcer] guard satisfied: {current_capacity} > 3")

    # 5. Tool executes under bounded authority
    receipt = kf.execute(
        proposal,
        authority,
        terminate_instance_tool,
        target=target,
    )

    print(f"[tool] terminated {target}")
    print(f"[receipt] {receipt.status.value}")
    print(f"          receipt_id={receipt.receipt_id}")
    print(f"          proposal={receipt.proposal_id}")
    print(f"          authority={receipt.authority_id}")

    # --- PHASE 2: Live Guard Blocks Execution When State Changes ---
    print("\n--- PHASE 2: Execution Blocked by Live Guard Change ---")
    print("[system] Changing global state: production.capacity = 3")
    kf.state.set("production.capacity", 3)

    # Agent proposes another termination (or tries to execute when capacity is 3)
    target_2 = "instance/i-18"
    print(f"\n[agent] proposing {operation} {target_2}")
    proposal_2 = kf.proposal(
        actor=actor,
        intent="remove second unhealthy capacity",
        operation=operation,
        target=target_2,
        parameters={},
        evidence=[{"type": "health", "value": "failed"}],
    )

    decision_2 = kf.propose(proposal_2)
    print(f"[controller] proposal received and granted (authority issued with guard {guard_desc})")
    assert decision_2.authority is not None

    print("[enforcer] validating authority and live guards against current state...")
    try:
        kf.execute(
            proposal_2,
            decision_2.authority,
            terminate_instance_tool,
            target=target_2,
        )
        print("[error] Execution should have been blocked!")
        sys.exit(1)
    except GuardFailedError as exc:
        print("[enforcer] guard failed")
        print(f"           {exc}")
        print("\n[result] EXECUTION BLOCKED! Live state violation prevented unsafe action.")

    print("\n" + "=" * 65)
    print(" DEMO COMPLETED SUCCESSFULLY: Live guard prevented unsafe execution.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_demo()
