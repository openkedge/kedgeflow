"""Policy evaluation engine interfaces and implementations."""

from typing import Any, Callable, Protocol

from pydantic import BaseModel, Field

from kedgeflow.protocol.guard import Guard, GuardOperator
from kedgeflow.protocol.proposal import Proposal
from kedgeflow.storage.memory import StateStore


class PolicyDecision(BaseModel):
    """The outcome of policy evaluation for an admitted or rejected proposal."""

    allowed: bool = Field(description="True if policy permits the transition, False if denied.")
    reason: str = Field(
        default="", description="Justification or explanation for the policy decision."
    )
    guards: list[Guard] = Field(
        default_factory=list,
        description="Execution guards required by policy to hold at execution time.",
    )
    parameter_constraints: dict[str, Any] = Field(
        default_factory=dict,
        description="Constraints that execution parameters must satisfy.",
    )
    ttl_seconds: int = Field(
        default=300,
        description="Validity window for granted authority in seconds.",
    )
    policy_version: str = Field(
        default="v1",
        description="Version identifier of the policy.",
    )


class PolicyEngine(Protocol):
    """Interface for evaluating a proposal against policy and global state."""

    def evaluate(self, proposal: Proposal, global_state: StateStore) -> PolicyDecision:
        """Evaluate proposal against current global state and return a PolicyDecision."""
        ...


RuleHandler = Callable[[Proposal, StateStore], PolicyDecision | None]


class RuleBasedPolicyEngine:
    """A flexible, extensible policy engine that evaluates proposals against rules."""

    def __init__(self) -> None:
        self._rules: dict[str, list[RuleHandler]] = {}
        self._default_policy_version = "v1"
        self._install_default_rules()

    def register(self, operation: str, handler: RuleHandler) -> None:
        """Register a custom rule handler for an operation."""
        self._rules.setdefault(operation, []).append(handler)

    def evaluate(self, proposal: Proposal, global_state: StateStore) -> PolicyDecision:
        """Evaluate the proposal against registered rules matching the operation."""
        # 1. Check operation-specific handlers
        handlers = self._rules.get(proposal.operation, [])
        for handler in handlers:
            decision = handler(proposal, global_state)
            if decision is not None:
                return decision

        # 2. Check wildcard '*' handlers if any
        for handler in self._rules.get("*", []):
            decision = handler(proposal, global_state)
            if decision is not None:
                return decision

        # 3. Default deny if no rule matched
        return PolicyDecision(
            allowed=False,
            reason=(
                f"No matching policy rule allowing operation '{proposal.operation}' "
                f"on target '{proposal.target}'"
            ),
            policy_version=self._default_policy_version,
        )

    def _install_default_rules(self) -> None:
        """Install reference rules for standard operations and demos."""

        def evaluate_compute_terminate(proposal: Proposal, state: StateStore) -> PolicyDecision:
            # Check for conflict with pending deployment on target
            pending = state.get(f"pending:{proposal.target}")
            if pending:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Conflicting pending transition on {proposal.target}: {pending}",
                )

            # Check evidence: must contain health == failed
            health_evidence_failed = False
            for item in proposal.evidence:
                if item.get("type") == "health" and item.get("value") == "failed":
                    health_evidence_failed = True
                    break
                if item.get("health") == "failed":
                    health_evidence_failed = True
                    break

            if not health_evidence_failed:
                return PolicyDecision(
                    allowed=False,
                    reason="compute.terminate requires evidence indicating health == failed",
                )

            # Guard required: production.capacity must be > 3 at execution time
            guards = [
                Guard(
                    key="production.capacity",
                    operator=GuardOperator.GREATER_THAN,
                    value=3,
                )
            ]
            return PolicyDecision(
                allowed=True,
                reason=(
                    "Evidence satisfied: health == failed. Guard attached: production.capacity > 3."
                ),
                guards=guards,
                ttl_seconds=300,
            )

        def evaluate_workload_deploy(proposal: Proposal, state: StateStore) -> PolicyDecision:
            # Check if target is undergoing termination or maintenance
            target_status = state.get(f"status:{proposal.target}")
            if target_status == "terminating":
                return PolicyDecision(
                    allowed=False,
                    reason=f"Cannot deploy workload: {proposal.target} is terminating",
                )

            # Record pending deployment to establish global control plane state
            workload = proposal.parameters.get("workload", "unknown")
            state.set(f"pending:{proposal.target}", f"deploy {workload}")

            return PolicyDecision(
                allowed=True,
                reason=f"Deployment of {workload} to {proposal.target} authorized.",
                ttl_seconds=300,
            )

        self.register("compute.terminate", evaluate_compute_terminate)
        self.register("workload.deploy", evaluate_workload_deploy)
