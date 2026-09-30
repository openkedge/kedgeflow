"""High-level Python SDK client for KedgeFlow."""

import functools
import secrets
from typing import Any, Callable
from uuid import UUID

from kedgeflow.controller.controller import Decision, KedgeFlowController
from kedgeflow.controller.policy import PolicyEngine, RuleBasedPolicyEngine
from kedgeflow.enforcement.local import LocalEnforcer
from kedgeflow.protocol.authority import (
    AuthorityGrant,
    HMACAuthoritySigner,
    HMACAuthorityVerifier,
)
from kedgeflow.protocol.proposal import Proposal
from kedgeflow.protocol.receipt import ExecutionReceipt
from kedgeflow.storage.memory import (
    GlobalState,
    InMemoryReceiptStore,
    ReceiptStore,
    StateStore,
)


class KedgeFlow:
    """Developer-facing SDK interface to KedgeFlow control plane and enforcement boundary."""

    def __init__(
        self,
        controller: KedgeFlowController,
        enforcer: LocalEnforcer,
        state: StateStore,
        receipt_store: ReceiptStore,
    ) -> None:
        self.controller = controller
        self.enforcer = enforcer
        self.state = state
        self.receipt_store = receipt_store

    @classmethod
    def local(
        cls,
        secret_key: str | None = None,
        initial_state: dict[str, Any] | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> "KedgeFlow":
        """Instantiate a local in-process KedgeFlow instance for development and embedded use."""
        key = secret_key or secrets.token_hex(32)
        signer = HMACAuthoritySigner(key)
        verifier = HMACAuthorityVerifier(key)

        state = GlobalState(initial=initial_state or {})
        receipt_store = InMemoryReceiptStore()
        engine = policy_engine or RuleBasedPolicyEngine()

        controller = KedgeFlowController(
            policy_engine=engine,
            state=state,
            signer=signer,
        )

        enforcer = LocalEnforcer(
            verifier=verifier,
            state=state,
            receipt_store=receipt_store,
            revocation_checker=controller.is_revoked,
            lifecycle_updater=controller.transition_proposal,
        )

        return cls(
            controller=controller,
            enforcer=enforcer,
            state=state,
            receipt_store=receipt_store,
        )

    def proposal(
        self,
        actor: str,
        intent: str,
        operation: str,
        target: str,
        parameters: dict[str, Any] | None = None,
        evidence: list[dict[str, Any]] | dict[str, Any] | None = None,
        expected_effect: dict[str, Any] | None = None,
        dependencies: list[str] | None = None,
        requested_scope: str | None = None,
    ) -> Proposal:
        """Helper to construct a well-typed Proposal object."""
        return Proposal(
            actor=actor,
            intent=intent,
            operation=operation,
            target=target,
            parameters=parameters or {},
            evidence=evidence if evidence is not None else [],  # type: ignore[arg-type]
            expected_effect=expected_effect,
            dependencies=dependencies or [],
            requested_scope=requested_scope,
        )

    def propose(self, proposal: Proposal) -> Decision:
        """Submit a proposal to the control plane controller for admission evaluation."""
        return self.controller.propose(proposal)

    def execute(
        self,
        proposal: Proposal,
        authority: AuthorityGrant,
        tool: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> ExecutionReceipt:
        """Execute a tool under bounded authority through the enforcement boundary."""
        return self.enforcer.execute(proposal, authority, tool, *args, **kwargs)

    def get_receipt(self, receipt_id: UUID) -> ExecutionReceipt | None:
        """Retrieve an execution receipt by ID."""
        return self.receipt_store.get(receipt_id)

    def list_receipts(self) -> list[ExecutionReceipt]:
        """List all execution receipts produced by the enforcer."""
        return self.receipt_store.list_all()

    def controlled(
        self,
        operation: str,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to wrap a tool execution function with KedgeFlow enforcement.

        Expects the decorated function to receive 'proposal' and 'authority' as keyword arguments.
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                proposal: Proposal | None = kwargs.pop("proposal", None)
                authority: AuthorityGrant | None = kwargs.pop("authority", None)

                if not proposal or not authority:
                    raise ValueError(
                        "Controlled execution requires both 'proposal' and "
                        "'authority' keyword arguments."
                    )
                if authority.operation != operation or proposal.operation != operation:
                    raise ValueError(
                        f"Controlled decorator for operation '{operation}' received authority for "
                        f"'{authority.operation}' or proposal for '{proposal.operation}'."
                    )

                receipt = self.enforcer.execute(proposal, authority, func, *args, **kwargs)
                return receipt.result

            return wrapper

        return decorator
