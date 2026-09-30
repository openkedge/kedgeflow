"""Local enforcement boundary validating authority grants and guards before tool execution."""

from datetime import datetime, timezone
from typing import Any, Callable
from uuid import UUID

from kedgeflow.protocol.authority import AuthorityGrant, AuthorityVerifier
from kedgeflow.protocol.errors import (
    AuthorityExhaustedError,
    AuthorityExpiredError,
    AuthorityRevokedError,
    ConstraintViolationError,
    GuardFailedError,
    InvalidAuthorityError,
    InvalidLifecycleTransitionError,
)
from kedgeflow.protocol.proposal import Proposal
from kedgeflow.protocol.receipt import ExecutionReceipt, ExecutionStatus
from kedgeflow.protocol.state_machine import LifecycleState
from kedgeflow.storage.memory import (
    GlobalState,
    InMemoryReceiptStore,
    ReceiptStore,
    StateStore,
)


class LocalEnforcer:
    """Enforces bounded authority at the local execution boundary."""

    def __init__(
        self,
        verifier: AuthorityVerifier,
        state: StateStore | None = None,
        receipt_store: ReceiptStore | None = None,
        revocation_checker: Callable[[UUID], bool] | None = None,
        lifecycle_updater: Callable[[UUID, LifecycleState], None] | None = None,
    ) -> None:
        self.verifier = verifier
        self.state: StateStore = state or GlobalState()
        self.receipt_store: ReceiptStore = receipt_store or InMemoryReceiptStore()
        self.revocation_checker = revocation_checker
        self.lifecycle_updater = lifecycle_updater
        self._usage_counts: dict[UUID, int] = {}

    def get_usage_count(self, authority_id: UUID) -> int:
        """Get the number of times an authority grant has been exercised."""
        return self._usage_counts.get(authority_id, 0)

    def validate_authority(self, proposal: Proposal, authority: AuthorityGrant) -> None:
        """Validate all cryptographic, identity, resource, constraint,
        and lifecycle boundaries of the grant.
        """
        # 1. Cryptographic signature verification
        if not self.verifier.verify(authority):
            raise InvalidAuthorityError(
                f"Cryptographic verification failed for authority grant {authority.authority_id}. "
                "The grant signature is invalid or the payload has been tampered with."
            )

        # 2. Proposal binding
        if authority.proposal_id != proposal.proposal_id:
            raise InvalidAuthorityError(
                f"Authority proposal_id '{authority.proposal_id}' does not match "
                f"proposal.proposal_id '{proposal.proposal_id}'"
            )

        # 3. Actor binding
        if authority.actor != proposal.actor:
            raise InvalidAuthorityError(
                f"Authority actor '{authority.actor}' does not match "
                f"proposal actor '{proposal.actor}'"
            )

        # 4. Operation binding
        if authority.operation != proposal.operation:
            raise InvalidAuthorityError(
                f"Authority operation '{authority.operation}' does not match "
                f"proposal operation '{proposal.operation}'"
            )

        # 5. Target binding
        if authority.target != proposal.target:
            raise InvalidAuthorityError(
                f"Authority target '{authority.target}' does not match "
                f"proposal target '{proposal.target}'"
            )

        # 6. Expiration check
        if authority.is_expired():
            if self.lifecycle_updater:
                self.lifecycle_updater(proposal.proposal_id, LifecycleState.EXPIRED)
            exp_str = authority.expires_at.isoformat()
            raise AuthorityExpiredError(
                f"Authority grant {authority.authority_id} expired at {exp_str}"
            )

        # 7. Revocation check
        if self.revocation_checker and self.revocation_checker(authority.authority_id):
            if self.lifecycle_updater:
                self.lifecycle_updater(proposal.proposal_id, LifecycleState.REVOKED)
            raise AuthorityRevokedError(
                f"Authority grant {authority.authority_id} has been revoked by the control plane"
            )

        # 8. Max uses check
        current_uses = self.get_usage_count(authority.authority_id)
        if current_uses >= authority.max_uses:
            raise AuthorityExhaustedError(
                f"Authority grant {authority.authority_id} has already been used "
                f"{current_uses} times (max_uses: {authority.max_uses})"
            )

        # 9. Parameter constraints check
        for param_key, expected_val in authority.parameter_constraints.items():
            actual_val = proposal.parameters.get(param_key)
            if actual_val != expected_val:
                raise ConstraintViolationError(
                    f"Parameter '{param_key}' value '{actual_val}' violates "
                    f"constraint '{expected_val}'"
                )

    def evaluate_guards(self, authority: AuthorityGrant) -> list[dict[str, Any]]:
        """Evaluate all guards in the authority grant against current live state.

        Raises GuardFailedError if any guard does not hold.
        Returns a list of observed guard evaluation records.
        """
        observed_records: list[dict[str, Any]] = []

        for guard in authority.guards:
            observed_val = self.state.get(guard.key)
            passed = guard.evaluate(observed_val)
            record = {
                "key": guard.key,
                "operator": guard.operator.value,
                "expected": guard.value,
                "observed": observed_val,
                "passed": passed,
            }
            observed_records.append(record)

            if not passed:
                raise GuardFailedError(
                    f"Live guard failed at execution time: '{guard.describe()}' "
                    f"(observed current state value: {observed_val!r})"
                )

        return observed_records

    def execute(
        self,
        proposal: Proposal,
        authority: AuthorityGrant,
        tool: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> ExecutionReceipt:
        """Perform verified execution of a tool under bounded authority,
        producing an execution receipt.
        """
        # Step 1: Validate authority
        self.validate_authority(proposal, authority)

        # Step 2: Evaluate live guards
        observed_guards = self.evaluate_guards(authority)

        # Step 3: Advance lifecycle state to EXECUTING
        if self.lifecycle_updater:
            try:
                self.lifecycle_updater(proposal.proposal_id, LifecycleState.EXECUTING)
            except InvalidLifecycleTransitionError:
                raise

        started_at = datetime.now(timezone.utc)
        result: Any = None
        error_msg: str | None = None
        status = ExecutionStatus.COMPLETED

        # Step 4: Invoke tool
        try:
            result = tool(*args, **kwargs)
            if self.lifecycle_updater:
                self.lifecycle_updater(proposal.proposal_id, LifecycleState.COMPLETED)
        except Exception as exc:
            status = ExecutionStatus.FAILED
            error_msg = str(exc)
            if self.lifecycle_updater:
                self.lifecycle_updater(proposal.proposal_id, LifecycleState.FAILED)
            raise
        finally:
            completed_at = datetime.now(timezone.utc)

            # Step 5: Increment usage counter
            self._usage_counts[authority.authority_id] = (
                self.get_usage_count(authority.authority_id) + 1
            )

            # Step 6: Create execution receipt
            receipt = ExecutionReceipt(
                proposal_id=proposal.proposal_id,
                authority_id=authority.authority_id,
                actor=proposal.actor,
                operation=proposal.operation,
                target=proposal.target,
                started_at=started_at,
                completed_at=completed_at,
                status=status,
                result=result,
                observed_guards=observed_guards,
                error=error_msg,
                policy_version=authority.policy_version,
            )
            self.receipt_store.save(receipt)

        return receipt
