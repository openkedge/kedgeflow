"""Protocol lifecycle state machine definitions and transition validation."""

from enum import Enum

from kedgeflow.protocol.errors import InvalidLifecycleTransitionError


class LifecycleState(str, Enum):
    """Formal protocol lifecycle states for proposals and execution."""

    CREATED = "CREATED"
    PROPOSED = "PROPOSED"
    DENIED = "DENIED"
    GRANTED = "GRANTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    EXECUTING = "EXECUTING"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


# Permitted state transitions mapping
VALID_TRANSITIONS: dict[LifecycleState, set[LifecycleState]] = {
    LifecycleState.CREATED: {LifecycleState.PROPOSED},
    LifecycleState.PROPOSED: {LifecycleState.GRANTED, LifecycleState.DENIED},
    LifecycleState.GRANTED: {
        LifecycleState.EXECUTING,
        LifecycleState.EXPIRED,
        LifecycleState.REVOKED,
    },
    LifecycleState.EXECUTING: {LifecycleState.COMPLETED, LifecycleState.FAILED},
    LifecycleState.DENIED: set(),
    LifecycleState.EXPIRED: set(),
    LifecycleState.REVOKED: set(),
    LifecycleState.COMPLETED: set(),
    LifecycleState.FAILED: set(),
}


def validate_transition(current: LifecycleState, target: LifecycleState) -> None:
    """Validate that moving from current to target lifecycle state is permitted by the protocol.

    Raises InvalidLifecycleTransitionError if the transition is prohibited.
    """
    allowed = VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidLifecycleTransitionError(
            f"Invalid protocol state transition from {current.value} to {target.value}. "
            f"Allowed next states: {[s.value for s in allowed] or 'None (terminal)'}"
        )


class ProposalLifecycle:
    """Tracks and enforces the state machine for a specific proposal lifecycle."""

    def __init__(self, initial_state: LifecycleState = LifecycleState.CREATED) -> None:
        self._state = initial_state
        self._history: list[LifecycleState] = [initial_state]

    @property
    def current_state(self) -> LifecycleState:
        return self._state

    @property
    def history(self) -> list[LifecycleState]:
        return list(self._history)

    def transition_to(self, target: LifecycleState) -> None:
        """Attempt to transition to a new lifecycle state."""
        validate_transition(self._state, target)
        self._state = target
        self._history.append(target)
