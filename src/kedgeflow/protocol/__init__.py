"""KedgeFlow protocol models, types, and state machine."""

from kedgeflow.protocol.authority import (
    AuthorityGrant,
    AuthoritySigner,
    AuthorityVerifier,
    HMACAuthoritySigner,
    HMACAuthorityVerifier,
)
from kedgeflow.protocol.errors import (
    AuthorityExhaustedError,
    AuthorityExpiredError,
    AuthorityRevokedError,
    ConflictError,
    ConstraintViolationError,
    GuardFailedError,
    InvalidAuthorityError,
    InvalidLifecycleTransitionError,
    KedgeFlowError,
    PolicyDeniedError,
)
from kedgeflow.protocol.guard import Guard, GuardOperator
from kedgeflow.protocol.proposal import Proposal
from kedgeflow.protocol.receipt import ExecutionReceipt, ExecutionStatus
from kedgeflow.protocol.state_machine import (
    VALID_TRANSITIONS,
    LifecycleState,
    ProposalLifecycle,
    validate_transition,
)

__all__ = [
    "AuthorityExhaustedError",
    "AuthorityExpiredError",
    "AuthorityGrant",
    "AuthorityRevokedError",
    "AuthoritySigner",
    "AuthorityVerifier",
    "ConflictError",
    "ConstraintViolationError",
    "ExecutionReceipt",
    "ExecutionStatus",
    "Guard",
    "GuardFailedError",
    "GuardOperator",
    "HMACAuthoritySigner",
    "HMACAuthorityVerifier",
    "InvalidAuthorityError",
    "InvalidLifecycleTransitionError",
    "KedgeFlowError",
    "LifecycleState",
    "PolicyDeniedError",
    "Proposal",
    "ProposalLifecycle",
    "VALID_TRANSITIONS",
    "validate_transition",
]
