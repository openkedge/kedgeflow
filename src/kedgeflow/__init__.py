"""KedgeFlow: Agents propose. KedgeFlow controls. Execution proves.

Open protocol and reference implementation for separating the control plane
from the data plane in AI agent systems.
"""

from kedgeflow.cli import __version__
from kedgeflow.controller.controller import (
    Decision,
    DecisionDisposition,
    KedgeFlowController,
)
from kedgeflow.controller.policy import (
    PolicyDecision,
    PolicyEngine,
    RuleBasedPolicyEngine,
)
from kedgeflow.enforcement.local import LocalEnforcer
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
from kedgeflow.protocol.state_machine import LifecycleState
from kedgeflow.sdk.client import KedgeFlow
from kedgeflow.storage.memory import GlobalState, InMemoryReceiptStore

__all__ = [
    "AuthorityExhaustedError",
    "AuthorityExpiredError",
    "AuthorityGrant",
    "AuthorityRevokedError",
    "AuthoritySigner",
    "AuthorityVerifier",
    "ConflictError",
    "ConstraintViolationError",
    "Decision",
    "DecisionDisposition",
    "ExecutionReceipt",
    "ExecutionStatus",
    "GlobalState",
    "Guard",
    "GuardFailedError",
    "GuardOperator",
    "HMACAuthoritySigner",
    "HMACAuthorityVerifier",
    "InMemoryReceiptStore",
    "InvalidAuthorityError",
    "InvalidLifecycleTransitionError",
    "KedgeFlow",
    "KedgeFlowController",
    "KedgeFlowError",
    "LifecycleState",
    "LocalEnforcer",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyDeniedError",
    "Proposal",
    "RuleBasedPolicyEngine",
    "__version__",
]
