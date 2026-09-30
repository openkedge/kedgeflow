"""KedgeFlow protocol and enforcement exceptions."""


class KedgeFlowError(Exception):
    """Base class for all KedgeFlow exceptions."""


class InvalidLifecycleTransitionError(KedgeFlowError):
    """Raised when an invalid state transition is attempted in the protocol lifecycle."""


class InvalidAuthorityError(KedgeFlowError):
    """Raised when an authority grant fails validation or cryptographic verification."""


class AuthorityExpiredError(InvalidAuthorityError):
    """Raised when an authority grant has expired."""


class AuthorityRevokedError(InvalidAuthorityError):
    """Raised when an authority grant has been revoked by the control plane."""


class AuthorityExhaustedError(InvalidAuthorityError):
    """Raised when an authority grant has exceeded its maximum allowed uses."""


class GuardFailedError(KedgeFlowError):
    """Raised when an execution guard fails evaluation against current state."""


class ConstraintViolationError(KedgeFlowError):
    """Raised when parameter constraints are violated."""


class ConflictError(KedgeFlowError):
    """Raised when a proposal conflicts with existing control plane state or pending transitions."""


class PolicyDeniedError(KedgeFlowError):
    """Raised when a proposal is explicitly denied by the controller's policy engine."""
