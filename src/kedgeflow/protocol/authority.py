"""Authority grant model and cryptographic signing interfaces."""

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from typing import Any, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from kedgeflow.protocol.guard import Guard


class AuthorityGrant(BaseModel):
    """A bounded authority token issued by the control plane for a specific proposal."""

    authority_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier of the granted authority.",
    )
    proposal_id: UUID = Field(
        description="Identifier of the admitted proposal this authority is bound to.",
    )
    actor: str = Field(description="Actor authorized to exercise this authority.")
    operation: str = Field(description="Specific operation permitted.")
    target: str = Field(description="Specific target resource permitted.")
    parameter_constraints: dict[str, Any] = Field(
        default_factory=dict,
        description="Parameter constraints that must be satisfied at execution time.",
    )
    guards: list[Guard] = Field(
        default_factory=list,
        description="Live state conditions that must evaluate to True at execution time.",
    )
    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the grant was issued.",
    )
    expires_at: datetime = Field(
        description="Timestamp after which the grant is invalid.",
    )
    policy_version: str = Field(
        default="v1",
        description="Version identifier of the policy that authorized this grant.",
    )
    nonce: str = Field(
        default_factory=lambda: secrets.token_hex(16),
        description="Cryptographic nonce to prevent replay attacks.",
    )
    max_uses: int = Field(
        default=1,
        description="Maximum number of times this authority may be exercised.",
    )
    signature: str | None = Field(
        default=None,
        description="Cryptographic signature proving issuance by the control plane.",
    )

    def canonical_payload(self) -> bytes:
        """Generate a deterministic, canonical byte representation of grant fields for signing."""
        data = {
            "authority_id": str(self.authority_id),
            "proposal_id": str(self.proposal_id),
            "actor": self.actor,
            "operation": self.operation,
            "target": self.target,
            "parameter_constraints": self.parameter_constraints,
            "guards": [
                {"key": g.key, "operator": g.operator.value, "value": g.value} for g in self.guards
            ],
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "policy_version": self.policy_version,
            "nonce": self.nonce,
            "max_uses": self.max_uses,
        }
        canonical_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return canonical_str.encode("utf-8")

    def is_expired(self, current_time: datetime | None = None) -> bool:
        """Check whether the authority has passed its expiration time."""
        now = current_time or datetime.now(timezone.utc)
        if self.expires_at.tzinfo is None:
            # Assume UTC if naive
            exp = self.expires_at.replace(tzinfo=timezone.utc)
        else:
            exp = self.expires_at
        return now > exp


class AuthoritySigner(Protocol):
    """Interface for signing authority grants."""

    def sign(self, grant: AuthorityGrant) -> AuthorityGrant:
        """Produce a signed copy of the authority grant."""
        ...


class AuthorityVerifier(Protocol):
    """Interface for verifying authority grant signatures."""

    def verify(self, grant: AuthorityGrant) -> bool:
        """Verify the cryptographic authenticity of an authority grant."""
        ...


class HMACAuthoritySigner:
    """Signs authority grants using HMAC-SHA256."""

    def __init__(self, secret_key: bytes | str) -> None:
        self.secret_key = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key

    def sign(self, grant: AuthorityGrant) -> AuthorityGrant:
        """Compute HMAC-SHA256 signature and attach to grant."""
        payload = grant.canonical_payload()
        sig = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
        # Return a copy with the signature attached
        signed_grant = grant.model_copy(update={"signature": sig})
        return signed_grant


class HMACAuthorityVerifier:
    """Verifies authority grants signed with HMAC-SHA256."""

    def __init__(self, secret_key: bytes | str) -> None:
        self.secret_key = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key

    def verify(self, grant: AuthorityGrant) -> bool:
        """Verify the signature against the canonical payload."""
        if not grant.signature:
            return False
        payload = grant.canonical_payload()
        expected_sig = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(grant.signature, expected_sig)
