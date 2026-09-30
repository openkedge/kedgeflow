"""Proposal domain model representing an agent's requested consequential transition."""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Proposal(BaseModel):
    """An agent's proposal for a consequential state transition."""

    proposal_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier of the proposal.",
    )
    actor: str = Field(description="Identifier of the proposing agent or principal.")
    intent: str = Field(description="Stated high-level intent behind the proposed action.")
    operation: str = Field(
        description="Target operation (e.g. compute.terminate, workload.deploy).",
    )
    target: str = Field(description="Resource URI or target identifier (e.g. instance/i-17).")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters for the proposed operation.",
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Evidence claims supporting the proposal (e.g. health checks, telemetry).",
    )
    expected_effect: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured description of the anticipated side effects.",
    )
    dependencies: list[str] = Field(
        default_factory=list,
        description="Optional list of prerequisite proposal IDs or conditions.",
    )
    requested_scope: str | None = Field(
        default=None,
        description="Optional scope or namespace requested by the actor.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the proposal was generated.",
    )

    @field_validator("evidence", mode="before")
    @classmethod
    def normalize_evidence(cls, v: Any) -> list[dict[str, Any]]:
        """Normalize evidence into a list of dicts if a single dict was provided."""
        if isinstance(v, dict):
            if "type" in v:
                return [v]
            return [{"type": k, "value": val} for k, val in v.items()]
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, dict):
                    res.append(item)
                else:
                    res.append({"value": item})
            return res
        return []
