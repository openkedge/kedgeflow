"""Execution receipt recording evidence of execution."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ExecutionStatus(str, Enum):
    """Status outcomes for an authorized execution."""

    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ExecutionReceipt(BaseModel):
    """An immutable record proving what was executed under what authority
    and observed conditions.
    """

    receipt_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier of the execution receipt.",
    )
    proposal_id: UUID = Field(description="Identifier of the original proposal.")
    authority_id: UUID = Field(description="Identifier of the authority grant used.")
    actor: str = Field(description="Actor that performed the execution.")
    operation: str = Field(description="Operation executed.")
    target: str = Field(description="Target resource on which operation was executed.")
    started_at: datetime = Field(description="Timestamp when execution began.")
    completed_at: datetime = Field(description="Timestamp when execution finished.")
    status: ExecutionStatus = Field(description="Execution result status (COMPLETED or FAILED).")
    result: Any = Field(default=None, description="Output payload or return value from the tool.")
    observed_guards: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Snapshot of evaluated guards and observed values at execution time.",
    )
    error: str | None = Field(
        default=None,
        description="Error details if execution status is FAILED.",
    )
    policy_version: str = Field(
        default="v1",
        description="Policy version under which authority was originally granted.",
    )
