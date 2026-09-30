"""Execution guard definitions and evaluator."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class GuardOperator(str, Enum):
    """Supported comparison operators for execution guards."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"


class Guard(BaseModel):
    """A guard condition that must evaluate to True at execution time against live state."""

    key: str = Field(description="The state key to check in global/enforcer state.")
    operator: GuardOperator = Field(description="The comparison operator.")
    value: Any = Field(description="The expected or threshold value.")

    def evaluate(self, observed: Any) -> bool:
        """Evaluate the guard against an observed value from state.

        Returns False if the value is missing or types are incompatible for comparison.
        """
        if observed is None and self.operator != GuardOperator.EQUALS:
            return False

        try:
            if self.operator == GuardOperator.EQUALS:
                return bool(observed == self.value)
            elif self.operator == GuardOperator.NOT_EQUALS:
                return bool(observed != self.value)
            elif self.operator == GuardOperator.GREATER_THAN:
                return bool(observed > self.value)
            elif self.operator == GuardOperator.GREATER_THAN_OR_EQUAL:
                return bool(observed >= self.value)
            elif self.operator == GuardOperator.LESS_THAN:
                return bool(observed < self.value)
            elif self.operator == GuardOperator.LESS_THAN_OR_EQUAL:
                return bool(observed <= self.value)
        except TypeError:
            return False

        return False

    def describe(self) -> str:
        """Return a human-readable representation of this guard condition."""
        op_map = {
            GuardOperator.EQUALS: "==",
            GuardOperator.NOT_EQUALS: "!=",
            GuardOperator.GREATER_THAN: ">",
            GuardOperator.GREATER_THAN_OR_EQUAL: ">=",
            GuardOperator.LESS_THAN: "<",
            GuardOperator.LESS_THAN_OR_EQUAL: "<=",
        }
        symbol = op_map.get(self.operator, str(self.operator.value))
        return f"{self.key} {symbol} {self.value}"
