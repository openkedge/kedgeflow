"""In-memory state and receipt storage implementations."""

import threading
from typing import Any, Protocol
from uuid import UUID

from kedgeflow.protocol.receipt import ExecutionReceipt


class StateStore(Protocol):
    """Protocol for state storage used by controller and enforcement layers."""

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a state value by key."""
        ...

    def set(self, key: str, value: Any) -> None:
        """Store or update a state value by key."""
        ...

    def delete(self, key: str) -> None:
        """Remove a key from state."""
        ...

    def snapshot(self) -> dict[str, Any]:
        """Return an immutable snapshot copy of current state."""
        ...


class GlobalState:
    """Thread-safe in-memory key-value state store."""

    def __init__(self, initial: dict[str, Any] | None = None) -> None:
        self._lock = threading.RLock()
        self._data: dict[str, Any] = dict(initial or {})

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)


class ReceiptStore(Protocol):
    """Protocol for persisting and retrieving execution receipts."""

    def save(self, receipt: ExecutionReceipt) -> None:
        """Persist an execution receipt."""
        ...

    def get(self, receipt_id: UUID) -> ExecutionReceipt | None:
        """Retrieve a receipt by receipt ID."""
        ...

    def list_all(self) -> list[ExecutionReceipt]:
        """List all stored execution receipts."""
        ...


class InMemoryReceiptStore:
    """Thread-safe in-memory execution receipt store."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._receipts: dict[UUID, ExecutionReceipt] = {}

    def save(self, receipt: ExecutionReceipt) -> None:
        with self._lock:
            self._receipts[receipt.receipt_id] = receipt

    def get(self, receipt_id: UUID) -> ExecutionReceipt | None:
        with self._lock:
            return self._receipts.get(receipt_id)

    def list_all(self) -> list[ExecutionReceipt]:
        with self._lock:
            return list(self._receipts.values())
