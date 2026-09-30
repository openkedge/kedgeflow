# KedgeFlow Protocol Overview

This guide provides a practical overview of how developers interact with the KedgeFlow protocol.

For the formal normative specification, see [spec/v0.1/protocol.md](../spec/v0.1/protocol.md).

---

## 1. Lifecycle Walkthrough

Every consequential transition proceeds through four distinct phases:

### Step 1: Propose
The agent declares what action it wants to take, including its intent, parameters, and supporting evidence.

```python
from kedgeflow import KedgeFlow

kf = KedgeFlow.local()

proposal = kf.proposal(
    actor="ops-agent",
    intent="remove unhealthy capacity",
    operation="compute.terminate",
    target="instance/i-17",
    evidence={"health": "failed"},
)
```

### Step 2: Authorize (Admission)
The controller evaluates the proposal against policy, evidence claims, and global control-plane state.

```python
decision = kf.propose(proposal)

if decision.disposition == "GRANT":
    authority = decision.authority
    print(f"Granted authority {authority.authority_id} expiring at {authority.expires_at}")
else:
    print(f"Denied: {decision.reason}")
```

### Step 3: Enforce (Execution Boundary)
Before calling the tool, the enforcement boundary validates the cryptographic signature, checks parameter constraints, verifies usage counters, and evaluates live state guards.

```python
def terminate_tool(target: str):
    return {"action": "terminated", "target": target}


# Enforce authority and execute
receipt = kf.execute(
    proposal,
    authority,
    terminate_tool,
    target="instance/i-17",
)
```

### Step 4: Prove (Receipt)
Execution generates an immutable `ExecutionReceipt`:

```python
print(f"Status: {receipt.status}")
print(f"Receipt ID: {receipt.receipt_id}")
print(f"Observed guards: {receipt.observed_guards}")
```

---

## 2. Live State Guards

A critical capability of KedgeFlow is separating **admission authority** from **live execution conditions**.

When the controller issues an `AuthorityGrant`, it attaches one or more `Guard` objects. For example:

```python
Guard(key="production.capacity", operator="greater_than", value=3)
```

Even if the controller approved the proposal when `production.capacity` was 4, if capacity drops to 3 before execution occurs (due to concurrent actions or infrastructure changes), the enforcer detects the violation and blocks execution:

```
GuardFailedError: Live guard failed at execution time: 'production.capacity > 3' (observed current state value: 3)
```

This prevents race conditions and ensures safety invariants are maintained.
