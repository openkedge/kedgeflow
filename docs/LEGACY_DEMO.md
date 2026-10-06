# KedgeFlow

Archived v0.1 demo documentation. The current Rust gateway and v0.9 scope are
described in the [repository README](../README.md).

**Agents propose. KedgeFlow controls. Execution proves.**

KedgeFlow is an open protocol and reference implementation for separating the control plane from the data plane in AI agent systems.

Today's agents often combine reasoning, judgment, tool selection, and execution authority in the same cognitive runtime loop. When an agent decides to act, it directly invokes tools using ambient credentials.

KedgeFlow introduces a programmable boundary:

```
    Agent
      │
   PROPOSE
      │
      ▼
Control Plane
      │
bounded authority
      │
      ▼
 Enforcement
      │
      ▼
  Execution
      │
      ▼
   Receipt
```

---

## Quick Start

Install KedgeFlow locally:

```bash
pip install -e .
```

Run the interactive demo:

```bash
kedgeflow demo
```

Run the multi-agent conflict resolution demo:

```bash
kedgeflow demo conflict
```

---

## 5-Minute Developer Experience

```python
from kedgeflow import KedgeFlow

# 1. Initialize local control plane
kf = KedgeFlow.local(initial_state={"production.capacity": 4})

# 2. Agent proposes an action with supporting evidence
proposal = kf.proposal(
    actor="ops-agent",
    intent="remove unhealthy capacity",
    operation="compute.terminate",
    target="instance/i-17",
    evidence={"health": "failed"},
)

# 3. Control plane evaluates policy and issues bounded authority
decision = kf.propose(proposal)
assert decision.disposition == "GRANT"
authority = decision.authority


# 4. Enforcer validates authority & live guards before calling the tool
def terminate_tool(target: str):
    return {"action": "terminated", "target": target}


receipt = kf.execute(proposal, authority, terminate_tool, target="instance/i-17")

# 5. Execution produces structured proof
print(f"Executed: {receipt.status} (Receipt ID: {receipt.receipt_id})")
```

---

## Why KedgeFlow?

1. **Agents Propose, Never Self-Authorize**: Agents are cognitive entities that generate proposals. The control plane evaluates whether a proposed transition is permitted under current policy, evidence, and state.
2. **Bounded Authority, Not Ambient Access**: Successful admission yields a signed, short-lived, actor-bound, operation-bound, target-bound, and single-use authority grant.
3. **Live Guards Separate Admission from Execution**: Environmental state can shift between admission and execution. Live guards evaluate live conditions immediately before tool invocation.
4. **Multi-Agent Conflict Resolution**: Isolated agents lack global visibility. The control plane detects and resolves conflicting transitions across concurrent agents.
5. **Structured Execution Evidence**: Every execution emits an immutable receipt capturing who proposed, what was authorized, which guards held, and what occurred.

---

## Where KedgeFlow Fits

KedgeFlow does **not** replace MCP, A2A, IAM, or existing agent frameworks:

- **Agent Frameworks** (LangGraph, AutoGen, CrewAI, ADK): Cognition, planning, memory, prompt routing.
- **MCP / A2A**: Connectivity, tool schema discovery, communication transport.
- **IAM**: Identity and permission (*"Is this agent allowed to call this API?"*).
- **KedgeFlow**: Admission and bounded authority for consequential transitions (*"Under current policy, evidence, and global state, is this specific transition permitted right now?"*).

---

## Architecture Overview

```
                      +-------------------+
                      |   Agent Cognition |
                      +-------------------+
                                │
                                │ PROPOSE
                                ▼
                      +-------------------+
                      |    Controller     |
                      |   (Policy Engine  |
                      |   + Global State) |
                      +-------------------+
                                │
                                │ GRANT (Signed Authority)
                                ▼
                      +-------------------+
                      |  Local Enforcer   |
                      |  (Guards + Sig)   |
                      +-------------------+
                                │
                                │ EXECUTE
                                ▼
                      +-------------------+
                      |   Tool / Target   |
                      +-------------------+
                                │
                                │ REPORT
                                ▼
                      +-------------------+
                      | Execution Receipt |
                      +-------------------+
```

For detailed architectural specifications, see [docs/architecture.md](docs/architecture.md) and [spec/v0.1/protocol.md](spec/v0.1/protocol.md).

---

## Security Model

The v0.1 reference implementation provides cryptographic tamper-evidence using HMAC-SHA256 signatures over canonical authority payloads.

**Important Boundary Distinction:**
- **In-Process Enforcement (v0.1)**: Advisory verification within the application process.
- **External Non-Bypassable Enforcement**: For production environments, enforcement can be placed at execution brokers, credential brokers, API gateways, database proxies, or sandboxes.

See [docs/threat-model.md](docs/threat-model.md) for full threat modeling.

---

## Relationship to OpenKedge

- **OpenKedge**: Umbrella research and open-source project.
- **Agentic Control Plane (ACP)**: Architectural framework formalizing programmable control planes for AI agents.
- **KedgeFlow**: The open protocol specification and reference implementation of the ACP programmable boundary.

KedgeFlow implements the programmable agent/control-plane boundary described by the OpenKedge Agentic Control Plane architecture.

---

## Roadmap

- [x] **v0.1.0-alpha.1**: Core protocol objects (`Proposal`, `AuthorityGrant`, `Guard`, `ExecutionReceipt`), HMAC signing, local enforcer, state machine, and multi-agent conflict detection.
- [ ] **v0.2.0**: FastAPI HTTP / REST server binding and OpenAPI schema integration.
- [ ] **v0.3.0**: Asymmetric cryptography (Ed25519) and pluggable KMS backends.
- [ ] **v0.4.0**: MCP proxy middleware adapter for transparent tool interception.
- [ ] **v0.5.0**: Persistent state engines (SQLite / PostgreSQL) and distributed locks.

---

## License

KedgeFlow is licensed under the [Apache License 2.0](LICENSE).
