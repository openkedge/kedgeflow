# KedgeFlow Architecture

**Agents propose. KedgeFlow controls. Execution proves.**

KedgeFlow implements the programmable agent/control-plane boundary described by the OpenKedge **Agentic Control Plane (ACP)** architecture.

---

## 1. Architectural Philosophy

Traditional agent architectures combine cognitive reasoning, policy judgment, tool selection, and execution authority into a single runtime loop. When an agent decides to call a tool, it directly invokes the underlying API using ambient credentials.

This monolithic model suffers from critical failure modes:
1. **Confused Deputy & Prompt Injection**: An agent convinced by untrusted prompt injection can misuse credentials without external oversight.
2. **Local vs. Global Blindness**: Multiple agents operating concurrently lack a unified global control plane, causing dangerous race conditions.
3. **Stale Environmental Assumptions**: Environmental invariants valid when an agent planned an action may no longer hold when the tool actually runs.
4. **Lack of Cryptographic Auditability**: Downstream systems cannot distinguish between an agent executing with proper authorization vs. executing uninspected calls.

### The KedgeFlow Invariant

KedgeFlow resolves these issues by decoupling **cognition** from **control** and **enforcement**:

```
      +-----------------------------------------+
      |             Agent Cognition             |
      |   (Reasoning, Planning, Tool Selection) |
      +-----------------------------------------+
                           |
                           | PROPOSE (Proposal)
                           v
      +-----------------------------------------+
      |          KedgeFlow Controller           |
      |        [Control Plane Admission]        |
      |  Evaluates Policy, Evidence, State      |
      +-----------------------------------------+
                           |
                           | GRANT (Bounded Authority)
                           v
      +-----------------------------------------+
      |           Local Enforcement             |
      |         [Enforcement Boundary]          |
      |  Verifies Signature, Nonce, Live Guards |
      +-----------------------------------------+
                           |
                           | EXECUTE (Authorized)
                           v
      +-----------------------------------------+
      |             Tool / Resource             |
      +-----------------------------------------+
                           |
                           | Result
                           v
      +-----------------------------------------+
      |            Execution Receipt            |
      |          (Tamper-evident Proof)         |
      +-----------------------------------------+
```

---

## 2. Component Structure

The reference architecture consists of modular, protocol-driven subsystems:

### 2.1. Protocol Layer (`kedgeflow.protocol`)
- `Proposal`: Canonical declaration of an agent's intended state transition, including parameters and supporting evidence.
- `AuthorityGrant`: Cryptographically signed, short-lived, actor-bound, operation-bound, and target-bound token.
- `Guard`: Dynamic condition evaluated against live state immediately prior to execution.
- `ExecutionReceipt`: Tamper-evident record documenting the execution outcome, evaluated guards, and timestamps.
- `ProposalLifecycle`: Formal state machine tracking transitions (`CREATED -> PROPOSED -> GRANTED -> EXECUTING -> COMPLETED`).

### 2.2. Controller Layer (`kedgeflow.controller`)
- `KedgeFlowController`: Central admission coordinator that receives proposals, invokes the policy engine, updates global control plane state, and signs authority grants.
- `PolicyEngine`: Pluggable evaluation interface (`evaluate(proposal, state) -> PolicyDecision`).
- `RuleBasedPolicyEngine`: Extensible rule registry supporting pattern-matching and custom rule functions.

### 2.3. Enforcement Layer (`kedgeflow.enforcement`)
- `LocalEnforcer`: Sits immediately in front of tools. It does **not** evaluate policy; it strictly validates authority grants (signatures, expiration, target matching, actor matching, usage counts) and live guards before dispatching tool calls.

### 2.4. State and Storage Layer (`kedgeflow.storage`)
- `StateStore`: Abstract key-value state interface used for controller admission and live guard evaluation.
- `GlobalState`: Thread-safe in-memory store.
- `ReceiptStore`: Persistence interface for execution receipts (`InMemoryReceiptStore`).

### 2.5. Developer SDK (`kedgeflow.sdk`)
- `KedgeFlow`: High-level entry point providing factory methods (`KedgeFlow.local(...)`), proposal builder, and `@kf.controlled(...)` decorators.

---

## 3. Position in the Agent Ecosystem

KedgeFlow does not replace existing components; it defines the missing control plane boundary:

| Technology | Primary Purpose | Relationship to KedgeFlow |
|---|---|---|
| **Agent Frameworks** (LangGraph, AutoGen, CrewAI, ADK) | Cognition, planning, memory, prompt management | KedgeFlow does not own cognition. Agents built with these frameworks propose transitions to KedgeFlow. |
| **Connectivity Protocols** (MCP, A2A) | Tool discovery, schema negotiation, RPC transport | MCP connects agents to tools. KedgeFlow determines whether a proposed tool execution is authorized and admits it under bounded authority. |
| **Identity and Access Management** (IAM, OAuth) | Long-lived identity, role permissions | IAM answers *"Can Agent X access Service Y?"*. KedgeFlow answers *"Under current policy, evidence, and global state, is this specific consequential transition permitted right now?"*. |

---

## 4. Relationship to OpenKedge

- **OpenKedge**: The overarching open research organization and umbrella project.
- **Agentic Control Plane (ACP)**: The architectural framework formalizing programmable control planes for autonomous systems.
- **KedgeFlow**: The concrete open protocol specification and production-oriented reference implementation of ACP.

---

## 5. Non-Goals for v0.1

To maintain simplicity, reliability, and clean interfaces, version 0.1 explicitly does **not** implement:
- Distributed consensus (Raft/Paxos)
- Kubernetes CRDs and operators
- Remote attestation / TPM hardware integration
- Heavy database backends (PostgreSQL, Kafka, Redis)
- Framework-specific adapters (OpenAI, Anthropic, LangGraph, Google ADK)
- Graphical user interfaces or web dashboards

These capabilities are planned for future phases using the extensible interfaces designed into v0.1.
