# KedgeFlow Protocol Specification v0.1

**Status:** Draft / Alpha  
**Version:** 0.1  
**Part of:** OpenKedge Agentic Control Plane (ACP) Architecture

---

## 1. Abstract

AI agents increasingly operate tools that enact consequential real-world transitions (e.g., dropping databases, terminating cloud infrastructure, executing financial transactions). Traditional tool execution frameworks conflate **reasoning** (cognition) with **authority** (authorization and enforcement) in a single loop.

KedgeFlow defines an open protocol for separating the **control plane** from the **data plane** in agent systems. Agents propose consequential transitions; the control plane evaluates admission using policy, evidence, and global state; the enforcement boundary admits execution only under bounded, tamper-evident authority with live guard verification; and execution emits an immutable evidence receipt.

---

## 2. Core Protocol Abstraction

The fundamental invariant of KedgeFlow is:

```
cognition proposes
control plane authorizes
execution plane enforces
execution produces evidence
```

### Protocol Flow

```
Agent                  Control Plane               Enforcement Boundary               Tool/Target
  |                          |                              |                              |
  |--- 1. PROPOSE ---------->|                              |                              |
  |    (Proposal)            |                              |                              |
  |                          | [Evaluate Policy,            |                              |
  |                          |  Evidence, Global State]     |                              |
  |                          |                              |                              |
  |<-- 2. GRANT or DENY -----|                              |                              |
  |    (AuthorityGrant)      |                              |                              |
  |                          |                              |                              |
  |--- 3. EXECUTE ----------------------------------------->|                              |
  |    (Proposal + Grant)    |                              | [Verify Authority,           |
  |                          |                              |  Signature, Nonce,           |
  |                          |                              |  Live State Guards]          |
  |                          |                              |                              |
  |                          |                              |--- 4. INVOKE --------------->|
  |                          |                              |<-- 5. RESULT ----------------|
  |                          |                              |                              |
  |                          |                              | [Record Receipt]             |
  |<-- 6. REPORT -------------------------------------------|                              |
       (ExecutionReceipt)
```

---

## 3. Protocol Objects

The protocol defines five wire objects. Formal JSON schemas are provided in `spec/v0.1/schemas/`.

### 3.1. Proposal

A `Proposal` represents an agent's request to effect a consequential state transition.

| Field | Type | Description |
|---|---|---|
| `proposal_id` | UUID | Unique identifier of the proposal. |
| `actor` | String | Identifier of the proposing principal or agent. |
| `intent` | String | Stated high-level intent behind the action. |
| `operation` | String | Consequential operation verb (e.g. `compute.terminate`). |
| `target` | String | Target resource identifier (e.g. `instance/i-17`). |
| `parameters` | Object | Operation parameters. |
| `evidence` | Array[Object] | Structured evidence claims supporting the proposal. |
| `expected_effect` | Object (optional) | Structured anticipated side-effects. |
| `dependencies` | Array[String] | Prerequisite proposal IDs or condition tags. |
| `requested_scope` | String (optional) | Namespace or security domain requested. |
| `created_at` | DateTime (ISO 8601) | Timestamp when proposal was created. |

### 3.2. Decision

The outcome returned by the Control Plane Controller upon evaluating a proposal.

| Field | Type | Description |
|---|---|---|
| `disposition` | Enum (`GRANT`, `DENY`) | Admission outcome. |
| `authority` | AuthorityGrant (optional) | Bounded authority grant if disposition is `GRANT`. |
| `reason` | String | Justification for the decision. |

### 3.3. AuthorityGrant

A bounded, cryptographically signed token issued by the control plane. Ambient bearer authority is strictly prohibited. Authority is explicitly:
1. **Proposal-bound** (`proposal_id`)
2. **Actor-bound** (`actor`)
3. **Operation-bound** (`operation`)
4. **Target-bound** (`target`)
5. **Short-lived** (`expires_at`)
6. **Usage-bounded** (`max_uses`, default = 1)
7. **Condition-guarded** (`guards`)

| Field | Type | Description |
|---|---|---|
| `authority_id` | UUID | Unique grant identifier. |
| `proposal_id` | UUID | Bound proposal ID. |
| `actor` | String | Authorized actor. |
| `operation` | String | Permitted operation. |
| `target` | String | Permitted target resource. |
| `parameter_constraints` | Object | Parameter constraints that execution must satisfy. |
| `guards` | Array[Guard] | Live conditions checked at execution time. |
| `issued_at` | DateTime (ISO 8601) | Issuance timestamp. |
| `expires_at` | DateTime (ISO 8601) | Expiration timestamp. |
| `policy_version` | String | Policy version that authorized the grant. |
| `nonce` | String | Cryptographic anti-replay nonce. |
| `max_uses` | Integer | Maximum permitted invocations (default 1). |
| `signature` | String | Cryptographic signature over canonical grant payload. |

### 3.4. Guard

A `Guard` specifies a live condition over current state that must evaluate to `True` at execution time immediately before the tool is invoked.

| Field | Type | Description |
|---|---|---|
| `key` | String | State key in controller/enforcer state. |
| `operator` | Enum | Comparison operator: `equals`, `not_equals`, `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal`. |
| `value` | Any | Threshold or expected value. |

### 3.5. ExecutionReceipt

An immutable, structured record proving what was executed, by whom, under what authority, and observed conditions.

| Field | Type | Description |
|---|---|---|
| `receipt_id` | UUID | Unique receipt identifier. |
| `proposal_id` | UUID | Original proposal identifier. |
| `authority_id` | UUID | Authority grant identifier. |
| `actor` | String | Executing actor. |
| `operation` | String | Executed operation. |
| `target` | String | Target resource. |
| `started_at` | DateTime (ISO 8601) | Execution start timestamp. |
| `completed_at` | DateTime (ISO 8601) | Execution completion timestamp. |
| `status` | Enum (`COMPLETED`, `FAILED`) | Execution outcome status. |
| `result` | Any | Output payload or return value. |
| `observed_guards` | Array[Object] | Snapshot of guard evaluations and observed values. |
| `error` | String (optional) | Error message if execution failed. |
| `policy_version` | String | Policy version under which execution was authorized. |

---

## 4. Lifecycle State Machine

The lifecycle of any consequential transition is strictly governed by the following state transitions:

```
    CREATED
       │
       ▼
    PROPOSED
       │
       ├──────────► DENIED
       │
       ▼
    GRANTED
       │
       ├──────────► EXPIRED
       │
       ├──────────► REVOKED
       │
       ▼
    EXECUTING
       │
       ├──────────► FAILED
       │
       ▼
    COMPLETED
```

### Transition Invariants

1. `CREATED -> PROPOSED`
2. `PROPOSED -> GRANTED | DENIED`
3. `GRANTED -> EXECUTING | EXPIRED | REVOKED`
4. `EXECUTING -> COMPLETED | FAILED`
5. `DENIED`, `EXPIRED`, `REVOKED`, `COMPLETED`, `FAILED` are terminal states.
6. Any illegal transition (e.g. `DENIED -> EXECUTING`, `EXPIRED -> EXECUTING`) must be rejected as an unrecoverable protocol violation.

---

## 5. Semantic Protocol vs. Transport Bindings

KedgeFlow protocol semantics are decoupled from wire transports:

- **In-Process Binding (v0.1 Reference)**: Direct Python method calls and in-memory structures.
- **HTTP / REST Binding (Planned)**:
  - `POST /v1/proposals` -> Returns `Decision` (containing `AuthorityGrant` if granted).
  - `POST /v1/execute` -> Accepts `Proposal` + `AuthorityGrant`, returns `ExecutionReceipt`.
- **gRPC / Protobuf Binding (Planned)**: High-performance streaming RPC for low-latency boundary enforcement.
- **Message Bus / Asynchronous (Planned)**: Event-driven proposal submission and asynchronous authority distribution.

The Python reference implementation in `kedgeflow` demonstrates compliance with protocol semantics; it does not limit or redefine the specification.
