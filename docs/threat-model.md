# KedgeFlow Threat Model (v0.1)

This document specifies the security assumptions, threat vectors, mitigations, and explicit non-guarantees of the KedgeFlow protocol and its v0.1 reference implementation.

---

## 1. Foundational Security Boundary Notice

### Advisory Integration vs. Non-Bypassable Enforcement

The most critical distinction in agent security is the physical and logical placement of the enforcement boundary:

> **Fundamental Limitation:**  
> If an agent possesses direct, ambient access to target resources or underlying credentials (e.g. cloud API keys, direct database connections, raw system shell access), any in-process enforcement layer is **advisory**, not authoritative. A compromised or misaligned cognitive process running within the same execution domain can simply bypass the adapter and invoke the resource directly.

### Taxonomy of Enforcement Topologies

1. **Advisory In-Process Enforcement (v0.1 Reference Model)**:
   - Placement: In the agent application runtime (`LocalEnforcer`).
   - Threat Mitigated: Accidental agent tool misuse, policy non-compliance, race conditions, stale environmental assumptions, lack of execution auditability.
   - Limitation: Cannot prevent adversarial code from bypassing the SDK if ambient credentials exist.

2. **Authoritative / Non-Bypassable Enforcement (Production Topologies)**:
   - Placement: In an isolated proxy or external gateway between the agent and target systems.
   - Examples:
     - **Execution Broker**: Isolated worker daemon that only accepts signed `AuthorityGrant` tokens before executing tools.
     - **Credential Broker / Secret Exchange**: Issues short-lived, single-use downstream API tokens only upon presentation of a valid `AuthorityGrant`.
     - **API Gateway / Service Mesh**: Ingress proxy validating KedgeFlow authority signatures before routing requests to backend services.
     - **Database Proxy**: Mediates SQL commands and enforces policy guards before query execution.
     - **Hardened Sandbox**: Container or microVM with zero external network access except via a controlled boundary proxy.

---

## 2. Threat Vectors and Mitigations

| Threat Vector | Description | Status in v0.1 | Mitigation Mechanism |
|---|---|---|---|
| **Compromised / Rogue Agent** | Agent hallucination, prompt injection, or malicious intent creates dangerous proposals. | **Mitigated** | Control plane policy engine evaluates proposal independently; agents cannot grant themselves authority. |
| **Forged Authority Grant** | Rogue agent manufactures an `AuthorityGrant` out of thin air. | **Mitigated** | Controller cryptographically signs grants using HMAC-SHA256 (future: asymmetric KMS). Enforcer rejects unsigned or unverifiable grants. |
| **Tampered / Modified Authority** | Attacker intercepts a valid grant and modifies `target`, `operation`, `guards`, or `expires_at`. | **Mitigated** | The cryptographic signature is computed over a canonical payload of all fields. Any modification breaks the signature verification. |
| **Replayed Authority** | Attacker replays a previously valid authority grant to execute an action multiple times. | **Mitigated** | `max_uses` (default: 1) is tracked and enforced by the enforcer; grants contain unique `nonce` and `authority_id` identifiers. |
| **Expired Authority** | Grant is executed long after conditions have shifted. | **Mitigated** | Grants are strictly time-bounded (`expires_at`, short TTLs); enforcers reject expired grants. |
| **Stale Environmental Guards** | Environmental conditions were valid during proposal admission but degraded before execution. | **Mitigated** | Live guards (`Guard`) are evaluated by the enforcer against current state *immediately* before tool execution. |
| **Bypassed Enforcer** | Rogue agent directly invokes target tool bypassing `enforcer.execute()`. | **Advisory in v0.1** | Addressed when enforcement is placed at an external network/credential boundary. |
| **Compromised Controller** | Controller signing key is leaked or controller state is maliciously altered. | **Out of Scope** | Requires secure key management (KMS/HSM), distributed consensus, and mTLS control plane protection. |
| **Compromised Enforcement Point** | The machine hosting the enforcement boundary is rooted. | **Out of Scope** | Requires host security, memory isolation, and remote attestation (e.g. confidential compute). |

---

## 3. Cryptographic Invariants

In v0.1:
- Controller signs `AuthorityGrant` objects using HMAC-SHA256 with a 256-bit secret key.
- The signed payload is computed over a deterministic, sorted-key JSON string of:
  - `authority_id`
  - `proposal_id`
  - `actor`
  - `operation`
  - `target`
  - `parameter_constraints`
  - `guards`
  - `issued_at`
  - `expires_at`
  - `policy_version`
  - `nonce`
  - `max_uses`
- Any mutation of any field invalidates the signature and halts execution immediately.

---

## 4. Security Recommendations for Deployers

1. **Do not embed long-lived target credentials inside agent memory.**
2. **Bind authority tightly:** Use the narrowest possible `target`, single-use `max_uses = 1`, and minimal TTLs.
3. **Always evaluate live guards at execution time:** Do not rely solely on controller admission time state checks.
4. **Transition from in-process to network-level boundaries** for high-impact production operations (e.g., cloud deletion, payments, infrastructure reboots).
