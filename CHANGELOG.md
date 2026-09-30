# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.1] - 2026-09-30

### Added
- Core protocol domain objects: `Proposal`, `AuthorityGrant`, `Guard`, `ExecutionReceipt`, `Decision`.
- Cryptographic tamper-evident authority signing and verification using HMAC-SHA256 (`AuthoritySigner`, `AuthorityVerifier`).
- Formal protocol lifecycle state machine (`CREATED`, `PROPOSED`, `DENIED`, `GRANTED`, `EXPIRED`, `REVOKED`, `EXECUTING`, `FAILED`, `COMPLETED`) with invalid transition prevention.
- Controller implementation (`KedgeFlowController`) with pluggable `PolicyEngine` interface and `RuleBasedPolicyEngine`.
- Global state management (`GlobalState` implementing `StateStore`) for admission state and dynamic execution-time guard evaluation.
- Local enforcement engine (`LocalEnforcer`) validating actor, operation, target, nonce, tamper signature, expiry, max uses, and live guards before tool execution.
- In-memory execution receipt store (`InMemoryReceiptStore`).
- High-level Python developer SDK (`KedgeFlow.local(...)` and `@kf.controlled(...)` decorator).
- Interactive CLI with `kedgeflow --version`, `kedgeflow status`, `kedgeflow demo`, and `kedgeflow demo conflict`.
- Specification document (`spec/v0.1/protocol.md`) and JSON Schema definitions (`spec/v0.1/schemas/`).
- Architecture, protocol, and threat model documentation (`docs/architecture.md`, `docs/protocol.md`, `docs/threat-model.md`).
- Working runnable examples:
  - `examples/hello_kedgeflow.py`: Single-agent admission, grant, live-guard check, execution, and receipt generation, plus execution block upon state change.
  - `examples/conflicting_agents.py`: Multi-agent proposal conflict resolution via controller global state.
- Comprehensive test suite covering valid proposals, invalid evidence, authority verification, guard evaluation, tamper detection, expiration, max-uses exhaustion, and multi-agent conflicts.
