# KedgeFlow Protocol Specifications

This directory contains versioned protocol specifications and schemas for KedgeFlow.

## Principles

1. **Protocol First**: Protocol semantics are decoupled from any transport (in-process, HTTP/REST, gRPC, message queues) and programming language.
2. **Deterministic Schemas**: The canonical wire objects are defined by standard JSON Schemas located in versioned directories.
3. **Reference Implementations**: Implementations (such as the Python package `kedgeflow`) are reference engines conforming to these specifications.

## Versions

- [v0.1 Specification](v0.1/protocol.md) - Initial core protocol specifying `Proposal`, `AuthorityGrant`, `Guard`, `ExecutionReceipt`, and the lifecycle state machine.
