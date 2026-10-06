# KedgeFlow Protocol Specifications

This directory contains versioned protocol specifications, normative schemas, and validation tooling for KedgeFlow.

## Principles

1. **Protocol First**: Protocol semantics are decoupled from any transport (in-process, HTTP/REST, gRPC, message queues) and programming language.
2. **Deterministic Schemas**: The canonical wire objects are defined by standard JSON Schemas (Draft 2020-12) located in this package.
3. **Bounded Reference Implementations**: The Rust gateway implements an explicitly restricted v0.9 execution profile; the Python package is a v0.1 local demo. Generic envelope verification alone is not complete admission or payload-schema validation.
4. **Offline Compatibility Vectors**: All normative signed envelopes, test keys, and compatibility fixtures are versioned under [`fixtures/`](../fixtures/).

## Specifications and Contracts

- **Complete Machine-Readable Contracts (v0.9 / KF-JSON-0.2)**:
  - Normative JSON Schema: [`kedgeflow.schema.json`](kedgeflow.schema.json) (Draft 2020-12, closed objects).
  - Validation Engine: [`validate.py`](validate.py) — verifies JSON Schema validity, Ed25519 signatures, RFC 8785 JCS canonicalization, and semantic bindings.
  - Cryptographic Primitives: [`profile.py`](profile.py) — domain-prefixed SHA-256 digests ($H(q)$, $H(E)$) and Ed25519 signing.
  - Schema Generator: [`build_schema.py`](build_schema.py).
  - Normative Fixtures Suite: [`../fixtures/`](../fixtures/) (see [`fixtures/README.md`](../fixtures/README.md)).
- **[v0.1 Specification](v0.1/protocol.md)**: Initial core protocol specifying `Proposal`, `AuthorityGrant`, `Guard`, `ExecutionReceipt`, and the lifecycle state machine.

## Running Conformance Verification

To run specification conformance checks against the complete fixture suite:

```bash
python spec/validate.py
```

or through pytest:

```bash
pytest tests/test_fixtures.py
```
