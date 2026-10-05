# KedgeFlow Normative Test Fixtures

This directory contains the canonical offline test vectors and compatibility fixtures for KedgeFlow **KF-JSON-0.2** (whitepaper v0.9).

These signed fixtures use public demonstration keys and deterministic test data to validate parser conformance, canonical hashing, Ed25519 signature verification, schema compliance, and cross-record semantic bindings.

## Directory Listings and Cryptographic Vectors

| Fixture File | Envelope Kind / Type | Issuing Role | Description & Canonical Digest $H(E)$ |
|---|---|---|---|
| `proposal.json` | `proposal` | Agent Adapter | Frozen proposal $q$ binding tool call, dual identity, parameters (`3456dd204af1e4b5345c1ec43b0f4e7784bce920bfebafb070ee8cef252c8a3b`) |
| `certificate.json` | `certificate` | Admission Controller | Signed admission certificate $C_q$ confirming policy and evidence satisfaction (`28b208aceae2b4a67f06ee797707e0a505a76af1a4236e9274d6222b5695db46`) |
| `grant.json` | `grant` | Grant Authority | Single-use execution grant $G$ bound to root generation and gateway audience (`c906936b8a7fd45c5438e51210a19006e4d267569c23532c8b8db6c6fc862fe4`) |
| `ctd.json` | `ctd` | Resource Registry | Consequential Tool Descriptor v1.0 defining tool action, scope, and obligations (`ccdb4ed2ce5ebe56d5d25f9b5ef69567d4c92028630ef76b052533e654757d6c`) |
| `ctd.yaml` | YAML authoring | Resource Registry | Human-friendly YAML authoring representation of the CTD fixture (decodes identically to `ctd.json`) |
| `hitl_witness.json` | `hitl_witness` | Evidence Provider | Hardware WebAuthn human-in-the-loop review assertion with cryptographic challenge binding (`17be039938fae1acd59ad4ad1a56b2cecfea814128171cb0c174b15e80843e8c`) |
| `evidence.json` | `evidence` | Evidence Provider | Candidate evidence statement with validity interval and uncertainty metadata (`dc427cc56de3330bd732c2498696a4884e42d2de4e65cafd7644075f82862e16`) |
| `manifest.json` | `manifest` | Admission Controller | Witness manifest declaring required evidence inputs and satisfaction obligations (`e725ae155d036bd7c85cff372d57def59b58c4d971354f29914c43f9aa85cb5f`) |
| `lease.json` | `lease` | Admission Controller | Pre-validation admission lease for static obligations (`e4b96e74051abb55c8ff4c4cd615d1012a025881c39974f1557daa8d4fa02183`) |
| `saga_root.json` | `saga_root` | Grant Authority | Composite saga authority root for coordinated multi-step allocations (`02c9c7ac98dbf83d03e9ec7cbd68c2953827f0d67fc47c6b1c2aa7b0d6a9b4cc`) |
| `remediation.json` | `remediation` | Execution Gateway | Structured remediation contract returned on `NEEDS_EVIDENCE` (-32001) (`cc6fabe4828c57400a5a15ca316ac57b8357d40bd31798b64a5f84c92f075aa6`) |
| `receipt.json` | `receipt` | Resource Adapter | Signed execution receipt recording attempt outcome and generation fence (`afa7d9820c7df35fb4ba8bebafac8dde677c6e748c145aa996ed0ca6d0011e23`) |
| `delegation.json` | `delegation` | Agent Adapter | Authenticated delegation record linking parent workflow to child subagent (`bd13e0adf562a77754b5228796f81386655c6dd5870f7940b3b37bb5f2ec82af`) |
| `token_exchange.json` | `token_exchange` | Execution Gateway | RFC 8693 token-exchange downscoping binding for backing target API (`86e6b2708f53c65c51b9e14cd8755e29725516db702ac123f36506b017db2070`) |
| `public-test-keys.json` | Keys registry | Multiple roles | Authenticated Ed25519 demonstration keys mapped to authorized role names |
| `dpop-public-test-key.json` | JWK key | Agent Plane | JWK demonstration key for DPoP proof generation |
| `dpop-proof.jwt` | JWT vector | Agent Plane | Demonstration RFC 9449 DPoP proof header bound to request URI and HTTP method |
| `access-token.jwt` | JWT vector | IdP / OAuth | Demonstration OAuth 2.0 access token binding human subject and permitted scopes |
| `capacity-review-template.txt` | Template | Evidence Provider | Immutable review template for human reviewer display |
| `capacity-review-rendered.txt` | Rendered bytes | Evidence Provider | Exact rendered byte sequence verified by the WebAuthn challenge digest |
| `a2a-root-reference.json` | Message Part | Agent Plane | Agent2Agent (A2A) protocol Part carrying reference to a delegated authority root |
| `fixture-digests.json` | Digest index | Specification | Machine-readable registry of canonical SHA-256 digests for all signed envelopes |

## Conformance Verification

To validate that these fixtures satisfy the JSON Schema Draft 2020-12 specification and cryptographic invariants, run:

```bash
python spec/validate.py
```

or using `pytest`:

```bash
pytest tests/test_fixtures.py
```
