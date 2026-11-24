# Security policy

KedgeFlow is experimental alpha. No version is presently an independently
accepted enterprise or production release. The SQL pilot is bounded by its exact
registered action, deployment and writer inventory.

| Component | Version/profile | Support boundary |
| --- | --- | --- |
| Rust services | `0.9.0-alpha.1`, named draft profiles | Experimental reference runtime; deployment-specific qualification required |
| Node Agent Adapter | Versioned reference profiles | Compatible only with explicitly supported discovery/action/schema bindings |
| Python local demo | `0.1.0a1` | Legacy educational implementation; in-process HMAC enforcement is advisory |
| Enterprise SQL pilot | `KF-POSTGRES-LEAF-0.1-draft` | Proposed isolated Linux/systemd pilot; independent acceptance pending |

## Report a vulnerability

Email `security@openkedge.org` with affected source/version, reproduction steps,
impact and relevant configuration boundaries. Keep credentials and private keys
out of reports and public issues. We aim to acknowledge reports within 48 hours;
this alpha policy is not a production support or patch-time SLA. Coordinated
triage, remediation and disclosure precede public advisory publication.

## Current authority boundary

The Rust services verify Ed25519 exact-action records and use authenticated TLS,
original-attempt claims, bounded one-shot broker authority, target guards and
retained outcomes. Subject/workload identity, DPoP and provider trust depend on
the enrolled profile and protected deployment configuration. An agent must not
possess service signing keys, target writer credentials, administration access
or an unmediated route to protected effects. Service root and cloud administrators
remain trusted deployment principals whose paths must be inventoried and reviewed.

SQL Level A covers only the actual conditional transaction and retained outcome
COMMIT under its declared writer/predicate scope. It does not cover arbitrary SQL,
external writers, stale physical restores or a wider business invariant without
separate qualification. An ambiguous outcome retains spent authority and is
queried through its original attempt; absence is not permission to resend.
Terraform profiles are Level C with `target_atomic:false`. Kubernetes controller
acceptance does not prove physical drain completion. Neither is part of the
current SQL-only pilot implementation milestone.

Self-hosted Keycloak/SPIRE, separate UIDs, independent witness/head/floor and audit
custody, protected backups, rotation, bypass denial and incident ownership require
actual deployment evidence. Local fixtures and cryptographic owner signatures
cannot themselves establish factual or administrative independence.

See [threat model](docs/threat-model.md), [current profiles](docs/PROTOCOL_PROFILES.md),
[production readiness](docs/PRODUCTION_READINESS.md), [pilot scope](docs/SQL_PILOT_RELEASE.md)
and [qualification gates](docs/ENTERPRISE_QUALIFICATION.md). Accepted version,
upgrade, retention, security review and maintenance commitments remain release
gates; no broad compatibility or multitenancy guarantee is implied.

Current implementation [dependency triage](docs/DEPENDENCY_SECURITY.md) records
patched packages, the expiring Cedar profile exclusion and remaining image/license/
independent review gates.
