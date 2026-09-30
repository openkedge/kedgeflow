# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

The KedgeFlow team takes security vulnerabilities seriously.

If you believe you have discovered a security vulnerability in KedgeFlow, please do **NOT** open a public issue. Instead, report it responsibly:

- Email: `security@openkedge.org`
- Include detailed steps to reproduce the vulnerability, along with an assessment of the impact.

You will receive an acknowledgment within 48 hours and regular updates on triage and mitigation.

## Security Boundary Notice

In v0.1:
- The local reference implementation uses HMAC-SHA256 signatures to protect `AuthorityGrant` objects against tampering.
- In-process enforcement (`LocalEnforcer`) provides boundary verification within the application process.
- **Important**: In-process enforcement is advisory if the executing process has ambient unmediated access to underlying infrastructure. For authoritative, non-bypassable enforcement in production environments, enforcement must be situated at execution brokers, credential brokers, API gateways, sandboxes, or target service proxies. See [docs/threat-model.md](docs/threat-model.md) for full threat modeling details.
