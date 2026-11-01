# Lifecycle qualification failed preflight — 31 October 2026

Actual Keycloak key rotation and provider restart completed, and both provider
containers/network were removed. The required native test did not run: Cargo
could not read the generated Cedar parser from its local target cache. See
`identity-lifecycle.log` and `runner-failed.log`. This is a failed qualification,
not a provider lifecycle pass. The isolated target cache dependency is rebuilt
before a new credential issuance and final qualification.

See the [final record](../rfc-m5-selfhosted-lifecycle-2026-10-31/README.md).
The VM remained running for the rerun. Original source and results are retained.
