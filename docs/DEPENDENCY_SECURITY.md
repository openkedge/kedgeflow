# Locked dependency advisory triage

Initial assessment: **12 November 2026**; patch verification: **13 November 2026**, for the `cura` SQL-pilot implementation branch.
This is implementation triage, not independent security acceptance or a complete
OS/container/binary audit. The [pilot acceptance gate](SQL_PILOT_RELEASE.md)
continues to require the security/reproducer owners and exact deployed evidence.

The initial OSV query covered 434 locked public Rust/Node package versions and
explicit Python CI constraints. Eleven package versions matched advisories,
including informational unsound/unmaintained records and duplicate aliases.
These are version matches, not proof of an exploitable deployed configuration.

| Package | Initial version | Disposition |
| --- | --- | --- |
| rustls | 0.23.45 | Patch to 0.23.46 for session-secret Debug, ECH ordering, optional Brotli and key-share prediction advisories |
| rustls-webpki | 0.103.15 | Patch to 0.103.16 for distrusted intermediary verification |
| webpki-roots | 1.0.9 | Patch to 1.0.10 trust bundle |
| rustix | 1.1.5 | Patch to 1.1.6 for zero-buffer xattr unsoundness |
| tokio | 1.53.2 | Patch to 1.53.3 for AsyncFd I/O-safety advisory |
| ctutils | 0.4.2 | Patch to 0.4.4 for constant-time mask/comparison fixes |
| rustls-pemfile | 2.2.0 | Remove unmaintained dependency; use Rustls's maintained pki-types PEM parser, preserving missing/ambiguous/malformed-key refusal |
| zod | 4.6.5 | Lock transitive override to 4.6.6 for collection-validation resource exhaustion |
| certifi (CI tooling) | 2026.7.22 | Pin 2026.10.19 trust bundle |
| opentelemetry-api (CI tooling) | 1.45.0 | Pin 1.45.1 for bounded tracestate parsing |
| cedar-policy | 4.7.1 | Retain supported engine/MSRV; narrowly exclude JSON-template/linking advisory for the source-only, template-refusing leaf ABI |

Primary references: [Rustls release](https://github.com/rustls/rustls/releases/tag/v/0.23.46),
[Rustix advisory](https://rustsec.org/advisories/RUSTSEC-2026-0486.html),
[WebPKI advisory](https://rustsec.org/advisories/RUSTSEC-2026-0382.html),
[trust roots](https://rustsec.org/advisories/RUSTSEC-2026-0381.html),
[Tokio](https://rustsec.org/advisories/RUSTSEC-2026-0386.html),
[ctutils](https://rustsec.org/advisories/RUSTSEC-2026-0385.html),
[PEM maintenance](https://rustsec.org/advisories/RUSTSEC-2025-0134.html),
[Zod](https://github.com/colinhacks/zod/pull/6652),
[Certifi](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2),
[OpenTelemetry](https://github.com/open-telemetry/opentelemetry-python/security/advisories/GHSA-xcq7-p3pf-p88h).

## Cedar profile exclusion

[GHSA-c33x-vcv4-vg3g](https://github.com/cedar-policy/cedar/security/advisories/GHSA-c33x-vcv4-vg3g)
requires malformed JSON policy templates and template linking. The leaf constructor
parses only Cedar source with `PolicySet::from_str`, refuses every template, and
requires strict ABI validation. It never imports JSON policies or calls a linking
API. A regression presents the malformed JSON form to the actual constructor and
requires refusal alongside existing textual-template refusal. This supports a
bounded source-level non-reachability inference for that ABI. It is not a global
statement that Cedar 4.7.1 is patched or safe in other applications.

The [triage record](../config/dependency-advisory-triage.json) binds this one advisory,
package and version to exact policy/negative-test hashes and expires on December
12, 2026 UTC. Changes to either source, another package/version/advisory, missing
triage or expiry block the audit. Independent security approval remains
**BLOCKED_EXTERNAL_INPUT**; this file contains no approval, key or signature.

## Reproduction and remaining review

```sh
python scripts/audit-dependencies.py --output /new/private/dependency-audit
```

The read-only query uses [OSV's batch API](https://google.github.io/osv.dev/post-v1-querybatch/)
and the patched Certifi trust bundle. It retains input/response bytes, refuses
incomplete/paginated responses, fails on unmatched advisories and reports source-bound
exclusions separately. Network/query failure fails the CI job. The mandatory
`dependency-audit` job feeds `release-required` and the exact-source CI record
verifier. The post-patch query covers 433 package versions, finds no untriaged
matches, and retains the single Cedar profile exclusion.

OS/AMI/provider/container packages, dynamically linked libraries, complete build-tool
transitives, exploit reachability outside the named profile, licensing and independent
security review are not established by this scan. A later advisory or expiry can
change the result. Generate the draft CycloneDX inventory, review actual image and
package materials, and obtain the real security/reproducer decisions before release.

## Private fixture prerequisites

A separate reproduced failure comes from default temporary-directory permissions.
With umask `0002`, `tempfile` creates group-writable parent directories (`0775`).
The protected file loader correctly rejects those ancestors; changing the loader
would weaken enforcement. `run-protected-tests.py` instead selects umask `0077`
and a canonical system temporary base before executing the unchanged test command
as a non-root identity. This avoids unsafe shared CI workspace ancestors. Custody unit
fixtures also explicitly request private directories. Auth, admission, custody,
managed-drain and operations tests pass with real etcd/SQL under that private setup,
with zero ignored cases or fixture-skip messages. The original hosted branch still
failed integration; this reproduction does not prove every failure had this
cause. Later authenticated log inspection and local stack-overflow reproduction
are recorded in [CI stabilization](CI_STABILIZATION.md). A new hosted run must
verify the corrected source.

CI compilation is bounded to two jobs and Rust cases run serially to match the
local qualification environment. Existing Kubernetes exclusions are unchanged:
real Kubernetes cases still run in their separately provisioned mandatory stage.
An automatic-review false positive regarding a new exclusion was resolved by
comparing both existing source revisions and preserving the exact exclusion count.
