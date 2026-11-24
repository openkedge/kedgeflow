# SQL pilot security and fixture privacy — 13 November 2026

Status: **local bounded verification passed; hosted source qualification pending**.
Milestone B remains **BLOCKED_EXTERNAL_INPUT**. No AWS resources, real owner
approvals or independent security acceptance were created.

This follow-up is relative to implementation `8245097`. The previous
[foundation record](../sql-pilot-foundation-2026-11-12/README.md) remains unchanged;
its hosted run failed Rust/SQL integration and correctly failed `release-required`.
The six passing jobs do not establish an R0 release. Full authenticated job logs
were unavailable, so the exact cause of every historical hosted failure is not
claimed.

## Dependency changes and evidence

The initial public OSV batch query matched 11 of 434 locked public package versions.
The [triage document](../../../docs/DEPENDENCY_SECURITY.md) records primary
advisories and exact patch versions. Bounded patch updates cover Rustls, WebPKI,
trust roots, Rustix, Tokio, ctutils, Zod and Python CA/telemetry tools. The unmaintained
PEM helper is removed; runtime and fixture parsing use maintained pki-types APIs.

The repeat query covers 433 versions, with **zero untriaged matches** and one
explicit source-bound Cedar leaf exclusion. Cedar remains 4.7.1: the supported
constructor accepts only source, rejects templates and never invokes the JSON
policy/template-linking path required by the advisory. The regression presents
the malformed JSON template to that constructor. Its exact source/test hashes and
December 12 UTC expiry are enforced by the new mandatory CI audit. This is an
implementation non-reachability inference, not an independent approval or a
statement that Cedar is patched. OS/AMI/container/dynamic-library, full build-tool,
license and independent security review remain required.

## Reproduced fixture failure and correction

A non-root Linux probe observes `tempfile` parent mode `0775` under umask `0002`.
The protected loader correctly refuses that group-writable ancestor. The same
file-only constructor succeeds with an explicitly private parent. Root execution
also correctly refuses. No loader permission rule was relaxed.

The fixture launcher now selects a canonical, protected system temporary base
and umask `0077` before exec, refusing root test execution. Custody fixtures also
request private directories explicitly. CI and Make invoke the actual unchanged
test command through this launcher. Compilation concurrency is bounded and Rust
cases serialize. The two preexisting Kubernetes exclusions are unchanged, and
real Kubernetes qualification remains in its required provisioned stage.

The initial root/unprivate test attempts failed; their failures are retained as
diagnostics and not counted as qualification. The corrected real-SQL/three-member
etcd non-root run passes:

- 59 auth/admission/custody/managed-drain/operations cases, no ignored or skipped cases;
- four additional protected service-custody cases;
- two fresh official SDK/native broker/SQL cases;
- all 17 SQL failure-module cases, including actual row-lock changes, process kills,
  commit/reply loss, original query recovery and retained incidents.

Rust 1.98 format and all-target, feature-enabled clippy pass. Python passes 132
cases plus six subtests; the four new cases check narrow/expiring/source-bound
triage and the private launcher. All 87 Node acceptance/CI cases and seven existing
SDK vector suites pass with patched dependencies. This is scoped verification,
not a new run of the entire historical corpus. Full hosted qualification, protected
branch configuration, independently operated cloud topology, measured SRE populations
and signed actual owner acceptance remain open.

`changed-source-hashes.json` pins the implementation delta and
`artifact-hashes.json` seals retained local evidence. Query responses are primary
OSV records of version matches; they are not binary reachability analysis or an
auditor's decision. Neither verification nor audit outputs grant execution or
set `production_qualified:true`.
