# RFC 0033: Reproducible software conformance bundle and release gates

- Status: Draft
- Profile/version: KF-SOFTWARE-CONFORMANCE-0.1-draft
- Milestone: M9a runner/corpus prerequisite; independent release acceptance open
- Baseline: RFCs 0001–0032
- Owners/reviewers: unassigned

## Runner

One fixed-command runner executes source formatting/linting, frozen paper/schema
verification, Node protocol vectors, Python checks, and the entire Rust suite with
required real three-member etcd, real peer-authenticated PostgreSQL, official MCP
SDK and the stale logical SQL restore rehearsal. The existing Rust corpus contains
positive, negative, replay, revocation, concurrency, crash and lost-response cases.
The newly added review/coordination state tests are library prerequisites only.

Required Rust execution may use separate sequential runtime and family-saga
batches, each with disposable PostgreSQL and etcd. Before either executes, the
runner inventories every workspace/all-targets test and target. The combined
executed `(target, case)` inventory MUST equal that manifest exactly once; failed,
ignored, skipped, omitted, duplicate and unrecognized cases refuse qualification.
Zero-test binaries MUST also execute. Each command retains the existing bounded
harness timeout. Batching changes neither native authority windows nor client
transport deadlines. New native public execution artifacts are required and
hashed separately; a missing aggregate/row/wire artifact fails the software gate.

The runner creates a new output directory and never overwrites previous evidence.
It retains command arguments, raw logs, source/tool pins and hashes, pass/fail status,
test populations and explicit remaining gates. No required runtime dependency may
silently skip. An unobserved independent peer, Linux account test, hardware ceremony
or production target never becomes passed because local software checks passed.

A successful run returns `passed_software_checks`, not accepted release or enterprise
qualification. Another developer can run the same commands; their reproduction is
a separate observation. Signed evidence, external trace exchange, actual independent
controllers, second runtime/target, intermediaries, A2A, provider enrollment and
owner release decisions remain required. Same-repository implementations do not
prove organizational or protocol-peer independence.

## Fresh Kubernetes qualification credentials

`scripts/conformance.py` creates an owned private bootstrap as a recorded command
immediately before Kubernetes RBAC qualification, after the long software/runtime
batches. Explicit task-owned kind context, kubectl and kubeconfig paths are
required. Pre-issued `KF_KUBE_FIXTURE` credentials are not reused by this runner.
The fixture helper retains its one-hour service-account lifetime; protocol windows
are unchanged. Each drain case still creates its own fresh namespace.

The runner retains public contract/fixture metadata, checks cleanup against the
exact owner and cluster/node identities, and treats cleanup failure as failed
qualification. Private credential files are removed when the run finishes. The
direct `scripts/test-kube-drain.py` driver still accepts an explicitly prepared
fixture when invoked separately.

## Open gates

Track M0 minimum-toolchain/paper reproduction, M1 owner decisions, M2–M6 deployment
and actual provider/pilot acceptance, M7 panel/service/lease/hardware integration,
M8 native reservation/grant/claim/A2A/saga/drain integration, and M9 independent
wire exchange/migration/release acceptance. Gate status is explicit data in the
new bundle. A CI account fixture is useful supporting evidence when actually run;
its mere presence is not an observation. Never relabel frozen/historical evidence.
