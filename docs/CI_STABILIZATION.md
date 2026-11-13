# SQL pilot CI stabilization

This record distinguishes observed failures from explanations still under test.
It does not establish enterprise qualification or independent acceptance.

| Source/run | Observation | Response |
| --- | --- | --- |
| `d1c6adb`, [43340090551](https://github.com/openkedge/kedgeflow/actions/runs/43340090551) | Lint rejects deprecated `AtomicUsize::fetch_update` in `ledger_read_tests.rs`; Linux staging refuses its placeholder as a non-regular binary | Pin Rust 1.98.0 and Ubuntu 24.04. Preserve the protected loader's regular-file requirement. |
| `8245097`, [43387470824](https://github.com/openkedge/kedgeflow/actions/runs/43387470824) | Hosted Rust/SQL qualification failed; independent non-root reproduction shows default `0775` temporary ancestors are refused | Execute fixtures with canonical system temporary storage and inherited umask `0077`. Root and writable ancestors continue to refuse. |
| `a0afae1`, [43392135727](https://github.com/openkedge/kedgeflow/actions/runs/43392135727) | MSRV, three Python versions, Linux packaging, SQL account isolation and dependency audit pass; SQL integration aborts on a stack overflow in `compensation_sql_failure_target_kill_after_commit_recovers_original_only` | Reproduce that abort on ARM64 Linux using the same non-root SQL/etcd fixture. Test an optimized Cargo test profile; keep debug assertions enabled. |
| Same run | Compensation CAS hook times out; two SQL SDK scenarios report `unissued`; a real-clock issuance candidate expires | Add early-completion/phase/fault diagnostics to the CAS test and method/status-only SDK assertion diagnostics. The two SDK scenarios and CAS race pass locally, so their hosted cause remains unproven. |
| `9bb5418`, [43397052628](https://github.com/openkedge/kedgeflow/actions/runs/43397052628) | Hosted native integration passes, including the previously failing SQL issuance/stack cases. Local real Kubernetes exposes two closure assumptions hidden by slower execution | Wait explicitly for the existing original expiry before final unaccepted absence. A successful authenticated retry must return the exact original closed state; closed absence must never become new acceptance. Both focused regressions pass; preserve runtime guards and physical/audit assertions. |

The test profile optimizes both dependencies and test code. Large composed async
futures otherwise produce debug-only stack copies, while unoptimized signature
and schema verification can consume finite fixture lifetimes. This is a test-build
change, not a relaxation of an authority boundary. The shipping release profile,
expiry rules, transaction comparisons, test deadlines, assertions and required
Kubernetes stage are unchanged. A passing build alone is insufficient: the exact
previously aborting case and the complete required hosted suite must pass.

The optimized local SQL/etcd run passes the previously aborting case, the unchanged
CAS race, both SDK scenarios and the real-clock shipping-target scenario. This
supports the local stack-overflow correction. It does not establish the cause
of every hosted refusal; the additional diagnostics and a new complete run are
still required. Release packaging also generates an unsigned draft CycloneDX
SBOM and tracked-checkout source manifest. Generated CI logs are excluded from
that source inventory, while tracked modifications still mark it dirty.
The release artifact also retains a deterministic `git archive` of the exact
checkout, including the versioned pilot infrastructure, operator tools and
runbooks that are distributed separately from the native core bundle. It is an
unsigned source archive, not an independently approved release.

Read-only AWS CloudFormation template validation with profile `cura` in
`us-west-2` succeeded. It validates template syntax and parameter declarations;
it does not provision resources, approve an account/budget, validate operational
isolation, or provide an owner's acceptance.

The immutable local foundation and dependency-security records preserve earlier
passing subsets and failed diagnostic attempts. Later results must be appended
as a new record rather than rewriting those historical claims. Milestone A stays
open until the remaining implementation and exact-source required qualification
are complete. Milestone B remains **BLOCKED_EXTERNAL_INPUT**.
