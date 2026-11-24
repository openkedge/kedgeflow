# SQL pilot CI stabilization, November 13, 2026

This is local diagnostic evidence, not complete qualification or independent
acceptance. The base commit plus `changed-source-hashes.json` pins the tested
delta. Earlier frozen records are unchanged.

The actual unoptimized Linux/non-root SQL/etcd invocation aborts in
`compensation_sql_failure_target_kill_after_commit_recovers_original_only` with
a stack overflow. The optimized Cargo test profile builds with Rust 1.98.0 and
passes that case, the unchanged CAS race, both SQL SDK scenarios, real-clock
issuance and all other selected SQL/compensation cases: **48 pass**. Expiry rules,
transaction comparisons, test deadlines and release optimization are unchanged.
Debug assertions remain enabled.

The broad local invocation also selects **30 existing real Kubernetes cases**.
They fail because this invocation has no owned Kubernetes fixture. Therefore the
retained command's outcome is **failure**, not a full green test run. It reports
48 passed, 30 failed, zero ignored and 207 filtered by the module selector. CI's
existing two `--skip kube_drain_real_` selections are unchanged; its separate
provisioned Kubernetes stage remains mandatory. No new test exclusion is added.

Python passes 132 cases plus six subtests with the local socket access required
by the HTTPS fixtures. A sandboxed attempt had socket-binding failures and is
not counted as passing evidence. Node acceptance/CI checks pass 87 cases and the
seven existing SDK vector suites pass. Formatting, ruff, mypy and CloudFormation
lint pass. Read-only AWS template validation succeeds with `cura` in `us-west-2`;
no AWS resources are created and no account, budget or owner approval is inferred.

Release CI additionally emits a draft unsigned CycloneDX inventory and tracked
source manifest alongside the native bundle. Generated logs are excluded from
that tracked source inventory; tracked modifications still mark it dirty. The
source must complete a fresh full hosted qualification run. Protected source,
release signature, independent reproduction/security/custody, actual deployment,
operational budgets and owner acceptance remain open. Milestone A stays in
progress; Milestone B is **BLOCKED_EXTERNAL_INPUT**.

`artifact-hashes.json` seals these retained bytes. None of these records grants
execution authority or sets production qualification.
