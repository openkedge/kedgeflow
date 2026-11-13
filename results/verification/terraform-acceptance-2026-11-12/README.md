# Exact Terraform deployment acceptance checker

Date: 12 November 2026, America/Los_Angeles. Baseline `ba1a21d`; implementation
`214884f`. See [RFC 0070](../../../docs/rfcs/0070-terraform-deployment-acceptance.md)
and the [operator guide](../../../docs/TERRAFORM_DEPLOYMENT_ACCEPTANCE.md).

This record qualifies an offline administrative checker and pending-request
preparation. It closes the missing executable acceptance-record check. It does
**not** close production acceptance: **zero fresh deployed workflows and zero
actual owner approvals** are credited. The exact missing inputs and seven gates
are retained in [pending-inputs.json](pending-inputs.json).

The checker binds externally pinned deployment and trust digests, exact source/
archive/configuration/writer inventory and the existing single or pair Level C
scope. Seven distinct registered owner principals/keys must accept all 25
required deployed checks. Deployment, storage, audit and independent-reproducer
administration domains must be distinct declarations. Actual independence,
complete writers, factual observations, current trust and host/clock custody are
externally approved assumptions; signatures cannot establish them by themselves.

All **55 Node tests pass**, with zero failures or skips. These include both
profiles, validly signed rejection/future/overlong records, substituted owner/
deployment/configuration/source/evidence, wrong signature domains, key reuse,
shared protected administration, sequence floors, expiry, missing/failed/unknown
or local-fixture checks, duplicate fields/checks/approvals, unsafe integer JSON,
artifact tampering/traversal, symlink/hardlink/FIFO inputs, finite read budgets,
current-time CLI behavior, overwrite refusal and non-execution of artifact text.
The schema matches the verifier's gate/role/check inventory. Eighteen positive
schema records and eight negative shape cases pass. Seven existing SDK suites
also pass, including 46 single and 67 pair vectors. CI now runs the new tests.
CI dispatch itself was not performed in this task.

[Synthetic records](synthetic) contain newly generated **test-only public keys**,
signed fictional observations and approvals, and inert artifact bytes. Private
signing keys existed only in test memory and were discarded. Their declared
synthetic clock is a mathematical fixture value, not the qualification wall
clock. [The replay](synthetic-replay.json) verifies these exact records at that
recorded test clock; the shipping CLI uses current time and has no backdating
flag. This is signature/record software evidence, not deployed measurements.
The report always retains `production_qualified: false` and
`execution_authority: false`, even when owner records verify.

[Pending preparation](pending-request/request.json) uses only that synthetic
deployment to demonstrate the operator workflow. Every check is unknown,
observations are unqualified and the approvals list is empty. Preparation creates
no keys, sign-offs or passing deployed observations. These pending records
intentionally fail accepted-record validation.

The checker does not inspect a live host or discover a newer trust snapshot.
Operators must independently determine current installed pins, require the
verifier's successful exit in their deployment pipeline and supply approved
current owner trust/floors and actual evidence. The running gateway does not
consume this report. No grant, mutation, allowance release, force-unlock or
recovery behavior changes. Existing production runtime, SDK, frozen schema,
deployment units and the actual [Linux qualification](../terraform-systemd-2026-11-12/README.md)
remain unchanged. No production credential, deployment or message to an owner
was created or sent.

Re-run the deterministic semantic cases with fresh test keys:

```sh
node --test tests/test_terraform_acceptance.mjs
```

[Summary](summary.json), [tests](tests.log), [schema checks](schema-checks.json),
[SDK results](sdk-vectors.log), [source pins](source-hashes.json),
[source patch](source.patch), [prior evidence hashes](prior-evidence-hashes.json),
[checks](checks.log) and [artifact hashes](artifact-hashes.json) preserve the
scope and review chain. Temporary test directories and special files are removed
by the tests; no VM, account, service or target was provisioned in this increment.
