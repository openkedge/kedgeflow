# Terraform deployment acceptance records

The N2 software handoff now has an executable administrative acceptance check.
It verifies owner signatures and retained evidence for one exact deployed scope.
It performs no network request, installation, signing, grant issuance, target
mutation, retry or allowance release. The gateway and accepted grant/wire
profiles are unchanged. This checker is intended for an operator's deployment
pipeline; the running gateway does not consume its report as execution authority.

A successful report says `owner_records_verified`. It always retains
`execution_authority: false` and `production_qualified: false`. A bundle remains
non-production-qualified. Cryptographic verification proves that the configured
owners accepted these exact records; it does not prove their factual claims or
that their administration is actually independent. The deployment owners must
approve the trust root, observations and physical topology independently.

## Required inputs

Keep credentials and private keys outside this package. Use only public,
appropriately sanitized evidence. The checker reads fixed local filenames and
content-addressed artifacts; it never follows URLs or paths supplied in records.

1. `deployment.json`: the exact deployment ID, 40-character source commit,
   archive SHA-256, protected configuration SHA-256, complete writer-inventory
   SHA-256, action profile/resource/incarnation/manifest/effect and validity window.
   The allowed profiles remain the single or pair Terraform gateway at Level C.
   Resource IDs must bind the selected manifest. Changed source, package,
   configuration, inventory, target incarnation or plan requires a new digest
   and matching owner records. The checker does not inspect the live host or
   discover drift itself: the pipeline must independently obtain current
   installed digests before selecting the expected deployment digest. Hash the
   actual protected configuration through
   its approved administrative process; do not copy secret configuration here.
2. An independently approved trust file and its externally pinned SHA-256. It
   binds the exact deployment digest, validity window, seven owner principals,
   roles, key IDs, canonical base64url Ed25519 public keys, administration domains,
   per-owner validity and minimum sequence floors. Principals/key IDs/public keys
   must be distinct. Deployment, storage, audit and independent-reproducer
   administration domains must be distinct. Actual independence and complete
   writer coverage remain independently checked deployment facts.
3. `evidence.json`: a current `deployed` observation for each gate, containing
   every required check and the digest of its retained artifact. All checks must
   be `pass`. Missing, failed, unknown, future, expired or local-fixture evidence
   blocks verification, even with a valid owner signature.
4. `approvals.json`: one valid acceptance for each gate, signed by its registered
   owner over the exact observation and deployment digest. Explicit rejection,
   wrong owner/role/key, expired acceptance or a sequence below the externally
   pinned floor blocks verification. Revocation/withdrawal requires publishing
   current approved trust/key/floor references to the deployment pipeline. An
   offline checker cannot discover a newer trust snapshot or enforce withdrawal
   if an operator deliberately supplies an older still-valid pin.
5. `artifacts/<sha256>`: the writer inventory plus every referenced evidence
   artifact. Digests are checked on bounded regular-file reads. Symlink parents,
   symlink/hardlinked leaf files and special files refuse. Records are at most
   1 MiB, individual artifacts at most 4 MiB, aggregate loaded evidence at most
   64 MiB. The caller must retain a trusted clock and approved filesystem custody.

| Gate | Required owner | Required checks |
| --- | --- | --- |
| identity_credentials | identity_security | Subject/workload binding; rotation/withdrawal; original-claim-bound broker |
| service_custody | deployment | Installed source/bundle/configuration; separate UIDs; file/socket/egress protection; upgrade preserves consumed history |
| writer_coverage | resource | All writer/admin/break-glass paths; agent/descendant bypass refusals; exact trusted runner/provider boundary |
| storage_restore | storage | Native least privilege; independent witness/head/floor; physical/stale restore refusal; original consumed attempt retained |
| audit_retention | audit | Independent collector; target-effect correlation; retained trace reconstruction |
| operations_recovery | sre | Capacity/latency budgets; refusal/unresolved-age alerts; query-only recovery; incident/abort/on-call rehearsal |
| release_reproduction | independent_reproducer | Source/release pins; dependency/security/license review; supported platform/upgrade policy; independent reproduction |

The [draft schema](../spec/drafts/terraform-deployment-acceptance-v0.1.schema.json)
fixes closed record shapes. The checker additionally enforces cryptographic,
current-time, exact scope, sequence, check coverage and administration constraints.
Its fixed gate/check IDs are in
[the record module](../scripts/terraform-acceptance-records.mjs).

## Prepare, review and verify

After the deployment owner supplies the exact `deployment.json`, prepare a new
reviewable directory. Existing output directories are refused:

```sh
node scripts/prepare-terraform-acceptance.mjs \
  --deployment /approved/public/deployment.json --output /approved/acceptance-request
```

This creates a pending request, `deployment.json`, `evidence.json`, empty
`approvals.json` and a private `artifacts` directory. It generates no keys,
observations, passing checks or approvals. Pending requests deliberately fail
accepted-record schema/semantic validation. Obtain actual deployed observations,
retained artifacts and separately authorized owner records through the approved
administrative process. No signing key belongs in an agent tool or this package.

Owners sign the exact UTF-8 bytes:

```text
KedgeFlow/KF-TERRAFORM-DEPLOYMENT-ACCEPTANCE-0.1-draft/owner<NUL>
```

followed immediately by the existing canonical JSON serialization of the entire
approval object with only `signature` omitted; there is no newline. The approval
includes profile, owner ID/role/key ID and a closed payload binding deployment,
gate, canonical observation SHA-256, decision, issuance/expiry and sequence.
The raw 64-byte Ed25519 signature uses canonical unpadded base64url encoding.
This domain is separate from all runtime signed records and grants.

The deployment digest is SHA-256 of the UTF-8 prefix
`KedgeFlow/KF-TERRAFORM-DEPLOYMENT-ACCEPTANCE-0.1-draft/deployment<NUL>` followed
immediately by canonical `deployment.json`. Observation hashes are SHA-256 of
canonical observation JSON; artifact and trust-file hashes cover exact bytes.

Pin both expected digests from the approved external review, then run:

```sh
node scripts/verify-terraform-acceptance.mjs \
  --directory /approved/acceptance-request \
  --trust /approved/owner-trust.json \
  --trust-sha256 EXPECTED_TRUST_SHA256 \
  --deployment-digest EXPECTED_DEPLOYMENT_DIGEST
```

Use canonical filesystem paths without symlink ancestors. The CLI uses the
current clock, has no backdating option, emits a bounded JSON report and exits
nonzero on missing/invalid inputs or any unmet gate. `gaps` identifies the
blocked gate and reason without echoing file contents or credential values.
The operator must require the check's successful exit in its deployment process;
ignoring that exit does not install an enforcement boundary.

## Qualification and present status

[The verification record](../results/verification/terraform-acceptance-2026-11-12/README.md)
retains synthetic positive and adversarial signature/record/CLI tests. They
qualify parser and checker behavior, including explicit refusal of local-fixture
records. They are not deployed observations or owner acceptance. The prior
[Linux record](../results/verification/terraform-systemd-2026-11-12/README.md)
remains immutable and retains its actual cgroup, custody and target evidence.

No approved production deployment, external owner trust or owner acceptance
records are present in this repository. The next real execution needs those
non-secret references and retained observations. Keep that missing-input state
open; neither a new fixture nor the checker can manufacture independent approval.
