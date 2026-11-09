# Terraform local-backend qualification (N2e)

This extends the protected [apply runner](TERRAFORM_APPLY.md) and
[gateway/SDK](TERRAFORM_GATEWAY.md) with controlled backend contention and drift.
[RFC 0063](rfcs/0063-terraform-backend-qualification.md) defines the scope. The
[verification record](../results/verification/terraform-backend-2026-11-09/README.md)
retains fresh execution evidence and compatibility results.

| Intervention | Refusal boundary | Intent | Ordinary native state |
| --- | --- | --- | --- |
| Exclusive OS lock on the actual local state file, acquired after durable intent | Terraform's existing state-lock acquisition | unknown | unknown |
| Live backend serial changed after dispatch, before the runner checks it | Runner's original-state hash comparison | absent | unknown |
| Live backend serial changed after durable intent | Terraform's saved-plan serial check | unknown | unknown |
| Live backend lineage changed after durable intent | Terraform's saved-plan lineage check | unknown | unknown |

Every case uses a fresh real saved plan and current native admission, issuance,
claim, broker permit and dispatch through the shipping gateway and official SDK.
The existing authenticated test relay holds a declared native reply. Independent
target/backend reads and original grant validity checks precede intervention.
The target must retain the exact original ConfigMap, including UID and
resourceVersion. The immutable plan capsule is unchanged.

The lock fixture holds an exclusive lock on the actual backend inode, verifies
that a second file descriptor cannot acquire it, and retains it until the native
refusal is observed. It verifies that the lock becomes available after release.
The drift fixtures edit only serial or lineage in the live local state file;
they certify the changed bytes and unchanged resource contents. These controlled
metadata changes do not stand in for a second successful Terraform apply.
The evidence verifier independently reconstructs their exact injected bytes
from the archived original state and checks the actual post-refusal hash.
Run it with:

```sh
python3 scripts/verify-terraform-backend.py results/verification/terraform-backend-2026-11-09
```

This read-only fixture replay checks consistency; it does not authenticate an
independent observer or grant execution authority.
All cases require the original grant to remain valid through refusal, so an
unrelated expiry cannot account for the result.

The runner retains one of three fixed diagnostic strings for recognized apply
failures. Unrecognized or ambiguous stderr yields a generic execution refusal.
Inspection diagnostics remain unchanged, and no raw Terraform/provider stderr,
credential, path or state value enters the retained diagnostic. These strings
are observations, not no-effect proofs or authority to retry. Successful exit,
backend progress and the separate target postcondition remain required for a
committed result.

After refusal, the gateway and SDK restart after original grant expiry and
domain revocation, with broker stopped and writer credential absent. Repeated
SDK execution must query the original attempt only. Intent, backend bytes and
all native execution/outcome counters remain unchanged, including after the
lock is released. There is no forced unlock, lock disabling, replan, reapply or
automatic authority release.

The existing one-second Terraform lock timeout and twenty-second subprocess
bound are unchanged. Terraform retains its native locking and saved-plan
semantics. Its [local backend](https://developer.hashicorp.com/terraform/language/backend/local)
uses OS locking, and its [state-locking documentation](https://developer.hashicorp.com/terraform/language/state/locking)
describes refusal when a lock cannot be acquired. The live pinned-tool results,
rather than documentation alone, establish the measured cases here.

This is a same-host Darwin ARM64 fixture with generated identity/evidence/policy
roles. The adapter remains Level C. Linux service custody, active-child
termination, arbitrary post-check target/dependency changes, multi-resource
partial apply, HCP/remote backends, automatic unknown/publication repair and
independent production acceptance remain open. N2 is not complete.
