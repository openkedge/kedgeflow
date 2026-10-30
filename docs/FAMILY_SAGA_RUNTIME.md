# Native family saga runtime

M8d3f implements the explicitly selected `KF-FAMILY-SAGA-0.1-draft` profile.
The [22 October qualification](../results/verification/rfc-m8-family-saga-native-2026-10-22/README.md) retains the frozen source,
required runtime logs and serialized public execution aggregates. This is bounded
local software qualification; M8 remains open. The earlier
[proposal qualification](../results/verification/rfc-m8-family-saga-draft-2026-10-18/README.md)
describes the previously disabled implementation.

The local qualification scope is two separately cataloged real SQL resources,
their actual native forwards and reverse original inverses, complete aggregate
replay, and the official Node SDK inverse runner across both contracts. It
includes a lost real SQL commit reply followed by original-attempt recovery and
a new Node process with status-only credentials after root stop and grant expiry.
The SDK fixture uses native host owner transitions and native host forwards; it
does not qualify SDK forward execution or shipping owner CLI phase submission.

## Protected enrollment and capture

`family_saga_config::Config` fixes one `family::Config`, an exact member-to-observer
map, a separate collector and a separate family allocation observer. Each observer
entry contains its pinned `id`, `key_id` and `signing_key_file`; member entries
contain `forward` and nullable `compound` entries. Public native trust, operation
keys, resource scopes, inverse contracts and dependency edges come exclusively
from the protected registration. Commands contain none of those credentials.
File custody and deployment administration remain explicit external assumptions.

Enroll only a fresh empty namespace. One CAS installs family allocation genesis,
all paired native topologies, phase genesis and native write epoch. Attach every
cataloged child and enroll every native budget, control and inverse qualifier.
The initial separately sealed complete `observe` capture is mandatory before
any native forward admission, including a child with no predecessors.

Every mutating native transaction, including shared authentication replay,
control and outcome retention, compares and advances a sequence plus random
nonce epoch. Reads compare an existing valid epoch without advancing it. Missing
or corrupt state refuses; there is no adoption or repair through collection.
Capture reads the epoch before all member exports and compares it, the phase and
the immutable enrollment markers after collection. The collector signs only a
complete inventory that survived those comparisons.

The native inverse qualifier has a real zero-record genesis. A claimed forward
can therefore have complete original forward evidence before any inverse proof
is available. The collector retains that verified empty qualification inventory
and positive inverse authority/spend/seal absence, encoded as
`qualification_absent: true`. It neither invents a qualification nor turns a
missing original outcome into a no-effect result. Once qualified, complete
compound history must remain present in every successor.

## Phases and original authority

The permanent phases are `forward`, `quiescing` and `compensating`. Forward
dependencies require globally observed original committed predecessors. Quiesce
closes new forward authority. Preparation requires complete known forward
inventory and fresh original inverse applicability/barrier proofs for every
committed reversible child. The proof, global phase and all relevant local
compensation-mode writes share one CAS. A committed irreversible child blocks
compensation.

Each native admission, issuance, claim and dispatch retains a supplemental global
authority binding in its original CAS. It identifies the exact family and phase
heads, child, lane and qualification. Non-observation owner transitions also
retain the exact live root family head checked by their original CAS. Offline
verification replays these heads, rather than checking whether a later state
could have permitted the operation.

An original native inverse claim reserves the sole global in-flight slot in the
same CAS as the native claimed event and held spend. Its issuer-signed binding,
grant digest, attempt and native claim timestamp are retained. Descendant
inverses must commit before an ancestor inverse can start. Only complete original
terminal evidence clears the slot. A complete original signed failure receipt yields `failed` in the saga summary
while native dispatched spend remains `unknown` and consumed. Its receipt digest
is retained; this does not claim proven no effect. Observing that terminal failure
clears only its global flight slot, and still blocks ancestor compensation.
An unknown or failed inverse holds capacity;
there is no replacement attempt, retry refund or implicit rollback.

Phase history is bounded to 96 events and 256 KiB; each capture is at most
512 KiB plus its seal, retained proofs total at most 16 MiB, and aggregate carriage
at most 18 MiB. Actual new-profile ledger transactions are bounded to 127
comparisons before the final restore-marker comparison and 1 MiB before the
restore wrapper. Event/state and proof storage reserve future closure captures.
Semantic no-op polling cannot consume phase history. Bound refusals retain held
authority and do not assert that an effect is absent.

## Durable local commands

The shipping binary offers `check`, `enroll`, `status`, `collect`, `stage`, `apply`,
`lookup`, `export` and offline `verify`. For example, after protected enrollment:

```sh
kf-family-saga --config /protected/family-saga.json stage \
  --action observe --operation-key "$OPERATION_KEY" \
  --owner-key-id owner --owner-key /protected/owner.key \
  --out /protected/operations/original.json
kf-family-saga --config /protected/family-saga.json apply \
  --prepared /protected/operations/original.json
```

The operation key is a permanent lowercase 64-character hexadecimal identity.
Staging exclusively creates and syncs the signed intent/capture file and its
parent directory before submission. An existing, partial or conflicting file
refuses restaging. It never overwrites, recollects or extends the original intent.
An uncommitted intent expires within 60 seconds and within the root window for
authority-changing transitions. After a lost reply, query the saved original:

```sh
kf-family-saga --config /protected/family-saga.json lookup \
  --prepared /protected/operations/original.json
```

Explicit `apply` replays identical saved bytes. Exact retained operation replay
and lookup remain available after expiry or stop. Absence is not permission to
invent a replacement operation. Historical `observe` can record original facts
after the execution window has closed.

The Node `LocalSagaClient` invokes the fixed binary/config with argument arrays.
`FamilySagaRunner` takes the protected registration, exact native `AgentAdapter`
instances, permanent qids/arguments, a durable `FileOperationStore` and an operation
directory. It checks fixed operation/action/audience bindings and persists
ambiguity before the first native admission request. Restart queries the same
original native operation. Owner submission saves a local prepared file first;
ambiguous replies query that file, and only explicit `replayOwner` resubmits it.
The runner never selects another qid or signs another intent automatically.

Use the local capture/sign/apply sequence without intervening authenticated native
requests. Shared DPoP replay retention is itself a native write and invalidates an
older capture epoch. A future network phase interface needs an explicit protocol
for that boundary; authentication writes are not exempted here.

## Complete historical verification

`export` includes the separate family allocation checkpoint, complete phase
history, exactly every referenced sealed capture and one current complete capture.
The aggregate collector signs the whole evidence digest. The offline verifier
takes public pins separately and needs no private config or live etcd connection:

```sh
kf-family-saga verify --bundle aggregate.json --trust public-saga-trust.json
```

`public-saga-trust.json` contains only `{"registration": ...}`. Verification checks
native signatures and histories, exact members and original operations, proof
continuity, phase/family head replay, original inverse claim ownership and held
costs. It reports unresolved, blocked, partial, failed or completed compensation
and whether a fresh observation is required. `execution_authority` remains false.
Observer correctness, protected storage/consensus, clocks and actual target
assertions are declared trust boundaries; a checkpoint is not a Byzantine ledger
proof, a new grant or independent deployed acceptance.

Historical caches include every immutable public catalog byte and pin, and every
stored phase/proof byte used for the cached replay. Positive catalog validation
is bounded to 32 entries and 16 MiB of serialized cache weight; changed catalogs revalidate. Current root,
phase, write epoch, qualification head and clocks remain live CAS inputs. No
negative observation or authority decision is cached.

Native original qualification replay also keys every contract, public historical
trust field and actual stored qualification byte. A historical verification at
`validated_at` proves the signed lower bounds and the upper `valid_until` bound.
Live use still checks the current clock inside that interval before and after
reading and pinning every native proof value. The original proof deadline is
neither renewed nor replaced. Canonical encoding memoization uses complete typed
input bytes as its private key; published canonical bytes and digest domains are
unchanged.

Expected native proof comparisons are keyed by the complete namespace, contract,
public trust and original proof. Every reuse checks the entire comparison set
against current etcd in a guarded read-only CAS; the same set is included again
in the final authority CAS. Missing or changed original bytes refuse. This
retains current proof validation while avoiding repeated downloads of unchanged
history. An issuer request can also carry that original read set through lookup,
fence allocation, signing and issuance. It stays private to that request, binds
the execution context, retains fresh clock checks and cannot escape in a returned
grant. Independent broker and gateway boundaries revalidate their own state.

The required conformance runner first inventories every Rust case and target,
then executes the existing runtime and family-saga cases in separate required
PostgreSQL/etcd batches. Their combined case inventory must match the manifest
exactly once, including target identity; zero-test binaries must also execute.
Each batch keeps its existing 1,200-second harness limit, and neither changes
production authority, credential, dispatch or client transport deadlines.

The local race scope pauses final capture and forward authority transactions;
real native writes, permanent quiesce or root stop must defeat their final CAS.
The local checks also race original inverse issuance against a new qualification,
retain one unknown claim slot under competing claims, reject deleted original
history after cache warming, and refuse fresh admission exactly at proof expiry.
An actual SQL guard failure preserves the other writer and blocks the ancestor;
its original negative adapter reply is retained. A negative query alone remains
unknown. Required public artifacts cover completed, unknown and failed states,
with separate-process shipping CLI replay of their serialized bytes.

Wider crash/failure combinations and shipping owner-command deployment remain
unqualified. A separate
Level C drain implementation and real Kubernetes qualification are still required.
Physical restore/cutover, deployed writer coverage and independent acceptance
cannot be inferred from local software tests.

## Current M8 exit

The [M8 completion checklist](M8_ACCEPTANCE.md) and its final frozen record
supersede the earlier increment notes about Level C and shipping owner commands.
The managed all-service unknown case exercises actual shipping owner CLI staging,
quiesce, lookup and exact original replay, then refuses preparation of an inverse
for unresolved physical work. It uses generated same-host collector credentials
and a separate owner signer; independent owner-command deployment acceptance
remains open. The SQL SDK fixture above still qualifies its stated inverse flow,
not SDK forward execution under every catalog/provider combination.
