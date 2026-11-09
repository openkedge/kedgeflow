# Controlled target changes through the fresh SQL execution path

This is the first N1 increment from the
[2 November plan](IMPLEMENTATION_UPDATE_2026_11_02.md). It extends the existing
[SQL failure fixture](SQL_FAILURE_QUALIFICATION.md) with six controlled target
cases. It changes qualification code and the SDK test driver; it introduces no
production fault endpoint, wire profile or broader target guard.

Each case obtains fresh signed admission and issuance through the official SDK,
then uses shipping gateway, broker and PostgreSQL target binaries. A protected
fixture writer locks the exact target row before execution. The test waits until
PostgreSQL reports the executor blocked by that writer's actual backend PID,
after the original claim, credential permit and dispatch authorization.
It does not infer the boundary from a timer or a tool-call log.

The writer changes the row inside its held transaction, checks that the change
is present there while a separate connection still sees the original baseline,
then commits and releases the target. A separate SQL connection observes the
resulting resource and the independently authenticated query role retrieves the
original retained target outcome.

| Case | Expected target result | Retained authority state |
| --- | --- | --- |
| No target change; same lock/release mechanism | Exactly one 241-to-242 mutation | committed |
| Version and reservation change before the target acquires its lock | Original mutation rejected; external change preserved | state_guard_violation |
| Incarnation changes with version still 241 | Original mutation rejected; replacement incarnation preserved | state_guard_violation |
| Fence advances with version still 241 | Original mutation rejected; advanced fence preserved | state_guard_violation |
| Resource becomes inactive with version still 241 | Original mutation rejected; inactive state preserved | state_guard_violation |
| Version changes and the successful guard-rejection response is discarded | Original mutation rejected; query recovers the same target record | unknown |

Every case restarts both gateway and target, waits for the original execution
grant to expire, runs the shipping recovery worker twice, and resumes the same
persisted operation in a new Node process with status-only delegation. The signed
receipt remains stable and consumed authority refuses replacement. Claim,
credential permit, broker forwarding and target dispatch counters stay at one;
resource state and original target outcome stay unchanged during recovery.

The lost-rejection case deliberately remains **unknown** at the authority layer.
RFC 0010 accepts a correlated target `fenced_no_effect` observation as evidence
but does not implement a target-specific terminal no-effect barrier. This
increment preserves that limit: no refund, reissuance, remint or redispatch is
inferred from the query. The separate target observation demonstrates rejection
in this fixture; it does not silently broaden recovery semantics.

## Oracle and retained evidence

The oracle checks the actual resource tuple (incarnation, version, fence,
reservation and active state), original request and target outcome. Every case
also verifies that the oracle rejects a corrupted terminal status and an
unauthorized reservation value. The unchanged control case demonstrates that the
same scheduling mechanism still permits a valid mutation.

Structured `SQL environment PASS` records retain injection and observation
tuples, attempt/grant correlation, target outcome, claim/permit/dispatch counts,
committed-effect count, unresolved classification and oracle checks. Only fixture
identities and nonsensitive target records are logged; no tokens or private keys
are included. See the [source-pinned verification record](../results/verification/sql-environment-2026-11-02/README.md)
for executed commands, exact results and source hashes.

## Reproduce

Use Rust with the locked dependencies, Python 3.11+, Node with the pinned SDK,
PostgreSQL 18.3 and etcd 3.6.5. Select writable Cargo cache/target directories if
needed. The PostgreSQL launcher creates a new temporary Unix-socket-only cluster;
the etcd launcher creates three temporary loopback members. Each composed case
also owns a separate temporary witness process. The launchers clean up their
owned services and require configured dependencies rather than accepting skips.

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 \
  python3 scripts/test-postgres.py --bindir /path/to/postgresql-18.3/bin --peer \
  --command scripts/start-etcd.sh -- \
  cargo test --locked --offline --test governance sql_failure::environment \
    -- --nocapture --test-threads=1
```

Run the `sql_failure` filter instead to include the eleven existing process,
restore, witness and recovery cases that share the harness. The PostgreSQL CI
job already selects the complete governance test target, including these cases.
CI configuration is distinct from an observed remote CI run.

## Remaining scope

These cases cover the registered one-row action and its existing atomic SQL
predicates, on one host with generated identity/evidence and test-owned mTLS
relays. PostgreSQL peer maps share a fixture OS UID; they do not establish
production account isolation, independent administration or writer coverage.
The external writer is intentionally privileged fixture administration.

Incarnation/fence/active changes with an unchanged version are target-state
tests, not proof of dependency-wide atomicity. Dependency-only changes, new
policy/delegation/suspension matrix coverage, compromised-tool deployment probes,
full Linux renewal/PKI/storage qualification and the Terraform integration
remain subsequent N1/N2 work. Existing tests for related behavior retain their
original source/scope; this increment does not reclassify them as new results.
