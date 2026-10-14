# M8b1 native reserved leaf — 14 October 2026

Baseline: 1a3f42a. [RFC 0038](../../../docs/rfcs/0038-native-reserved-leaf.md)
and the [operator guide](../../../docs/NATIVE_RESERVED_LEAF.md) add the opt-in
KF-RESERVED-LEAF-0.1-draft profile without changing frozen grant/HTTP records.

The required complete run passed **320 Rust tests across 45 binaries**, **18 SQL
storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. There were no
Rust failures, ignored tests or required-mode skips. All **420 source files**
remained unchanged throughout the full run and match final-source.json.
summary.json pins sources, commands, logs and tool versions: Darwin ARM64,
Rust 1.98.0, PostgreSQL 18.3, etcd 3.6.5, Python 3.13.12, Node 25.2.1 and pinned
official MCP client 2.3.0. Prior evidence and frozen artifacts are unchanged.

## New observations

Fifteen new test groups qualify:

- Independently approved create-only budget registration under managed control;
  native producer retries/recreation reuse one allocation, signed binding, grant
  and fence. Another budget root cannot capture the same tenant/domain.
- Eight native proposals compete for one forward and compensation slot. Exactly
  one issues. Eight claims likewise consume only one original attempt, holding
  the allocation unknown with that attempt.
- Allocation shares the fence CAS; binding indexes/seals share grant issuance;
  unknown consumption shares nonce/root/attempt/context CAS. Test-owned transaction
  barriers race permanent stop at fencing, issuance, claim and dispatch. Each
  raced authority mutation refuses; retained allocations remain allocated/unknown
  as appropriate, and stopped roots do not reopen.
- Sealed allocations cannot become composite parents or be consumed/refined via
  the state-only coordination ports. Omitted native configuration, changed
  registration pins/incarnation/grant/attempt, raw issuance/replacement, missing
  or corrupt index/seal records and repeated enrollment refuse without consuming
  an allocation.
- Offline closed-carriage/signature/context substitution checks include correctly
  signed wrong-context bindings. The shipping verifier reports a historical issuer
  statement with execution authority and live-budget verification explicitly false.
  Existing reserved lineage export refuses pending versioned budget carriage.
- Shipping control CLI local check, create-only enrollment, permanent stop and
  changed-pin refusal run with protected generated files and actual TLS forwarding
  to etcd. Check alone creates no authority state.
- Three official SDK/native mTLS/DPoP/managed-control/etcd workflows qualify normal
  execution, lost execution reply and lost issuer reply. Separate Node processes
  resolve the original committed or unclaimed operation after expiry/stop without
  another claim, broker exchange, target call or witness collection. Both reserved
  budgets remain held; committed effects retain unknown budget classification.

## Limits and next milestone

M8b1 is fixed-cost, root-level, single-resource native leaf integration. The
provider, broker, guarded effect, keys and clocks in its SDK cases are software
fixtures. The existing full SQL corpus passes, but these new reservation cases do
not qualify a reserved SQL deployment or actual Kubernetes drain.

Budget state stays allocated/unknown after failures and unknown after known native
outcomes. There is no timer refund, replacement, compensation grant or implicit
migration. A stop cannot undo a previously authorized external send. Independent
binding verification does not prove current capacity, consensus or actual effects.

Next software work is M8b2 versioned reserved history and native original-attempt
known-outcome refinement while retaining allowances. Hierarchical grants, A2A,
durable saga/compensation, physical/hardware failures, accepted writer/predicate
coverage, all-service custody and enterprise/independent release gates remain open.
Linux separate-account and minimum Rust CI execution were not observed locally.
