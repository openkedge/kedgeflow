# RFC 0036: Historical lease and membership verification

- Status: Draft
- Profiles: KF-ADMISSION-LINEAGE-0.2-draft, KF-CONTROL-HISTORY-0.2-draft,
  KF-CONTROL-BINDINGS-0.2-draft
- Milestone: M7d1 historical audit integration
- Baseline: e7188e4; RFCs 0012–0014, 0035
- Owners/reviewers: unassigned

## Retention and compatibility

Retain an immutable membership/cache snapshot with the certificate and with the
issued grant in their respective authority transactions. The same exact-value
comparisons that authorize each write cover the snapshot. Record phase, authority
digest and check time. Retain membership even for full-evidence admission without
a lease when lease registration is configured. Do not add lease checks to grant
claim/dispatch: withdrawal blocks new admission/issuance, not existing grants.

Export the two original snapshots, never current membership or a reconstructed
cache. Require both snapshots for a lease-enabled operation. Historical records
created before this retention increment cannot be upgraded by synthesis.

New closed v0.2 schemas carry these records and optional leased packets. v0.1
schemas remain unchanged and reject v0.2 records. Legacy operations retain v0.1
serialization and signature domains. History and control-binding wrappers must
match their nested version and checkpoint version. Each checkpoint uses its own
profile as the signature domain, preventing a signed wrapper from being relabeled.

## Independent verification

Approve historical admission, lease, policy, provider and observer pins outside
the bundle. Reverify the retained static-only packet at the signed lease issue
time. Recompute its verified-input binding, complete membership registration
binding, signer/member cache identity and signed lid. Check original canonical
signed static records against the final packet and signed discharges. Reverify the full static
and JIT input chain and Cedar policy at admission and issuance, including signed
lease, certificate and grant links and all original freshness bounds.

Require exactly one admission and one issuance snapshot, linked to the correct
signed authority digest. Membership must be active, in a valid generation and
match the approved registration. Cache membership and signed lease must match the
phase snapshot. Check time must fall within the signed authority's lifetime; it
can follow the signed creation time because preparation precedes the transaction.
For a leased operation both phases necessarily use the generation sealed by lid.

Unsigned lineage records alone do not prove that a membership comparison occurred
in consensus. A separately approved history observer attests the complete nested
lineage; operation-bound control exports retain their existing per-phase installed
control checks. Observer custody, honest ledger operation and clock trust remain
explicit assumptions. This profile does not supply membership lifecycle history,
original authentication transcripts, review-enrollment history, hardware ceremony
or independent enterprise acceptance. Static inputs and current review facts are
still verified live by the service; historical review consumption remains a gap.

## Qualification

Exercise real-etcd prevalidation/admission/issuance and retained outcomes, audit
before and after withdrawal, independent static/JIT and generation recomputation,
missing/replaced snapshots, altered static packets, signer/phase/time substitutions,
version downgrade/cross-version wrappers, independently signed observer checkpoints
and unchanged legacy verification. Qualify shipping offline verifier execution.

Next software increment is Node Agent Adapter static cache and fresh JIT acquisition.
M7 physical ceremony and accepted enterprise custody/provider lifecycle remain open.
