# M8 completion and acceptance

M8 implements bounded shared reservations, narrowed family/A2A coordination,
multi-contract SQL sagas and the separately enrolled Level C managed drain.
The [software completion record](../results/verification/rfc-m8-software-completion-2026-10-29/README.md)
is authoritative only when its frozen-source summary reports
`passed_software_checks`. Independent deployment acceptance remains open.

## Software exit checks

The required conformance runner discovers every Rust and Kubernetes case, refuses
skips and source changes, and replays the exported aggregates with separate CLI
processes. These checks close the bounded implementation; they do not create an
open-ended requirement for additional frameworks or optional protocol profiles.

| Requirement | Required evidence |
| --- | --- |
| Last-slot competition, deduplication and held unknown costs | Native reserved-leaf and family tests; complete reserved/family histories |
| Narrowed delegation and task correlation without execution authority | Hierarchical history and official A2A SDK/native task exchange |
| Global saga phases, original inverse flight slot and ancestor blocking | Two actual SQL contracts, reverse original inverses, competing claims, failed inverse, fresh-expiry/deleted-history and final-capture races |
| Stable commands and query-only crash recovery | Shipping owner CLI stages/quiesces/looks up/replays the exact saved command and refuses inverse preparation for unknown physical work; shipping target kills before/after COMMIT; official SDK lost-reply/root-stop recovery |
| Positive physical completion/no-effect/absence | Actual Kubernetes cordon/eviction/PDB cases, protected closure commands and separate complete physical/operating audit |
| Managed Pending/Send versus root stop and deadline | Four `kube_drain_real_managed_race_*` cases release the exact held request to real etcd, require false CAS, zero physical mutations and unchanged mechanical state |
| Unknown at deadline retains both allowances | Shipping control/broker/gateway, controller/source/supervisor/recovery and official SDK; lost original signed HTTP reply, original restart, durable incident and ACK, unresolved audit with forward 2 / compensation 1 held |
| Bounded complete-proof reads | `kube_drain_real_managed_proof_fault_*`: one actual epoch race recaptures; two stop after one recapture; corrupt signed source refuses without recapture; original target acceptance and broker exchange occur once |
| No omitted or substituted proof bodies | Acceptance verifier/CLI rejects missing claims/control/authorization, changed admission, context, profile and unknown fields |
| Bounded native storage and source use | Actual four-claim crash/restart/last-slot exhaustion; 513 native material entries refuse; native oversized response hits the existing 4 MiB wire cap; exact 512 and 32 MiB wrapper accounting remain quota-only unit vectors |
| Reproducible combined O4 | Exact pre-run source archive; unchanged complete corpus; actual per-case Kubernetes/RBAC records; standalone acceptance and physical/operating replay; prior evidence unchanged |

The storage negatives deliberately inject invalid data into an owned fixture
after saving a valid aggregate. They establish refusal and unchanged operating
head, not positive evidence at the maximum storage size. The existing 512 KiB
capture, 32 MiB journal, original 5s grant/source/transport, 10s ACK, 1s final-send
and family/inverse windows stay unchanged. Native response limits can refuse
before the journal quota is reached. Read recapture never repeats admission,
issuance, token exchange, acceptance or physical mutation.

## Independent acceptance still required

| Gate | Required owner-supplied acceptance |
| --- | --- |
| Protected deployment | Separate OS/service identities, native ACLs and endpoint/credential custody; rotation/revocation and bypass tests |
| Writer/storage boundary | Declared SQL/Kubernetes writers, independently held storage head/floor and restore authority, real physical restore/cutover and retention/budget acceptance |
| Physical operations | Resource owner/on-call and incident routing, production maintenance and host/node/storage failure rehearsal, accepted workload availability/SLO |
| Protocol/release independence | Independent authority peer and whole-saga observer acceptance; protocol/release-owner review and reproduced evidence |

Generated identities, a local VM and another process using this implementation
cannot sign those independent acceptances. M8 release acceptance stays open until
those records exist. The repository must not mark them passed from local tests.

The bounded catalog does not enable arbitrary dynamic workflows, cross-cluster
atomic reservations, a protected physical review ceremony, frozen HitlWitness
carriage, or unqualified physical human-review/static-lease combinations. Those
remain explicit unsupported profiles or separate enrollment/qualification work;
they are not implicitly enabled by software completion.

Independent dispatch preparation reads run concurrently, with their entire fresh
comparison sets retained in the original single final CAS. The current original
recovery snapshot and predecessor issuance are also read concurrently. This
removes sequential latency without caching live authority or extending credential
validity; the gateway still refuses expired grants/tokens before dispatch.
The acceptance proof reads its original authorization and complete control
sources concurrently, verifies their correlation, and compares every captured
value in the final native transaction. Original-packet snapshot reads use the
existing bounded read-only epoch recapture; malformed replies never recapture.

Managed SDK acceptance cases pause the controller before the first advance-query
CAS, so the initial proof read is isolated from mutation-worker epoch changes. The held query
is never committed or counted as consumed; separate Pending/Send cases qualify
the consequential race boundaries. Every injected epoch change is an actual
native CAS, and original signed target acceptance is retained separately.
Status queries use the same bounded read-only epoch recapture. Their final
snapshot rereads and matches the original root/grant/nonce alongside the original
attempt/outbox; recapture cannot select a replacement identity or report an
absent original as completed.
New owner transitions are staged and applied while the family is live. The
original quiesce command is then looked up and replayed, without resigning or
changing bytes, after permanent root stop. Stop does not authorize a new owner
transition or a replacement inverse.
