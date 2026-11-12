# Active Terraform/provider lifecycle qualification (N2g)

The shared protected subprocess runner stops remaining process-group members as
soon as Terraform exits, before draining inherited output pipes. A failed
Terraform process can otherwise leave an active provider holding those pipes
open until the tool deadline. The existing timeout/cancellation cleanup remains
in force. This affects both single-resource and pair runners without changing
accepted request, grant, capability or result schemas.

The test-only `terraform_active_gate.py` fixture forwards a pinned loopback
Kubernetes API for the existing single-resource action. Planning and read-only
observation use the same real API; only the one owned ConfigMap mutation is
held. The protected plan pins the gate's endpoint and CA. It never selects a
production endpoint, acquires ambient credentials or creates apply authority.

At the held real mutation, the fixture observes the actual gateway → Terraform
→ Kubernetes provider parent chain and common process group. It verifies the
original started intent, current grant validity and unchanged target/backend.
It then exercises:

| Intervention | Required retained behavior |
| --- | --- |
| SIGKILL sent to the live provider | Terraform fails, original intent/ordinary status stay unknown, no local group remains |
| SIGKILL sent to live Terraform while provider holds a request/output pipes | Provider group stops promptly; no wait until the 20-second pipe deadline; original unknown remains held |
| Original dispatch expires while both children are active | Cancellation stops the local group; ordinary unknown and started native intent remain unresolved |

The last case deliberately forwards the **already captured original request**
only after local process cleanup and ordinary unknown publication. The real
Kubernetes API can still commit that in-flight request. Separate target reads
and metadata audit records check the resulting desired annotation while the
local Terraform backend remains original. No new Terraform invocation, claim,
broker permit or dispatch is issued.

This is why local process disappearance and backend nonprogress are not an
authoritative no-effect barrier. The original allowance stays held. Cold SDK
recovery after expiry/revocation, broker shutdown and writer removal reports
original unknown, even if the target now matches the desired state. Native
history, counters, backend and target-write audit events must remain unchanged.

This is bounded local software qualification. Unix process groups do not
contain a compromised provider that escapes its group, and killing a gateway
with SIGKILL does not execute its Rust cleanup handlers. Whole-service abrupt
death, Linux cgroup/service isolation, production credential custody and a
qualified target-side late-effect barrier remain separate gates. There is no
automatic retry, release, refund, compensation or outcome repair. Level C and
the complete N2 deployment limits remain unchanged.
