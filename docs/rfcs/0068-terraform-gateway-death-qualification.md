# RFC 0068: Whole gateway death with active Terraform children

Status: draft; N2h local failure qualification, no runtime or wire change.

A gateway killed with SIGKILL cannot run the shared subprocess group's Drop
handler. Qualify the actual active-child lifetime boundary separately from N2g's
provider/Terraform death and cancellable futures. The fixture must observe both
live descendants after a reaped gateway signal-9 exit while the original
provider request is held. It must retain the original started intent and
`dispatch_authorized` native phase with zero terminal outcome publications.

An explicit fixture-owned orphan-group cleanup/drop case and an original request
forwarded after gateway death and grant expiry check independent real target
behavior. Fixture cleanup cannot be credited to production containment. Target
coincidence and backend progress cannot promote history or release the original
allowance. Cold shipping gateway/official SDK recovery queries the same consumed
authority after expiry/revocation, broker shutdown and writer removal.

The test gate, identity/evidence roles and audit policy share fixture
administration. This is local software evidence, not independent attestation,
Linux cgroup/service containment or a target-side no-effect barrier. Production
custody and independently accepted deployment gates remain open. See the
[qualification guide](../TERRAFORM_GATEWAY_DEATH_QUALIFICATION.md).
