//! Durable managed-operation transitions. Pure replay is checked before native
//! expected-head CAS; callers cannot turn an unavailable source into no effect.
use crate::{
    contracts::{MAX_SAFE_INTEGER, canonical, digest},
    error::{Error, Result},
    managed_drain::{Enrollment, PROFILE},
    physical_operations::{Original, PostDeadline, Resolution},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
pub const MAX_EVENTS: usize = 640;
pub const MAX_SOURCE_BYTES: usize = 32 << 20;
fn refuse() -> Error {
    Error::Refused("managed operating event, bound or original state refused".into())
}
pub fn add(at: i64, delta: u64) -> Result<i64> {
    let v = at
        .checked_add(i64::try_from(delta).map_err(|_| refuse())?)
        .ok_or_else(refuse)?;
    time(v)?;
    Ok(v)
}
fn time(at: i64) -> Result<()> {
    if !(0..=MAX_SAFE_INTEGER as i64).contains(&at) {
        return Err(refuse());
    }
    Ok(())
}
fn reference(s: &str) -> Result<()> {
    if !crate::grant_reference::valid_reference(s) {
        return Err(refuse());
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub original: Original,
    pub signed_grant: String,
    pub forward_signed_grant: String,
    pub forward_attempt_id: String,
    pub grant_expires_at: i64,
}
impl Origin {
    pub fn digest(&self) -> Result<String> {
        digest("managed-drain-origin", &json!(self))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    Accept,
    Advance,
    Observe,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    pub number: u64,
    pub kind: QueryKind,
    pub reserved_at: i64,
    pub expires_at: i64,
    pub reservation_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeliverySlot {
    pub number: u64,
    pub reserved_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub id: String,
    pub deadline: i64,
    pub opened_at: i64,
    pub event_digest: String,
    pub attempts: u64,
    pub next_allowed_at: i64,
    pub pending: Option<DeliverySlot>,
    pub acknowledgement_digest: Option<String>,
}
/// Missing native receipt is a first-class original state, never a synthetic
/// receipt/digest or permission to infer that no physical request was accepted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeReceipt {
    Missing {},
    Retained { digest: String, status: String },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub aggregate_digest: String,
    pub captured_at: i64,
    pub native: NativeReceipt,
    pub acceptance: Option<crate::physical_operations::Acceptance>,
    pub physical_status: String,
    pub resolution: Resolution,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Core {
    pub origin_digest: String,
    pub deadline: i64,
    pub observation_until: i64,
    pub updated_at: i64,
    pub next_query_at: i64,
    pub before_queries: u64,
    pub after_queries: u64,
    pub pending: Option<Slot>,
    pub accepted: bool,
    pub accepted_proof: Option<String>,
    pub pending_proof: Option<String>,
    pub send_proof: Option<String>,
    pub closure_proof: Option<String>,
    pub pending_steps: u64,
    pub send_checks: u64,
    pub closed: bool,
    pub stop_required: bool,
    pub observation: Option<Observation>,
    pub incident: Option<Incident>,
}
impl Core {
    pub fn initial(e: &Enrollment, o: &Origin) -> Result<Self> {
        e.policy.validate()?;
        time(o.original.dispatched_at)?;
        time(o.grant_expires_at)?;
        if o.original.profile != crate::physical_operations::PROFILE
            || o.original.enrollment_digest != e.digest()?
            || o.original.policy_digest != e.policy.digest()?
            || o.original.child_id != e.child_id
            || o.original.operation_key != e.operation_key
            || o.original.contract_digest != e.mechanical_contract_digest
            || o.grant_expires_at <= o.original.dispatched_at
            || o.signed_grant.is_empty()
            || o.signed_grant.len() > 1 << 20
            || o.forward_signed_grant.is_empty()
            || o.forward_signed_grant.len() > 1 << 20
        {
            return Err(refuse());
        }
        let deadline = add(o.original.dispatched_at, e.policy.reconcile_for_ms)?;
        let observation_until = match e.policy.post_deadline_observation {
            PostDeadline::Disabled => deadline,
            PostDeadline::QueryOnly { observe_for_ms, .. } => add(deadline, observe_for_ms)?,
        };
        Ok(Self {
            origin_digest: o.digest()?,
            deadline,
            observation_until,
            updated_at: o.original.dispatched_at,
            next_query_at: o.original.dispatched_at,
            before_queries: 0,
            after_queries: 0,
            pending: None,
            accepted: false,
            accepted_proof: None,
            pending_proof: None,
            send_proof: None,
            closure_proof: None,
            pending_steps: 0,
            send_checks: 0,
            closed: false,
            stop_required: false,
            observation: None,
            incident: None,
        })
    }
    pub fn unresolved(&self) -> bool {
        self.observation
            .as_ref()
            .is_none_or(|v| v.resolution == Resolution::Unresolved)
    }
    pub fn due(&self, at: i64) -> bool {
        self.unresolved() && at >= self.deadline && self.incident.is_none()
    }
    pub fn incident_id(&self, e: &Enrollment) -> Result<String> {
        digest(
            "managed-drain-incident",
            &json!({"origin_digest":self.origin_digest,"policy_digest":e.policy.digest()?}),
        )
    }
    fn backoff(e: &Enrollment, number: u64) -> Result<u64> {
        if !(1..=64).contains(&number) {
            return Err(refuse());
        }
        let mut n = e.policy.initial_backoff_ms;
        for _ in 1..number {
            n = n
                .checked_mul(2)
                .ok_or_else(refuse)?
                .min(e.policy.maximum_backoff_ms);
        }
        Ok(n)
    }
    pub fn apply(
        &self,
        e: &Enrollment,
        o: &Origin,
        at: i64,
        change: &Change,
        verified_observation: Option<&Observation>,
    ) -> Result<Self> {
        time(at)?;
        let after_limit = match e.policy.post_deadline_observation {
            PostDeadline::Disabled => 0,
            PostDeadline::QueryOnly {
                maximum_queries, ..
            } => maximum_queries,
        };
        if self.before_queries > e.policy.maximum_automated_queries
            || self.after_queries > after_limit
            || self.pending_steps > crate::kube_drain::MAX_REQUESTS as u64
            || self.send_checks > self.pending_steps
            || self
                .incident
                .as_ref()
                .is_some_and(|i| i.attempts > e.policy.incident_sink.maximum_delivery_attempts)
            || at < self.updated_at
            || self.origin_digest != o.digest()?
        {
            return Err(refuse());
        }
        if self.due(at) && !matches!(change, Change::Escalated) {
            return Err(refuse());
        }
        let mut s = self.clone();
        s.updated_at = at;
        match change {
            Change::Dispatched => {
                if *self != Self::initial(e, o)? || at != o.original.dispatched_at {
                    return Err(refuse());
                }
            }
            Change::Escalated => {
                if !self.due(at) {
                    return Err(refuse());
                }
                s.stop_required = true;
                let id = self.incident_id(e)?;
                // Stable outbox identity covers immutable original/policy/deadline, never
                // a delivery attempt or a later native acceptance/status refinement.
                let event_digest = digest(
                    "managed-drain-incident-outbox",
                    &json!({"incident_id":id,"origin_digest":self.origin_digest,"deadline":self.deadline,"policy_digest":e.policy.digest()?,"opened_at":at,"owner":e.policy.resource_owner_id,"on_call":e.policy.on_call_team_id,"sink":e.policy.incident_sink.id}),
                )?;
                s.incident = Some(Incident {
                    id,
                    deadline: self.deadline,
                    opened_at: at,
                    event_digest,
                    attempts: 0,
                    next_allowed_at: at,
                    pending: None,
                    acknowledgement_digest: None,
                });
            }
            Change::QueryReserved {
                query_kind: kind,
                number,
            } => {
                if self.pending.is_some()
                    || !self.unresolved()
                    || at < self.next_query_at
                    || *number != self.before_queries + self.after_queries + 1
                {
                    return Err(refuse());
                }
                if *kind != QueryKind::Observe && (self.stop_required || at >= self.deadline) {
                    return Err(refuse());
                }
                if *kind == QueryKind::Observe
                    && !self.accepted
                    && !self.stop_required
                    && at < o.grant_expires_at
                {
                    return Err(refuse());
                }
                if *kind == QueryKind::Accept && self.accepted
                    || *kind == QueryKind::Advance && !self.accepted
                {
                    return Err(refuse());
                }
                let ordinal = if at < self.deadline {
                    if self.before_queries >= e.policy.maximum_automated_queries {
                        return Err(refuse());
                    }
                    s.before_queries += 1;
                    s.before_queries
                } else {
                    let PostDeadline::QueryOnly {
                        maximum_queries, ..
                    } = e.policy.post_deadline_observation
                    else {
                        return Err(refuse());
                    };
                    if *kind != QueryKind::Observe
                        || self.incident.is_none()
                        || !self.stop_required
                        || at >= self.observation_until
                        || self.after_queries >= maximum_queries
                    {
                        return Err(refuse());
                    }
                    s.after_queries += 1;
                    s.after_queries
                };
                let timeout = if *kind == QueryKind::Observe {
                    30000
                } else {
                    5000
                };
                let reservation_digest = digest(
                    "managed-drain-query-slot",
                    &json!({"origin_digest":self.origin_digest,"number":number,"kind":kind,"at":at}),
                )?;
                s.pending = Some(Slot {
                    number: *number,
                    kind: kind.clone(),
                    reserved_at: at,
                    expires_at: add(at, timeout)?.min(if *kind == QueryKind::Observe {
                        self.observation_until
                    } else if *kind == QueryKind::Accept {
                        self.deadline.min(o.grant_expires_at)
                    } else {
                        self.deadline
                    }),
                    reservation_digest,
                });
                s.next_query_at = add(at, Self::backoff(e, ordinal)?)?;
            }
            Change::QueryUnavailable { number, reason } => {
                let q = self.pending.as_ref().ok_or_else(refuse)?;
                if q.number != *number
                    || reason == "interrupted" && at < q.expires_at
                    || !["transport", "malformed", "interrupted", "refused"]
                        .contains(&reason.as_str())
                {
                    return Err(refuse());
                }
                s.pending = None;
            }
            Change::Observed {
                number,
                aggregate_digest,
            } => {
                let q = self.pending.as_ref().ok_or_else(refuse)?;
                let v = verified_observation.ok_or_else(refuse)?;
                if q.number != *number
                    || q.kind != QueryKind::Observe
                    || at >= q.expires_at
                    || v.aggregate_digest != *aggregate_digest
                    || v.captured_at > at
                    || v.captured_at < q.reserved_at
                    || v.acceptance.is_some() != self.accepted
                    || self
                        .observation
                        .as_ref()
                        .is_some_and(|old| v.captured_at < old.captured_at)
                    || v.resolution == Resolution::NoPhysicalDispatch && self.accepted
                    || matches!(
                        v.resolution,
                        Resolution::NoPhysicalDispatch | Resolution::NoPhysicalEffect
                    ) && self.pending_steps > 0
                {
                    return Err(refuse());
                }
                s.observation = Some(v.clone());
                s.stop_required |= v.resolution != Resolution::Unresolved;
                s.pending = None;
            }
            Change::ControllerAccepted { proof_digest } => {
                reference(proof_digest)?;
                let q = self.pending.as_ref().ok_or_else(refuse)?;
                if q.kind != QueryKind::Accept
                    || self.accepted
                    || self.stop_required
                    || at >= q.expires_at
                    || at >= o.grant_expires_at
                    || at >= self.deadline
                {
                    return Err(refuse());
                }
                s.accepted = true;
                s.accepted_proof = Some(proof_digest.clone());
                s.pending = None;
            }
            Change::ControllerPending {
                sequence,
                proof_digest,
            } => {
                reference(proof_digest)?;
                let q = self.pending.as_ref().ok_or_else(refuse)?;
                if q.kind != QueryKind::Advance
                    || !self.accepted
                    || self.stop_required
                    || self.closed
                    || at >= q.expires_at
                    || at >= self.deadline
                    || *sequence != self.pending_steps + 1
                    || self.send_checks != self.pending_steps
                {
                    return Err(refuse());
                }
                s.pending_steps += 1;
                s.pending_proof = Some(proof_digest.clone());
                s.pending = None;
            }
            Change::SendChecked {
                sequence,
                proof_digest,
            } => {
                reference(proof_digest)?;
                if !self.accepted
                    || self.stop_required
                    || self.closed
                    || at >= self.deadline
                    || *sequence != self.pending_steps
                    || *sequence != self.send_checks + 1
                {
                    return Err(refuse());
                }
                s.send_checks += 1;
                s.send_proof = Some(proof_digest.clone());
            }
            Change::ClosedNoEffect { proof_digest } => {
                reference(proof_digest)?;
                if !self.accepted || self.pending_steps != 0 || self.closed {
                    return Err(refuse());
                }
                s.closed = true;
                s.closure_proof = Some(proof_digest.clone());
                s.stop_required = true;
                s.pending = None;
            }
            Change::ClosedAbsence { proof_digest } => {
                reference(proof_digest)?;
                if self.accepted || self.pending_steps != 0 || self.closed {
                    return Err(refuse());
                }
                s.closed = true;
                s.closure_proof = Some(proof_digest.clone());
                s.stop_required = true;
                s.pending = None;
            }
            Change::DeliveryReserved { number } => {
                let i = s.incident.as_mut().ok_or_else(refuse)?;
                if i.pending.is_some()
                    || i.acknowledgement_digest.is_some()
                    || at < i.next_allowed_at
                    || i.attempts >= e.policy.incident_sink.maximum_delivery_attempts
                    || *number != i.attempts + 1
                {
                    return Err(refuse());
                }
                i.attempts += 1;
                i.pending = Some(DeliverySlot {
                    number: *number,
                    reserved_at: at,
                    expires_at: add(at, 5000)?,
                });
                i.next_allowed_at = add(at, Self::backoff(e, *number)?)?;
            }
            Change::DeliveryFailed { number, reason } => {
                let i = s.incident.as_mut().ok_or_else(refuse)?;
                let q = i.pending.as_ref().ok_or_else(refuse)?;
                if q.number != *number
                    || reason == "interrupted" && at < q.expires_at
                    || !["transport", "malformed", "interrupted"].contains(&reason.as_str())
                {
                    return Err(refuse());
                }
                i.pending = None;
            }
            Change::DeliveryAcknowledged {
                number,
                acknowledgement_digest,
            } => {
                reference(acknowledgement_digest)?;
                let i = s.incident.as_mut().ok_or_else(refuse)?;
                let q = i.pending.as_ref().ok_or_else(refuse)?;
                if q.number != *number || at >= q.expires_at {
                    return Err(refuse());
                }
                i.pending = None;
                i.acknowledgement_digest = Some(acknowledgement_digest.clone());
                // Delivery is never a physical outcome transition. Stop and held authority
                // remain unchanged even if the human incident is administratively closed.
            }
        }
        Ok(s)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Dispatched,
    Escalated,
    QueryReserved {
        query_kind: QueryKind,
        number: u64,
    },
    QueryUnavailable {
        number: u64,
        reason: String,
    },
    Observed {
        number: u64,
        aggregate_digest: String,
    },
    ControllerAccepted {
        proof_digest: String,
    },
    ControllerPending {
        sequence: u64,
        proof_digest: String,
    },
    SendChecked {
        sequence: u64,
        proof_digest: String,
    },
    ClosedNoEffect {
        proof_digest: String,
    },
    ClosedAbsence {
        proof_digest: String,
    },
    DeliveryReserved {
        number: u64,
    },
    DeliveryFailed {
        number: u64,
        reason: String,
    },
    DeliveryAcknowledged {
        number: u64,
        acknowledgement_digest: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub profile: String,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub origin_digest: String,
    pub at: i64,
    pub change: Change,
    pub after: Core,
}
impl Event {
    pub fn new(
        previous: Option<&Event>,
        before: &Core,
        e: &Enrollment,
        o: &Origin,
        at: i64,
        change: Change,
        view: Option<&Observation>,
    ) -> Result<Self> {
        let sequence = match previous {
            Some(p) => {
                p.bound()?;
                if p.after != *before || p.origin_digest != o.digest()? {
                    return Err(refuse());
                }
                p.sequence.checked_add(1).ok_or_else(refuse)?
            }
            None => 1,
        };
        if sequence > MAX_EVENTS as u64 {
            return Err(refuse());
        }
        if previous.is_none() && !matches!(change, Change::Dispatched)
            || previous.is_some() && matches!(change, Change::Dispatched)
        {
            return Err(refuse());
        }
        Ok(Self {
            profile: PROFILE.into(),
            sequence,
            previous_digest: previous.map(Self::digest).transpose()?,
            origin_digest: o.digest()?,
            at,
            after: before.apply(e, o, at, &change, view)?,
            change,
        })
    }
    pub fn digest(&self) -> Result<String> {
        digest("managed-drain-operating-event", &json!(self))
    }
    pub fn bound(&self) -> Result<()> {
        if self.profile != PROFILE
            || self.sequence == 0
            || self.sequence > MAX_EVENTS as u64
            || canonical(&json!(self))?.len() > 32 << 10
        {
            return Err(refuse());
        }
        Ok(())
    }
}
