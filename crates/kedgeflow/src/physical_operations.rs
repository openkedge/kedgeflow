//! RFC 0056 record/replay prerequisite. No persistence, dispatch, refund or
//! incident delivery is performed here; managed controller enforcement is O2.
use crate::{
    contracts::{MAX_SAFE_INTEGER, canonical, digest, record_digest, strict_value},
    error::{Error, Result},
    family_saga::{AggregateBundle, AuditTrust, ForwardState, ObserverPin},
    grant_reference::{fixed_https, valid_reference},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
pub const PROFILE: &str = "KF-PHYSICAL-OPERATIONS-0.1-draft";
pub const MAX_QUERIES: u64 = 64;
pub const MAX_EVENTS: usize = 258;
pub const MAX_BYTES: usize = 32 << 20;
const MAX_DURATION: u64 = 604800000;
fn refuse() -> Error {
    Error::Refused("physical operating record, policy or original evidence refused".into())
}
fn id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/@".contains(&b))
}
fn time(v: i64) -> Result<()> {
    if v < 0 || v > MAX_SAFE_INTEGER as i64 {
        return Err(refuse());
    }
    Ok(())
}
fn add(at: i64, duration: u64) -> Result<i64> {
    time(at)?;
    let v = at
        .checked_add(i64::try_from(duration).map_err(|_| refuse())?)
        .ok_or_else(refuse)?;
    time(v)?;
    Ok(v)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8], bound: usize) -> Result<T> {
    if raw.len() > bound {
        return Err(refuse());
    }
    let v = strict_value(raw)?;
    let t: T = serde_json::from_value(v.clone())?;
    if json!(t) != v {
        return Err(refuse());
    }
    Ok(t)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncidentSink {
    pub id: String,
    pub url: String,
    pub acknowledgement_keys: BTreeMap<String, String>,
    pub maximum_delivery_attempts: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum PostDeadline {
    Disabled,
    QueryOnly {
        maximum_queries: u64,
        observe_for_ms: u64,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryAction {
    StopConsequentialWork,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub profile: String,
    pub tenant: String,
    pub resource_owner_id: String,
    pub on_call_team_id: String,
    pub incident_sink: IncidentSink,
    pub initial_backoff_ms: u64,
    pub maximum_backoff_ms: u64,
    pub maximum_automated_queries: u64,
    pub reconcile_for_ms: u64,
    pub post_deadline_observation: PostDeadline,
    pub expiry_action: ExpiryAction,
}
impl Policy {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let p: Self = decode(raw, 64 << 10)?;
        p.validate()?;
        Ok(p)
    }
    pub fn validate(&self) -> Result<()> {
        if self.profile != PROFILE
            || !id(&self.tenant)
            || !id(&self.resource_owner_id)
            || !id(&self.on_call_team_id)
            || !id(&self.incident_sink.id)
            || !(1..=MAX_QUERIES).contains(&self.incident_sink.maximum_delivery_attempts)
            || self.initial_backoff_ms == 0
            || self.initial_backoff_ms > self.maximum_backoff_ms
            || self.maximum_backoff_ms > MAX_DURATION
            || !(1..=MAX_QUERIES).contains(&self.maximum_automated_queries)
            || !(1..=MAX_DURATION).contains(&self.reconcile_for_ms)
            || self.incident_sink.acknowledgement_keys.is_empty()
            || self.incident_sink.acknowledgement_keys.len() > 16
            || self
                .incident_sink
                .acknowledgement_keys
                .keys()
                .any(|k| !id(k))
        {
            return Err(refuse());
        }
        let keys = crate::control_config::keys(&self.incident_sink.acknowledgement_keys)?;
        if keys
            .values()
            .map(|k| *k.as_bytes())
            .collect::<BTreeSet<_>>()
            .len()
            != keys.len()
            || fixed_https(&self.incident_sink.url)?.as_str() != self.incident_sink.url
        {
            return Err(refuse());
        }
        if let PostDeadline::QueryOnly {
            maximum_queries,
            observe_for_ms,
        } = self.post_deadline_observation
            && (!(1..=MAX_QUERIES).contains(&maximum_queries)
                || !(1..=MAX_DURATION).contains(&observe_for_ms))
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("physical-operating-policy", &json!(self))
    }
    fn backoff(&self, number: u64) -> Result<u64> {
        if !(1..=MAX_QUERIES).contains(&number) {
            return Err(refuse());
        }
        let mut delay = self.initial_backoff_ms;
        for _ in 1..number {
            delay = delay
                .checked_mul(2)
                .ok_or_else(refuse)?
                .min(self.maximum_backoff_ms);
        }
        Ok(delay)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Original {
    pub profile: String,
    pub enrollment_digest: String,
    pub policy_digest: String,
    pub family_registration_digest: String,
    pub child_id: String,
    pub operation_key: String,
    pub root_id: String,
    pub grant_digest: String,
    pub attempt_id: String,
    pub contract_digest: String,
    pub resource: crate::contracts::Resource,
    pub realm_uid: String,
    pub node_uid: String,
    pub dispatched_at: i64,
    pub native_dispatch_digest: String,
}
impl Original {
    pub fn digest(&self) -> Result<String> {
        digest("physical-operating-original", &json!(self))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Unresolved,
    ObservedCompleted,
    NoPhysicalDispatch,
    NoPhysicalEffect,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub controller_digest: String,
    pub accepted_at: i64,
    pub deferred_until: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub aggregate_digest: String,
    pub captured_at: i64,
    pub native_receipt_digest: String,
    pub native_status: String,
    pub acceptance: Option<Acceptance>,
    pub physical_status: String,
    pub resolution: Resolution,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub profile: String,
    pub enrollment_digest: String,
    pub policy_digest: String,
    pub child_id: String,
    pub physical: AuditTrust,
    pub observer: ObserverPin,
}
impl Trust {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let t: Self = decode(raw, 2 << 20)?;
        t.validate()?;
        Ok(t)
    }
    fn validate(&self) -> Result<()> {
        self.physical.registration.validate()?;
        if self.profile != PROFILE
            || !valid_reference(&self.enrollment_digest)
            || !valid_reference(&self.policy_digest)
            || !id(&self.child_id)
            || !id(&self.observer.id)
            || self.observer.keys.is_empty()
            || self.observer.keys.len() > 16
            || self.observer.keys.keys().any(|k| !id(k))
        {
            return Err(refuse());
        }
        let keys = crate::control_config::keys(&self.observer.keys)?;
        if keys
            .values()
            .map(|k| *k.as_bytes())
            .collect::<BTreeSet<_>>()
            .len()
            != keys.len()
        {
            return Err(refuse());
        }
        let plan = self
            .physical
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?;
        let node = plan.node(&self.child_id)?;
        let physical = node.physical.as_ref().ok_or_else(refuse)?;
        let native = node.forward()?;
        let other = [
            &physical.controller,
            &physical.observer,
            &plan.observer,
            &plan.family_observer,
        ];
        for pin in other {
            if pin.id == self.observer.id {
                return Err(refuse());
            }
            let pinned = crate::control_config::keys(&pin.keys)?;
            if keys.values().any(|k| pinned.values().any(|v| v == k)) {
                return Err(refuse());
            }
        }
        if keys
            .values()
            .any(|k| native.lineage.grants.keys.values().any(|v| v == k))
        {
            return Err(refuse());
        }
        Ok(())
    }
}
fn observe(
    bundle: &AggregateBundle,
    t: &Trust,
    policy: &Policy,
) -> Result<(Original, Observation)> {
    use crate::family_saga_cache::{ByteCache, key};
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<ByteCache<(Original, Observation)>>> = OnceLock::new();
    // All actual historical proof bytes, policy and separately supplied public
    // pins participate. No current clock, event state or live decision is cached.
    let proof = serde_json::to_vec(bundle)?;
    let pins = serde_json::to_vec(t)?;
    let policy_bytes = serde_json::to_vec(policy)?;
    if proof.len() > crate::family_saga_audit::MAX_BUNDLE
        || pins.len() > 2 << 20
        || policy_bytes.len() > 64 << 10
    {
        return Err(refuse());
    }
    let identity = key(
        "physical-operating-verified-history",
        &[&proof, &pins, &policy_bytes],
    );
    let cache = CACHE.get_or_init(|| Mutex::new(ByteCache::new(8)));
    if let Some(value) = cache.lock().map_err(|_| refuse())?.get(&identity) {
        return Ok(value);
    }
    let value = observe_uncached(bundle, t, policy)?;
    cache.lock().map_err(|_| refuse())?.insert(
        identity,
        proof.len() + pins.len() + policy_bytes.len(),
        value.clone(),
    );
    Ok(value)
}
fn observe_uncached(
    bundle: &AggregateBundle,
    t: &Trust,
    policy: &Policy,
) -> Result<(Original, Observation)> {
    t.validate()?;
    if policy.digest()? != t.policy_digest {
        return Err(refuse());
    }
    // A sink acknowledgment and an operating checkpoint are different roles;
    // neither may reuse a native authority/evidence/controller signing key.
    let operating_keys = crate::control_config::keys(&t.observer.keys)?;
    let sink_keys = crate::control_config::keys(&policy.incident_sink.acknowledgement_keys)?;
    if operating_keys
        .values()
        .any(|k| sink_keys.values().any(|v| v == k))
    {
        return Err(refuse());
    }
    let plan = t
        .physical
        .registration
        .composition
        .as_ref()
        .ok_or_else(refuse)?;
    let physical = plan
        .node(&t.child_id)?
        .physical
        .as_ref()
        .ok_or_else(refuse)?;
    let mut control = physical.control()?;
    for pin in [
        &physical.controller,
        &physical.observer,
        &plan.observer,
        &plan.family_observer,
    ] {
        let keys = crate::control_config::keys(&pin.keys)?;
        if sink_keys.values().any(|k| keys.values().any(|v| v == k)) {
            return Err(refuse());
        }
    }
    for (role, keys) in [
        ("operating", &operating_keys),
        ("incident-sink", &sink_keys),
    ] {
        for (id, key) in keys {
            if control
                .observer_keys
                .insert(format!("{role}:{id}"), *key)
                .is_some()
            {
                return Err(refuse());
            }
        }
    }
    control.validate()?;
    let verified = crate::family_saga::verify_aggregate(bundle, &t.physical)?;
    let r = &t.physical.registration;
    if r.tenant != policy.tenant {
        return Err(refuse());
    }
    let node = r
        .composition
        .as_ref()
        .ok_or_else(refuse)?
        .node(&t.child_id)?;
    let physical = node.physical.as_ref().ok_or_else(refuse)?;
    let m = bundle
        .evidence
        .current
        .snapshot
        .members
        .get(&t.child_id)
        .ok_or_else(refuse)?;
    let execution = m.executions.get(&node.operation_key).ok_or_else(refuse)?;
    let outcome = &execution.lineage.outcomes;
    let v = node
        .forward()?
        .lineage
        .grants
        .verify_retained(outcome.execution.signed_grant.as_bytes())?;
    let dispatches: Vec<_> = outcome
        .journal
        .iter()
        .filter(|e| e["phase"] == "dispatch_authorized")
        .collect();
    if dispatches.len() != 1 {
        return Err(refuse());
    }
    let dispatch = dispatches[0];
    let at = dispatch["event_time"].as_i64().ok_or_else(refuse)?;
    time(at)?;
    if dispatch["attempt_id"] != outcome.attempt_id
        || dispatch["grant_digest"] != v.digest
        || dispatch["root_id"] != v.grant.root_id
    {
        return Err(refuse());
    }
    let original = Original {
        profile: PROFILE.into(),
        enrollment_digest: t.enrollment_digest.clone(),
        policy_digest: t.policy_digest.clone(),
        family_registration_digest: r.digest()?,
        child_id: t.child_id.clone(),
        operation_key: node.operation_key.clone(),
        root_id: v.grant.root_id,
        grant_digest: v.digest,
        attempt_id: outcome.attempt_id.clone(),
        contract_digest: physical.contract.digest()?,
        resource: physical.contract.resource()?,
        realm_uid: physical.contract.cluster_uid.clone(),
        node_uid: physical.contract.node.uid.clone(),
        dispatched_at: at,
        native_dispatch_digest: digest("kube-drain-native-dispatch", dispatch)?,
    };
    let native_raw = outcome.receipts.last().ok_or_else(refuse)?;
    let native: crate::contracts::Envelope =
        serde_json::from_value(strict_value(native_raw.as_bytes())?)?;
    let summary = verified.nodes.get(&t.child_id).ok_or_else(refuse)?;
    let status = summary.physical_status.clone().ok_or_else(refuse)?;
    let resolution = match (status.as_str(), &summary.forward) {
        ("observed_completed", ForwardState::Committed) => Resolution::ObservedCompleted,
        ("no_physical_dispatch", ForwardState::NoEffect) => Resolution::NoPhysicalDispatch,
        ("no_physical_effect", ForwardState::NoEffect) => Resolution::NoPhysicalEffect,
        (_, ForwardState::Unknown) => Resolution::Unresolved,
        _ => return Err(refuse()),
    };
    let acceptance = m
        .physical
        .as_ref()
        .ok_or_else(refuse)?
        .controller
        .as_ref()
        .map(|s| {
            Ok::<_, Error>(Acceptance {
                controller_digest: s.digest()?,
                accepted_at: s.body.accepted.accepted_at,
                deferred_until: s.body.accepted.deferred_until,
            })
        })
        .transpose()?;
    Ok((
        original,
        Observation {
            aggregate_digest: digest("physical-operating-aggregate", &json!(bundle))?,
            captured_at: bundle.checkpoint.captured_at,
            native_receipt_digest: record_digest(&native)?,
            native_status: native.payload["status"].as_str().ok_or_else(refuse)?.into(),
            acceptance,
            physical_status: status,
            resolution,
        },
    ))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryStage {
    BeforeDeadline,
    AfterDeadline,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unavailable {
    Transport,
    Malformed,
    Interrupted,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Opened {
        aggregate_digest: String,
    },
    QueryReserved {
        number: u64,
        stage: QueryStage,
    },
    QueryObserved {
        number: u64,
        aggregate_digest: String,
    },
    QueryUnavailable {
        number: u64,
        reason: Unavailable,
    },
    Escalated {
        incident_id: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub profile: String,
    pub sequence: u64,
    pub original_digest: String,
    pub policy_digest: String,
    pub at: i64,
    pub previous_digest: Option<String>,
    pub change: Change,
}
impl Event {
    pub fn digest(&self) -> Result<String> {
        digest("physical-operating-event", &json!(self))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub incident_id: String,
    pub resource_owner_id: String,
    pub on_call_team_id: String,
    pub sink_id: String,
    pub opened_at: i64,
    pub outbox_event_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingQuery {
    pub number: u64,
    pub stage: QueryStage,
    pub reserved_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub original_digest: String,
    pub deadline: i64,
    pub observation_until: i64,
    pub next_allowed_at: i64,
    pub before_queries: u64,
    pub after_queries: u64,
    pub pending: Option<PendingQuery>,
    pub stop_required: bool,
    pub incident: Option<Incident>,
    pub observation: Observation,
    pub event_count: u64,
    pub head_digest: String,
    pub updated_at: i64,
    pub execution_authority: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub profile: String,
    pub policy: Policy,
    pub original: Original,
    pub events: Vec<Event>,
    pub aggregates: BTreeMap<String, AggregateBundle>,
}
impl History {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        decode(raw, MAX_BYTES)
    }
    pub fn open(
        policy: Policy,
        trust: &Trust,
        aggregate: AggregateBundle,
        at: i64,
    ) -> Result<Self> {
        let (original, observation) = observe(&aggregate, trust, &policy)?;
        let key = observation.aggregate_digest.clone();
        let mut h = Self {
            profile: PROFILE.into(),
            policy,
            original,
            events: vec![],
            aggregates: BTreeMap::from([(key.clone(), aggregate)]),
        };
        h.push(
            at,
            Change::Opened {
                aggregate_digest: key,
            },
        )?;
        if observation.resolution == Resolution::Unresolved
            && at >= add(h.original.dispatched_at, h.policy.reconcile_for_ms)?
        {
            h.push(
                at,
                Change::Escalated {
                    incident_id: h.incident_id()?,
                },
            )?;
        }
        h.replay(trust)?;
        Ok(h)
    }
    fn push(&mut self, at: i64, change: Change) -> Result<()> {
        if self.events.len() >= MAX_EVENTS {
            return Err(refuse());
        }
        self.events.push(Event {
            profile: PROFILE.into(),
            sequence: self.events.len() as u64 + 1,
            original_digest: self.original.digest()?,
            policy_digest: self.policy.digest()?,
            at,
            previous_digest: self.events.last().map(Event::digest).transpose()?,
            change,
        });
        Ok(())
    }
    fn incident_id(&self) -> Result<String> {
        digest(
            "physical-operating-incident",
            &json!({"original_digest":self.original.digest()?,"policy_digest":self.policy.digest()?}),
        )
    }
    fn ensure_deadline(&mut self, trust: &Trust, at: i64) -> Result<()> {
        let s = self.replay(trust)?;
        if s.observation.resolution == Resolution::Unresolved
            && at >= s.deadline
            && s.incident.is_none()
        {
            self.push(
                at,
                Change::Escalated {
                    incident_id: self.incident_id()?,
                },
            )?;
        }
        Ok(())
    }
    /// Pure plan. The caller must durably CAS this entire transition before I/O.
    pub fn reserve_query(&self, trust: &Trust, at: i64) -> Result<Self> {
        let mut next = self.clone();
        next.ensure_deadline(trust, at)?;
        let s = next.replay(trust)?;
        let stage = if at < s.deadline {
            QueryStage::BeforeDeadline
        } else {
            QueryStage::AfterDeadline
        };
        next.push(
            at,
            Change::QueryReserved {
                number: s.before_queries + s.after_queries + 1,
                stage,
            },
        )?;
        next.replay(trust)?;
        Ok(next)
    }
    pub fn record_unavailable(&self, trust: &Trust, at: i64, reason: Unavailable) -> Result<Self> {
        let mut next = self.clone();
        next.ensure_deadline(trust, at)?;
        let s = next.replay(trust)?;
        next.push(
            at,
            Change::QueryUnavailable {
                number: s.pending.ok_or_else(refuse)?.number,
                reason,
            },
        )?;
        next.replay(trust)?;
        Ok(next)
    }
    pub fn record_observation(
        &self,
        trust: &Trust,
        at: i64,
        aggregate: AggregateBundle,
    ) -> Result<Self> {
        let mut next = self.clone();
        next.ensure_deadline(trust, at)?;
        let s = next.replay(trust)?;
        let (original, observation) = observe(&aggregate, trust, &next.policy)?;
        if original != next.original {
            return Err(refuse());
        }
        let key = observation.aggregate_digest;
        next.aggregates.insert(key.clone(), aggregate);
        next.push(
            at,
            Change::QueryObserved {
                number: s.pending.ok_or_else(refuse)?.number,
                aggregate_digest: key,
            },
        )?;
        next.replay(trust)?;
        Ok(next)
    }
    pub fn escalate(&self, trust: &Trust, at: i64) -> Result<Self> {
        let mut next = self.clone();
        next.ensure_deadline(trust, at)?;
        if next.events.len() == self.events.len() {
            return Err(refuse());
        }
        next.replay(trust)?;
        Ok(next)
    }
    pub fn replay(&self, trust: &Trust) -> Result<State> {
        trust.validate()?;
        if self.profile != PROFILE
            || self.policy.digest()? != trust.policy_digest
            || self.events.is_empty()
            || self.events.len() > MAX_EVENTS
            || self.aggregates.is_empty()
            || self.aggregates.len() > (2 * MAX_QUERIES + 1) as usize
            || canonical(&json!(self))?.len() > MAX_BYTES
        {
            return Err(refuse());
        }
        let mut views = BTreeMap::new();
        for (key, b) in &self.aggregates {
            let (original, observation) = observe(b, trust, &self.policy)?;
            if original != self.original || *key != observation.aggregate_digest {
                return Err(refuse());
            }
            views.insert(key.clone(), observation);
        }
        let Change::Opened { aggregate_digest } = &self.events[0].change else {
            return Err(refuse());
        };
        let first = views.get(aggregate_digest).ok_or_else(refuse)?.clone();
        let deadline = add(self.original.dispatched_at, self.policy.reconcile_for_ms)?;
        let observation_until = match self.policy.post_deadline_observation {
            PostDeadline::Disabled => deadline,
            PostDeadline::QueryOnly { observe_for_ms, .. } => add(deadline, observe_for_ms)?,
        };
        let mut state = State {
            original_digest: self.original.digest()?,
            deadline,
            observation_until,
            next_allowed_at: self.original.dispatched_at,
            before_queries: 0,
            after_queries: 0,
            pending: None,
            stop_required: first.resolution != Resolution::Unresolved,
            incident: None,
            observation: first,
            event_count: 0,
            head_digest: String::new(),
            updated_at: self.original.dispatched_at,
            execution_authority: false,
        };
        let mut used = BTreeSet::new();
        for (index, event) in self.events.iter().enumerate() {
            time(event.at)?;
            if event.profile != PROFILE
                || event.sequence != index as u64 + 1
                || event.original_digest != state.original_digest
                || event.policy_digest != self.original.policy_digest
                || event.at < state.updated_at
                || event.previous_digest != (index > 0).then(|| state.head_digest.clone())
            {
                return Err(refuse());
            }
            if index > 0
                && event.at >= state.deadline
                && state.observation.resolution == Resolution::Unresolved
                && state.incident.is_none()
                && !matches!(event.change, Change::Escalated { .. })
            {
                return Err(refuse());
            }
            match &event.change {
                Change::Opened { aggregate_digest } if index == 0 => {
                    if state.observation.captured_at > event.at {
                        return Err(refuse());
                    }
                    used.insert(aggregate_digest.clone());
                }
                Change::Escalated { incident_id } => {
                    if state.observation.resolution != Resolution::Unresolved
                        || state.incident.is_some()
                        || event.at < state.deadline
                        || *incident_id != self.incident_id()?
                    {
                        return Err(refuse());
                    }
                    state.stop_required = true;
                    state.incident = Some(Incident {
                        incident_id: incident_id.clone(),
                        resource_owner_id: self.policy.resource_owner_id.clone(),
                        on_call_team_id: self.policy.on_call_team_id.clone(),
                        sink_id: self.policy.incident_sink.id.clone(),
                        opened_at: event.at,
                        outbox_event_digest: event.digest()?,
                    });
                }
                Change::QueryReserved { number, stage } => {
                    if state.observation.resolution != Resolution::Unresolved
                        || state.pending.is_some()
                        || event.at < state.next_allowed_at
                        || *number != state.before_queries + state.after_queries + 1
                    {
                        return Err(refuse());
                    }
                    let ordinal = match stage {
                        QueryStage::BeforeDeadline => {
                            if event.at >= state.deadline
                                || state.before_queries >= self.policy.maximum_automated_queries
                            {
                                return Err(refuse());
                            }
                            state.before_queries += 1;
                            state.before_queries
                        }
                        QueryStage::AfterDeadline => {
                            let PostDeadline::QueryOnly {
                                maximum_queries, ..
                            } = self.policy.post_deadline_observation
                            else {
                                return Err(refuse());
                            };
                            if event.at < state.deadline
                                || event.at >= state.observation_until
                                || state.incident.is_none()
                                || state.after_queries >= maximum_queries
                                || !state.stop_required
                            {
                                return Err(refuse());
                            }
                            state.after_queries += 1;
                            state.after_queries
                        }
                    };
                    state.pending = Some(PendingQuery {
                        number: *number,
                        stage: stage.clone(),
                        reserved_at: event.at,
                    });
                    state.next_allowed_at = add(event.at, self.policy.backoff(ordinal)?)?;
                }
                Change::QueryUnavailable { number, .. } => {
                    if state.pending.as_ref().is_none_or(|p| p.number != *number) {
                        return Err(refuse());
                    }
                    state.pending = None;
                }
                Change::QueryObserved {
                    number,
                    aggregate_digest,
                } => {
                    if state.pending.as_ref().is_none_or(|p| p.number != *number) {
                        return Err(refuse());
                    }
                    let view = views.get(aggregate_digest).ok_or_else(refuse)?;
                    if view.captured_at < state.observation.captured_at
                        || view.captured_at > event.at
                    {
                        return Err(refuse());
                    }
                    state.observation = view.clone();
                    state.stop_required |= view.resolution != Resolution::Unresolved;
                    state.pending = None;
                    used.insert(aggregate_digest.clone());
                }
                _ => return Err(refuse()),
            }
            // A newly recorded post-deadline action requires the stop/outbox first.
            if index > 0
                && event.at >= state.deadline
                && state.observation.resolution == Resolution::Unresolved
                && state.incident.is_none()
            {
                return Err(refuse());
            }
            state.head_digest = event.digest()?;
            state.event_count = event.sequence;
            state.updated_at = event.at;
        }
        if state.updated_at >= state.deadline
            && state.observation.resolution == Resolution::Unresolved
            && state.incident.is_none()
        {
            return Err(refuse());
        }
        if used != self.aggregates.keys().cloned().collect() {
            return Err(refuse());
        }
        Ok(state)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub profile: String,
    pub observer_id: String,
    pub key_id: String,
    pub enrollment_digest: String,
    pub policy_digest: String,
    pub original_digest: String,
    pub event_count: u64,
    pub head_digest: String,
    pub history_digest: String,
    pub captured_at: i64,
    pub signature: String,
}
impl Checkpoint {
    fn message(&self) -> Result<Vec<u8>> {
        let mut v = json!(self);
        v.as_object_mut().ok_or_else(refuse)?.remove("signature");
        let mut bytes = format!("KedgeFlow:{PROFILE}:operating-history\0").into_bytes();
        bytes.extend(canonical(&v)?);
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub profile: String,
    pub history: History,
    pub checkpoint: Checkpoint,
}
impl Bundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        decode(raw, MAX_BYTES)
    }
    pub fn sign(
        history: History,
        trust: &Trust,
        key_id: &str,
        key: &ed25519_dalek::SigningKey,
        at: i64,
    ) -> Result<Self> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::Signer;
        let s = history.replay(trust)?;
        if crate::control_config::keys(&trust.observer.keys)?.get(key_id)
            != Some(&key.verifying_key())
        {
            return Err(refuse());
        }
        let mut cp = Checkpoint {
            profile: PROFILE.into(),
            observer_id: trust.observer.id.clone(),
            key_id: key_id.into(),
            enrollment_digest: trust.enrollment_digest.clone(),
            policy_digest: trust.policy_digest.clone(),
            original_digest: s.original_digest,
            event_count: s.event_count,
            head_digest: s.head_digest,
            history_digest: digest("physical-operating-history", &json!(history))?,
            captured_at: at,
            signature: String::new(),
        };
        cp.signature = URL_SAFE_NO_PAD.encode(key.sign(&cp.message()?).to_bytes());
        let b = Self {
            profile: PROFILE.into(),
            history,
            checkpoint: cp,
        };
        b.verify(trust)?;
        Ok(b)
    }
    pub fn verify(&self, trust: &Trust) -> Result<State> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let s = self.history.replay(trust)?;
        let cp = &self.checkpoint;
        time(cp.captured_at)?;
        if self.profile != PROFILE
            || cp.profile != PROFILE
            || cp.observer_id != trust.observer.id
            || cp.enrollment_digest != trust.enrollment_digest
            || cp.policy_digest != trust.policy_digest
            || cp.original_digest != s.original_digest
            || cp.event_count != s.event_count
            || cp.head_digest != s.head_digest
            || cp.history_digest != digest("physical-operating-history", &json!(self.history))?
            || cp.captured_at < s.updated_at
            || (cp.captured_at >= s.deadline
                && s.observation.resolution == Resolution::Unresolved
                && s.incident.is_none())
            || canonical(&json!(self))?.len() > MAX_BYTES
        {
            return Err(refuse());
        }
        let keys = crate::control_config::keys(&trust.observer.keys)?;
        let key = keys.get(&cp.key_id).ok_or_else(refuse)?;
        let raw = URL_SAFE_NO_PAD
            .decode(&cp.signature)
            .map_err(|_| refuse())?;
        if URL_SAFE_NO_PAD.encode(&raw) != cp.signature {
            return Err(refuse());
        }
        let sig = ed25519_dalek::Signature::from_slice(&raw).map_err(|_| refuse())?;
        key.verify_strict(&cp.message()?, &sig)
            .map_err(|_| refuse())?;
        Ok(s)
    }
}

#[cfg(test)]
mod arithmetic {
    use super::*;
    #[test]
    fn operating_deadlines_refuse_unsafe_overflow() {
        assert_eq!(
            add(MAX_SAFE_INTEGER as i64 - 1, 1).unwrap(),
            MAX_SAFE_INTEGER as i64
        );
        assert!(add(MAX_SAFE_INTEGER as i64, 1).is_err());
        assert!(add(-1, 1).is_err());
        assert!(add(0, u64::MAX).is_err());
    }
}
