//! Durable query-only orchestration observations, never execution/compensation authority.
use crate::{
    contracts::{canonical, digest, record_digest, strict_value},
    coordination::{Allocation, ReservationSnapshot, ReservationState as B},
    error::{Error, Result},
    governance::EnforcementScope,
    hierarchical_leaf::Principal,
    ledger::{EtcdLedger, get, key_part, put, record, value_eq, version_zero},
    lineage::{AuthorizationBundle, verify_authorization},
    recovery::{Candidate, OutcomeBundle, verify_outcomes},
    reserved_leaf::ReservationBinding,
    reserved_lineage::{Trust, leaf_trust},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
pub const PROFILE: &str = "KF-SAGA-OBSERVATION-0.1-draft";
pub const MAX_EVENTS: u64 = 128;
const MAX_STATE: usize = 64 << 10;
const MAX_PROOF: usize = 64 << 10;
fn refuse() -> Error {
    Error::Refused("saga observation identity, proof or transition refused".into())
}
fn bounded(compare: &mut Vec<Value>, operations: &[Value]) -> Result<()> {
    let mut seen = BTreeSet::new();
    compare.retain(|v| seen.insert(v.to_string()));
    if compare.len() > 96
        || operations.len() > 32
        || canonical(&json!({"compare":compare,"success":operations,"failure":[]}))?.len() > 1 << 20
    {
        return Err(refuse());
    }
    Ok(())
}

fn schema(v: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let s = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/saga-observation-v0.1.schema.json"
            ))
            .expect("saga schema"),
        )
        .expect("valid saga schema")
    });
    if s.is_valid(v) { Ok(()) } else { Err(refuse()) }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Inverse {
    pub scope: EnforcementScope,
    pub semantics_digest: String,
    pub applicability_digest: String,
    pub late_effect_barrier_digest: String,
    pub compensation_units: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub node_id: String,
    pub operation_key: String,
    pub principal: Principal,
    pub depends_on: Vec<String>,
    pub inverse: Option<Inverse>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub profile: String,
    pub saga_id: String,
    pub registration_digest: String,
    pub nodes: Vec<Node>,
}
impl Plan {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_STATE {
            return Err(refuse());
        }
        let v = strict_value(raw)?;
        schema(&v)?;
        Ok(serde_json::from_value(v)?)
    }
    pub fn digest(&self) -> Result<String> {
        digest("saga-observation-plan", &json!(self))
    }
    pub fn validate(&self, trust: &Trust) -> Result<()> {
        trust.validate()?;
        schema(&json!(self))?;
        let r = &trust.registration;
        if canonical(&json!(self))?.len() > MAX_STATE
            || r.profile != crate::reservation_history::HIERARCHICAL_LEAF_PROFILE
            || self.registration_digest != r.digest()?
        {
            return Err(refuse());
        }
        let h = r.hierarchy.as_ref().ok_or_else(refuse)?;
        let nodes: BTreeMap<_, _> = self.nodes.iter().map(|n| (n.node_id.as_str(), n)).collect();
        let mut operations = BTreeSet::new();
        let mut hypothetical = ReservationSnapshot {
            profile: crate::coordination::PROFILE.into(),
            enrollment: r.enrollment.clone(),
            active: true,
            execution_authority: false,
            allocations: h.initial()?,
        };
        for n in &self.nodes {
            let assignment = h
                .assignments
                .iter()
                .find(|a| a.principal == n.principal)
                .ok_or_else(refuse)?;
            if !trust.lineage.subjects.contains(&n.principal.subject)
                || !operations.insert(n.operation_key.clone())
                || nodes.len() != self.nodes.len()
                || n.depends_on.iter().collect::<BTreeSet<_>>().len() != n.depends_on.len()
            {
                return Err(refuse());
            }
            let mut pending = n.depends_on.clone();
            let mut visited = BTreeSet::new();
            while let Some(id) = pending.pop() {
                if id == n.node_id {
                    return Err(refuse());
                }
                let parent = nodes.get(id.as_str()).ok_or_else(refuse)?;
                if visited.insert(id) {
                    pending.extend(parent.depends_on.clone());
                }
            }
            if let Some(i) = &n.inverse {
                crate::grant_reference::fixed_https(&i.scope.audience)?;
                if i.scope.resource != r.scope.resource
                    || i.scope.conflict_domain != r.scope.conflict_domain
                    || i.scope.action.id == r.scope.action.id
                    || i.compensation_units > r.compensation_units
                {
                    return Err(refuse());
                }
            }
            let a = Allocation {
                operation_digest: n.operation_key.clone(),
                parent: Some(assignment.parent_grant_digest.clone()),
                scope: crate::coordination::ReservationScope {
                    actions: BTreeSet::from([r.scope.action.id.clone()]),
                    resources: BTreeSet::from([r.scope.resource.id.clone()]),
                },
                forward: r.forward_units,
                compensation: r.compensation_units,
                state: B::Allocated,
                attempt_id: None,
            };
            if hypothetical
                .allocations
                .insert(n.operation_key.clone(), a)
                .is_some()
            {
                return Err(refuse());
            }
        }
        hypothetical.validate()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Forward {
    Planned,
    Issued,
    Unknown,
    Committed,
    ProvenNoEffect,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Compensation {
    Unregistered,
    NotRequested,
    BlockedForwardUnknown,
    BlockedNotCommitted,
    RequiresFreshAdmissionAndBarrier,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub forward: Forward,
    pub grant_digest: Option<String>,
    pub attempt_id: Option<String>,
    pub receipt_digest: Option<String>,
    pub proof_digest: Option<String>,
    pub compensation: Compensation,
    pub unmet_dependencies: Vec<String>,
    pub dependency_violation: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    Unresolved,
    Completed,
    NeedsOperator,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub profile: String,
    pub plan_digest: String,
    pub revision: u64,
    pub compensation_requested: bool,
    pub budget_active: bool,
    pub status: Status,
    pub nodes: BTreeMap<String, Observation>,
    pub execution_authority: bool,
    pub dependency_order_enforced: bool,
}
impl Snapshot {
    fn derive(&mut self, plan: &Plan) {
        let committed: BTreeSet<_> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.forward == Forward::Committed)
            .map(|(id, _)| id.clone())
            .collect();
        for n in &plan.nodes {
            let o = self.nodes.get_mut(&n.node_id).expect("plan node");
            o.unmet_dependencies = n
                .depends_on
                .iter()
                .filter(|id| !committed.contains(*id))
                .cloned()
                .collect();
            o.dependency_violation |=
                o.forward != Forward::Planned && !o.unmet_dependencies.is_empty();
            o.compensation = if n.inverse.is_none() {
                Compensation::Unregistered
            } else if !self.compensation_requested {
                Compensation::NotRequested
            } else {
                match o.forward {
                    Forward::Unknown => Compensation::BlockedForwardUnknown,
                    Forward::Committed => Compensation::RequiresFreshAdmissionAndBarrier,
                    _ => Compensation::BlockedNotCommitted,
                }
            };
        }
        self.status = if self.nodes.values().any(|n| {
            n.dependency_violation || matches!(n.forward, Forward::Failed | Forward::ProvenNoEffect)
        }) || self.compensation_requested
        {
            Status::NeedsOperator
        } else if self.nodes.values().any(|n| n.forward == Forward::Unknown) {
            Status::Unresolved
        } else if self.nodes.values().all(|n| n.forward == Forward::Committed) {
            Status::Completed
        } else {
            Status::Active
        };
    }
    fn validate(&self, plan: &Plan) -> Result<()> {
        schema(&json!(self))?;
        if self.plan_digest != plan.digest()?
            || canonical(&json!(self))?.len() > MAX_STATE
            || self.nodes.keys().collect::<BTreeSet<_>>()
                != plan.nodes.iter().map(|n| &n.node_id).collect()
        {
            return Err(refuse());
        }
        for o in self.nodes.values() {
            if match o.forward {
                Forward::Planned => {
                    o.proof_digest.is_some()
                        || o.grant_digest.is_some()
                        || o.attempt_id.is_some()
                        || o.receipt_digest.is_some()
                        || o.dependency_violation
                }
                Forward::Issued => {
                    o.proof_digest.is_none()
                        || o.grant_digest.is_none()
                        || o.attempt_id.is_some()
                        || o.receipt_digest.is_some()
                }
                Forward::Unknown => {
                    o.proof_digest.is_none() || o.grant_digest.is_none() || o.attempt_id.is_none()
                }
                _ => {
                    o.proof_digest.is_none()
                        || o.grant_digest.is_none()
                        || o.attempt_id.is_none()
                        || o.receipt_digest.is_none()
                }
            } {
                return Err(refuse());
            }
        }
        let mut expected = self.clone();
        expected.derive(plan);
        if expected != *self {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub profile: String,
    pub plan_digest: String,
    pub revision: u64,
    pub previous_digest: Option<String>,
    pub phase: String,
    pub after: Snapshot,
}
impl Event {
    fn digest(&self) -> Result<String> {
        digest("saga-observation-event", &json!(self))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    profile: String,
    revision: u64,
    event_digest: String,
    state_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimProof {
    attempt: crate::ledger::Attempt,
    outbox: String,
    execution: crate::recovery::ExecutionRecord,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    authorization: AuthorizationBundle,
    binding: ReservationBinding,
    claim: Option<ClaimProof>,
    outcomes: Option<OutcomeBundle>,
}
struct Retained {
    state: Snapshot,
    head: Head,
    compare: Vec<Value>,
}
/// Operator-owned observer. Its API cannot issue, claim, dispatch or execute inverses.
pub struct SagaObserver {
    ledger: EtcdLedger,
    plan: Plan,
    trust: Trust,
    base: String,
}
impl SagaObserver {
    pub fn new(ledger: EtcdLedger, plan: Plan, trust: Trust) -> Result<Self> {
        plan.validate(&trust)?;
        if ledger.namespace() != trust.namespace
            || ledger.reservation.as_deref() != Some(&trust.registration)
        {
            return Err(refuse());
        }
        let base = format!(
            "{}/saga-observations/{}",
            ledger.namespace(),
            key_part(&plan.saga_id)
        );
        Ok(Self {
            ledger,
            plan,
            trust,
            base,
        })
    }
    fn root_key(&self) -> String {
        format!(
            "{}/saga-observation-roots/{}",
            self.ledger.namespace(),
            key_part(&self.trust.registration.root_id)
        )
    }
    fn operation_key(&self, op: &str) -> String {
        format!(
            "{}/saga-observation-operations/{op}",
            self.ledger.namespace()
        )
    }
    fn marker(&self) -> Result<String> {
        let t = &self.trust.lineage;
        let encode = |keys: &BTreeMap<String, ed25519_dalek::VerifyingKey>| {
            keys.iter()
                .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                .collect::<BTreeMap<_, _>>()
        };
        // The enforcement digest includes all evidence/review/lease definitions
        // and signer pins through the registered obligation manifest digest.
        let trust_digest = digest(
            "saga-observation-trust",
            &json!({
                "registration":self.plan.registration_digest,"namespace":self.trust.namespace,
                "enforcement_trust":crate::governance::trust_digest(&t.admission,&t.admission_keys,&t.grants.keys)?,
                "policy":t.policy,"subjects":t.subjects,"delegation_audience":t.delegation_audience,
                "workload":t.admission.proposal_workload_id,"scope":t.admission.required_scope,
                "max_proposal_age_ms":t.admission.max_proposal_age_ms,
                "outcome_keys":encode(&t.outcome_keys),"source_id":t.source_id,
                "observer_id":self.trust.observer_id,"observer_keys":encode(&self.trust.observer_keys)
            }),
        )?;
        record(&json!({"profile":PROFILE,"saga_id":self.plan.saga_id,
            "plan_digest":self.plan.digest()?,"registration_digest":self.plan.registration_digest,
            "trust_digest":trust_digest}))
    }
    fn event_key(&self, n: u64) -> String {
        format!("{}/events/{n:06}", self.base)
    }
    fn proof_key(&self, d: &str) -> String {
        format!("{}/proofs/{d}", self.base)
    }
    async fn raw(&self, key: &str, bound: usize) -> Result<Vec<u8>> {
        let b = self.ledger.read_key(key).await?.ok_or_else(refuse)?;
        if b.len() > bound {
            return Err(refuse());
        }
        Ok(b)
    }
    async fn retained(&self) -> Result<Retained> {
        let plan_key = format!("{}/plan", self.base);
        let expected = record(&self.plan)?;
        if self.raw(&plan_key, MAX_STATE).await? != expected.as_bytes() {
            return Err(refuse());
        }
        let marker = self.marker()?;
        let mut compare = vec![value_eq(&plan_key, &expected)];
        for key in std::iter::once(self.root_key()).chain(
            self.plan
                .nodes
                .iter()
                .map(|n| self.operation_key(&n.operation_key)),
        ) {
            if self.raw(&key, 4096).await? != marker.as_bytes() {
                return Err(refuse());
            }
            compare.push(value_eq(&key, &marker));
        }
        let state_key = format!("{}/state", self.base);
        let raw = self.raw(&state_key, MAX_STATE).await?;
        let v = strict_value(&raw)?;
        schema(&v)?;
        let state: Snapshot = serde_json::from_value(v)?;
        state.validate(&self.plan)?;
        compare.push(value_eq(
            &state_key,
            std::str::from_utf8(&raw).map_err(|_| refuse())?,
        ));
        let head_key = format!("{}/head", self.base);
        let raw = self.raw(&head_key, 4096).await?;
        let v = strict_value(&raw)?;
        schema(&v)?;
        let head: Head = serde_json::from_value(v)?;
        compare.push(value_eq(
            &head_key,
            std::str::from_utf8(&raw).map_err(|_| refuse())?,
        ));
        let key = self.event_key(head.revision);
        let raw = self.raw(&key, 128 << 10).await?;
        let v = strict_value(&raw)?;
        schema(&v)?;
        let e: Event = serde_json::from_value(v)?;
        if head.revision != state.revision
            || head.event_digest != e.digest()?
            || head.state_digest != digest("saga-observation-state", &json!(state))?
            || e.plan_digest != self.plan.digest()?
            || e.revision != state.revision
            || e.after != state
        {
            return Err(refuse());
        }
        compare.push(value_eq(
            &key,
            std::str::from_utf8(&raw).map_err(|_| refuse())?,
        ));
        for o in state.nodes.values() {
            if let Some(d) = &o.proof_digest {
                let raw = self.raw(&self.proof_key(d), MAX_PROOF).await?;
                let v = strict_value(&raw)?;
                let _: Proof = serde_json::from_value(v.clone())?;
                if digest("saga-observation-proof", &v)? != *d {
                    return Err(refuse());
                }
                compare.push(value_eq(
                    &self.proof_key(d),
                    std::str::from_utf8(&raw).map_err(|_| refuse())?,
                ));
            }
        }
        Ok(Retained {
            state,
            head,
            compare,
        })
    }
    pub async fn status(&self) -> Result<Snapshot> {
        let r = self.retained().await?;
        if !self
            .ledger
            .txn(
                r.compare,
                vec![get(&format!("{}/state", self.base))],
                vec![],
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(r.state)
    }
    pub async fn enroll(&self) -> Result<Snapshot> {
        if self
            .ledger
            .read_key(&format!("{}/plan", self.base))
            .await?
            .is_some()
        {
            return self.status().await;
        }
        let r = &self.trust.registration;
        let gate = self
            .ledger
            .reservation_gate_for(&r.scope.conflict_domain, true)
            .await?
            .ok_or_else(refuse)?;
        if gate.r != *r
            || gate.state.allocations != r.hierarchy.as_ref().ok_or_else(refuse)?.initial()?
        {
            return Err(refuse());
        }
        let mut compare = gate.compare;
        let marker = self.marker()?;
        let mut writes = vec![];
        for key in std::iter::once(self.root_key()).chain(
            self.plan
                .nodes
                .iter()
                .map(|n| self.operation_key(&n.operation_key)),
        ) {
            compare.push(version_zero(&key));
            writes.push(put(&key, &marker));
        }
        for n in &self.plan.nodes {
            compare.push(version_zero(&format!(
                "{}/issuance/{}",
                self.ledger.namespace(),
                n.operation_key
            )));
        }
        let key = format!("{}/plan", self.base);
        compare.push(version_zero(&key));
        writes.push(put(&key, &record(&self.plan)?));
        let mut state = Snapshot {
            profile: PROFILE.into(),
            plan_digest: self.plan.digest()?,
            revision: 1,
            compensation_requested: false,
            budget_active: true,
            status: Status::Active,
            nodes: self
                .plan
                .nodes
                .iter()
                .map(|n| {
                    (
                        n.node_id.clone(),
                        Observation {
                            forward: Forward::Planned,
                            grant_digest: None,
                            attempt_id: None,
                            receipt_digest: None,
                            proof_digest: None,
                            compensation: Compensation::Unregistered,
                            unmet_dependencies: vec![],
                            dependency_violation: false,
                        },
                    )
                })
                .collect(),
            execution_authority: false,
            dependency_order_enforced: false,
        };
        state.derive(&self.plan);
        self.save(None, state, "enroll", compare, writes).await
    }
    async fn save(
        &self,
        before: Option<&Retained>,
        mut state: Snapshot,
        phase: &str,
        mut compare: Vec<Value>,
        mut writes: Vec<Value>,
    ) -> Result<Snapshot> {
        let revision = before.map_or(1, |b| b.state.revision + 1);
        if revision > MAX_EVENTS {
            return Err(refuse());
        }
        state.revision = revision;
        state.validate(&self.plan)?;
        let e = Event {
            profile: PROFILE.into(),
            plan_digest: self.plan.digest()?,
            revision,
            previous_digest: before.map(|b| b.head.event_digest.clone()),
            phase: phase.into(),
            after: state.clone(),
        };
        let raw = record(&e)?;
        if raw.len() > 128 << 10 {
            return Err(refuse());
        }
        let head = Head {
            profile: PROFILE.into(),
            revision,
            event_digest: e.digest()?,
            state_digest: digest("saga-observation-state", &json!(state))?,
        };
        let key = self.event_key(revision);
        compare.push(version_zero(&key));
        writes.push(put(&key, &raw));
        for (suffix, value) in [("head", record(&head)?), ("state", record(&state)?)] {
            let key = format!("{}/{suffix}", self.base);
            if before.is_none() {
                compare.push(version_zero(&key));
            }
            writes.push(put(&key, &value));
        }
        bounded(&mut compare, &writes)?;
        if !self.ledger.txn(compare, writes, vec![]).await?.succeeded {
            return Err(refuse());
        }
        Ok(state)
    }
    pub async fn request_compensation(&self) -> Result<Snapshot> {
        let before = self.retained().await?;
        if before.state.compensation_requested {
            return self.status().await;
        }
        let mut after = before.state.clone();
        after.compensation_requested = true;
        after.derive(&self.plan);
        self.save(
            Some(&before),
            after,
            "request_compensation",
            before.compare.clone(),
            vec![],
        )
        .await
    }
    async fn observe(
        &self,
        node: &Node,
        compare: &mut Vec<Value>,
    ) -> Result<(Observation, Option<Proof>)> {
        let issuance_key = format!(
            "{}/issuance/{}",
            self.ledger.namespace(),
            node.operation_key
        );
        let Some(proof) = self.ledger.retained_operation(&node.operation_key).await? else {
            compare.push(version_zero(&issuance_key));
            return Ok((
                Observation {
                    forward: Forward::Planned,
                    grant_digest: None,
                    attempt_id: None,
                    receipt_digest: None,
                    proof_digest: None,
                    compensation: Compensation::Unregistered,
                    unmet_dependencies: vec![],
                    dependency_violation: false,
                },
                None,
            ));
        };
        let auth = self
            .ledger
            .export_authorization(&node.operation_key)
            .await?;
        let g = self
            .trust
            .lineage
            .grants
            .verify_retained(auth.issuance.signed_grant.as_bytes())?;
        let verified = verify_authorization(&auth, &leaf_trust(&self.trust, &g.grant)?)?;
        if proof.0 != auth.issuance
            || verified.operation_key != node.operation_key
            || Principal::from_grant(&g.grant) != node.principal
        {
            return Err(refuse());
        }
        compare.push(value_eq(&issuance_key, &record(&auth.issuance)?));
        let (gate, binding) = self
            .ledger
            .reservation_bound(&g.grant, &g.digest, false)
            .await?
            .ok_or_else(refuse)?;
        compare.extend(gate.compare);
        let allocation = gate
            .state
            .allocations
            .get(&node.operation_key)
            .ok_or_else(refuse)?;
        let mut observation = Observation {
            forward: Forward::Issued,
            grant_digest: Some(g.digest.clone()),
            attempt_id: allocation.attempt_id.clone(),
            receipt_digest: None,
            proof_digest: None,
            compensation: Compensation::Unregistered,
            unmet_dependencies: vec![],
            dependency_violation: false,
        };
        let mut claim = None;
        let outcomes = if let Some(id) = &allocation.attempt_id {
            observation.forward = Forward::Unknown;
            let candidate = Candidate {
                grant: g.grant.clone(),
                attempt_id: id.clone(),
            };
            let s = self.ledger.recovery_snapshot(&candidate).await?;
            s.context.validate(&g.grant, &g.digest)?;
            if s.context.parameters != verified.parameters {
                return Err(refuse());
            }
            compare.extend([
                value_eq(&self.ledger.attempt(&g.grant, id), &record(&s.attempt)?),
                value_eq(&self.ledger.outbox(&g.grant, id), &s.outbox),
                value_eq(
                    &crate::recovery::context_key(&self.ledger, &g.grant, id),
                    &s.context_raw,
                ),
            ]);
            claim = Some(ClaimProof {
                attempt: s.attempt.clone(),
                outbox: s.outbox.clone(),
                execution: s.context.clone(),
            });
            let key = format!("{}/receipt-head", self.ledger.attempt(&g.grant, id));
            compare.push(match &s.head_raw {
                Some(raw) => value_eq(&key, raw),
                None => version_zero(&key),
            });
            if let Some(head) = s.head {
                let out = self.ledger.export_outcomes(&candidate).await?;
                let v = verify_outcomes(
                    &out,
                    &self.trust.lineage.grants,
                    &self.trust.lineage.outcome_keys,
                    &self.trust.lineage.source_id,
                )?;
                let last = crate::schema::verify_record(
                    out.receipts.last().ok_or_else(refuse)?.as_bytes(),
                    "receipt",
                    &self.trust.lineage.outcome_keys,
                )?;
                if record_digest(&last)? != head.receipt_digest {
                    return Err(refuse());
                }
                observation.receipt_digest = Some(head.receipt_digest);
                observation.forward = match (v.reported_status.as_str(), &allocation.state) {
                    ("committed", B::Committed) => Forward::Committed,
                    ("not_dispatched", B::ProvenNoEffect) => Forward::ProvenNoEffect,
                    ("failed", B::Unknown) => Forward::Failed,
                    (_, B::Unknown) => Forward::Unknown,
                    _ => return Err(refuse()),
                };
                Some(out)
            } else {
                if matches!(allocation.state, B::Committed | B::ProvenNoEffect) {
                    return Err(refuse());
                }
                None
            }
        } else {
            if allocation.state != B::Allocated {
                return Err(refuse());
            }
            None
        };
        Ok((
            observation,
            Some(Proof {
                authorization: auth,
                binding,
                claim,
                outcomes,
            }),
        ))
    }
    pub async fn reconcile(&self) -> Result<Snapshot> {
        let before = self.retained().await?;
        let r = &self.trust.registration;
        let gate = self
            .ledger
            .reservation_gate_for(&r.scope.conflict_domain, false)
            .await?
            .ok_or_else(refuse)?;
        let skeleton = r.hierarchy.as_ref().ok_or_else(refuse)?.initial()?;
        if gate.r != *r
            || gate.state.allocations.keys().any(|op| {
                !skeleton.contains_key(op)
                    && !self.plan.nodes.iter().any(|n| &n.operation_key == op)
            })
        {
            return Err(refuse());
        }
        let mut compare = before.compare.clone();
        compare.extend(gate.compare);
        let mut after = before.state.clone();
        after.budget_active = gate.state.active;
        let mut writes = vec![];
        for n in &self.plan.nodes {
            let (mut observed, proof) = self.observe(n, &mut compare).await?;
            let old = &before.state.nodes[&n.node_id];
            if observed.forward == Forward::Planned
                && gate.state.allocations.contains_key(&n.operation_key)
            {
                return Err(refuse());
            }
            if old.grant_digest.is_some() && old.grant_digest != observed.grant_digest
                || old.attempt_id.is_some() && old.attempt_id != observed.attempt_id
                || matches!(
                    old.forward,
                    Forward::Committed | Forward::ProvenNoEffect | Forward::Failed
                ) && old.forward != observed.forward
                || old.forward == Forward::Unknown
                    && matches!(observed.forward, Forward::Planned | Forward::Issued)
                || old.forward == Forward::Issued && observed.forward == Forward::Planned
            {
                return Err(refuse());
            }
            observed.dependency_violation = old.dependency_violation;
            if let Some(proof) = proof {
                if let Some(previous) = &old.receipt_digest {
                    let chain = proof.outcomes.as_ref().ok_or_else(refuse)?;
                    if !chain.receipts.iter().any(|raw| {
                        crate::schema::verify_record(
                            raw.as_bytes(),
                            "receipt",
                            &self.trust.lineage.outcome_keys,
                        )
                        .and_then(|e| record_digest(&e))
                        .is_ok_and(|d| &d == previous)
                    }) {
                        return Err(refuse());
                    }
                }
                let raw = record(&proof)?;
                if raw.len() > MAX_PROOF {
                    return Err(refuse());
                }
                let d = digest("saga-observation-proof", &json!(proof))?;
                let key = self.proof_key(&d);
                match self.ledger.read_key(&key).await? {
                    Some(bytes) if bytes == raw.as_bytes() => compare.push(value_eq(&key, &raw)),
                    None => {
                        compare.push(version_zero(&key));
                        writes.push(put(&key, &raw));
                    }
                    _ => return Err(refuse()),
                }
                observed.proof_digest = Some(d);
            }
            after.nodes.insert(n.node_id.clone(), observed);
        }
        after.derive(&self.plan);
        if after == before.state {
            bounded(&mut compare, &[get(&format!("{}/state", self.base))])?;
            if !self
                .ledger
                .txn(compare, vec![get(&format!("{}/state", self.base))], vec![])
                .await?
                .succeeded
            {
                return Err(refuse());
            }
            return Ok(after);
        }
        self.save(Some(&before), after, "reconcile", compare, writes)
            .await
    }
    pub async fn history(&self) -> Result<Vec<Event>> {
        let before = self.retained().await?;
        let mut events: Vec<Event> = vec![];
        let mut previous = None;
        for n in 1..=before.head.revision {
            let raw = self.raw(&self.event_key(n), 128 << 10).await?;
            let v = strict_value(&raw)?;
            schema(&v)?;
            let e: Event = serde_json::from_value(v)?;
            e.after.validate(&self.plan)?;
            if e.plan_digest != self.plan.digest()?
                || e.revision != n
                || e.after.revision != n
                || e.previous_digest != previous
                || (n == 1) != (e.phase == "enroll")
            {
                return Err(refuse());
            }
            if let Some(old) = events.last() {
                if old.after.compensation_requested && !e.after.compensation_requested
                    || !old.after.budget_active && e.after.budget_active
                {
                    return Err(refuse());
                }
                match e.phase.as_str() {
                    "request_compensation" => {
                        if old.after.compensation_requested {
                            return Err(refuse());
                        }
                        let mut expected = old.after.clone();
                        expected.revision = n;
                        expected.compensation_requested = true;
                        expected.derive(&self.plan);
                        if expected != e.after {
                            return Err(refuse());
                        }
                    }
                    "reconcile" => {
                        if old.after.compensation_requested != e.after.compensation_requested {
                            return Err(refuse());
                        }
                        for (id, a) in &old.after.nodes {
                            let b = &e.after.nodes[id];
                            if a.grant_digest.is_some() && a.grant_digest != b.grant_digest
                                || a.attempt_id.is_some() && a.attempt_id != b.attempt_id
                                || a.dependency_violation && !b.dependency_violation
                                || matches!(
                                    a.forward,
                                    Forward::Committed | Forward::ProvenNoEffect | Forward::Failed
                                ) && a.forward != b.forward
                                || a.forward != Forward::Planned && b.forward == Forward::Planned
                                || a.forward == Forward::Unknown && b.forward == Forward::Issued
                            {
                                return Err(refuse());
                            }
                        }
                    }
                    _ => return Err(refuse()),
                }
            } else if e.after.compensation_requested
                || !e.after.budget_active
                || e.after
                    .nodes
                    .values()
                    .any(|n| n.forward != Forward::Planned)
            {
                return Err(refuse());
            }
            for o in e.after.nodes.values() {
                if let Some(d) = &o.proof_digest {
                    let raw = self.raw(&self.proof_key(d), MAX_PROOF).await?;
                    let value = strict_value(&raw)?;
                    let _: Proof = serde_json::from_value(value.clone())?;
                    if digest("saga-observation-proof", &value)? != *d {
                        return Err(refuse());
                    }
                }
            }
            previous = Some(e.digest()?);
            events.push(e);
        }
        if previous.as_ref() != Some(&before.head.event_digest)
            || events.last().is_none_or(|e| e.after != before.state)
        {
            return Err(refuse());
        }
        if !self
            .ledger
            .txn(
                before.compare,
                vec![get(&format!("{}/state", self.base))],
                vec![],
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(events)
    }
}
