//! Explicit reserved-lineage carriage with independently approved observer and role pins.
use crate::{
    contracts::{GrantVerifier, canonical, digest, record_digest, strict_value},
    control_history::HistoryObserver,
    coordination::{ReservationSnapshot, ReservationState as S},
    error::{Error, Result},
    ledger::{EtcdLedger, get},
    lineage::{
        AuthorizationBundle, LineageBundle, LineageTrust, LineageVerification,
        verify_authorization, verify_lineage,
    },
    lineage_config::LineageTrustConfig,
    recovery::Candidate,
    reservation_history::{
        Event, EventData, HIERARCHICAL_LEAF_PROFILE, HIERARCHICAL_PROFILE, LEAF_PROFILE,
        MAX_BUNDLE, MAX_EVENTS, PROFILE, history_profile,
    },
    reserved_leaf::Registration,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
fn refuse() -> Error {
    Error::Refused("reserved lineage verification refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPayload {
    pub observer_id: String,
    pub namespace: String,
    pub registration_digest: String,
    pub event_count: u64,
    pub head_digest: String,
    pub lineage_digest: String,
    pub operation_key: String,
    pub grant_digest: String,
    pub attempt_id: String,
    pub captured_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorizations_digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub profile: String,
    pub key_id: String,
    pub payload: CheckpointPayload,
    pub signature: String,
}
impl Checkpoint {
    fn message(&self) -> Result<Vec<u8>> {
        let mut b = format!("KedgeFlow:{}\0", self.profile).into_bytes();
        b.extend(canonical(
            &json!({"profile":self.profile,"key_id":self.key_id,"payload":self.payload}),
        )?);
        Ok(b)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub profile: String,
    pub lineage: LineageBundle,
    pub events: Vec<Event>,
    pub checkpoint: Checkpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorizations: Option<BTreeMap<String, AuthorizationBundle>>,
}
impl Bundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BUNDLE {
            return Err(refuse());
        }
        let value = strict_value(raw)?;
        validate(&value)?;
        let b: Self = serde_json::from_value(value)?;
        b.bound()?;
        Ok(b)
    }
    fn bound(&self) -> Result<()> {
        if ![
            PROFILE,
            HIERARCHICAL_PROFILE,
            crate::saga_forward::LINEAGE_PROFILE,
        ]
        .contains(&self.profile.as_str())
            || self.events.is_empty()
            || self.events.len() > MAX_EVENTS as usize
            || canonical(&json!(self))?.len() > MAX_BUNDLE
        {
            return Err(refuse());
        }
        validate(&json!(self))?;
        LineageBundle::decode(&canonical(&json!(self.lineage))?)?;
        for event in &self.events {
            if canonical(&json!(event))?.len() > 256 << 10
                || canonical(&json!(event.after))?.len() > 128 << 10
            {
                return Err(refuse());
            }
        }
        Ok(())
    }
}
fn validate(value: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    static HIERARCHICAL_SCHEMA: std::sync::OnceLock<jsonschema::Validator> =
        std::sync::OnceLock::new();
    static SAGA_SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let (slot, raw) = match value["profile"].as_str() {
        Some(crate::saga_forward::LINEAGE_PROFILE) => (
            &SAGA_SCHEMA,
            include_str!("../../../spec/drafts/saga-forward-lineage-v0.1.schema.json"),
        ),
        Some(PROFILE) => (
            &SCHEMA,
            include_str!("../../../spec/drafts/reserved-lineage-v0.1.schema.json"),
        ),
        Some(HIERARCHICAL_PROFILE) => (
            &HIERARCHICAL_SCHEMA,
            include_str!("../../../spec/drafts/hierarchical-lineage-v0.1.schema.json"),
        ),
        _ => return Err(refuse()),
    };
    let schema = slot.get_or_init(|| {
        crate::schema::compile(&serde_json::from_str(raw).expect("lineage schema"))
            .expect("valid lineage schema")
    });
    if !schema.is_valid(value) {
        return Err(refuse());
    }
    Ok(())
}
#[derive(Clone)]
pub struct Trust {
    pub registration: Registration,
    pub namespace: String,
    pub observer_id: String,
    pub observer_keys: BTreeMap<String, VerifyingKey>,
    pub lineage: LineageTrust,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    pub registration: Registration,
    pub namespace: String,
    pub observer_id: String,
    pub observer_keys: BTreeMap<String, String>,
    pub lineage: LineageTrustConfig,
}
impl TrustConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(refuse());
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub fn registration(&self) -> Result<Trust> {
        let t = Trust {
            registration: self.registration.clone(),
            namespace: self.namespace.clone(),
            observer_id: self.observer_id.clone(),
            observer_keys: crate::control_config::keys(&self.observer_keys)?,
            lineage: self.lineage.registration()?,
        };
        t.validate()?;
        Ok(t)
    }
}
impl Trust {
    pub fn validate(&self) -> Result<()> {
        self.registration.validate()?;
        self.lineage.validate()?;
        let r = &self.registration;
        if ![
            LEAF_PROFILE,
            HIERARCHICAL_LEAF_PROFILE,
            crate::saga_forward::PROFILE,
        ]
        .contains(&r.profile.as_str())
            || self.namespace.is_empty()
            || self.namespace.len() > 1024
            || self.observer_id.is_empty()
            || self.observer_id.len() > 256
            || self.observer_keys.is_empty()
            || r.enrollment.tenant != self.lineage.admission.tenant
            || r.policy != self.lineage.admission.policy
            || r.ownership_epoch != self.lineage.admission.ownership_epoch
            || r.scope.action.digest != self.lineage.admission.descriptor_digest
            || r.scope.audience != self.lineage.grants.audience
            || crate::control_config::keys(&r.issuer_keys)? != self.lineage.grants.keys
        {
            return Err(refuse());
        }
        if let Some(p) = &r.saga
            && (p.keys()? != self.lineage.outcome_keys || p.source_id != self.lineage.source_id)
        {
            return Err(refuse());
        }
        let t = &self.lineage;
        let roles = t
            .admission
            .proposal_keys
            .values()
            .chain(t.admission.registry_keys.values())
            .chain(t.admission.manifest_keys.values())
            .chain(t.admission.evidence.values().flat_map(|e| e.keys.values()))
            .chain(t.admission_keys.values())
            .chain(t.grants.keys.values())
            .chain(t.outcome_keys.values())
            .collect::<Vec<_>>();
        if self.observer_keys.values().any(|k| roles.contains(&k)) {
            return Err(refuse());
        }
        if let Some(h) = &r.hierarchy
            && (!h.distinct(roles) || !h.distinct(self.observer_keys.values()))
        {
            return Err(refuse());
        }
        Ok(())
    }
}
// The protected registration approves the exact subject/workload assignment.
// Other historical role/policy pins are never inferred from exported material.
pub(crate) fn leaf_trust(trust: &Trust, grant: &crate::contracts::Grant) -> Result<LineageTrust> {
    trust.registration.grant(grant)?;
    let mut t = trust.lineage.clone();
    if trust.registration.hierarchy.is_some() {
        t.admission.proposal_workload_id = grant.workload_id.clone();
    }
    Ok(t)
}
fn equal(a: &impl Serialize, b: &impl Serialize) -> Result<bool> {
    Ok(canonical(&serde_json::to_value(a)?)? == canonical(&serde_json::to_value(b)?)?)
}
struct Replay {
    state: ReservationSnapshot,
    refinements: BTreeMap<String, String>,
}
fn replay(
    events: &[Event],
    trust: &Trust,
    captured_at: i64,
    authorizations: Option<&BTreeMap<String, AuthorizationBundle>>,
) -> Result<Replay> {
    let r = &trust.registration;
    let mut state = ReservationSnapshot {
        profile: crate::coordination::PROFILE.into(),
        enrollment: r.enrollment.clone(),
        active: true,
        execution_authority: false,
        allocations: r.initial_allocations()?,
    };
    let mut remaining = authorizations.cloned().unwrap_or_default();
    if (r.hierarchy.is_some()) != authorizations.is_some() {
        return Err(refuse());
    }
    let mut previous = None;
    let mut issued = BTreeMap::new();
    let mut fences = BTreeMap::new();
    let mut last_fence = 0;
    let mut claimed = BTreeMap::new();
    let mut dispatched = BTreeSet::new();
    let mut refinements = BTreeMap::new();
    let grants = GrantVerifier {
        keys: crate::control_config::keys(&r.issuer_keys)?,
        audience: r.scope.audience.clone(),
    };
    for (i, event) in events.iter().enumerate() {
        if event.profile != history_profile(r)
            || event.registration_digest != r.digest()?
            || event.sequence != i as u64 + 1
            || event.previous_digest != previous
            || event.sequence == MAX_EVENTS && event.data.phase != "stop"
        {
            return Err(refuse());
        }
        let d = &event.data;
        let op = d.operation_key.as_deref();
        let mut clean = EventData::new(&d.phase, op);
        let mut after = state.clone();
        match d.phase.as_str() {
            "enroll" => {
                if i != 0 || op.is_some() {
                    return Err(refuse());
                }
            }
            "stop" => {
                if i == 0 || !state.active || op.is_some() {
                    return Err(refuse());
                }
                after.active = false;
            }
            "allocate" => {
                if r.hierarchy.is_some() {
                    return Err(refuse());
                }
                let op = op.ok_or_else(refuse)?;
                if i == 0
                    || !state.active
                    || !crate::grant_reference::valid_reference(op)
                    || state.allocations.contains_key(op)
                {
                    return Err(refuse());
                }
                let fence = d.fence.ok_or_else(refuse)?;
                if fence <= last_fence || fence > crate::contracts::MAX_SAFE_INTEGER {
                    return Err(refuse());
                }
                last_fence = fence;
                fences.insert(op.to_owned(), fence);
                clean.fence = Some(fence);
                after.allocations.insert(op.into(), r.allocation(op));
            }
            "issue" => {
                let op = op.ok_or_else(refuse)?;
                if !state.active || issued.contains_key(op) {
                    return Err(refuse());
                }
                let raw = d.signed_grant.as_ref().ok_or_else(refuse)?;
                let g = grants.verify_retained(raw.as_bytes())?;
                r.grant(&g.grant)?;
                if g.grant.issued_at > captured_at {
                    return Err(refuse());
                }
                if r.hierarchy.is_some() {
                    let fence = d.fence.ok_or_else(refuse)?;
                    if (r.saga.is_none() && state.allocations.contains_key(op))
                        || fence != g.grant.fence
                        || fence == 0
                        || fence > crate::contracts::MAX_SAFE_INTEGER
                        || fences.values().any(|f| *f == fence)
                    {
                        return Err(refuse());
                    }
                    let proof = remaining.remove(op).ok_or_else(refuse)?;
                    let verified = verify_authorization(&proof, &leaf_trust(trust, &g.grant)?)?;
                    if verified.operation_key != op
                        || verified.issuance.grant_digest != g.digest
                        || !equal(
                            &strict_value(proof.issuance.signed_grant.as_bytes())?,
                            &strict_value(raw.as_bytes())?,
                        )?
                    {
                        return Err(refuse());
                    }
                    fences.insert(op.to_owned(), fence);
                    clean.fence = Some(fence);
                    if let Some(plan) = &r.saga {
                        plan.dependencies(&state, op)?;
                    } else {
                        after
                            .allocations
                            .insert(op.into(), r.allocation_for(op, &g.grant)?);
                    }
                }
                let a = after.allocations.get(op).ok_or_else(refuse)?;
                if r.hierarchy.is_some() {
                    r.matches_for(a, op, &g.grant)?;
                } else {
                    r.matches(a, op)?;
                }
                if a.state != S::Allocated || fences.get(op) != Some(&g.grant.fence) {
                    return Err(refuse());
                }
                let b = d.binding.as_ref().ok_or_else(refuse)?;
                b.verify(r, &g.grant, &g.digest)?;
                if b.payload.operation_key != op
                    || d.grant_digest.as_deref() != Some(g.digest.as_str())
                {
                    return Err(refuse());
                }
                clean.grant_digest = d.grant_digest.clone();
                clean.binding = d.binding.clone();
                clean.signed_grant = d.signed_grant.clone();
                issued.insert(op.to_owned(), g);
            }
            "claim" | "dispatch" | "refine" => {
                let op = op.ok_or_else(refuse)?;
                let g = issued.get(op).ok_or_else(refuse)?;
                let attempt = d.attempt_id.as_ref().ok_or_else(refuse)?;
                if attempt.is_empty()
                    || attempt.len() > 256
                    || d.grant_digest.as_deref() != Some(g.digest.as_str())
                {
                    return Err(refuse());
                }
                clean.grant_digest = d.grant_digest.clone();
                clean.attempt_id = d.attempt_id.clone();
                if d.phase != "refine"
                    && let Some(plan) = &r.saga
                {
                    plan.dependencies(&state, op)?;
                }
                let a = after.allocations.get_mut(op).ok_or_else(refuse)?;
                if d.phase == "claim" {
                    if !state.active
                        || a.state != S::Allocated
                        || a.attempt_id.is_some()
                        || claimed.insert(op.to_owned(), attempt.clone()).is_some()
                    {
                        return Err(refuse());
                    }
                    a.state = S::Unknown;
                    a.attempt_id = Some(attempt.clone());
                } else {
                    if claimed.get(op) != Some(attempt)
                        || a.state != S::Unknown
                        || a.attempt_id.as_ref() != Some(attempt)
                    {
                        return Err(refuse());
                    }
                    if d.phase == "dispatch" {
                        if !state.active || !dispatched.insert(op.to_owned()) {
                            return Err(refuse());
                        }
                    } else {
                        let h = d.outcome.as_ref().ok_or_else(refuse)?;
                        let evidence = d.evidence.as_ref().ok_or_else(refuse)?;
                        let receipt = crate::schema::verify_record(
                            h.signed_receipt.as_bytes(),
                            "receipt",
                            &trust.lineage.outcome_keys,
                        )?;
                        crate::recovery::verify_receipt_binding(
                            &receipt,
                            &g.grant,
                            &g.digest,
                            attempt,
                            &trust.lineage.source_id,
                        )?;
                        let event_time =
                            receipt.payload["event_time"].as_i64().ok_or_else(refuse)?;
                        if event_time < g.grant.issued_at || event_time > captured_at {
                            return Err(refuse());
                        }
                        if record_digest(&receipt)? != h.receipt_digest
                            || digest("outcome-evidence", evidence)? != h.evidence_digest
                            || receipt.payload["resolution_evidence"]
                                != json!([{"id":h.evidence_digest,"schema":crate::recovery::EVIDENCE_SCHEMA,"digest":h.evidence_digest}])
                        {
                            return Err(refuse());
                        }
                        a.state = match h.state.as_str() {
                            "committed"
                                if dispatched.contains(op)
                                    && receipt.payload["status"] == "committed" =>
                            {
                                S::Committed
                            }
                            "not_dispatched"
                                if !dispatched.contains(op)
                                    && receipt.payload["status"] == "not_dispatched" =>
                            {
                                S::ProvenNoEffect
                            }
                            _ => return Err(refuse()),
                        };
                        if refinements
                            .insert(op.to_owned(), h.receipt_digest.clone())
                            .is_some()
                        {
                            return Err(refuse());
                        }
                        clean.outcome = d.outcome.clone();
                        clean.evidence = d.evidence.clone();
                    }
                }
            }
            _ => return Err(refuse()),
        }
        if i > 0 && d.phase == "enroll" || !equal(d, &clean)? || after != event.after {
            return Err(refuse());
        }
        event.after.validate()?;
        if let Some(h) = &r.hierarchy {
            h.snapshot(r, &event.after)?;
        }
        state = after;
        previous = Some(event.digest()?);
    }
    if !remaining.is_empty() || events.first().is_none_or(|e| e.data.phase != "enroll") {
        return Err(refuse());
    }
    Ok(Replay { state, refinements })
}
#[derive(Serialize)]
pub struct Verification {
    pub profile: String,
    pub lineage: LineageVerification,
    pub events_verified: usize,
    pub budget_active: bool,
    pub budget_state: S,
    pub held_forward: u64,
    pub held_compensation: u64,
    pub execution_authority: bool,
    pub missing_links: Vec<String>,
}
pub fn verify(bundle: &Bundle, trust: &Trust) -> Result<Verification> {
    trust.validate()?;
    bundle.bound()?;
    let c = &bundle.checkpoint;
    let p = &c.payload;
    let key = trust.observer_keys.get(&c.key_id).ok_or_else(refuse)?;
    let raw = URL_SAFE_NO_PAD.decode(&c.signature).map_err(|_| refuse())?;
    let sig = Signature::from_slice(&raw).map_err(|_| refuse())?;
    if bundle.profile != history_profile(&trust.registration)
        || c.profile != bundle.profile
        || p.authorizations_digest
            != bundle
                .authorizations
                .as_ref()
                .map(|a| digest("hierarchical-authorizations", &json!(a)))
                .transpose()?
        || key.verify_strict(&c.message()?, &sig).is_err()
        || p.observer_id != trust.observer_id
        || p.namespace != trust.namespace
        || p.registration_digest != trust.registration.digest()?
        || p.event_count != bundle.events.len() as u64
        || p.head_digest != bundle.events.last().ok_or_else(refuse)?.digest()?
        || p.lineage_digest != digest("reserved-inner-lineage", &json!(bundle.lineage))?
    {
        return Err(refuse());
    }
    let selected = trust
        .lineage
        .grants
        .verify_retained(bundle.lineage.issuance.signed_grant.as_bytes())?;
    let lineage = verify_lineage(&bundle.lineage, &leaf_trust(trust, &selected.grant)?)?;
    if p.operation_key != lineage.operation_key
        || p.grant_digest != lineage.grant_digest
        || p.attempt_id != lineage.attempt_id
    {
        return Err(refuse());
    }
    let replay = replay(
        &bundle.events,
        trust,
        p.captured_at,
        bundle.authorizations.as_ref(),
    )?;
    let a = replay
        .state
        .allocations
        .get(&lineage.operation_key)
        .ok_or_else(refuse)?;
    if a.attempt_id.as_deref() != Some(lineage.attempt_id.as_str()) {
        return Err(refuse());
    }
    let issue = bundle
        .events
        .iter()
        .find(|e| {
            e.data.phase == "issue"
                && e.data.operation_key.as_deref() == Some(lineage.operation_key.as_str())
        })
        .ok_or_else(refuse)?;
    if issue.data.grant_digest.as_deref() != Some(lineage.grant_digest.as_str())
        || !equal(
            &strict_value(
                issue
                    .data
                    .signed_grant
                    .as_ref()
                    .ok_or_else(refuse)?
                    .as_bytes(),
            )?,
            &strict_value(bundle.lineage.issuance.signed_grant.as_bytes())?,
        )?
    {
        return Err(refuse());
    }
    if let Some(receipt) = replay.refinements.get(&lineage.operation_key)
        && !bundle.lineage.outcomes.receipts.iter().any(|r| {
            crate::schema::verify_record(r.as_bytes(), "receipt", &trust.lineage.outcome_keys)
                .is_ok_and(|e| record_digest(&e).is_ok_and(|d| &d == receipt))
        })
    {
        return Err(refuse());
    }
    if lineage.reported_status == "committed" && a.state != S::Committed {
        return Err(refuse());
    }
    let dispatched = bundle.events.iter().any(|e| {
        e.data.phase == "dispatch"
            && e.data.operation_key.as_deref() == Some(lineage.operation_key.as_str())
    });
    if lineage.reported_status == "not_dispatched" && !dispatched && a.state != S::ProvenNoEffect {
        return Err(refuse());
    }
    if a.state == S::Committed && lineage.reported_status != "committed"
        || a.state == S::ProvenNoEffect && lineage.reported_status != "not_dispatched"
    {
        return Err(refuse());
    }
    Ok(Verification {
        profile: bundle.profile.clone(),
        lineage,
        events_verified: bundle.events.len(),
        budget_active: replay.state.active,
        budget_state: a.state.clone(),
        held_forward: a.forward,
        held_compensation: a.compensation,
        execution_authority: false,
        missing_links: vec![
            "observer correctness, ledger custody/consensus, restore and clock trust".into(),
            "actual target effects, physical failures and complete writer/predicate coverage"
                .into(),
            "existing inner admission/governance/runtime gaps remain applicable".into(),
        ],
    })
}
impl EtcdLedger {
    pub async fn export_reserved_lineage(
        &self,
        candidate: &Candidate,
        operation_key: &str,
        observer: &HistoryObserver,
        trust: &Trust,
    ) -> Result<Bundle> {
        trust.validate()?;
        if self.namespace() != trust.namespace
            || observer.id != trust.observer_id
            || trust.observer_keys.get(&observer.key_id) != Some(&observer.key.verifying_key())
        {
            return Err(refuse());
        }
        let retained = self
            .retained_operation(operation_key)
            .await?
            .ok_or_else(refuse)?
            .0;
        let (gate, binding) = self
            .reservation_bound(&candidate.grant, &retained.grant_digest, false)
            .await?
            .ok_or_else(refuse)?;
        if gate.r != trust.registration
            || ![
                LEAF_PROFILE,
                HIERARCHICAL_LEAF_PROFILE,
                crate::saga_forward::PROFILE,
            ]
            .contains(&gate.r.profile.as_str())
            || binding.payload.operation_key != operation_key
        {
            return Err(refuse());
        }
        let lineage = self.export_lineage_inner(candidate, operation_key).await?;
        let (events, history_compare) = self.read_reservation_history(&gate.r, &gate.state).await?;
        let mut export_size = canonical(&json!(lineage))?.len() + canonical(&json!(events))?.len();
        if export_size > MAX_BUNDLE {
            return Err(refuse());
        }
        let authorizations = if gate.r.hierarchy.is_some() {
            let mut proofs = BTreeMap::new();
            for e in &events {
                if e.data.phase == "issue" {
                    let op = e.data.operation_key.as_deref().ok_or_else(refuse)?;
                    let proof = self.export_authorization(op).await?;
                    let size = canonical(&json!(proof))?.len();
                    export_size = export_size.checked_add(size).ok_or_else(refuse)?;
                    if size > 16 << 20 || export_size > MAX_BUNDLE {
                        return Err(refuse());
                    }
                    if proofs.insert(op.to_owned(), proof).is_some() {
                        return Err(refuse());
                    }
                }
            }
            Some(proofs)
        } else {
            None
        };
        let mut compare = gate.compare;
        compare.extend(history_compare);
        if !self
            .txn(compare, vec![get(&gate.c.key)], Vec::new())
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        let payload = CheckpointPayload {
            observer_id: observer.id.clone(),
            namespace: self.namespace().into(),
            registration_digest: gate.r.digest()?,
            event_count: events.len() as u64,
            head_digest: events.last().ok_or_else(refuse)?.digest()?,
            lineage_digest: digest("reserved-inner-lineage", &json!(lineage))?,
            operation_key: operation_key.into(),
            grant_digest: retained.grant_digest,
            attempt_id: candidate.attempt_id.clone(),
            captured_at: self.authority_clock.now_ms(),
            authorizations_digest: authorizations
                .as_ref()
                .map(|a| digest("hierarchical-authorizations", &json!(a)))
                .transpose()?,
        };
        let mut checkpoint = Checkpoint {
            profile: history_profile(&gate.r).into(),
            key_id: observer.key_id.clone(),
            payload,
            signature: String::new(),
        };
        checkpoint.signature =
            URL_SAFE_NO_PAD.encode(observer.key.sign(&checkpoint.message()?).to_bytes());
        let bundle = Bundle {
            profile: history_profile(&gate.r).into(),
            lineage,
            events,
            checkpoint,
            authorizations,
        };
        verify(&bundle, trust)?;
        Ok(bundle)
    }
}
