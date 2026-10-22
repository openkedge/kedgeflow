//! Complete bounded historical evidence, never new saga or inverse authority.
use crate::{
    action_domain::{Lane, Selection, Topology},
    broker_authorization::{BrokerRegistration, ExchangePermit},
    compensation::{Contract, Qualification},
    compensation_execution::{Binding, Payload, Spend},
    contracts::{Envelope, Grant, canonical, digest, record_digest, strict_value},
    control_history::HistoryObserver,
    coordination::ReservationState as S,
    error::{Error, Result},
    hierarchical_leaf::Principal,
    ledger::{EtcdLedger, record, value_eq, version_zero},
    lineage::{
        AuthorizationBundle, LineageBundle, LineageTrust, verify_authorization, verify_lineage,
    },
    lineage_config::LineageTrustConfig,
    recovery::Candidate,
    reserved_lineage::{
        Bundle as ForwardBundle, Trust as ForwardTrust, TrustConfig as ForwardTrustConfig,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &str = "KF-COMPENSATION-LINEAGE-0.1-draft";
pub const MAX_BUNDLE: usize = 8 << 20;
fn refuse() -> Error {
    Error::Refused("complete compensation lineage refused".into())
}
#[derive(Clone)]
pub struct Trust {
    pub forward: ForwardTrust,
    pub inverse: LineageTrust,
    pub topology: Topology,
    pub contract: Contract,
    pub broker: BrokerRegistration,
    pub observer_id: String,
    pub observer_keys: BTreeMap<String, VerifyingKey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    pub forward: ForwardTrustConfig,
    pub inverse: LineageTrustConfig,
    pub topology: Topology,
    pub contract: Contract,
    pub broker: BrokerRegistration,
    pub observer_id: String,
    pub observer_keys: BTreeMap<String, String>,
}
impl TrustConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 2 << 20 {
            return Err(refuse());
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub fn registration(&self) -> Result<Trust> {
        let t = Trust {
            forward: self.forward.registration()?,
            inverse: self.inverse.registration()?,
            topology: self.topology.clone(),
            contract: self.contract.clone(),
            broker: self.broker.clone(),
            observer_id: self.observer_id.clone(),
            observer_keys: crate::control_config::keys(&self.observer_keys)?,
        };
        t.validate()?;
        Ok(t)
    }
}
fn role_keys(t: &LineageTrust) -> Vec<&VerifyingKey> {
    t.admission
        .proposal_keys
        .values()
        .chain(t.admission.registry_keys.values())
        .chain(t.admission.manifest_keys.values())
        .chain(t.admission.evidence.values().flat_map(|e| e.keys.values()))
        .chain(t.admission_keys.values())
        .chain(t.grants.keys.values())
        .chain(t.outcome_keys.values())
        .collect()
}
impl Trust {
    pub fn validate(&self) -> Result<()> {
        let c = &self.contract;
        c.validate(&self.forward)?;
        self.inverse.validate()?;
        self.topology.validate()?;
        self.broker.validate()?;
        let f = &self.topology.forward;
        let i = &self.topology.inverse;
        if self.observer_id.is_empty()
            || self.observer_id == self.forward.observer_id
            || self.observer_id.len() > 256
            || !(1..=16).contains(&self.observer_keys.len())
            || !(Selection {
                topology: self.topology.clone(),
                lane: Lane::Forward,
            })
            .accepts_reservation(&self.forward.registration)
            || f.trust_digest
                != crate::governance::trust_digest(
                    &self.forward.lineage.admission,
                    &self.forward.lineage.admission_keys,
                    &self.forward.lineage.grants.keys,
                )?
            || i.trust_digest
                != crate::governance::trust_digest(
                    &self.inverse.admission,
                    &self.inverse.admission_keys,
                    &self.inverse.grants.keys,
                )?
            || i.scope != c.inverse_scope
            || i.policy != c.inverse_policy
            || self.inverse.admission.inverse_contract.as_ref() != Some(c)
            || self.inverse.admission.policy != c.inverse_policy
            || self.inverse.grants.audience != c.inverse_scope.audience
            || self.inverse.admission.tenant != self.forward.registration.enrollment.tenant
            || !self.inverse.subjects.contains(&c.inverse_principal.subject)
            || self.inverse.admission.proposal_workload_id != c.inverse_principal.workload_id
            || self
                .inverse
                .grants
                .keys
                .iter()
                .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                .collect::<BTreeMap<_, _>>()
                != i.issuer_keys
            || self.broker.tool.inverse_contract.as_ref() != Some(c)
        {
            return Err(refuse());
        }
        let barriers = crate::control_config::keys(&c.barrier_keys)?;
        let app = crate::control_config::keys(&c.applicability_keys)?;
        let mut keys = role_keys(&self.forward.lineage);
        keys.extend(role_keys(&self.inverse));
        keys.extend(self.forward.observer_keys.values());
        keys.extend(barriers.values());
        keys.extend(app.values());
        let h = self
            .forward
            .registration
            .hierarchy
            .as_ref()
            .ok_or_else(refuse)?;
        if self.observer_keys.values().any(|k| keys.contains(&k))
            || !h.distinct(self.observer_keys.values())
        {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inverse {
    pub authorization: AuthorizationBundle,
    pub binding: Binding,
    pub spend: Spend,
    pub lineage: Option<LineageBundle>,
    pub permit: Option<ExchangePermit>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub forward: BTreeMap<String, ForwardBundle>,
    pub qualifications: Vec<Qualification>,
    pub compensating: bool,
    pub inverse: Option<Inverse>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub profile: String,
    pub observer_id: String,
    pub key_id: String,
    pub namespace: String,
    pub topology_digest: String,
    pub contract_digest: String,
    pub registration_digest: String,
    pub evidence_digest: String,
    pub captured_at: i64,
    pub signature: String,
}
impl Checkpoint {
    fn message(&self) -> Result<Vec<u8>> {
        let mut v = json!(self);
        v.as_object_mut().ok_or_else(refuse)?.remove("signature");
        let mut b = format!("KedgeFlow:{PROFILE}\0").into_bytes();
        b.extend(canonical(&v)?);
        Ok(b)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub profile: String,
    pub evidence: Evidence,
    pub checkpoint: Checkpoint,
}
impl Bundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BUNDLE {
            return Err(refuse());
        }
        let v = strict_value(raw)?;
        // Required nullable fields express absence explicitly, with no default omission.
        let e = &v["evidence"];
        if e.get("inverse").is_none()
            || e["inverse"].is_object()
                && (e["inverse"].get("lineage").is_none() || e["inverse"].get("permit").is_none())
        {
            return Err(refuse());
        }
        let b: Self = serde_json::from_value(v)?;
        b.bound()?;
        Ok(b)
    }
    fn bound(&self) -> Result<()> {
        static PIN: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
        let pin = PIN.get_or_init(|| {
            crate::schema::compile(
                &serde_json::from_str(include_str!(
                    "../../../spec/drafts/compensation-lineage-v0.1.schema.json"
                ))
                .expect("compound schema"),
            )
            .expect("local compound schema")
        });
        if !pin.is_valid(&json!(self))
            || self.profile != PROFILE
            || self.evidence.forward.is_empty()
            || self.evidence.forward.len() > 8
            || self.evidence.qualifications.is_empty()
            || self.evidence.qualifications.len() > 32
            || canonical(&json!(self))?.len() > MAX_BUNDLE
        {
            return Err(refuse());
        }
        for b in self.evidence.forward.values() {
            ForwardBundle::decode(&canonical(&json!(b))?)?;
        }
        for q in &self.evidence.qualifications {
            crate::compensation::Proof::decode(&canonical(&json!(q.proof))?)?;
        }
        if let Some(i) = &self.evidence.inverse {
            if let Some(l) = &i.lineage {
                LineageBundle::decode(&canonical(&json!(l))?)?;
            }
            if let Some(p) = &i.permit {
                crate::broker_authorization::validate_permit(&json!(p))?;
            }
        }
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Verification {
    pub profile: String,
    pub status: String,
    pub nodes: BTreeMap<String, String>,
    pub qualifications_verified: usize,
    pub inverse_status: Option<String>,
    pub complete_evidence: bool,
    pub execution_authority: bool,
    pub missing_links: Vec<String>,
}
fn same(a: &impl Serialize, b: &impl Serialize) -> Result<bool> {
    Ok(canonical(&json!(a))? == canonical(&json!(b))?)
}
fn receipt_digest(l: &LineageBundle, keys: &BTreeMap<String, VerifyingKey>) -> Result<String> {
    record_digest(&crate::schema::verify_record(
        l.outcomes.receipts.last().ok_or_else(refuse)?.as_bytes(),
        "receipt",
        keys,
    )?)
}
fn times(l: &LineageBundle, keys: &BTreeMap<String, VerifyingKey>, at: i64) -> Result<()> {
    if l.admission.admitted_at > at {
        return Err(refuse());
    }
    for raw in &l.outcomes.receipts {
        let r = crate::schema::verify_record(raw.as_bytes(), "receipt", keys)?;
        if r.payload["event_time"].as_i64().ok_or_else(refuse)? > at {
            return Err(refuse());
        }
    }
    Ok(())
}
pub fn verify(b: &Bundle, t: &Trust) -> Result<Verification> {
    t.validate()?;
    b.bound()?;
    let cp = &b.checkpoint;
    let sig = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&cp.signature)
            .map_err(|_| refuse())?,
    )
    .map_err(|_| refuse())?;
    if cp.profile != PROFILE
        || cp.observer_id != t.observer_id
        || cp.namespace != t.forward.namespace
        || cp.topology_digest != t.topology.digest()?
        || cp.contract_digest != t.contract.digest()?
        || cp.registration_digest != t.forward.registration.digest()?
        || cp.evidence_digest != digest("compensation-lineage-evidence", &json!(b.evidence))?
        || cp.captured_at < 0
        || t.observer_keys
            .get(&cp.key_id)
            .ok_or_else(refuse)?
            .verify_strict(&cp.message()?, &sig)
            .is_err()
    {
        return Err(refuse());
    }
    let e = &b.evidence;
    let c = &t.contract;
    let selected = e.forward.get(&c.forward_operation_key).ok_or_else(refuse)?;
    let state = &selected.events.last().ok_or_else(refuse)?.after;
    let plan = t.forward.registration.saga.as_ref().ok_or_else(refuse)?;
    let expected: BTreeSet<_> = plan
        .nodes
        .iter()
        .filter(|n| {
            state
                .allocations
                .get(&n.operation_key)
                .is_some_and(|a| a.attempt_id.is_some())
        })
        .map(|n| n.operation_key.clone())
        .collect();
    if expected != e.forward.keys().cloned().collect() {
        return Err(refuse());
    }
    let mut nodes = BTreeMap::new();
    for n in &plan.nodes {
        let a = state.allocations.get(&n.operation_key).ok_or_else(refuse)?;
        let status = match a.state {
            S::Allocated => "held",
            S::Unknown => "unresolved",
            S::Committed => "uncompensated",
            S::ProvenNoEffect => "no_effect",
            _ => return Err(refuse()),
        };
        nodes.insert(n.operation_key.clone(), status.into());
    }
    for (op, f) in &e.forward {
        let v = crate::reserved_lineage::verify(f, &t.forward)?;
        times(&f.lineage, &t.forward.lineage.outcome_keys, cp.captured_at)?;
        if v.lineage.operation_key != *op
            || f.checkpoint.payload.captured_at > cp.captured_at
            || !same(&f.events, &selected.events)?
            || !same(&f.authorizations, &selected.authorizations)?
        {
            return Err(refuse());
        }
    }
    let mut previous = None;
    let mut last_time = None;
    for (n, q) in e.qualifications.iter().enumerate() {
        if q.profile != crate::compensation::PROFILE
            || q.sequence != n as u64 + 1
            || q.previous_digest != previous
            || q.verification
                != crate::compensation::verify(
                    c,
                    &t.forward,
                    &q.proof,
                    q.verification.validated_at,
                )?
            || q.verification.validated_at > cp.captured_at
            || last_time.is_some_and(|at| at > q.verification.validated_at)
            || q.proof.forward.events.len() > selected.events.len()
            || !same(
                &q.proof.forward.events,
                &selected.events[..q.proof.forward.events.len()].to_vec(),
            )?
            || q.proof.forward.lineage.issuance.grant_digest
                != selected.lineage.issuance.grant_digest
            || receipt_digest(&q.proof.forward.lineage, &t.forward.lineage.outcome_keys)?
                != receipt_digest(&selected.lineage, &t.forward.lineage.outcome_keys)?
        {
            return Err(refuse());
        }
        previous = Some(q.digest()?);
        last_time = Some(q.verification.validated_at);
    }
    let mut inverse_status = None;
    if let Some(i) = &e.inverse {
        if !e.compensating {
            return Err(refuse());
        }
        let auth = verify_authorization(&i.authorization, &t.inverse)?;
        let g = &auth.issuance.grant;
        let gd = &auth.issuance.grant_digest;
        let p = &i.binding.payload;
        i.binding.verify(&t.inverse.grants.keys)?;
        let q = e
            .qualifications
            .iter()
            .find(|q| q.digest().is_ok_and(|d| d == p.qualification_digest))
            .ok_or_else(refuse)?;
        let outcome_keys = t
            .inverse
            .outcome_keys
            .iter()
            .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
            .collect::<BTreeMap<_, _>>();
        let payload = Payload {
            outcome_trust_digest: digest(
                "compensation-outcome-trust",
                &json!({"source_id":t.inverse.source_id,"keys":outcome_keys}),
            )?,
            topology_digest: t.topology.digest()?,
            contract_digest: c.digest()?,
            qualification_digest: q.digest()?,
            forward: q.verification.forward.clone(),
            inverse_operation_key: c.inverse_operation_key.clone(),
            grant_digest: gd.clone(),
            certificate_digest: g.certificate_digest.clone(),
            parameters_digest: g.parameters_digest.clone(),
            compensation_units: c.compensation_units,
            valid_from: g.valid_from,
            expires_at: g.expires_at,
        };
        let s = &i.spend;
        if *p != payload
            || auth.operation_key != c.inverse_operation_key
            || Principal::from_grant(g) != c.inverse_principal
            || g.policy != c.inverse_policy
            || crate::governance::EnforcementScope::grant(g)? != c.inverse_scope
            || g.ownership_epoch != t.forward.registration.ownership_epoch
            || selected
                .events
                .iter()
                .filter_map(|e| e.data.fence)
                .max()
                .is_some_and(|f| g.fence <= f)
            || g.parameters_digest != q.verification.parameters_digest
            || g.expires_at > q.verification.valid_until
            || auth.admitted_at < q.verification.validated_at
            || auth.issued_at > cp.captured_at
            || s.profile != crate::compensation_execution::PROFILE
            || s.forward_operation_key != c.forward_operation_key
            || s.inverse_operation_key != c.inverse_operation_key
            || s.grant_digest != *gd
            || s.binding_digest != i.binding.digest()?
            || s.compensation_units != c.compensation_units
        {
            return Err(refuse());
        }
        if s.state == S::Allocated {
            if s.attempt_id.is_some()
                || s.receipt_digest.is_some()
                || i.lineage.is_some()
                || i.permit.is_some()
            {
                return Err(refuse());
            }
            inverse_status = Some("allocated".into());
        } else {
            let l = i.lineage.as_ref().ok_or_else(refuse)?;
            let a = AuthorizationBundle {
                admission: l.admission.clone(),
                packet: l.packet.clone(),
                issuance: l.issuance.clone(),
                lease_authority: l.lease_authority.clone(),
            };
            let v = verify_lineage(l, &t.inverse)?;
            times(l, &t.inverse.outcome_keys, cp.captured_at)?;
            let dispatched = l
                .outcomes
                .journal
                .iter()
                .any(|v| v["phase"] == "dispatch_authorized");
            if l.outcomes.execution.tool != t.broker.tool.name
                || !same(&a, &i.authorization)?
                || s.attempt_id.as_deref() != Some(v.attempt_id.as_str())
                || v.operation_key != c.inverse_operation_key
            {
                return Err(refuse());
            }
            match s.state {
                S::Committed
                    if v.reported_status == "committed"
                        && s.receipt_digest.as_deref()
                            == Some(receipt_digest(l, &t.inverse.outcome_keys)?.as_str()) =>
                {
                    nodes.insert(c.forward_operation_key.clone(), "compensated".into());
                }
                S::ProvenNoEffect
                    if v.reported_status == "not_dispatched"
                        && !dispatched
                        && s.receipt_digest.as_deref()
                            == Some(receipt_digest(l, &t.inverse.outcome_keys)?.as_str()) => {}
                S::Unknown
                    if s.receipt_digest.is_none()
                        && v.reported_status != "committed"
                        && !(v.reported_status == "not_dispatched" && !dispatched) => {}
                _ => return Err(refuse()),
            }
            inverse_status = Some(
                match s.state {
                    S::Committed => "committed",
                    S::ProvenNoEffect => "no_effect",
                    _ => "unresolved",
                }
                .into(),
            );
            if dispatched && i.permit.is_none() {
                return Err(refuse());
            }
            if let Some(permit) = &i.permit {
                verify_permit(permit, t, g, gd, &v.attempt_id, cp.captured_at)?;
                let claimed = l
                    .outcomes
                    .journal
                    .iter()
                    .find(|e| e["phase"] == "claimed")
                    .and_then(|e| e["event_time"].as_i64())
                    .ok_or_else(refuse)?;
                let dispatched_at = l
                    .outcomes
                    .journal
                    .iter()
                    .find(|e| e["phase"] == "dispatch_authorized")
                    .and_then(|e| e["event_time"].as_i64());
                if permit.authorized_at < claimed
                    || dispatched_at
                        .is_some_and(|at| permit.authorized_at > at || permit.expires_at <= at)
                {
                    return Err(refuse());
                }
            }
        }
    }
    let status = if nodes.values().any(|s| s == "unresolved")
        || inverse_status.as_deref() == Some("unresolved")
    {
        "unresolved"
    } else if !e.compensating {
        "forward_only"
    } else if inverse_status.as_deref() == Some("committed")
        && !nodes.values().any(|s| s == "uncompensated")
    {
        "compensated"
    } else {
        "partial"
    };
    Ok(Verification {profile:PROFILE.into(),status:status.into(),nodes,qualifications_verified:e.qualifications.len(),inverse_status,complete_evidence:true,execution_authority:false,
        missing_links:vec!["observer correctness, clock, ledger consensus/custody and native authentication".into(),"actual target assertions, complete writers, physical failures and independent peer acceptance".into(),"multi-contract inverse execution and actual Kubernetes drain".into()]})
}
fn verify_permit(
    p: &ExchangePermit,
    t: &Trust,
    g: &Grant,
    gd: &str,
    id: &str,
    at: i64,
) -> Result<()> {
    crate::broker_authorization::validate_permit(&json!(p))?;
    let mut v = json!(p);
    v.as_object_mut().ok_or_else(refuse)?.remove("permit_id");
    let b = &t.broker;
    if p.permit_id != digest("broker-permit", &v)?
        || p.registration_digest != digest("broker-registration", &json!(b))?
        || p.grant_digest != gd
        || p.root_id != g.root_id
        || p.attempt_id != id
        || p.gateway_workload != b.gateway_workload
        || p.target_audience != b.target_audience
        || p.target_scope != b.target_scope
        || p.authorized_at < g.valid_from
        || p.authorized_at > at
        || p.expires_at > g.expires_at
        || p.expires_at <= p.authorized_at
        || p.expires_at - p.authorized_at > b.max_lifetime_ms
    {
        return Err(refuse());
    }
    Ok(())
}

async fn pin_json(
    l: &EtcdLedger,
    key: String,
    expected: Value,
    compare: &mut Vec<Value>,
) -> Result<()> {
    let raw = l.read_key(&key).await?.ok_or_else(refuse)?;
    if raw.len() > 1 << 20 || strict_value(&raw)? != expected {
        return Err(refuse());
    }
    compare.push(value_eq(
        &key,
        std::str::from_utf8(&raw).map_err(|_| refuse())?,
    ));
    Ok(())
}
pub(crate) fn pin_unclaimed(
    l: &EtcdLedger,
    g: &Grant,
    gd: &str,
    compare: &mut Vec<Value>,
) -> Result<()> {
    compare.extend([
        value_eq(&l.root(g), &record(&crate::ledger::expected_root(g))?),
        value_eq(&l.grant_key(g), gd),
        version_zero(&l.nonce(g)),
    ]);
    Ok(())
}
async fn pin_authorization(
    l: &EtcdLedger,
    op: &str,
    a: &AuthorizationBundle,
    compare: &mut Vec<Value>,
) -> Result<()> {
    pin_json(
        l,
        format!("{}/issuance/{op}", l.namespace()),
        json!(a.issuance),
        compare,
    )
    .await?;
    pin_json(
        l,
        format!("{}/admission/{op}", l.namespace()),
        json!(a.admission),
        compare,
    )
    .await?;
    pin_json(l,format!("{}/admission-chain/{op}",l.namespace()),json!({"admission_key":op,"certificate_digest":a.admission.certificate_digest,"packet":a.packet}),compare).await?;
    for (n, phase) in ["admission", "issuance"].iter().enumerate() {
        let key = l.lease_authority_key(op, phase);
        if let Some(b) = &a.lease_authority {
            pin_json(l, key, json!(b.get(n).ok_or_else(refuse)?), compare).await?;
        } else {
            compare.push(version_zero(&key));
        }
    }
    Ok(())
}
fn authorization(l: &LineageBundle) -> AuthorizationBundle {
    AuthorizationBundle {
        admission: l.admission.clone(),
        packet: l.packet.clone(),
        issuance: l.issuance.clone(),
        lease_authority: l.lease_authority.clone(),
    }
}
async fn pin_lineage(
    l: &EtcdLedger,
    c: &Candidate,
    b: &LineageBundle,
    compare: &mut Vec<Value>,
) -> Result<()> {
    pin_authorization(l, &b.issuance.issuance_key, &authorization(b), compare).await?;
    let s = l.recovery_snapshot(c).await?;
    if !same(&s.context, &b.outcomes.execution)?
        || s.head.as_ref().ok_or_else(refuse)?.signed_receipt
            != *b.outcomes.receipts.last().ok_or_else(refuse)?
    {
        return Err(refuse());
    }
    let g = &c.grant;
    let id = &c.attempt_id;
    let base = l.attempt(g, id);
    let mut root = crate::ledger::expected_root(g);
    root.status = "claimed".into();
    compare.extend([
        value_eq(&l.root(g), &record(&root)?),
        value_eq(&l.grant_key(g), &b.issuance.grant_digest),
        value_eq(&l.nonce(g), id),
        value_eq(&base, &record(&s.attempt)?),
        value_eq(&l.outbox(g, id), &s.outbox),
        value_eq(&crate::recovery::context_key(l, g, id), &s.context_raw),
        value_eq(
            &format!("{base}/receipt-head"),
            s.head_raw.as_deref().ok_or_else(refuse)?,
        ),
    ]);
    for raw in &b.outcomes.receipts {
        let e: Envelope = serde_json::from_value(strict_value(raw.as_bytes())?)?;
        let key = format!("{base}/receipts/{}", record_digest(&e)?);
        if l.read_key(&key).await?.as_deref() != Some(raw.as_bytes()) {
            return Err(refuse());
        }
        compare.push(value_eq(&key, raw));
    }
    for (ed, v) in &b.outcomes.evidence {
        pin_json(
            l,
            format!("{base}/reports/evidence/{ed}"),
            v.clone(),
            compare,
        )
        .await?;
    }
    for event in &b.outcomes.journal {
        let phase = event["phase"].as_str().ok_or_else(refuse)?;
        pin_json(
            l,
            crate::recovery::journal_key(l, g, id, phase),
            event.clone(),
            compare,
        )
        .await?;
    }
    for phase in [
        "claimed",
        "dispatch_authorized",
        "not_dispatched",
        "unknown",
        "committed",
        "state_guard_violation",
    ] {
        if !b.outcomes.journal.iter().any(|e| e["phase"] == phase) {
            compare.push(version_zero(&crate::recovery::journal_key(l, g, id, phase)));
        }
    }
    let key = crate::recovery::evidence_key(l, g, id);
    if let Some(v) = s.evidence {
        pin_json(l, key, v, compare).await?;
    } else {
        compare.push(version_zero(&key));
    }
    Ok(())
}
impl EtcdLedger {
    /// Protected, historical, query-only export. Missing receipts require the
    /// existing recovery worker; this API never invents one or contacts targets.
    pub async fn export_compensation_lineage(
        &self,
        observer: &HistoryObserver,
        forward_observer: &HistoryObserver,
        trust: &Trust,
    ) -> Result<Bundle> {
        trust.validate()?;
        if observer.id != trust.observer_id
            || trust.observer_keys.get(&observer.key_id) != Some(&observer.key.verifying_key())
            || self.namespace() != trust.forward.namespace
        {
            return Err(refuse());
        }
        let e = self.inverse_execution.as_ref().ok_or_else(refuse)?;
        if e.contract != trust.contract
            || self.action_domain.as_ref().ok_or_else(refuse)?.topology != trust.topology
        {
            return Err(refuse());
        }
        let f = e.forward_ledger(self)?;
        let gate = f
            .reservation_gate_for(&trust.forward.registration.scope.conflict_domain, false)
            .await?
            .ok_or_else(refuse)?;
        if gate.r != trust.forward.registration {
            return Err(refuse());
        }
        let (events, hc) = f.read_reservation_history(&gate.r, &gate.state).await?;
        let mut compare = gate.compare;
        compare.extend(hc);
        for event in &events {
            pin_json(
                &f,
                format!(
                    "{}/events/{:06}",
                    crate::reservation_history::base(&f, &gate.r)?,
                    event.sequence
                ),
                json!(event),
                &mut compare,
            )
            .await?;
        }
        let mut forward = BTreeMap::new();
        for node in &gate.r.saga.as_ref().ok_or_else(refuse)?.nodes {
            let op = &node.operation_key;
            let a = gate.state.allocations.get(op).ok_or_else(refuse)?;
            if let Some(id) = &a.attempt_id {
                let auth = f.export_authorization(op).await?;
                let g = trust
                    .forward
                    .lineage
                    .grants
                    .verify_retained(auth.issuance.signed_grant.as_bytes())?;
                let candidate = Candidate {
                    grant: g.grant,
                    attempt_id: id.clone(),
                };
                let bundle = f
                    .export_reserved_lineage(&candidate, op, forward_observer, &trust.forward)
                    .await?;
                if !same(&events, &bundle.events)? {
                    return Err(refuse());
                }
                let (dependency, binding) = f
                    .reservation_bound(&candidate.grant, &g.digest, false)
                    .await?
                    .ok_or_else(refuse)?;
                if binding.payload.operation_key != *op {
                    return Err(refuse());
                }
                compare.extend(dependency.compare);
                pin_lineage(&f, &candidate, &bundle.lineage, &mut compare).await?;
                for (issued, proof) in bundle.authorizations.as_ref().ok_or_else(refuse)? {
                    pin_authorization(&f, issued, proof, &mut compare).await?;
                }
                forward.insert(op.clone(), bundle);
            } else {
                let key = format!("{}/issuance/{op}", f.namespace());
                if let Some(raw) = f.read_key(&key).await? {
                    let auth = f.export_authorization(op).await?;
                    if strict_value(&raw)? != json!(auth.issuance) {
                        return Err(refuse());
                    }
                    pin_authorization(&f, op, &auth, &mut compare).await?;
                    let g = trust
                        .forward
                        .lineage
                        .grants
                        .verify_retained(auth.issuance.signed_grant.as_bytes())?;
                    let (bound, binding) = f
                        .reservation_bound(&g.grant, &g.digest, false)
                        .await?
                        .ok_or_else(refuse)?;
                    if binding.payload.operation_key != *op {
                        return Err(refuse());
                    }
                    compare.extend(bound.compare);
                    pin_unclaimed(&f, &g.grant, &g.digest, &mut compare)?;
                } else {
                    compare.push(version_zero(&key));
                }
            }
        }
        let (qualifications, qc) = e.qualifier(self)?.retained_history().await?;
        compare.extend(qc);
        let mode_key = crate::compensation_execution::mode_key(self, &gate.r)?;
        let mode = record(
            &json!({"profile":crate::compensation_execution::PROFILE,"registration_digest":gate.r.digest()?,"topology_digest":trust.topology.digest()?,"mode":"compensating"}),
        )?;
        let compensating = match self.read_key(&mode_key).await? {
            Some(raw) if raw == mode.as_bytes() => {
                compare.push(value_eq(&mode_key, &mode));
                true
            }
            None => {
                compare.push(version_zero(&mode_key));
                false
            }
            _ => return Err(refuse()),
        };
        let op = &trust.contract.inverse_operation_key;
        let inverse = if self
            .read_key(&format!("{}/issuance/{op}", self.namespace()))
            .await?
            .is_some()
        {
            let auth = self.export_authorization(op).await?;
            pin_authorization(self, op, &auth, &mut compare).await?;
            let g = trust
                .inverse
                .grants
                .verify_retained(auth.issuance.signed_grant.as_bytes())?;
            let (binding, spend, c) = e.bound(self, &g.grant, &g.digest, false).await?;
            compare.extend(c);
            let (lineage, permit) = if let Some(id) = &spend.attempt_id {
                let c = Candidate {
                    grant: g.grant,
                    attempt_id: id.clone(),
                };
                let l = self.export_lineage_inner(&c, op).await?;
                pin_lineage(self, &c, &l, &mut compare).await?;
                let key = format!("{}/credential-permit", self.attempt(&c.grant, id));
                let permit = if let Some(raw) = self.read_key(&key).await? {
                    let p: ExchangePermit = serde_json::from_value(strict_value(&raw)?)?;
                    compare.push(value_eq(
                        &key,
                        std::str::from_utf8(&raw).map_err(|_| refuse())?,
                    ));
                    Some(p)
                } else {
                    compare.push(version_zero(&key));
                    None
                };
                (Some(l), permit)
            } else {
                pin_unclaimed(self, &g.grant, &g.digest, &mut compare)?;
                (None, None)
            };
            Some(Inverse {
                authorization: auth,
                binding,
                spend,
                lineage,
                permit,
            })
        } else {
            compare.push(version_zero(&format!("{}/issuance/{op}", self.namespace())));
            compare.push(version_zero(&format!(
                "{}/compensation-spends/{}",
                self.namespace(),
                trust.contract.forward_operation_key
            )));
            compare.push(version_zero(&format!(
                "{}/compensation-seals/{}",
                self.namespace(),
                trust.contract.forward_operation_key
            )));
            None
        };
        let evidence = Evidence {
            forward,
            qualifications,
            compensating,
            inverse,
        };
        let mut seen = BTreeSet::new();
        compare.retain(|v| seen.insert(v.to_string()));
        // Leave room for the paired topology and restore absence comparisons.
        if compare.len() > 120
            || canonical(&json!({"compare":compare,"success":[],"failure":[]}))?.len() > 1 << 20
            || !self.txn(compare, vec![], vec![]).await?.succeeded
        {
            return Err(refuse());
        }
        let mut checkpoint = Checkpoint {
            profile: PROFILE.into(),
            observer_id: observer.id.clone(),
            key_id: observer.key_id.clone(),
            namespace: self.namespace().into(),
            topology_digest: trust.topology.digest()?,
            contract_digest: trust.contract.digest()?,
            registration_digest: gate.r.digest()?,
            evidence_digest: digest("compensation-lineage-evidence", &json!(evidence))?,
            captured_at: self.authority_clock.now_ms(),
            signature: String::new(),
        };
        checkpoint.signature =
            URL_SAFE_NO_PAD.encode(observer.key.sign(&checkpoint.message()?).to_bytes());
        let b = Bundle {
            profile: PROFILE.into(),
            evidence,
            checkpoint,
        };
        verify(&b, trust)?;
        Ok(b)
    }
}
