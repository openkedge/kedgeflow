//! Explicit compound inverse authority; held costs are never refunded.
use crate::{
    action_domain::{Lane, Selection},
    compensation::{Contract, Forward, Qualification, Qualifier},
    contracts::{Grant, GrantVerifier, canonical, digest, strict_value},
    coordination::ReservationState as S,
    error::{Error, Result},
    hierarchical_leaf::Principal,
    ledger::{EtcdLedger, IssuanceRecord, put, record, value_eq, version_zero},
    reserved_leaf::{Change, Registration},
    reserved_lineage::{Trust, TrustConfig},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
pub const PROFILE: &str = "KF-COMPENSATION-LEAF-0.1-draft";
pub const EXTENSION: &str = "io.kedgeflow/compensation-leaf";
/// One issuer request's original proof read set. It cannot escape through the
/// returned issuance record and every use carries these comparisons into CAS.
#[derive(Debug)]
pub(crate) struct PreparedIssuance {
    namespace: String,
    execution_pin: String,
    checked_at: i64,
    qualification: Qualification,
    compare: Vec<Value>,
}
fn refuse() -> Error {
    Error::Refused("fresh compensation authority or held spend refused".into())
}
fn validate(value: &Value) -> Result<()> {
    static PIN: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let pin = PIN.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/compensation-leaf-v0.1.schema.json"
            ))
            .expect("compensation schema"),
        )
        .expect("local compensation schema")
    });
    if !pin.is_valid(value) {
        return Err(refuse());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfig {
    pub profile: String,
    pub contract: Contract,
    pub forward: TrustConfig,
    pub outcome_keys: BTreeMap<String, String>,
    pub source_id: String,
}
impl std::fmt::Debug for ExecutionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionConfig")
            .field("profile", &self.profile)
            .field("contract_id", &self.contract.contract_id)
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
pub(crate) struct Execution {
    pub contract: Contract,
    pub trust: Trust,
    pub outcome_keys: BTreeMap<String, VerifyingKey>,
    pub source_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub outcome_trust_digest: String,
    pub topology_digest: String,
    pub contract_digest: String,
    pub qualification_digest: String,
    pub forward: Forward,
    pub inverse_operation_key: String,
    pub grant_digest: String,
    pub certificate_digest: String,
    pub parameters_digest: String,
    pub compensation_units: u64,
    pub valid_from: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub profile: String,
    pub key_id: String,
    pub payload: Payload,
    pub signature: String,
}
impl Binding {
    fn message(&self) -> Result<Vec<u8>> {
        let mut b = format!("KedgeFlow:{PROFILE}\0").into_bytes();
        b.extend(canonical(
            &json!({"profile":self.profile,"key_id":self.key_id,"payload":self.payload}),
        )?);
        Ok(b)
    }
    pub fn digest(&self) -> Result<String> {
        digest("compensation-binding", &json!(self))
    }
    pub fn verify(&self, keys: &BTreeMap<String, VerifyingKey>) -> Result<()> {
        validate(&json!(self))?;
        let sig = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| refuse())?;
        let sig = Signature::from_slice(&sig).map_err(|_| refuse())?;
        if self.profile != PROFILE
            || keys
                .get(&self.key_id)
                .ok_or_else(refuse)?
                .verify_strict(&self.message()?, &sig)
                .is_err()
        {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Spend {
    pub profile: String,
    pub forward_operation_key: String,
    pub inverse_operation_key: String,
    pub grant_digest: String,
    pub binding_digest: String,
    pub compensation_units: u64,
    pub state: S,
    pub attempt_id: Option<String>,
    pub receipt_digest: Option<String>,
}
fn change(compare: Vec<Value>, writes: Vec<Value>) -> Change {
    Change {
        compare,
        writes,
        newly_allocated: false,
    }
}
pub(crate) fn mode_key(ledger: &EtcdLedger, r: &Registration) -> Result<String> {
    Ok(format!(
        "{}/saga-compensating/{}",
        ledger.namespace(),
        r.digest()?
    ))
}
fn spend_key(l: &EtcdLedger, op: &str) -> String {
    format!("{}/compensation-spends/{op}", l.namespace())
}
fn binding_key(l: &EtcdLedger, gd: &str) -> String {
    format!("{}/compensated-grants/{gd}", l.namespace())
}
fn seal_key(l: &EtcdLedger, op: &str) -> String {
    format!("{}/compensation-seals/{op}", l.namespace())
}
fn issuer_keys(s: &Selection) -> Result<BTreeMap<String, VerifyingKey>> {
    s.registration()
        .issuer_keys
        .iter()
        .map(|(id, v)| {
            let bytes: [u8; 32] = hex::decode(v)
                .map_err(|_| refuse())?
                .try_into()
                .map_err(|_| refuse())?;
            Ok((
                id.clone(),
                VerifyingKey::from_bytes(&bytes).map_err(|_| refuse())?,
            ))
        })
        .collect()
}
fn mode_value(l: &EtcdLedger, r: &Registration) -> Result<String> {
    let s = l.action_domain.as_ref().ok_or_else(refuse)?;
    record(
        &json!({"profile":PROFILE,"registration_digest":r.digest()?,"topology_digest":s.topology.digest()?,"mode":"compensating"}),
    )
}
impl ExecutionConfig {
    pub fn attach(&self, mut ledger: EtcdLedger) -> Result<EtcdLedger> {
        let s = ledger.action_domain.as_ref().ok_or_else(refuse)?;
        let t = self.forward.registration()?;
        self.contract.validate(&t)?;
        let outcome_keys = crate::control_config::keys(&self.outcome_keys)?;
        if self.profile != PROFILE
            || !(1..=16).contains(&outcome_keys.len())
            || s.lane != Lane::Inverse
            || ledger.reservation.is_some()
            || t.namespace != ledger.namespace()
            || s.topology.forward.scope != t.registration.scope
            || s.topology.forward.policy != t.registration.policy
            || s.topology.inverse.scope != self.contract.inverse_scope
            || s.topology.inverse.policy != self.contract.inverse_policy
            || self.source_id.is_empty()
            || self.source_id.len() > 1024
            || !(Selection {
                topology: s.topology.clone(),
                lane: Lane::Forward,
            })
            .accepts_reservation(&t.registration)
            || crate::governance::trust_digest(
                &t.lineage.admission,
                &t.lineage.admission_keys,
                &t.lineage.grants.keys,
            )? != s.topology.forward.trust_digest
        {
            return Err(refuse());
        }
        let reserved = crate::control_config::keys(&self.contract.barrier_keys)?
            .into_values()
            .chain(crate::control_config::keys(&self.contract.applicability_keys)?.into_values())
            .collect::<Vec<_>>();
        if issuer_keys(s)?
            .values()
            .chain(outcome_keys.values())
            .any(|k| reserved.contains(k))
            || outcome_keys
                .values()
                .any(|k| issuer_keys(s).is_ok_and(|keys| keys.values().any(|i| i == k)))
        {
            return Err(refuse());
        }
        ledger.inverse_execution = Some(Arc::new(Execution {
            contract: self.contract.clone(),
            trust: t,
            outcome_keys,
            source_id: self.source_id.clone(),
        }));
        Ok(ledger)
    }
}
pub fn deserialize_execution<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<ExecutionConfig>, D::Error> {
    Ok(Some(ExecutionConfig::deserialize(deserializer)?))
}
impl Execution {
    fn issuance_pin(&self) -> Result<String> {
        let Self {
            contract,
            trust,
            outcome_keys,
            source_id,
        } = self;
        let keys = outcome_keys
            .iter()
            .map(|(id, key)| (id.clone(), hex::encode(key.as_bytes())))
            .collect::<BTreeMap<_, _>>();
        Ok(crate::family_saga_cache::key(
            "inverse-issuance-public-context",
            &[
                &canonical(&json!(contract))?,
                &crate::family_saga_cache::trust_bytes(trust)?,
                &canonical(&json!({"outcome_keys":keys,"source_id":source_id}))?,
            ],
        ))
    }
    async fn issuance_proof(
        &self,
        l: &EtcdLedger,
        a: &crate::issuance::AdmittedIssuance,
    ) -> Result<(Qualification, Vec<Value>)> {
        let Some(p) = &a.inverse_prepared else {
            return self.live(l).await;
        };
        let now = l.authority_clock.now_ms();
        if p.namespace != l.namespace()
            || p.execution_pin != self.issuance_pin()?
            || now < p.checked_at
            || now >= p.qualification.verification.valid_until
        {
            return Err(refuse());
        }
        Ok((p.qualification.clone(), p.compare.clone()))
    }
    pub(crate) fn forward_ledger(&self, l: &EtcdLedger) -> Result<EtcdLedger> {
        let s = l.action_domain.as_ref().ok_or_else(refuse)?;
        let mut f = l.clone();
        f.inverse_execution = None;
        f.action_domain = Some(Arc::new(Selection {
            topology: s.topology.clone(),
            lane: Lane::Forward,
        }));
        f.reservation = Some(Arc::new(self.trust.registration.clone()));
        f.required_trust_digest = Some(s.topology.forward.trust_digest.clone());
        Ok(f)
    }
    pub(crate) fn qualifier(&self, l: &EtcdLedger) -> Result<Qualifier> {
        Qualifier::new(
            self.forward_ledger(l)?,
            self.contract.clone(),
            self.trust.clone(),
        )
    }
    async fn live(&self, l: &EtcdLedger) -> Result<(Qualification, Vec<Value>)> {
        let (q, mut c) = self.qualifier(l)?.live_qualification().await?;
        let key = mode_key(l, &self.trust.registration)?;
        let expected = mode_value(l, &self.trust.registration)?;
        if l.read_key(&key).await?.as_deref() != Some(expected.as_bytes()) {
            return Err(refuse());
        }
        c.push(value_eq(&key, &expected));
        self.reverse_dependencies(l, &q, &mut c).await?;
        Ok((q, c))
    }
    async fn reverse_dependencies(
        &self,
        l: &EtcdLedger,
        q: &Qualification,
        c: &mut Vec<Value>,
    ) -> Result<()> {
        let plan = self.trust.registration.saga.as_ref().ok_or_else(refuse)?;
        let mut descendants = BTreeSet::from([self.contract.node_id.clone()]);
        loop {
            let old = descendants.len();
            for n in &plan.nodes {
                if n.depends_on.iter().any(|id| descendants.contains(id)) {
                    descendants.insert(n.node_id.clone());
                }
            }
            if old == descendants.len() {
                break;
            }
        }
        let state = &q.proof.forward.events.last().ok_or_else(refuse)?.after;
        for n in &plan.nodes {
            if n.node_id == self.contract.node_id || !descendants.contains(&n.node_id) {
                continue;
            }
            let a = state.allocations.get(&n.operation_key).ok_or_else(refuse)?;
            match a.state {
                S::Allocated | S::ProvenNoEffect => {}
                S::Committed => {
                    let key = spend_key(l, &n.operation_key);
                    let raw = l.read_key(&key).await?.ok_or_else(refuse)?;
                    let s: Spend = serde_json::from_value(strict_value(&raw)?)?;
                    if s.profile != PROFILE
                        || s.forward_operation_key != n.operation_key
                        || s.state != S::Committed
                        || s.attempt_id.is_none()
                        || s.receipt_digest.is_none()
                    {
                        return Err(refuse());
                    }
                    c.push(value_eq(
                        &key,
                        std::str::from_utf8(&raw).map_err(|_| refuse())?,
                    ));
                }
                _ => return Err(refuse()),
            }
        }
        Ok(())
    }
    fn request(
        &self,
        q: &Qualification,
        op: &str,
        p: &Principal,
        pd: &str,
        expires: i64,
    ) -> Result<()> {
        if op != self.contract.inverse_operation_key
            || p != &self.contract.inverse_principal
            || pd != q.verification.parameters_digest
            || expires > q.verification.valid_until
        {
            return Err(refuse());
        }
        Ok(())
    }
    fn payload(&self, l: &EtcdLedger, q: &Qualification, g: &Grant, gd: &str) -> Result<Payload> {
        let s = l.action_domain.as_ref().ok_or_else(refuse)?;
        if crate::governance::EnforcementScope::grant(g)? != self.contract.inverse_scope
            || g.policy != self.contract.inverse_policy
            || g.ownership_epoch != self.trust.registration.ownership_epoch
        {
            return Err(refuse());
        }
        self.request(
            q,
            &self.contract.inverse_operation_key,
            &Principal::from_grant(g),
            &g.parameters_digest,
            g.expires_at,
        )?;
        Ok(Payload {
            outcome_trust_digest: digest(
                "compensation-outcome-trust",
                &json!({"source_id":self.source_id,"keys":self.outcome_keys.iter().map(|(id,k)|(id.clone(),hex::encode(k.as_bytes()))).collect::<BTreeMap<_,_>>()}),
            )?,
            topology_digest: s.topology.digest()?,
            contract_digest: self.contract.digest()?,
            qualification_digest: q.digest()?,
            forward: q.verification.forward.clone(),
            inverse_operation_key: self.contract.inverse_operation_key.clone(),
            grant_digest: gd.into(),
            certificate_digest: g.certificate_digest.clone(),
            parameters_digest: g.parameters_digest.clone(),
            compensation_units: self.contract.compensation_units,
            valid_from: g.valid_from,
            expires_at: g.expires_at,
        })
    }
    pub(crate) async fn bound(
        &self,
        l: &EtcdLedger,
        g: &Grant,
        gd: &str,
        live: bool,
    ) -> Result<(Binding, Spend, Vec<Value>)> {
        let key = binding_key(l, gd);
        let raw = l.read_key(&key).await?.ok_or_else(refuse)?;
        if raw.len() > 16384 {
            return Err(refuse());
        }
        let b: Binding = serde_json::from_value(strict_value(&raw)?)?;
        let s = l.action_domain.as_ref().ok_or_else(refuse)?;
        b.verify(&issuer_keys(s)?)?;
        let (q, mut compare) = if live {
            self.live(l).await?
        } else {
            self.qualifier(l)?
                .historical_qualification(&b.payload.qualification_digest)
                .await?
        };
        if b.payload != self.payload(l, &q, g, gd)? {
            return Err(refuse());
        }
        let seal = seal_key(l, &self.contract.forward_operation_key);
        if l.read_key(&seal).await?.as_deref() != Some(raw.as_slice()) {
            return Err(refuse());
        }
        let sk = spend_key(l, &self.contract.forward_operation_key);
        let sr = l.read_key(&sk).await?.ok_or_else(refuse)?;
        if sr.len() > 8192 {
            return Err(refuse());
        }
        let spend: Spend = serde_json::from_value(strict_value(&sr)?)?;
        validate(&json!(spend))?;
        if spend.profile != PROFILE
            || spend.forward_operation_key != self.contract.forward_operation_key
            || spend.inverse_operation_key != self.contract.inverse_operation_key
            || spend.grant_digest != gd
            || spend.binding_digest != b.digest()?
            || spend.compensation_units != self.contract.compensation_units
            || spend.state == S::Composite
            || (spend.state == S::Allocated) != (spend.attempt_id.is_none())
            || (matches!(spend.state, S::Committed | S::ProvenNoEffect))
                != spend.receipt_digest.is_some()
        {
            return Err(refuse());
        }
        compare.extend([
            value_eq(&key, std::str::from_utf8(&raw).map_err(|_| refuse())?),
            value_eq(&seal, std::str::from_utf8(&raw).map_err(|_| refuse())?),
            value_eq(&sk, std::str::from_utf8(&sr).map_err(|_| refuse())?),
        ]);
        if live
            && (l.authority_clock.now_ms() < g.valid_from
                || l.authority_clock.now_ms() >= g.expires_at)
        {
            return Err(refuse());
        }
        Ok((b, spend, compare))
    }
}
impl Qualifier {
    pub async fn begin_compensation(&self) -> Result<()> {
        self.begin_native_compensation().await
    }
}
impl EtcdLedger {
    pub(crate) async fn prepare_inverse_issuance(&self) -> Result<Option<Arc<PreparedIssuance>>> {
        if !crate::family_saga_epoch::selected(self) {
            return Ok(None);
        }
        let Some(e) = &self.inverse_execution else {
            return Ok(None);
        };
        let (qualification, compare) = e.live(self).await?;
        Ok(Some(Arc::new(PreparedIssuance {
            namespace: self.namespace().into(),
            execution_pin: e.issuance_pin()?,
            checked_at: self.authority_clock.now_ms(),
            qualification,
            compare,
        })))
    }
    pub(crate) async fn inverse_operation_compare(&self, op: &str) -> Result<Vec<Value>> {
        let key = format!("{}/inverse-operations/{op}", self.namespace());
        if let Some(e) = &self.inverse_execution {
            if op != e.contract.inverse_operation_key {
                return Err(refuse());
            }
            return Ok(vec![value_eq(&key, &e.qualifier(self)?.marker()?)]);
        }
        Ok(vec![version_zero(&key)])
    }
    pub(crate) async fn inverse_admission(
        &self,
        p: &crate::policy::PreparedAdmission,
    ) -> Result<Vec<Value>> {
        let Some(e) = &self.inverse_execution else {
            return Ok(vec![]);
        };
        if !self.inverse_record_roles(p.record_keys.iter()) {
            return Err(refuse());
        }
        let (q, mut c) = e.live(self).await?;
        e.request(
            &q,
            &p.key,
            &Principal {
                subject: p.context.subject.clone(),
                workload_id: p.context.workload_id.clone(),
            },
            &digest(
                "parameters",
                &strict_value(p.packet.proposal.as_bytes())?["payload"]["parameters"],
            )?,
            p.expires_at,
        )?;
        if p.control_scope != e.contract.inverse_scope
            || p.context.policy != e.contract.inverse_policy
            || p.context.tenant != e.trust.registration.enrollment.tenant
        {
            return Err(refuse());
        }
        c.extend(self.inverse_operation_compare(&p.key).await?);
        if self.authority_clock.now_ms() >= p.expires_at {
            return Err(refuse());
        }
        Ok(c)
    }
    pub(crate) async fn inverse_candidate(
        &self,
        a: &crate::issuance::AdmittedIssuance,
    ) -> Result<Vec<Value>> {
        let Some(e) = &self.inverse_execution else {
            return Ok(vec![]);
        };
        let (q, mut c) = e.issuance_proof(self, a).await?;
        e.payload(self, &q, &a.grant, &a.grant_digest)?;
        if a.key != e.contract.inverse_operation_key
            || a.tenant != e.trust.registration.enrollment.tenant
        {
            return Err(refuse());
        }
        c.extend(self.inverse_operation_compare(&a.key).await?);
        if self.authority_clock.now_ms() < a.grant.valid_from
            || self.authority_clock.now_ms() >= a.grant.expires_at
        {
            return Err(refuse());
        }
        Ok(c)
    }
    pub(crate) async fn sign_inverse(
        &self,
        a: &crate::issuance::AdmittedIssuance,
        id: &str,
        key: &SigningKey,
    ) -> Result<Option<Binding>> {
        let Some(e) = &self.inverse_execution else {
            return Ok(None);
        };
        let (q, _) = e.issuance_proof(self, a).await?;
        let mut b = Binding {
            profile: PROFILE.into(),
            key_id: id.into(),
            payload: e.payload(self, &q, &a.grant, &a.grant_digest)?,
            signature: String::new(),
        };
        b.signature = URL_SAFE_NO_PAD.encode(key.sign(&b.message()?).to_bytes());
        Ok(Some(b))
    }
    pub(crate) async fn inverse_issue(
        &self,
        a: &crate::issuance::AdmittedIssuance,
        b: Option<&Binding>,
    ) -> Result<Change> {
        let Some(e) = &self.inverse_execution else {
            if b.is_some() {
                return Err(refuse());
            }
            return Ok(change(vec![], vec![]));
        };
        let b = b.ok_or_else(refuse)?;
        let (q, mut c) = e.issuance_proof(self, a).await?;
        b.verify(&issuer_keys(
            self.action_domain.as_ref().ok_or_else(refuse)?,
        )?)?;
        if b.payload != e.payload(self, &q, &a.grant, &a.grant_digest)?
            || a.key != e.contract.inverse_operation_key
        {
            return Err(refuse());
        }
        let sk = spend_key(self, &e.contract.forward_operation_key);
        let bk = binding_key(self, &a.grant_digest);
        let seal = seal_key(self, &e.contract.forward_operation_key);
        c.extend([version_zero(&sk), version_zero(&bk), version_zero(&seal)]);
        let state = q
            .proof
            .forward
            .events
            .last()
            .ok_or_else(refuse)?
            .after
            .allocations
            .get(&e.contract.forward_operation_key)
            .ok_or_else(refuse)?;
        if state.state != S::Committed || state.compensation < e.contract.compensation_units {
            return Err(refuse());
        }
        let spend = Spend {
            profile: PROFILE.into(),
            forward_operation_key: e.contract.forward_operation_key.clone(),
            inverse_operation_key: a.key.clone(),
            grant_digest: a.grant_digest.clone(),
            binding_digest: b.digest()?,
            compensation_units: e.contract.compensation_units,
            state: S::Allocated,
            attempt_id: None,
            receipt_digest: None,
        };
        if self.authority_clock.now_ms() < a.grant.valid_from
            || self.authority_clock.now_ms() >= a.grant.expires_at
        {
            return Err(refuse());
        }
        Ok(change(
            c,
            vec![
                put(&sk, &record(&spend)?),
                put(&bk, &record(b)?),
                put(&seal, &record(b)?),
            ],
        ))
    }
    pub(crate) async fn inverse_check_issuance(&self, r: &IssuanceRecord) -> Result<()> {
        let Some(e) = &self.inverse_execution else {
            return Ok(());
        };
        let s = self.action_domain.as_ref().ok_or_else(refuse)?;
        let g = GrantVerifier {
            keys: issuer_keys(s)?,
            audience: s.registration().scope.audience.clone(),
        }
        .verify_retained(r.signed_grant.as_bytes())?;
        let (_, _, c) = e.bound(self, &g.grant, &g.digest, true).await?;
        if r.issuance_key != e.contract.inverse_operation_key
            || !self.txn(c, vec![], vec![]).await?.succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub(crate) async fn inverse_claim(
        &self,
        g: &Grant,
        gd: &str,
        attempt: &str,
        claimed_at: i64,
    ) -> Result<Change> {
        let Some(e) = &self.inverse_execution else {
            return Ok(change(vec![], vec![]));
        };
        let (binding, mut s, mut c) = e.bound(self, g, gd, true).await?;
        if s.state != S::Allocated {
            return Err(refuse());
        }
        s.state = S::Unknown;
        s.attempt_id = Some(attempt.into());
        let global = crate::family_saga_runtime::claim(self, binding, attempt, claimed_at).await?;
        c.extend(global.compare);
        let mut writes = global.writes;
        writes.push(put(
            &spend_key(self, &e.contract.forward_operation_key),
            &record(&s)?,
        ));
        Ok(change(c, writes))
    }
    pub(crate) async fn inverse_dispatch(
        &self,
        g: &Grant,
        gd: &str,
        attempt: &str,
    ) -> Result<Change> {
        let Some(e) = &self.inverse_execution else {
            return Ok(change(vec![], vec![]));
        };
        let (_, s, c) = e.bound(self, g, gd, true).await?;
        if s.state != S::Unknown || s.attempt_id.as_deref() != Some(attempt) {
            return Err(refuse());
        }
        Ok(change(c, vec![]))
    }
    pub(crate) async fn inverse_refine(
        &self,
        g: &Grant,
        gd: &str,
        attempt: &str,
        head: &crate::recovery::ReceiptHead,
    ) -> Result<Change> {
        let Some(e) = &self.inverse_execution else {
            if g.action.id == crate::compensation::ACTION {
                return Err(refuse());
            }
            return Ok(change(vec![], vec![]));
        };
        let (_, mut s, c) = e.bound(self, g, gd, false).await?;
        if s.attempt_id.as_deref() != Some(attempt) {
            return Err(refuse());
        }
        let receipt = crate::schema::verify_record(
            head.signed_receipt.as_bytes(),
            "receipt",
            &e.outcome_keys,
        )?;
        if receipt.payload["source_id"] != e.source_id
            || receipt.payload["attempt_id"] != attempt
            || receipt.payload["grant_digest"] != gd
            || receipt.payload["root_id"] != g.root_id
        {
            return Err(refuse());
        }
        let next = match receipt.payload["status"].as_str() {
            Some("committed") => S::Committed,
            Some("not_dispatched") => S::ProvenNoEffect,
            _ => S::Unknown,
        };
        if s.state != S::Unknown && s.state != next {
            return Err(refuse());
        }
        s.state = next;
        s.receipt_digest = if s.state == S::Unknown {
            None
        } else {
            Some(head.receipt_digest.clone())
        };
        Ok(change(
            c,
            vec![put(
                &spend_key(self, &e.contract.forward_operation_key),
                &record(&s)?,
            )],
        ))
    }
    /// Export only the original bound dispatch material after native dispatch
    /// authorization. This performs a read CAS and confers no send permission.
    pub async fn compensation_dispatch_material(
        &self,
        g: &Grant,
        gd: &str,
        attempt: &str,
    ) -> Result<(Binding, Qualification)> {
        let e = self.inverse_execution.as_ref().ok_or_else(refuse)?;
        let (binding, spend, mut compare) = e.bound(self, g, gd, true).await?;
        if spend.state != S::Unknown || spend.attempt_id.as_deref() != Some(attempt) {
            return Err(refuse());
        }
        let candidate = crate::recovery::Candidate {
            grant: g.clone(),
            attempt_id: attempt.into(),
        };
        let snapshot = self.recovery_snapshot(&candidate).await?;
        if snapshot.attempt.grant_digest != gd || snapshot.outbox != "dispatch_authorized" {
            return Err(refuse());
        }
        let (q, proof_compare) = e.live(self).await?;
        if q.digest()? != binding.payload.qualification_digest {
            return Err(refuse());
        }
        compare.extend(proof_compare);
        if !self.txn(compare, vec![], vec![]).await?.succeeded {
            return Err(refuse());
        }
        Ok((binding, q))
    }
    pub async fn compensation_spend(&self) -> Result<Spend> {
        let e = self.inverse_execution.as_ref().ok_or_else(refuse)?;
        let raw = self
            .read_key(&spend_key(self, &e.contract.forward_operation_key))
            .await?
            .ok_or_else(refuse)?;
        let value = strict_value(&raw)?;
        validate(&value)?;
        Ok(serde_json::from_value(value)?)
    }
    pub(crate) fn inverse_recovery_role(&self, id: &str, key: &VerifyingKey, source: &str) -> bool {
        self.inverse_execution
            .as_ref()
            .is_none_or(|e| e.source_id == source && e.outcome_keys.get(id) == Some(key))
    }
    pub(crate) fn inverse_input_roles(
        &self,
        trust: &crate::admission::AdmissionTrust,
        admission: &BTreeMap<String, VerifyingKey>,
        issuers: &BTreeMap<String, VerifyingKey>,
    ) -> bool {
        self.inverse_execution.as_ref().is_none_or(|e| {
            let Ok(barrier) = crate::control_config::keys(&e.contract.barrier_keys) else {
                return false;
            };
            let Ok(app) = crate::control_config::keys(&e.contract.applicability_keys) else {
                return false;
            };
            let forbidden = barrier
                .values()
                .chain(app.values())
                .chain(e.outcome_keys.values())
                .collect::<Vec<_>>();
            trust
                .proposal_keys
                .values()
                .chain(trust.registry_keys.values())
                .chain(trust.manifest_keys.values())
                .chain(trust.evidence.values().flat_map(|r| r.keys.values()))
                .chain(admission.values())
                .chain(issuers.values())
                .all(|k| !forbidden.contains(&k))
        })
    }
    pub(crate) fn inverse_record_roles<'a>(
        &self,
        keys: impl IntoIterator<Item = &'a VerifyingKey>,
    ) -> bool {
        let Some(e) = &self.inverse_execution else {
            return true;
        };
        let Ok(barrier) = crate::control_config::keys(&e.contract.barrier_keys) else {
            return false;
        };
        let Ok(app) = crate::control_config::keys(&e.contract.applicability_keys) else {
            return false;
        };
        let forbidden = barrier
            .values()
            .chain(app.values())
            .chain(e.outcome_keys.values())
            .collect::<Vec<_>>();
        keys.into_iter().all(|k| !forbidden.contains(&k))
    }
}
