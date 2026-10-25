//! Explicit multi-contract family composition. Native child authority remains
//! independently admitted; orchestration records never become executable grants.
use crate::{
    contracts::{canonical, digest, strict_value},
    error::{Error, Result},
    family::Registration,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

pub const PROFILE: &str = "KF-FAMILY-SAGA-0.1-draft";
pub const MAX_PROOF: usize = 512 << 10;
pub const MAX_HISTORY_BYTES: usize = 16 << 20;
pub use crate::family_saga_audit::{
    AuditTrust, Bundle as AggregateBundle, Checkpoint as AggregateCheckpoint,
    Evidence as AggregateEvidence, Verification as AggregateVerification,
    verify as verify_aggregate,
};
pub use crate::family_saga_bindings::{AuthorityBinding, View as AuthorityView};
pub use crate::family_saga_manager::{MemberObservers, Saga};
pub use crate::family_saga_phase::{Event as PhaseEvent, Flight, Phase, State as PhaseState};
pub use crate::family_saga_prepared::Prepared;
// Explicit protected opt-in. The named profile never changes legacy family or
// child wire behavior, and collection/owner commands confer no native grant.
pub(crate) fn native_enabled() -> bool {
    true
}
pub(crate) fn require_native(r: &Registration) -> Result<()> {
    if r.composition.is_some() && !native_enabled() {
        return Err(Error::Refused(
            "native family saga profile is not enabled".into(),
        ));
    }
    Ok(())
}
fn refused() -> Error {
    Error::Refused("family saga plan, phase or complete original evidence refused".into())
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObserverPin {
    pub id: String,
    pub keys: BTreeMap<String, String>,
}
impl ObserverPin {
    fn parsed(&self) -> Result<BTreeMap<String, VerifyingKey>> {
        if !id(&self.id) || !(1..=16).contains(&self.keys.len()) {
            return Err(refused());
        }
        let keys = crate::control_config::keys(&self.keys)?;
        if keys.keys().any(|k| !id(k))
            || keys
                .values()
                .map(|k| *k.as_bytes())
                .collect::<BTreeSet<_>>()
                .len()
                != keys.len()
        {
            return Err(refused());
        }
        Ok(keys)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub child_id: String,
    pub operation_key: String,
    pub depends_on: Vec<String>,
    /// Closed public native trust, decoded by the existing profile validator.
    pub forward_trust: Value,
    pub compound_trust: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::kube_drain_proof::deserialize_optional"
    )]
    pub physical: Option<crate::kube_drain_proof::Trust>,
}
impl Node {
    pub(crate) fn trust_digest(&self, inverse: bool) -> Result<String> {
        use crate::family_saga_cache::{ByteCache, key};
        static CACHE: OnceLock<Mutex<ByteCache<String>>> = OnceLock::new();
        let raw = serde_json::to_vec(self)?;
        let identity = key("family-native-trust-digest", &[&raw, &[u8::from(inverse)]]);
        let cache = CACHE.get_or_init(|| Mutex::new(ByteCache::new(32)));
        if let Some(digest) = cache.lock().map_err(|_| refused())?.get(&identity) {
            return Ok(digest);
        }
        let t = if inverse {
            self.compound()?.ok_or_else(refused)?.inverse
        } else {
            self.forward()?.lineage
        };
        let digest =
            crate::governance::trust_digest(&t.admission, &t.admission_keys, &t.grants.keys)?;
        cache
            .lock()
            .map_err(|_| refused())?
            .insert(identity, raw.len(), digest.clone());
        Ok(digest)
    }
    pub(crate) fn forward(&self) -> Result<crate::reserved_lineage::Trust> {
        static CACHE: OnceLock<Mutex<BTreeMap<String, crate::reserved_lineage::Trust>>> =
            OnceLock::new();
        let raw = serde_json::to_vec(&self.forward_trust)?;
        if raw.len() > 128 << 10 {
            return Err(refused());
        }
        let key = crate::family_saga_cache::key("family-saga-forward-public-pins", &[&raw]);
        let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
        if let Some(t) = cache.lock().map_err(|_| refused())?.get(&key).cloned() {
            return Ok(t);
        }
        let t = crate::reserved_lineage::TrustConfig::decode(&raw)?.registration()?;
        let mut cache = cache.lock().map_err(|_| refused())?;
        if cache.len() >= 32 {
            cache.pop_first();
        }
        cache.insert(key, t.clone());
        Ok(t)
    }
    pub(crate) fn compound(&self) -> Result<Option<crate::compensation_lineage::Trust>> {
        static CACHE: OnceLock<Mutex<BTreeMap<String, crate::compensation_lineage::Trust>>> =
            OnceLock::new();
        let Some(v) = &self.compound_trust else {
            return Ok(None);
        };
        let raw = serde_json::to_vec(v)?;
        if raw.len() > 128 << 10 {
            return Err(refused());
        }
        let key = crate::family_saga_cache::key("family-saga-compound-public-pins", &[&raw]);
        let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
        if let Some(t) = cache.lock().map_err(|_| refused())?.get(&key).cloned() {
            return Ok(Some(t));
        }
        let t = crate::compensation_lineage::TrustConfig::decode(&raw)?.registration()?;
        let mut cache = cache.lock().map_err(|_| refused())?;
        if cache.len() >= 32 {
            cache.pop_first();
        }
        cache.insert(key, t.clone());
        Ok(Some(t))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub profile: String,
    pub saga_id: String,
    pub nodes: Vec<Node>,
    pub family_observer: ObserverPin,
    pub observer: ObserverPin,
}
impl Plan {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 128 << 10 {
            return Err(refused());
        }
        let v = strict_value(raw)?;
        let p: Self = serde_json::from_value(v.clone())?;
        if json!(p) != v {
            return Err(refused());
        }
        Ok(p)
    }
    pub fn digest(&self) -> Result<String> {
        digest("family-saga-plan", &json!(self))
    }
    pub fn node(&self, id: &str) -> Result<&Node> {
        self.nodes
            .iter()
            .find(|n| n.child_id == id)
            .ok_or_else(refused)
    }
    pub fn validate(&self, r: &Registration) -> Result<()> {
        if self.profile != PROFILE
            || r.profile != PROFILE
            || r.composition.as_ref() != Some(self)
            || !id(&self.saga_id)
            || self.nodes.is_empty()
            || self.nodes.len() > 8
            || self.nodes.len() != r.children.len()
            || canonical(&json!(self))?.len() > 128 << 10
        {
            return Err(refused());
        }
        let aggregate = self.observer.parsed()?;
        let family = self.family_observer.parsed()?;
        if self.observer.id == self.family_observer.id
            || aggregate.values().any(|k| family.values().any(|f| f == k))
        {
            return Err(refused());
        }
        let observers: Vec<_> = aggregate.values().chain(family.values()).collect();
        let owners = r
            .signers
            .values()
            .map(|s| {
                VerifyingKey::from_bytes(&crate::config::key(&s.public_key)?).map_err(|_| refused())
            })
            .collect::<Result<Vec<_>>>()?;
        let mut physical_keys = Vec::new();
        if self.nodes.iter().filter(|n| n.physical.is_some()).count() > 1 {
            return Err(refused());
        }
        for n in &self.nodes {
            if let Some(p) = &n.physical {
                p.validate()?;
                if p.control_trust["operation"] != n.forward_trust["lineage"]
                    || p.control()?.namespace != r.namespace
                {
                    return Err(refused());
                }
                let child = r.child(&n.child_id)?;
                let scope = &child.reservation.scope;
                if child.inverse.is_some()
                    || child.topology.is_some()
                    || scope.action.id != p.action()
                    || scope.action.version != p.version()
                    || scope.resource != p.contract.resource()?
                    || scope.adapter_contract != p.adapter()
                    || child.reservation.enrollment.compensation != 0
                {
                    return Err(refused());
                }
                if let Some(e) = &p.operating {
                    e.validate_child(r, &n.child_id, &p.contract)?;
                }
                for key in &p.signing_keys()? {
                    if owners.contains(key) || observers.contains(&key) {
                        return Err(refused());
                    }
                }
                for key in &p.audit_signing_keys()? {
                    if physical_keys.contains(key)
                        || owners.contains(key)
                        || observers.contains(&key)
                    {
                        return Err(refused());
                    }
                    physical_keys.push(*key);
                }
            } else if crate::kube_drain::is_action(
                &r.child(&n.child_id)?.reservation.scope.action.id,
            ) {
                return Err(refused());
            }
        }
        let reserved: Vec<_> = observers
            .iter()
            .copied()
            .chain(owners.iter())
            .chain(physical_keys.iter())
            .collect();
        if r.signers.values().any(|s| {
            crate::config::key(&s.public_key)
                .is_ok_and(|k| observers.iter().any(|o| o.as_bytes() == &k))
        }) {
            return Err(refused());
        }
        let mut children = BTreeSet::new();
        let mut operations = BTreeSet::new();
        let mut forward = 0u64;
        let mut compensation = 0u64;
        for n in &self.nodes {
            if !id(&n.child_id)
                || !crate::grant_reference::valid_reference(&n.operation_key)
                || !children.insert(n.child_id.clone())
                || !operations.insert(n.operation_key.clone())
                || n.depends_on.iter().collect::<BTreeSet<_>>().len() != n.depends_on.len()
            {
                return Err(refused());
            }
            let child = r.child(&n.child_id)?;
            if child.keys()?.iter().any(|k| observers.contains(&k)) {
                return Err(refused());
            }
            let native = child.reservation.saga.as_ref().ok_or_else(refused)?;
            if native.nodes.len() != 1
                || native.nodes[0].operation_key != n.operation_key
                || !native.nodes[0].depends_on.is_empty()
                || n.depends_on.len() > self.nodes.len() - 1
                || r.valid_from < native.valid_from
                || r.expires_at > native.expires_at
            {
                return Err(refused());
            }
            let mut trust = n.forward()?;
            if trust.registration != child.reservation
                || trust.namespace != r.namespace
                || reserved
                    .iter()
                    .any(|k| trust.observer_keys.values().any(|o| o == *k))
            {
                return Err(refused());
            }
            for (i, k) in reserved.iter().enumerate() {
                trust.observer_keys.insert(format!("composition-{i}"), **k);
            }
            // Reuse the complete native role/hierarchy separation checks for
            // both extra observer roles, without changing actual child pins.
            trust.validate()?;
            match (&child.inverse, &child.topology, n.compound()?) {
                (Some(contract), Some(topology), Some(mut compound)) => {
                    if !operations.insert(contract.inverse_operation_key.clone()) {
                        return Err(refused());
                    }
                    if n.compound_trust.as_ref().ok_or_else(refused)?["forward"] != n.forward_trust
                        || r.valid_from < contract.valid_from
                        || r.expires_at > contract.expires_at
                        || compound.forward.registration != child.reservation
                        || compound.forward.namespace != r.namespace
                        || compound.contract != *contract
                        || compound.topology != *topology
                        || reserved
                            .iter()
                            .any(|k| compound.observer_keys.values().any(|o| o == *k))
                    {
                        return Err(refused());
                    }
                    for (i, k) in reserved.iter().enumerate() {
                        compound
                            .observer_keys
                            .insert(format!("composition-{i}"), **k);
                    }
                    compound.validate()?;
                }
                (None, None, None) => {}
                _ => return Err(refused()),
            }
            forward = forward
                .checked_add(child.reservation.enrollment.forward)
                .ok_or_else(refused)?;
            compensation = compensation
                .checked_add(child.reservation.enrollment.compensation)
                .ok_or_else(refused)?;
            let mut pending = n.depends_on.clone();
            let mut seen = BTreeSet::new();
            while let Some(parent) = pending.pop() {
                if parent == n.child_id {
                    return Err(refused());
                }
                let p = self.node(&parent)?;
                if seen.insert(parent) {
                    pending.extend(p.depends_on.clone());
                }
            }
        }
        if forward > r.forward || compensation > r.compensation {
            return Err(refused());
        }
        Ok(())
    }
}
pub fn deserialize_plan<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Plan>, D::Error> {
    let value = crate::contracts::strict_deserialize(d)?;
    Plan::decode(&serde_json::to_vec(&value).map_err(serde::de::Error::custom)?)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardState {
    Unissued,
    Unclaimed,
    Unknown,
    Committed,
    NoEffect,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InverseState {
    Absent,
    Unclaimed,
    Unknown,
    Failed,
    Committed,
    NoEffect,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemberSummary {
    pub forward: ForwardState,
    pub forward_grant: Option<String>,
    pub forward_attempt: Option<String>,
    pub forward_head: String,
    pub inverse: InverseState,
    pub inverse_grant: Option<String>,
    pub inverse_attempt: Option<String>,
    pub inverse_receipt: Option<String>,
    pub qualification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_head: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSnapshot {
    pub captured_at: i64,
    pub events: Vec<crate::reservation_history::Event>,
    pub authorizations: BTreeMap<String, crate::lineage::AuthorizationBundle>,
    pub executions: BTreeMap<String, crate::reserved_lineage::Bundle>,
    /// Qualified by the collector's original native root/nonce comparisons.
    pub unclaimed: bool,
    /// Qualified absence of inverse authority/spend/seal when no forward claim exists.
    pub inverse_absent: bool,
    pub compound: Option<crate::compensation_lineage::Bundle>,
    /// Separate collector's positive pre-qualification inventory. A claimed
    /// forward may be unknown or known before any inverse qualification exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_absent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composition_bindings: Option<BTreeMap<String, AuthorityBinding>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::kube_drain_proof::deserialize_optional"
    )]
    pub physical: Option<crate::kube_drain_proof::Capture>,
}
impl MemberSnapshot {
    pub fn verify(&self, r: &Registration, n: &Node) -> Result<MemberSummary> {
        use crate::coordination::ReservationState as S;
        r.validate()?;
        if r.composition
            .as_ref()
            .ok_or_else(refused)?
            .node(&n.child_id)?
            != n
        {
            return Err(refused());
        }
        if self.captured_at < r.valid_from
            || self.captured_at > crate::contracts::MAX_SAFE_INTEGER as i64
            || canonical(&json!(self))?.len() > MAX_PROOF
        {
            return Err(refused());
        }
        let t = n.forward()?;
        if self.qualification_absent.is_some()
            && (self.qualification_absent != Some(true)
                || self.compound.is_some()
                || n.compound()?.is_none()
                || self.unclaimed
                || !self.inverse_absent)
        {
            return Err(refused());
        }
        if t.registration != r.child(&n.child_id)?.reservation || t.namespace != r.namespace {
            return Err(refused());
        }
        let state = crate::reserved_lineage::verify_inventory(
            &self.events,
            &t,
            self.captured_at,
            &self.authorizations,
        )?;
        let a = state
            .allocations
            .get(&n.operation_key)
            .ok_or_else(refused)?;
        let forward_head = self.events.last().ok_or_else(refused)?.digest()?;
        if self.authorizations.keys().any(|op| op != &n.operation_key)
            || self.executions.keys().any(|op| op != &n.operation_key)
        {
            return Err(refused());
        }
        let authorization = self.authorizations.get(&n.operation_key);
        let forward_grant = authorization.map(|a| a.issuance.grant_digest.clone());
        let forward = if let Some(id) = &a.attempt_id {
            if self.unclaimed || authorization.is_none() {
                return Err(refused());
            }
            let b = self.executions.get(&n.operation_key).ok_or_else(refused)?;
            if b.checkpoint.payload.captured_at > self.captured_at {
                return Err(refused());
            }
            let v = crate::reserved_lineage::verify(b, &t)?;
            if v.lineage.operation_key != n.operation_key
                || v.lineage.attempt_id != *id
                || Some(v.lineage.grant_digest) != forward_grant
                || canonical(&json!(b.events))? != canonical(&json!(self.events))?
            {
                return Err(refused());
            }
            match a.state {
                S::Unknown => ForwardState::Unknown,
                S::Committed => ForwardState::Committed,
                S::ProvenNoEffect => ForwardState::NoEffect,
                _ => return Err(refused()),
            }
        } else {
            if !self.unclaimed || a.state != S::Allocated || !self.executions.is_empty() {
                return Err(refused());
            }
            if authorization.is_some() {
                ForwardState::Unclaimed
            } else {
                ForwardState::Unissued
            }
        };
        let mut summary = MemberSummary {
            forward,
            forward_grant,
            forward_attempt: a.attempt_id.clone(),
            forward_head,
            inverse: InverseState::Absent,
            inverse_grant: None,
            inverse_attempt: None,
            inverse_receipt: None,
            qualification: None,
            physical_status: None,
            physical_head: None,
        };
        match (n.compound()?, self.compound.as_ref()) {
            (Some(t), Some(b)) if a.attempt_id.is_some() => {
                if b.checkpoint.captured_at > self.captured_at
                    || Some(&t.contract) != r.child(&n.child_id)?.inverse.as_ref()
                    || Some(&t.topology) != r.child(&n.child_id)?.topology.as_ref()
                {
                    return Err(refused());
                }
                if self.inverse_absent {
                    return Err(refused());
                }
                crate::compensation_lineage::verify(b, &t)?;
                let f = b
                    .evidence
                    .forward
                    .get(&n.operation_key)
                    .ok_or_else(refused)?;
                if canonical(&json!(f.events))? != canonical(&json!(self.events))? {
                    return Err(refused());
                }
                summary.qualification = b
                    .evidence
                    .qualifications
                    .last()
                    .map(|q| q.digest())
                    .transpose()?;
                if let Some(i) = &b.evidence.inverse {
                    summary.inverse_grant = Some(i.authorization.issuance.grant_digest.clone());
                    summary.inverse_attempt = i.spend.attempt_id.clone();
                    summary.inverse_receipt = i.spend.receipt_digest.clone();
                    summary.inverse = match i.spend.state {
                        S::Allocated => InverseState::Unclaimed,
                        S::Unknown => InverseState::Unknown,
                        S::Committed => InverseState::Committed,
                        S::ProvenNoEffect => InverseState::NoEffect,
                        _ => return Err(refused()),
                    };
                    // The native allowance deliberately stays Unknown after a
                    // dispatched guard failure. A complete original signed
                    // failure receipt can nevertheless report that terminal
                    // failure without refunding spend or calling it no effect.
                    if summary.inverse == InverseState::Unknown
                        && let Some(receipt) =
                            i.lineage.as_ref().and_then(|l| l.outcomes.receipts.last())
                    {
                        let receipt = crate::schema::verify_record(
                            receipt.as_bytes(),
                            "receipt",
                            &t.inverse.outcome_keys,
                        )?;
                        if receipt.payload["status"] == "failed" {
                            summary.inverse = InverseState::Failed;
                            summary.inverse_receipt =
                                Some(crate::contracts::record_digest(&receipt)?);
                        }
                    }
                }
            }
            (Some(_), None) if a.attempt_id.is_none() && self.inverse_absent => {}
            (Some(_), None) if self.qualification_absent == Some(true) && self.inverse_absent => {}
            (None, None) if self.inverse_absent => {}
            _ => return Err(refused()),
        }
        if let Some(bindings) = &self.composition_bindings {
            crate::family_saga_bindings::verify_member(r, n, self, bindings)?;
        }
        crate::kube_drain_verify::member(r, n, self, &mut summary)?;
        Ok(summary)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntentAction {
    Quiesce,
    Observe,
    PrepareCompensation,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntentPayload {
    pub family_digest: String,
    pub operation_key: String,
    pub expected_head: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub action: IntentAction,
    pub proof_digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub profile: String,
    pub key_id: String,
    pub payload: IntentPayload,
    pub signature: String,
}
impl Intent {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 16 << 10 {
            return Err(refused());
        }
        let v = strict_value(raw)?;
        let c: Self = serde_json::from_value(v.clone())?;
        if json!(c) != v {
            return Err(refused());
        }
        c.structural()?;
        Ok(c)
    }
    fn structural(&self) -> Result<()> {
        let p = &self.payload;
        if self.profile != PROFILE
            || !id(&self.key_id)
            || !crate::grant_reference::valid_reference(&p.family_digest)
            || !crate::grant_reference::valid_reference(&p.operation_key)
            || !crate::grant_reference::valid_reference(&p.expected_head)
            || p.issued_at < 0
            || p.expires_at > crate::contracts::MAX_SAFE_INTEGER as i64
            || p.expires_at <= p.issued_at
            || p.expires_at - p.issued_at > 60000
            || canonical(&json!(self))?.len() > 16 << 10
            || p.proof_digest
                .as_ref()
                .is_some_and(|s| !crate::grant_reference::valid_reference(s))
            || (p.action == IntentAction::Quiesce) != p.proof_digest.is_none()
        {
            return Err(refused());
        }
        Ok(())
    }
    fn message(&self) -> Result<Vec<u8>> {
        let mut bytes = format!("KedgeFlow:{PROFILE}:owner-intent\0").into_bytes();
        bytes.extend(canonical(
            &json!({"profile":self.profile,"key_id":self.key_id,"payload":self.payload}),
        )?);
        Ok(bytes)
    }
    pub fn sign(
        payload: IntentPayload,
        key_id: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let mut c = Self {
            profile: PROFILE.into(),
            key_id: key_id.into(),
            payload,
            signature: String::new(),
        };
        c.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key.sign(&c.message()?).to_bytes());
        c.structural()?;
        Ok(c)
    }
    pub fn verify_owner(&self, r: &Registration) -> Result<()> {
        use base64::Engine;
        self.structural()?;
        if r.profile != PROFILE
            || r.composition.is_none()
            || self.payload.family_digest != r.digest()?
        {
            return Err(refused());
        }
        let pin = r.signers.get(&self.key_id).ok_or_else(refused)?;
        if pin.principal != r.owner {
            return Err(refused());
        }
        let key = VerifyingKey::from_bytes(&crate::config::key(&pin.public_key)?)
            .map_err(|_| refused())?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| refused())?;
        if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != self.signature {
            return Err(refused());
        }
        key.verify_strict(
            &self.message()?,
            &ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| refused())?,
        )
        .map_err(|_| refused())
    }
    /// Check an owner intent. Validation alone retains nothing and conveys no
    /// native leaf execution authority.
    pub fn validate_at(&self, r: &Registration, now: i64) -> Result<()> {
        self.verify_owner(r)?;
        let p = &self.payload;
        if now < p.issued_at
            || now >= p.expires_at
            || p.issued_at < r.valid_from
            || p.action != IntentAction::Observe
                && (now >= r.expires_at || p.expires_at > r.expires_at)
        {
            return Err(refused());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub profile: String,
    pub registration_digest: String,
    pub phase_head: String,
    pub epoch: String,
    pub captured_at: i64,
    pub members: BTreeMap<String, MemberSnapshot>,
}
impl Snapshot {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_PROOF {
            return Err(Error::Refused(
                "complete family snapshot exceeds 512 KiB".into(),
            ));
        }
        let v = strict_value(raw)?;
        let s: Self = serde_json::from_value(v.clone())?;
        if json!(s) != v {
            return Err(refused());
        }
        Ok(s)
    }
    pub fn digest(&self) -> Result<String> {
        digest("family-saga-complete-snapshot", &json!(self))
    }
    /// Check carriage and original native evidence. The separate signed
    /// aggregate collector must also qualify namespace, absence and epoch;
    /// this unsigned snapshot establishes neither current state nor authority.
    pub fn verify(&self, r: &Registration) -> Result<BTreeMap<String, MemberSummary>> {
        use crate::family_saga_cache::{ByteCache, key};
        static CACHE: OnceLock<Mutex<ByteCache<BTreeMap<String, MemberSummary>>>> = OnceLock::new();
        let raw = canonical(&json!(self))?;
        if raw.len() > MAX_PROOF {
            return Err(refused());
        }
        let registration = r.digest()?;
        let cached_key = key(
            "verified-original-family-snapshot",
            &[registration.as_bytes(), &raw],
        );
        let cache = CACHE.get_or_init(|| Mutex::new(ByteCache::new(128)));
        if let Some(states) = cache.lock().map_err(|_| refused())?.get(&cached_key) {
            return Ok(states);
        }
        r.validate()?;
        let plan = r.composition.as_ref().ok_or_else(refused)?;
        if self.profile != PROFILE
            || self.registration_digest != registration
            || !crate::grant_reference::valid_reference(&self.phase_head)
            || !crate::grant_reference::valid_reference(&self.epoch)
            || self.captured_at < r.valid_from
            || self.captured_at > crate::contracts::MAX_SAFE_INTEGER as i64
            || self.members.len() != plan.nodes.len()
        {
            return Err(refused());
        }
        let mut states = BTreeMap::new();
        for node in &plan.nodes {
            let member = self.members.get(&node.child_id).ok_or_else(refused)?;
            if member.captured_at > self.captured_at {
                return Err(refused());
            }
            if member
                .physical
                .as_ref()
                .is_some_and(|p| p.observation.body.native_epoch != self.epoch)
            {
                return Err(refused());
            }
            states.insert(node.child_id.clone(), member.verify(r, node)?);
        }
        let weight = canonical(&json!(states))?.len() + cached_key.len();
        cache
            .lock()
            .map_err(|_| refused())?
            .insert(cached_key, weight, states.clone());
        Ok(states)
    }
    /// Validate complete original inventories across observations. This checks
    /// historical continuity, not a current storage epoch or native authority.
    pub fn verify_successor(&self, previous: &Self, r: &Registration) -> Result<()> {
        let before = previous.verify(r)?;
        let after = self.verify(r)?;
        if self.captured_at < previous.captured_at {
            return Err(refused());
        }
        for (id, old) in &previous.members {
            let new = self.members.get(id).ok_or_else(refused)?;
            if new.captured_at < old.captured_at
                || !prefix(&old.events, &new.events)?
                || old.authorizations.iter().any(|(op, proof)| {
                    new.authorizations
                        .get(op)
                        .is_none_or(|p| json!(p) != json!(proof))
                })
                || old.composition_bindings.as_ref().is_some_and(|bindings| {
                    new.composition_bindings.as_ref().is_none_or(|next| {
                        bindings.iter().any(|(phase, b)| next.get(phase) != Some(b))
                    })
                })
            {
                return Err(refused());
            }
            crate::kube_drain_verify::successor(old.physical.as_ref(), new.physical.as_ref())?;
            let a = &before[id];
            let b = &after[id];
            if a.forward_attempt
                .as_ref()
                .is_some_and(|v| Some(v) != b.forward_attempt.as_ref())
                || a.forward_grant
                    .as_ref()
                    .is_some_and(|v| Some(v) != b.forward_grant.as_ref())
                || a.inverse_attempt
                    .as_ref()
                    .is_some_and(|v| Some(v) != b.inverse_attempt.as_ref())
                || a.inverse_grant
                    .as_ref()
                    .is_some_and(|v| Some(v) != b.inverse_grant.as_ref())
                || matches!(a.forward, ForwardState::Committed | ForwardState::NoEffect)
                    && a.forward != b.forward
                || matches!(
                    a.inverse,
                    InverseState::Committed | InverseState::NoEffect | InverseState::Failed
                ) && (a.inverse != b.inverse || a.inverse_receipt != b.inverse_receipt)
            {
                return Err(refused());
            }
            match (&old.compound, &new.compound) {
                (Some(a), Some(b)) => {
                    if !prefix(&a.evidence.qualifications, &b.evidence.qualifications)?
                        || a.evidence.compensating && !b.evidence.compensating
                        || a.evidence.inverse.as_ref().is_some_and(|i| {
                            b.evidence.inverse.as_ref().is_none_or(|j| {
                                json!(i.authorization) != json!(j.authorization)
                                    || i.binding != j.binding
                            })
                        })
                    {
                        return Err(refused());
                    }
                }
                (Some(_), None) => return Err(refused()),
                _ => {}
            }
        }
        Ok(())
    }
}
fn prefix<T: Serialize>(before: &[T], after: &[T]) -> Result<bool> {
    Ok(after.len() >= before.len()
        && canonical(&json!(before))? == canonical(&json!(&after[..before.len()]))?)
}

/// A separate protected collector attests the native capture/absence boundary.
/// Owner intent alone cannot authenticate a proposed unsigned Snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSeal {
    pub profile: String,
    pub observer_id: String,
    pub key_id: String,
    pub namespace: String,
    pub registration_digest: String,
    pub snapshot_digest: String,
    pub signature: String,
}
impl CaptureSeal {
    fn message(&self) -> Result<Vec<u8>> {
        let mut value = json!(self);
        value
            .as_object_mut()
            .ok_or_else(refused)?
            .remove("signature");
        let mut bytes = format!("KedgeFlow:{PROFILE}:native-capture\0").into_bytes();
        bytes.extend(canonical(&value)?);
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collected {
    pub snapshot: Snapshot,
    pub seal: CaptureSeal,
}
impl Collected {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_PROOF + 4096 {
            return Err(refused());
        }
        let value = strict_value(raw)?;
        let c: Self = serde_json::from_value(value.clone())?;
        if json!(c) != value {
            return Err(refused());
        }
        Ok(c)
    }
    pub fn verify(&self, r: &Registration) -> Result<BTreeMap<String, MemberSummary>> {
        use base64::Engine;
        let pin = &r.composition.as_ref().ok_or_else(refused)?.observer;
        let s = &self.seal;
        if s.profile != PROFILE
            || s.observer_id != pin.id
            || !id(&s.key_id)
            || s.namespace != r.namespace
            || s.registration_digest != r.digest()?
            || s.snapshot_digest != self.snapshot.digest()?
            || canonical(&json!(self))?.len() > MAX_PROOF + 4096
        {
            return Err(refused());
        }
        let keys = pin.parsed()?;
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&s.signature)
            .map_err(|_| refused())?;
        if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig) != s.signature {
            return Err(refused());
        }
        keys.get(&s.key_id)
            .ok_or_else(refused)?
            .verify_strict(
                &s.message()?,
                &ed25519_dalek::Signature::from_slice(&sig).map_err(|_| refused())?,
            )
            .map_err(|_| refused())?;
        let states = self.snapshot.verify(r)?;
        if self
            .snapshot
            .members
            .values()
            .any(|m| m.composition_bindings.is_none())
        {
            return Err(refused());
        }
        Ok(states)
    }
    pub(crate) fn sign(
        snapshot: Snapshot,
        r: &Registration,
        observer: &crate::control_history::HistoryObserver,
    ) -> Result<Self> {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let mut seal = CaptureSeal {
            profile: PROFILE.into(),
            observer_id: observer.id.clone(),
            key_id: observer.key_id.clone(),
            namespace: r.namespace.clone(),
            registration_digest: r.digest()?,
            snapshot_digest: snapshot.digest()?,
            signature: String::new(),
        };
        seal.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(observer.key.sign(&seal.message()?).to_bytes());
        let c = Self { snapshot, seal };
        c.verify(r)?;
        Ok(c)
    }
}
