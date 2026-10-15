//! Static signed composite authority plus freshly admitted executable leaves.
//! Composite grants are never executable; no live delegation or refund API.
use crate::{
    contracts::{Grant, Policy, Subject, canonical, digest, strict_value},
    coordination::{Allocation, ReservationScope, ReservationSnapshot, ReservationState},
    error::{Error, Result},
    governance::EnforcementScope,
    reserved_leaf::Registration,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};
pub const PROFILE: &str = "KF-HIERARCHICAL-LEAF-0.1-draft";
pub const COMPOSITE_PROFILE: &str = "KF-COMPOSITE-GRANT-0.1-draft";
fn refuse() -> Error {
    Error::Refused("hierarchical scope, lineage or authority refused".into())
}
pub(crate) fn validate(value: &Value, kind: &str) -> Result<()> {
    static PINS: OnceLock<std::result::Result<BTreeMap<String, jsonschema::Validator>, String>> =
        OnceLock::new();
    let pins=PINS.get_or_init(||{
        let s:Value=serde_json::from_str(include_str!("../../../spec/drafts/hierarchical-leaf-v0.1.schema.json")).map_err(|e|e.to_string())?;
        ["config","composite","binding"].into_iter().map(|k|{
            let v=json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":format!("#/$defs/{k}"),"$defs":s["$defs"]});
            Ok((k.into(),crate::schema::compile(&v).map_err(|e|e.to_string())?))
        }).collect()
    });
    if !pins
        .as_ref()
        .map_err(|e| Error::Unavailable(e.clone()))?
        .get(kind)
        .is_some_and(|p| p.is_valid(value))
    {
        return Err(refuse());
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub subject: Subject,
    pub workload_id: String,
}
impl Principal {
    fn tuple(&self) -> (&str, &str, &str) {
        (&self.subject.iss, &self.subject.sub, &self.workload_id)
    }
    fn valid(&self) -> bool {
        !self.subject.iss.is_empty()
            && !self.subject.sub.is_empty()
            && crate::auth::valid_spiffe_id(&self.workload_id)
    }
    pub fn from_grant(g: &Grant) -> Self {
        Self {
            subject: g.subject.clone(),
            workload_id: g.workload_id.clone(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompositePayload {
    pub tenant: String,
    pub conflict_domain: String,
    pub root_id: String,
    pub root_generation: u64,
    pub parent_grant_digest: Option<String>,
    pub policy: Policy,
    pub ownership_epoch: u64,
    pub leaf_scope_digest: String,
    pub scope: ReservationScope,
    pub principals: Vec<Principal>,
    pub forward: u64,
    pub compensation: u64,
    pub valid_from: i64,
    pub expires_at: i64,
    pub execution_authority: bool,
}
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompositeGrant {
    pub profile: String,
    pub kind: String,
    pub key_id: String,
    pub payload: CompositePayload,
    pub signature: String,
}
impl<'de> Deserialize<'de> for CompositeGrant {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            profile: String,
            kind: String,
            key_id: String,
            payload: CompositePayload,
            signature: String,
        }
        let value = crate::contracts::strict_deserialize(d)?;
        validate(&value, "composite").map_err(serde::de::Error::custom)?;
        let fields: Fields =
            serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
        let grant = Self {
            profile: fields.profile,
            kind: fields.kind,
            key_id: fields.key_id,
            payload: fields.payload,
            signature: fields.signature,
        };
        // Set decoding must not change a signed JSON value. Canonical scope
        // arrays are unique and sorted by UTF-8 bytes before the signer sees them.
        if serde_json::to_value(&grant).map_err(serde::de::Error::custom)? != value {
            return Err(serde::de::Error::custom(
                "noncanonical composite scope order",
            ));
        }
        Ok(grant)
    }
}
impl CompositeGrant {
    fn message(&self) -> Result<Vec<u8>> {
        let mut raw = format!("KedgeFlow:{COMPOSITE_PROFILE}\0").into_bytes();
        raw.extend(canonical(&json!({"profile":self.profile,"kind":self.kind,"key_id":self.key_id,"payload":self.payload}))?);
        Ok(raw)
    }
    pub fn digest(&self) -> Result<String> {
        digest("hierarchical-composite-grant", &json!(self))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 16384 {
            return Err(refuse());
        }
        let v = strict_value(raw)?;
        validate(&v, "composite")?;
        Ok(serde_json::from_value(v)?)
    }
    fn verify(&self, keys: &BTreeMap<String, VerifyingKey>) -> Result<()> {
        validate(&json!(self), "composite")?;
        if canonical(&json!(self))?.len() > 16384
            || self.payload.expires_at <= self.payload.valid_from
        {
            return Err(refuse());
        }
        let key = keys.get(&self.key_id).ok_or_else(refuse)?;
        let sig = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&self.signature)
                .map_err(|_| refuse())?,
        )
        .map_err(|_| refuse())?;
        key.verify_strict(&self.message()?, &sig)
            .map_err(|_| refuse())
    }
}
/// Privileged operator signer. A composite signature never authorizes an effect.
pub fn sign_composite(
    payload: CompositePayload,
    key_id: &str,
    key: &SigningKey,
) -> Result<CompositeGrant> {
    let mut grant = CompositeGrant {
        profile: COMPOSITE_PROFILE.into(),
        kind: "composite_grant".into(),
        key_id: key_id.into(),
        payload,
        signature: String::new(),
    };
    grant.signature = URL_SAFE_NO_PAD.encode(key.sign(&grant.message()?).to_bytes());
    grant.verify(&BTreeMap::from([(key_id.into(), key.verifying_key())]))?;
    Ok(grant)
}
pub fn scope_digest(scope: &EnforcementScope) -> Result<String> {
    digest("hierarchical-leaf-scope", &json!(scope))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub principal: Principal,
    pub parent_grant_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Hierarchy {
    pub delegation_keys: BTreeMap<String, String>,
    pub grants: Vec<CompositeGrant>,
    pub assignments: Vec<Assignment>,
}
/// A present field must be a closed object; null cannot normalize away a field
/// newly forbidden in the old profiles. Validate arrays before set decoding.
pub(crate) fn deserialize_optional<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Hierarchy>, D::Error> {
    let v = crate::contracts::strict_deserialize(d)?;
    validate(&v, "config").map_err(serde::de::Error::custom)?;
    serde_json::from_value(v)
        .map(Some)
        .map_err(serde::de::Error::custom)
}
impl Hierarchy {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 128 << 10 {
            return Err(refuse());
        }
        let v = strict_value(raw)?;
        validate(&v, "config")?;
        Ok(serde_json::from_value(v)?)
    }
    pub(crate) fn keys(&self) -> Result<BTreeMap<String, VerifyingKey>> {
        crate::control_config::keys(&self.delegation_keys)
    }
    fn indexed(&self) -> Result<BTreeMap<String, &CompositeGrant>> {
        let mut all = BTreeMap::new();
        for g in &self.grants {
            if all.insert(g.digest()?, g).is_some() {
                return Err(refuse());
            }
        }
        Ok(all)
    }
    pub(crate) fn initial(&self) -> Result<BTreeMap<String, Allocation>> {
        self.grants
            .iter()
            .map(|g| {
                let id = g.digest()?;
                Ok((
                    id.clone(),
                    Allocation {
                        operation_digest: id,
                        parent: g.payload.parent_grant_digest.clone(),
                        scope: g.payload.scope.clone(),
                        forward: g.payload.forward,
                        compensation: g.payload.compensation,
                        state: ReservationState::Composite,
                        attempt_id: None,
                    },
                ))
            })
            .collect()
    }
    pub(crate) fn validate(&self, r: &Registration) -> Result<()> {
        validate(&json!(self), "config")?;
        let keys = self.keys()?;
        if keys.values().any(|k| {
            crate::control_config::keys(&r.issuer_keys).is_ok_and(|i| i.values().any(|v| v == k))
        }) {
            return Err(refuse());
        }
        let all = self.indexed()?;
        let scope = scope_digest(&r.scope)?;
        for (id, g) in &all {
            g.verify(&keys)?;
            let p = &g.payload;
            let mut principals = BTreeSet::new();
            if p.tenant != r.enrollment.tenant
                || p.conflict_domain != r.enrollment.conflict_domain
                || p.root_id != r.root_id
                || p.root_generation != r.root_generation
                || p.policy != r.policy
                || p.ownership_epoch != r.ownership_epoch
                || p.leaf_scope_digest != scope
                || !p.scope.narrows(&r.enrollment.scope)
                || p.principals
                    .iter()
                    .any(|x| !x.valid() || !principals.insert(x.tuple()))
            {
                return Err(refuse());
            }
            let mut chain = BTreeSet::from([id.as_str()]);
            let mut current = g;
            while let Some(parent) = &current.payload.parent_grant_digest {
                if !chain.insert(parent.as_str()) || chain.len() > 7 {
                    return Err(refuse());
                }
                let ancestor = all.get(parent).ok_or_else(refuse)?;
                let child = &current.payload;
                let a = &ancestor.payload;
                if !child.scope.narrows(&a.scope)
                    || child.principals.iter().any(|p| !a.principals.contains(p))
                    || child.valid_from < a.valid_from
                    || child.expires_at > a.expires_at
                {
                    return Err(refuse());
                }
                current = ancestor;
            }
        }
        let leaf = ReservationScope {
            actions: BTreeSet::from([r.scope.action.id.clone()]),
            resources: BTreeSet::from([r.scope.resource.id.clone()]),
        };
        let mut assigned = BTreeSet::new();
        for a in &self.assignments {
            let parent = all.get(&a.parent_grant_digest).ok_or_else(refuse)?;
            if !a.principal.valid()
                || !assigned.insert(a.principal.tuple())
                || !parent.payload.principals.contains(&a.principal)
                || !leaf.narrows(&parent.payload.scope)
                || r.forward_units > parent.payload.forward
                || r.compensation_units > parent.payload.compensation
            {
                return Err(refuse());
            }
        }
        let state = ReservationSnapshot {
            profile: crate::coordination::PROFILE.into(),
            enrollment: r.enrollment.clone(),
            active: true,
            execution_authority: false,
            allocations: self.initial()?,
        };
        state.validate()
    }
    pub(crate) fn parent(&self, g: &Grant) -> Result<&str> {
        let p = Principal::from_grant(g);
        self.assignments
            .iter()
            .find(|a| a.principal == p)
            .map(|a| a.parent_grant_digest.as_str())
            .ok_or_else(refuse)
    }
    pub(crate) fn grant(&self, g: &Grant) -> Result<()> {
        let all = self.indexed()?;
        let mut next = Some(self.parent(g)?);
        while let Some(id) = next {
            let p = &all.get(id).ok_or_else(refuse)?.payload;
            if !p.principals.contains(&Principal::from_grant(g))
                || g.valid_from < p.valid_from
                || g.issued_at < p.valid_from
                || g.expires_at > p.expires_at
            {
                return Err(refuse());
            }
            next = p.parent_grant_digest.as_deref();
        }
        Ok(())
    }
    pub(crate) fn snapshot(&self, r: &Registration, s: &ReservationSnapshot) -> Result<()> {
        s.validate()?;
        let skeleton = self.initial()?;
        for (id, p) in &skeleton {
            if s.allocations.get(id) != Some(p) {
                return Err(refuse());
            }
        }
        if let Some(plan) = &r.saga {
            let planned = plan.allocations(r)?;
            if planned.len() != s.allocations.len() {
                return Err(refuse());
            }
            for (id, expected) in planned {
                let actual = s.allocations.get(&id).ok_or_else(refuse)?;
                if actual.parent != expected.parent
                    || actual.scope != expected.scope
                    || actual.forward != expected.forward
                    || actual.compensation != expected.compensation
                {
                    return Err(refuse());
                }
            }
        }
        let leaf = ReservationScope {
            actions: BTreeSet::from([r.scope.action.id.clone()]),
            resources: BTreeSet::from([r.scope.resource.id.clone()]),
        };
        for (id, a) in &s.allocations {
            if skeleton.contains_key(id) {
                continue;
            }
            if !self
                .assignments
                .iter()
                .any(|x| Some(&x.parent_grant_digest) == a.parent.as_ref())
                || a.scope != leaf
                || a.forward != r.forward_units
                || a.compensation != r.compensation_units
                || !(matches!(
                    a.state,
                    ReservationState::Allocated | ReservationState::Unknown
                ) || crate::reservation_history::audited(&r.profile)
                    && matches!(
                        a.state,
                        ReservationState::Committed | ReservationState::ProvenNoEffect
                    ))
            {
                return Err(refuse());
            }
        }
        Ok(())
    }
    pub(crate) fn distinct<'a>(&self, keys: impl IntoIterator<Item = &'a VerifyingKey>) -> bool {
        self.keys().is_ok_and(|ours| {
            let other: Vec<_> = keys.into_iter().collect();
            ours.values().all(|k| !other.contains(&k))
        })
    }
}
pub(crate) fn composite_key(
    ledger: &crate::ledger::EtcdLedger,
    r: &Registration,
    id: &str,
) -> String {
    format!(
        "{}/hierarchical-composites/{}/{id}",
        ledger.namespace(),
        crate::ledger::key_part(&r.root_id)
    )
}
