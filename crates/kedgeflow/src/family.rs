//! Shared held capacity, live narrowed branches and mandatory native child pins.
//! No executable parent grant, refund, replacement or cross-namespace atomicity.
use crate::{
    action_domain::{Lane, Topology},
    contracts::{canonical, digest, strict_value},
    coordination::{
        Allocation, ReservationEnrollment, ReservationScope, ReservationSnapshot, ReservationState,
    },
    error::{Error, Result},
    hierarchical_leaf::Principal,
    ledger::{EtcdLedger, get, put, range_kv, record, value_eq, version_zero},
    reserved_leaf::Registration as LeafRegistration,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
pub const PROFILE: &str = "KF-FAMILY-AUTHORITY-0.1-draft";
pub const MAX_BYTES: usize = 512 << 10;
fn refused() -> Error {
    Error::Refused("family authority, delegation or held capacity refused".into())
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}
fn principal_valid(p: &Principal) -> bool {
    !p.subject.iss.is_empty()
        && p.subject.iss.len() <= 256
        && !p.subject.sub.is_empty()
        && p.subject.sub.len() <= 256
        && crate::auth::valid_spiffe_id(&p.workload_id)
}
fn principal_set(p: &[Principal]) -> bool {
    !p.is_empty()
        && p.len() <= 32
        && p.iter().all(principal_valid)
        && p.iter().enumerate().all(|(i, v)| !p[..i].contains(v))
}
fn digest_value<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    digest(domain, &json!(value))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignerPin {
    pub principal: Principal,
    pub public_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Child {
    pub id: String,
    pub reservation: LeafRegistration,
    pub topology: Option<Topology>,
    pub inverse: Option<crate::compensation::Contract>,
}
impl Child {
    pub(crate) fn keys(&self) -> Result<Vec<ed25519_dalek::VerifyingKey>> {
        let mut keys = crate::control_config::keys(&self.reservation.issuer_keys)?
            .into_values()
            .collect::<Vec<_>>();
        if let Some(h) = &self.reservation.hierarchy {
            keys.extend(h.keys()?.into_values());
        }
        if let Some(s) = &self.reservation.saga {
            keys.extend(crate::control_config::keys(&s.outcome_keys)?.into_values());
        }
        if let Some(c) = &self.inverse {
            keys.extend(crate::control_config::keys(&c.barrier_keys)?.into_values());
            keys.extend(crate::control_config::keys(&c.applicability_keys)?.into_values());
        }
        if let Some(t) = &self.topology {
            for r in [&t.forward, &t.inverse] {
                for k in r.issuer_keys.values() {
                    let k: [u8; 32] = hex::decode(k)
                        .map_err(|_| refused())?
                        .try_into()
                        .map_err(|_| refused())?;
                    keys.push(ed25519_dalek::VerifyingKey::from_bytes(&k).map_err(|_| refused())?);
                }
                keys.extend(
                    crate::governance::acknowledgement_keys(&r.acknowledger)?.into_values(),
                );
            }
        }
        Ok(keys)
    }
    fn scope(&self) -> ReservationScope {
        let mut s = self.reservation.enrollment.scope.clone();
        if let Some(c) = &self.inverse {
            s.actions.insert(c.inverse_scope.action.id.clone());
            s.resources.insert(c.inverse_scope.resource.id.clone());
        }
        s
    }
    fn principals(&self) -> Vec<Principal> {
        let mut p = Vec::new();
        if let Some(h) = &self.reservation.hierarchy {
            for a in &h.assignments {
                if !p.contains(&a.principal) {
                    p.push(a.principal.clone());
                }
            }
        }
        if let Some(c) = &self.inverse
            && !p.contains(&c.inverse_principal)
        {
            p.push(c.inverse_principal.clone());
        }
        p
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub profile: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::family_saga::deserialize_plan"
    )]
    pub composition: Option<crate::family_saga::Plan>,
    pub namespace: String,
    pub family_id: String,
    pub tenant: String,
    pub owner: Principal,
    pub principals: Vec<Principal>,
    pub scope: ReservationScope,
    pub forward: u64,
    pub compensation: u64,
    pub valid_from: i64,
    pub expires_at: i64,
    pub signers: BTreeMap<String, SignerPin>,
    pub children: Vec<Child>,
}
impl Registration {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let r: Self = decode(raw, 128 << 10)?;
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            (self.profile.as_str(), self.composition.as_ref()),
            (PROFILE, None) | (crate::family_saga::PROFILE, Some(_))
        ) || !self.namespace.starts_with('/')
            || self.namespace.ends_with('/')
            || self.namespace.len() > 1024
            || !valid_id(&self.family_id)
            || self.tenant.is_empty()
            || self.tenant.len() > 256
            || !principal_set(&self.principals)
            || !self.principals.contains(&self.owner)
            || !self.scope.valid()
            || self.expires_at <= self.valid_from
            || self.valid_from < 0
            || self.expires_at > crate::contracts::MAX_SAFE_INTEGER as i64
            || self.children.is_empty()
            || self.children.len() > 8
            || self.signers.is_empty()
            || self.signers.len() > 32
            || canonical(&json!(self))?.len() > 128 << 10
        {
            return Err(refused());
        }
        let mut keys = BTreeSet::new();
        let mut people = Vec::new();
        for (id, s) in &self.signers {
            if !valid_id(id)
                || !self.principals.contains(&s.principal)
                || people.contains(&s.principal)
            {
                return Err(refused());
            }
            let k = crate::config::key(&s.public_key)?;
            ed25519_dalek::VerifyingKey::from_bytes(&k).map_err(|_| refused())?;
            if !keys.insert(k) {
                return Err(refused());
            }
            people.push(s.principal.clone());
        }
        if !people.contains(&self.owner) {
            return Err(refused());
        }
        let mut ids = BTreeSet::new();
        let mut domains = BTreeSet::new();
        let mut resources = BTreeSet::new();
        let mut roots = BTreeSet::new();
        for child in &self.children {
            let r = &child.reservation;
            r.validate()?;
            if !valid_id(&child.id)
                || !ids.insert(&child.id)
                || !domains.insert(&r.scope.conflict_domain)
                || !resources.insert(&r.scope.resource.id)
                || !roots.insert(&r.root_id)
                || r.enrollment.tenant != self.tenant
                || r.hierarchy.is_none()
                || !crate::reservation_history::audited(&r.profile)
                || !child.scope().narrows(&self.scope)
                || child
                    .principals()
                    .iter()
                    .any(|p| !self.principals.contains(p))
                || child.principals().is_empty()
            {
                return Err(refused());
            }
            for k in child.keys()? {
                if keys.contains(k.as_bytes()) {
                    return Err(refused());
                }
            }
            match (&child.topology, &child.inverse) {
                (Some(t), Some(c)) => {
                    t.validate()?;
                    if t.forward.tenant != self.tenant
                        || t.forward.scope != r.scope
                        || t.forward.policy != r.policy
                        || t.forward.ownership_epoch != r.ownership_epoch
                        || c.inverse_scope != t.inverse.scope
                        || c.inverse_policy != t.inverse.policy
                        || c.registration_digest != r.digest()?
                    {
                        return Err(refused());
                    }
                }
                (None, None) => {}
                _ => return Err(refused()),
            }
        }
        if let Some(plan) = &self.composition {
            plan.validate(self)?;
        }
        self.genesis()?.budget.validate()
    }
    pub fn digest(&self) -> Result<String> {
        digest_value("family-registration", self)
    }
    pub fn child(&self, id: &str) -> Result<&Child> {
        self.children
            .iter()
            .find(|c| c.id == id)
            .ok_or_else(refused)
    }
    fn genesis(&self) -> Result<State> {
        Ok(State {
            profile: PROFILE.into(),
            registration_digest: self.digest()?,
            active: true,
            head: digest("family-genesis", &json!(self))?,
            budget: ReservationSnapshot {
                profile: crate::coordination::PROFILE.into(),
                enrollment: ReservationEnrollment {
                    tenant: self.tenant.clone(),
                    conflict_domain: format!("family:{}", self.family_id),
                    scope: self.scope.clone(),
                    forward: self.forward,
                    compensation: self.compensation,
                },
                active: true,
                execution_authority: false,
                allocations: BTreeMap::new(),
            },
            branches: BTreeMap::new(),
            attachments: BTreeMap::new(),
            events: vec![],
        })
    }
}
fn decode<T: for<'a> Deserialize<'a> + Serialize>(raw: &[u8], limit: usize) -> Result<T> {
    if raw.len() > limit {
        return Err(refused());
    }
    let v = strict_value(raw)?;
    let t: T = serde_json::from_value(v.clone())?;
    if json!(t) != v {
        return Err(refused());
    }
    Ok(t)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Branch {
    pub parent: String,
    pub owner: Principal,
    pub principals: Vec<Principal>,
    pub scope: ReservationScope,
    pub forward: u64,
    pub compensation: u64,
    pub valid_from: i64,
    pub expires_at: i64,
    pub active: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Delegate { parent: String, branch: Branch },
    Attach { parent: String, child_id: String },
    Stop { branch_id: String },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandPayload {
    pub family_digest: String,
    pub operation_key: String,
    pub expected_head: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub action: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub profile: String,
    pub key_id: String,
    pub payload: CommandPayload,
    pub signature: String,
}
impl Command {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let c: Self = decode(raw, 16 << 10)?;
        c.structural()?;
        Ok(c)
    }
    fn structural(&self) -> Result<()> {
        static PIN: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
        let pin = PIN.get_or_init(|| {
            crate::schema::compile(
                &serde_json::from_str(include_str!(
                    "../../../spec/drafts/family-authority-command-v0.1.schema.json"
                ))
                .expect("embedded family command schema"),
            )
            .expect("valid family command schema")
        });
        if pin.is_valid(&json!(self)) {
            Ok(())
        } else {
            Err(refused())
        }
    }
    fn message(&self) -> Result<Vec<u8>> {
        let mut raw = format!("KedgeFlow:{PROFILE}:command\0").into_bytes();
        raw.extend(canonical(
            &json!({"profile":self.profile,"key_id":self.key_id,"payload":self.payload}),
        )?);
        Ok(raw)
    }
    pub fn sign(payload: CommandPayload, key_id: &str, key: &SigningKey) -> Result<Self> {
        let mut c = Self {
            profile: PROFILE.into(),
            key_id: key_id.into(),
            payload,
            signature: String::new(),
        };
        c.signature = URL_SAFE_NO_PAD.encode(key.sign(&c.message()?).to_bytes());
        Ok(c)
    }
    pub(crate) fn principal<'a>(&self, r: &'a Registration) -> Result<&'a Principal> {
        self.structural()?;
        if self.profile != PROFILE
            || canonical(&json!(self))?.len() > 16 << 10
            || !crate::grant_reference::valid_reference(&self.payload.operation_key)
            || self.payload.family_digest != r.digest()?
            || !crate::grant_reference::valid_reference(&self.payload.expected_head)
        {
            return Err(refused());
        }
        let s = r.signers.get(&self.key_id).ok_or_else(refused)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&crate::config::key(&s.public_key)?)
            .map_err(|_| refused())?;
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&self.signature)
                .map_err(|_| refused())?,
        )
        .map_err(|_| refused())?;
        key.verify_strict(&self.message()?, &signature)
            .map_err(|_| refused())?;
        Ok(&s.principal)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub parent: String,
    pub operation_key: String,
    pub child_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub at: i64,
    pub command: Command,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub profile: String,
    pub registration_digest: String,
    pub active: bool,
    pub head: String,
    pub budget: ReservationSnapshot,
    pub branches: BTreeMap<String, Branch>,
    pub attachments: BTreeMap<String, Attachment>,
    pub events: Vec<Event>,
}
impl State {
    fn branch(&self, r: &Registration, id: &str) -> Result<Branch> {
        if id == "root" {
            return Ok(Branch {
                parent: String::new(),
                owner: r.owner.clone(),
                principals: r.principals.clone(),
                scope: r.scope.clone(),
                forward: r.forward,
                compensation: r.compensation,
                valid_from: r.valid_from,
                expires_at: r.expires_at,
                active: self.active,
            });
        }
        self.branches.get(id).cloned().ok_or_else(refused)
    }
    pub(crate) fn live(&self, r: &Registration, id: &str, now: i64) -> Result<Branch> {
        let selected = self.branch(r, id)?;
        let mut next = id.to_owned();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(next.clone()) || seen.len() > 8 {
                return Err(refused());
            }
            let b = self.branch(r, &next)?;
            if !b.active || now < b.valid_from || now >= b.expires_at {
                return Err(refused());
            }
            if next == "root" {
                break;
            }
            next = b.parent;
        }
        Ok(selected)
    }
    fn apply(&mut self, r: &Registration, c: &Command, now: i64) -> Result<()> {
        let signer = c.principal(r)?;
        let p = &c.payload;
        if !self.active
            || self.events.len() >= 64
            || (self.events.len() >= 63
                && !matches!(&p.action,Action::Stop { branch_id } if branch_id=="root"))
            || p.expected_head != self.head
            || p.issued_at < r.valid_from
            || now < p.issued_at
            || now >= p.expires_at
            || p.expires_at > r.expires_at
            || p.expires_at - p.issued_at > 60000
            || self.events.last().is_some_and(|e| e.at > now)
            || self
                .events
                .iter()
                .any(|e| e.command.payload.operation_key == p.operation_key)
        {
            return Err(refused());
        }
        match &p.action {
            Action::Delegate { parent, branch: b } => {
                let ancestor = self.live(r, parent, now)?;
                if &ancestor.owner != signer
                    || !b.active
                    || b.parent != *parent
                    || !b.scope.narrows(&ancestor.scope)
                    || !principal_set(&b.principals)
                    || b.principals
                        .iter()
                        .any(|x| !ancestor.principals.contains(x))
                    || !b.principals.contains(&b.owner)
                    || !r.signers.values().any(|s| s.principal == b.owner)
                    || b.valid_from < ancestor.valid_from
                    || b.expires_at > ancestor.expires_at
                    || b.expires_at <= b.valid_from
                    || now < b.valid_from
                    || now >= b.expires_at
                    || self.branches.len() >= 16
                    || self.branches.contains_key(&p.operation_key)
                {
                    return Err(refused());
                }
                self.branches.insert(p.operation_key.clone(), b.clone());
                self.live(r, &p.operation_key, now)?;
                self.budget.allocations.insert(
                    p.operation_key.clone(),
                    Allocation {
                        operation_digest: p.operation_key.clone(),
                        parent: if parent == "root" {
                            None
                        } else {
                            Some(parent.clone())
                        },
                        scope: b.scope.clone(),
                        forward: b.forward,
                        compensation: b.compensation,
                        state: ReservationState::Composite,
                        attempt_id: None,
                    },
                );
            }
            Action::Attach { parent, child_id } => {
                let ancestor = self.live(r, parent, now)?;
                let child = r.child(child_id)?;
                if &ancestor.owner != signer
                    || self.attachments.contains_key(child_id)
                    || !child.scope().narrows(&ancestor.scope)
                    || child
                        .principals()
                        .iter()
                        .any(|p| !ancestor.principals.contains(p))
                {
                    return Err(refused());
                }
                self.budget.allocations.insert(
                    p.operation_key.clone(),
                    Allocation {
                        operation_digest: p.operation_key.clone(),
                        parent: if parent == "root" {
                            None
                        } else {
                            Some(parent.clone())
                        },
                        scope: child.scope(),
                        forward: child.reservation.enrollment.forward,
                        compensation: child.reservation.enrollment.compensation,
                        state: ReservationState::Allocated,
                        attempt_id: None,
                    },
                );
                self.attachments.insert(
                    child_id.clone(),
                    Attachment {
                        parent: parent.clone(),
                        operation_key: p.operation_key.clone(),
                        child_digest: digest_value("family-child", child)?,
                    },
                );
            }
            Action::Stop { branch_id } => {
                let b = self.branch(r, branch_id)?;
                if &b.owner != signer && &r.owner != signer {
                    return Err(refused());
                }
                if branch_id == "root" {
                    self.active = false;
                    self.budget.active = false;
                } else {
                    self.branches.get_mut(branch_id).ok_or_else(refused)?.active = false;
                }
            }
        }
        self.budget.validate()?;
        self.head = digest(
            "family-event",
            &json!({"previous":self.head,"at":now,"command":c}),
        )?;
        self.events.push(Event {
            at: now,
            command: c.clone(),
        });
        if canonical(&json!(self))?.len() > MAX_BYTES {
            return Err(refused());
        }
        Ok(())
    }
    pub fn verify(&self, r: &Registration) -> Result<()> {
        r.validate()?;
        if self.events.len() > 64 || canonical(&json!(self))?.len() > MAX_BYTES {
            return Err(refused());
        }
        let mut expected = r.genesis()?;
        for e in &self.events {
            expected.apply(r, &e.command, e.at)?;
        }
        if &expected != self {
            return Err(refused());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub registration: Registration,
    pub child_id: String,
}
impl Selection {
    pub fn attach(&self, mut l: EtcdLedger) -> Result<EtcdLedger> {
        self.registration.validate()?;
        crate::family_saga::require_native(&self.registration)?;
        let child = self.registration.child(&self.child_id)?;
        if l.family.is_some() {
            return Err(refused());
        }
        if l.namespace() != self.registration.namespace {
            return Err(refused());
        }
        l.require_control = true;
        let inverse = l
            .action_domain
            .as_ref()
            .is_some_and(|s| s.lane == Lane::Inverse);
        if inverse {
            if l.inverse_execution
                .as_ref()
                .is_some_and(|e| child.inverse.as_ref() != Some(&e.contract))
            {
                return Err(refused());
            }
        } else {
            if l.reservation
                .as_ref()
                .is_some_and(|r| **r != child.reservation)
            {
                return Err(refused());
            }
            l = l.with_reservation(child.reservation.clone())?;
        }
        if let Some(plan) = &self.registration.composition {
            let expected = plan.node(&self.child_id)?.trust_digest(inverse)?;
            if l.required_trust_digest
                .as_ref()
                .is_some_and(|d| d != &expected)
            {
                return Err(refused());
            }
            l.required_trust_digest = Some(expected);
        }
        self.context(&l)?;
        l.family = Some(Arc::new(Access::Child(self.clone())));
        Ok(l)
    }
    fn context(&self, l: &EtcdLedger) -> Result<()> {
        let c = self.registration.child(&self.child_id)?;
        if let Some(plan) = &self.registration.composition {
            let inverse = l
                .action_domain
                .as_ref()
                .is_some_and(|s| s.lane == Lane::Inverse);
            if l.required_trust_digest.as_deref()
                != Some(plan.node(&self.child_id)?.trust_digest(inverse)?.as_str())
            {
                return Err(refused());
            }
        }
        if l.action_domain.as_ref().map(|s| &s.topology) != c.topology.as_ref() {
            return Err(refused());
        }
        if l.action_domain
            .as_ref()
            .is_some_and(|s| s.lane == Lane::Inverse)
        {
            // Governance and query-only collectors may pin the inverse lane
            // before selecting execution. Actual inverse authority still
            // requires the separate native compound execution profile.
            if let Some(e) = &l.inverse_execution
                && (Some(&e.contract) != c.inverse.as_ref()
                    || e.trust.registration != c.reservation
                    || e.outcome_keys.values().any(|k| {
                        self.registration.signers.values().any(|p| {
                            crate::config::key(&p.public_key).is_ok_and(|p| p == *k.as_bytes())
                        })
                    }))
            {
                return Err(refused());
            }
        } else if l.reservation.as_ref().is_none_or(|r| **r != c.reservation) {
            return Err(refused());
        }
        Ok(())
    }
}
/// Presence selects a profile; explicit null cannot erase a required selection.
pub fn deserialize_selection<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Selection>, D::Error> {
    let s = Selection::deserialize(d)?;
    s.registration
        .validate()
        .map_err(serde::de::Error::custom)?;
    s.registration
        .child(&s.child_id)
        .map_err(serde::de::Error::custom)?;
    Ok(Some(s))
}
#[derive(Clone)]
pub(crate) enum Access {
    Manager(Registration),
    Child(Selection),
}
pub(crate) fn marker(l: &EtcdLedger) -> String {
    format!("{}/family/required", l.namespace())
}
fn state_key(l: &EtcdLedger) -> String {
    format!("{}/family/state", l.namespace())
}
pub struct Family {
    ledger: EtcdLedger,
    registration: Registration,
}
impl Family {
    pub fn registration(&self) -> &Registration {
        &self.registration
    }
    // Shared authentication can retain proof replay without native execution.
    pub(crate) fn manager_ledger(&self) -> EtcdLedger {
        self.ledger.clone()
    }
    pub fn new(mut ledger: EtcdLedger, registration: Registration) -> Result<Self> {
        registration.validate()?;
        crate::family_saga::require_native(&registration)?;
        if ledger.family.is_some()
            || ledger.namespace() != registration.namespace
            || ledger.reservation.is_some()
            || ledger.action_domain.is_some()
            || ledger.inverse_execution.is_some()
        {
            return Err(refused());
        }
        ledger.family = Some(Arc::new(Access::Manager(registration.clone())));
        Ok(Self {
            ledger,
            registration,
        })
    }
    pub async fn enroll(&self) -> Result<()> {
        let start = format!("{}/", self.ledger.namespace());
        let end = format!("{}0", self.ledger.namespace());
        let witness = crate::restore::marker_key(&self.ledger);
        let empty = |a: &str, b: &str| json!({"key":STANDARD.encode(a),"range_end":STANDARD.encode(b),"target":"VERSION","result":"EQUAL","version":"0"});
        let state = self.registration.genesis()?;
        let mut writes = vec![
            put(&marker(&self.ledger), &record(&self.registration)?),
            put(&state_key(&self.ledger), &record(&state)?),
        ];
        // The whole namespace is empty. Install every protected pair in the
        // same transaction, before the mandatory family marker takes effect.
        for child in &self.registration.children {
            if let Some(t) = &child.topology {
                writes.extend(t.initial_writes(&self.ledger)?);
            }
        }
        if !self
            .ledger
            .txn(
                vec![
                    empty(&start, &witness),
                    empty(&format!("{witness}\0"), &end),
                ],
                writes,
                vec![],
            )
            .await?
            .succeeded
        {
            return Err(refused());
        }
        Ok(())
    }
    pub async fn status(&self) -> Result<State> {
        let t = self
            .ledger
            .txn(vec![], vec![get(&state_key(&self.ledger))], vec![])
            .await?;
        let raw = range_kv(t.responses.first().ok_or_else(refused)?)?.ok_or_else(refused)?;
        let s: State = decode(&raw.value, MAX_BYTES)?;
        s.verify(&self.registration)?;
        Ok(s)
    }
    pub async fn apply(&self, command: Command) -> Result<State> {
        let old = self.status().await?;
        if let Some(e) = old
            .events
            .iter()
            .find(|e| e.command.payload.operation_key == command.payload.operation_key)
        {
            command.principal(&self.registration)?;
            if e.command != command {
                return Err(refused());
            }
            return Ok(old);
        }
        let mut next = old.clone();
        next.apply(
            &self.registration,
            &command,
            self.ledger.authority_clock.now_ms(),
        )?;
        if !matches!(&command.payload.action, Action::Stop { branch_id } if branch_id == "root") {
            self.reserve_root_stop(&next)?;
        }
        if !self
            .ledger
            .txn(
                vec![value_eq(&state_key(&self.ledger), &record(&old)?)],
                vec![put(&state_key(&self.ledger), &record(&next)?)],
                vec![],
            )
            .await?
            .succeeded
        {
            return Err(refused());
        }
        Ok(next)
    }
    fn reserve_root_stop(&self, next: &State) -> Result<()> {
        // A reserved event slot is insufficient when a large record leaves no
        // room for that event or its final native transaction. Keep the old
        // history format and reserve both serialized state and wire capacity.
        const STOP_GROWTH: usize = 4096;
        const TRANSPORT_MARGIN: usize = 64 << 10;
        let state = record(next)?;
        let refused = || Error::Refused("family root stop capacity is reserved".into());
        if state.len() + STOP_GROWTH > MAX_BYTES {
            return Err(refused());
        }
        let key = state_key(&self.ledger);
        let compare = vec![
            value_eq(&marker(&self.ledger), &record(&self.registration)?),
            value_eq(&key, &state),
        ];
        let success = vec![put(&key, &"x".repeat(state.len() + STOP_GROWTH))];
        // The values in etcd's JSON transaction are base64 encoded. Measuring
        // this envelope includes that expansion and the actual namespace keys.
        // Leave room for restore-witness and transport guard bookkeeping too.
        if canonical(&json!({"compare":compare,"success":success,"failure":[]}))?.len()
            > (1 << 20) - TRANSPORT_MARGIN
        {
            return Err(refused());
        }
        Ok(())
    }
}
impl EtcdLedger {
    pub(crate) fn family_distinct<'a>(
        &self,
        mut keys: impl Iterator<Item = &'a ed25519_dalek::VerifyingKey>,
    ) -> bool {
        let Some(access) = &self.family else {
            return true;
        };
        let Access::Child(s) = access.as_ref() else {
            return false;
        };
        keys.all(|k| {
            s.registration
                .signers
                .values()
                .all(|pin| crate::config::key(&pin.public_key).is_ok_and(|p| p != *k.as_bytes()))
        })
    }
    pub(crate) async fn family_compares(&self, authority: bool) -> Result<Vec<Value>> {
        // Legacy authority checks only need absence in their eventual CAS.
        // Ungated transactions check presence alongside the existing restore
        // marker read below; avoid adding a network round trip to every old port.
        if self.family.is_none() && (authority || self.restore_gate.is_none()) {
            return Ok(vec![
                version_zero(&marker(self)),
                version_zero(&state_key(self)),
            ]);
        }
        let t = self
            .raw_txn(
                vec![],
                vec![get(&marker(self)), get(&state_key(self))],
                vec![],
            )
            .await?;
        let raw = range_kv(t.responses.first().ok_or_else(refused)?)?;
        let Some(access) = &self.family else {
            if raw.is_some() {
                return Err(Error::Refused(
                    "family selection required for enrolled namespace".into(),
                ));
            }
            return Ok(vec![
                version_zero(&marker(self)),
                version_zero(&state_key(self)),
            ]);
        };
        let reg = match access.as_ref() {
            Access::Manager(r) => r,
            Access::Child(s) => &s.registration,
        };
        let Some(raw) = raw else {
            return match access.as_ref() {
                Access::Manager(_) => Ok(vec![
                    version_zero(&marker(self)),
                    version_zero(&state_key(self)),
                ]),
                _ => Err(refused()),
            };
        };
        if raw.value != record(reg)?.as_bytes() {
            return Err(refused());
        }
        let state = range_kv(t.responses.get(1).ok_or_else(refused)?)?.ok_or_else(refused)?;
        let s: State = decode(&state.value, MAX_BYTES)?;
        s.verify(reg)?;
        if let Access::Child(selection) = access.as_ref() {
            selection.context(self)?;
            let a = s.attachments.get(&selection.child_id).ok_or_else(refused)?;
            if a.child_digest != digest_value("family-child", reg.child(&selection.child_id)?)? {
                return Err(refused());
            }
            if authority {
                if self
                    .action_domain
                    .as_ref()
                    .is_some_and(|s| s.lane == Lane::Inverse)
                    && self.inverse_execution.is_none()
                {
                    return Err(refused());
                }
                s.live(reg, &a.parent, self.authority_clock.now_ms())?;
            }
        } else if authority {
            return Err(refused());
        }
        Ok(vec![
            value_eq(
                &marker(self),
                std::str::from_utf8(&raw.value).map_err(|_| refused())?,
            ),
            value_eq(
                &state_key(self),
                std::str::from_utf8(&state.value).map_err(|_| refused())?,
            ),
        ])
    }
}

/// Public historical pins are supplied separately from the exported payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTrust {
    pub registration: Registration,
    pub namespace: String,
    pub observer_id: String,
    pub observer_keys: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub profile: String,
    pub observer_id: String,
    pub key_id: String,
    pub namespace: String,
    pub captured_at: i64,
    pub state_digest: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub state: State,
    pub checkpoint: Checkpoint,
}
impl Checkpoint {
    fn message(&self) -> Result<Vec<u8>> {
        let mut value = json!(self);
        value
            .as_object_mut()
            .ok_or_else(refused)?
            .remove("signature");
        let mut raw = format!("KedgeFlow:{PROFILE}:checkpoint\0").into_bytes();
        raw.extend(canonical(&value)?);
        Ok(raw)
    }
}
impl AuditTrust {
    fn keys(&self) -> Result<BTreeMap<String, ed25519_dalek::VerifyingKey>> {
        self.registration.validate()?;
        if self.observer_id.is_empty()
            || self.namespace != self.registration.namespace
            || self.observer_id.len() > 256
            || !self.namespace.starts_with('/')
            || self.namespace.ends_with('/')
            || self.namespace.len() > 1024
        {
            return Err(refused());
        }
        let keys = crate::control_config::keys(&self.observer_keys)?;
        for key in keys.values() {
            if self
                .registration
                .signers
                .values()
                .any(|s| crate::config::key(&s.public_key).is_ok_and(|k| k == *key.as_bytes()))
            {
                return Err(refused());
            }
            for child in &self.registration.children {
                if child.keys()?.contains(key) {
                    return Err(refused());
                }
            }
        }
        Ok(keys)
    }
}
pub fn verify(bundle: &Bundle, trust: &AuditTrust) -> Result<()> {
    let keys = trust.keys()?;
    bundle.state.verify(&trust.registration)?;
    let c = &bundle.checkpoint;
    if c.profile != PROFILE
        || c.namespace != trust.namespace
        || c.observer_id != trust.observer_id
        || c.state_digest != digest_value("family-state", &bundle.state)?
        || c.captured_at < trust.registration.valid_from
        || c.captured_at > crate::contracts::MAX_SAFE_INTEGER as i64
        || bundle
            .state
            .events
            .last()
            .is_some_and(|e| e.at > c.captured_at)
    {
        return Err(refused());
    }
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&c.signature)
            .map_err(|_| refused())?,
    )
    .map_err(|_| refused())?;
    keys.get(&c.key_id)
        .ok_or_else(refused)?
        .verify_strict(&c.message()?, &signature)
        .map_err(|_| refused())
}
impl Family {
    pub async fn export(
        &self,
        observer: &crate::control_history::HistoryObserver,
        trust: &AuditTrust,
    ) -> Result<Bundle> {
        let keys = trust.keys()?;
        if trust.registration != self.registration
            || trust.namespace != self.ledger.prefix
            || trust.observer_id != observer.id
            || keys.get(&observer.key_id) != Some(&observer.key.verifying_key())
        {
            return Err(refused());
        }
        let state = self.status().await?;
        let captured_at = self.ledger.authority_clock.now_ms();
        if state.events.last().is_some_and(|e| e.at > captured_at) {
            return Err(refused());
        }
        let t = self
            .ledger
            .txn(
                vec![value_eq(&state_key(&self.ledger), &record(&state)?)],
                vec![],
                vec![],
            )
            .await?;
        if !t.succeeded {
            return Err(refused());
        }
        let mut checkpoint = Checkpoint {
            profile: PROFILE.into(),
            observer_id: observer.id.clone(),
            key_id: observer.key_id.clone(),
            namespace: self.ledger.prefix.clone(),
            captured_at,
            state_digest: digest_value("family-state", &state)?,
            signature: String::new(),
        };
        checkpoint.signature =
            URL_SAFE_NO_PAD.encode(observer.key.sign(&checkpoint.message()?).to_bytes());
        let bundle = Bundle { state, checkpoint };
        verify(&bundle, trust)?;
        Ok(bundle)
    }
}
/// Protected operator/client files. TLS and tokens remain independent of request data.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub registration: Registration,
    pub etcd_endpoint: String,
    pub etcd_prefix: String,
    pub etcd_ca: std::path::PathBuf,
    pub etcd_certificate: std::path::PathBuf,
    pub etcd_private_key: std::path::PathBuf,
    pub etcd_token_file: std::path::PathBuf,
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(refused());
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        c.registration.validate()?;
        Ok(c)
    }
    pub async fn ledger(&self) -> Result<EtcdLedger> {
        let client = crate::tls::pinned_http_client(
            &self.etcd_ca,
            &self.etcd_certificate,
            &self.etcd_private_key,
            std::time::Duration::from_secs(5),
        )?;
        let mut l = EtcdLedger::new(client, &self.etcd_endpoint, &self.etcd_prefix)?
            .with_auth_token(&crate::config::read_secret(&self.etcd_token_file).await?)?;
        if let Some(g) = &self.restore_gate {
            l = g.attach(l).await?;
        }
        Ok(l)
    }
    pub async fn family(&self) -> Result<Family> {
        Family::new(self.ledger().await?, self.registration.clone())
    }
}
pub async fn observer_from_file(
    id: String,
    key_id: String,
    path: &std::path::Path,
) -> Result<crate::control_history::HistoryObserver> {
    let key = crate::config::key(&crate::config::read_secret(&path.to_path_buf()).await?)?;
    crate::control_history::HistoryObserver::new(id, key_id, SigningKey::from_bytes(&key))
}
