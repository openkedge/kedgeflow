//! Fixed-cost native leaf reservations. Signed bindings are historical statements,
//! not standalone execution capabilities. Every authority mutation uses etcd CAS.
use crate::{
    contracts::{Grant, GrantVerifier, Policy, canonical, digest, strict_value},
    coordination::{
        Allocation, Coordination, ReservationEnrollment, ReservationScope, ReservationSnapshot,
        ReservationState,
    },
    error::{Error, Result},
    governance::EnforcementScope,
    issuance::AdmittedIssuance,
    ledger::{
        EtcdLedger, IssuanceRecord, get, key_part, put, range_kv, record, value_eq, version_zero,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
pub const PROFILE: &str = "KF-RESERVED-LEAF-0.1-draft";
fn refuse() -> Error {
    Error::Refused("reserved leaf registration, allocation or authority refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::hierarchical_leaf::deserialize_optional"
    )]
    pub hierarchy: Option<crate::hierarchical_leaf::Hierarchy>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::saga_forward::deserialize_optional"
    )]
    pub saga: Option<crate::saga_forward::Plan>,
    pub profile: String,
    pub root_id: String,
    pub root_generation: u64,
    pub enrollment: ReservationEnrollment,
    pub scope: EnforcementScope,
    pub policy: Policy,
    pub ownership_epoch: u64,
    pub forward_units: u64,
    pub compensation_units: u64,
    pub issuer_keys: BTreeMap<String, String>,
}
impl Registration {
    pub fn validate(&self) -> Result<()> {
        ReservationSnapshot {
            profile: crate::coordination::PROFILE.into(),
            enrollment: self.enrollment.clone(),
            active: true,
            execution_authority: false,
            allocations: BTreeMap::new(),
        }
        .validate()?;
        let leaf = ReservationScope {
            actions: BTreeSet::from([self.scope.action.id.clone()]),
            resources: BTreeSet::from([self.scope.resource.id.clone()]),
        };
        if ![
            PROFILE,
            crate::reservation_history::LEAF_PROFILE,
            crate::hierarchical_leaf::PROFILE,
            crate::reservation_history::HIERARCHICAL_LEAF_PROFILE,
            crate::saga_forward::PROFILE,
        ]
        .contains(&self.profile.as_str())
            || self.root_generation != 1
            || self.root_id.is_empty()
            || self.root_id.len() > 256
            || if self.hierarchy.is_some() {
                !leaf.narrows(&self.enrollment.scope)
            } else {
                self.enrollment.scope != leaf
            }
            || matches!(
                self.profile.as_str(),
                crate::hierarchical_leaf::PROFILE
                    | crate::reservation_history::HIERARCHICAL_LEAF_PROFILE
                    | crate::saga_forward::PROFILE
            ) != self.hierarchy.is_some()
            || (self.profile == crate::saga_forward::PROFILE) != self.saga.is_some()
            || self.enrollment.conflict_domain != self.scope.conflict_domain
            || self.forward_units == 0
            || self.forward_units > self.enrollment.forward
            || self.compensation_units > self.enrollment.compensation
            || self.ownership_epoch == 0
            || self.ownership_epoch > crate::contracts::MAX_SAFE_INTEGER
            || self.policy.epoch == 0
            || self.policy.epoch > crate::contracts::MAX_SAFE_INTEGER
            || self.policy.id.is_empty()
            || self.scope.action.version.is_empty()
            || self.scope.resource.incarnation.is_empty()
            || !crate::grant_reference::valid_reference(&self.policy.digest)
            || !crate::grant_reference::valid_reference(&self.scope.action.digest)
            || self.issuer_keys.len() > 64
            || self
                .issuer_keys
                .keys()
                .any(|k| k.is_empty() || k.len() > 256)
        {
            return Err(refuse());
        }
        crate::endpoint::EndpointPolicy::new(&self.scope.audience)?;
        crate::control_config::keys(&self.issuer_keys)?;
        if let Some(h) = &self.hierarchy {
            h.validate(self)?;
        }
        if let Some(plan) = &self.saga {
            plan.validate(self)?;
        }
        if canonical(&json!(self))?.len()
            > if self.hierarchy.is_some() {
                128 << 10
            } else {
                16384
            }
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub(crate) fn initial_allocations(&self) -> Result<BTreeMap<String, Allocation>> {
        if let Some(plan) = &self.saga {
            plan.allocations(self)
        } else {
            self.hierarchy
                .as_ref()
                .map(|h| h.initial())
                .transpose()
                .map(Option::unwrap_or_default)
        }
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("reserved-leaf-registration", &json!(self))
    }
    pub(crate) fn grant(&self, g: &Grant) -> Result<()> {
        if EnforcementScope::grant(g)? != self.scope
            || g.policy != self.policy
            || g.ownership_epoch != self.ownership_epoch
            || g.root_generation != 1
            || g.parent_grant_digest.is_some()
            || !g.saga_budget.is_null()
            || g.completion_mode != "dispatch_bound"
        {
            return Err(refuse());
        }
        if let Some(h) = &self.hierarchy {
            h.grant(g)?;
        }
        if let Some(plan) = &self.saga {
            plan.grant(g)?;
        }
        Ok(())
    }
    pub(crate) fn binding_profile(&self) -> &str {
        if self.saga.is_some() {
            crate::saga_forward::PROFILE
        } else if self.hierarchy.is_some() {
            crate::hierarchical_leaf::PROFILE
        } else {
            PROFILE
        }
    }
    pub(crate) fn allocation_for(&self, operation: &str, g: &Grant) -> Result<Allocation> {
        if let Some(plan) = &self.saga
            && plan.node(operation)?.principal != crate::hierarchical_leaf::Principal::from_grant(g)
        {
            return Err(refuse());
        }
        let mut a = self.allocation(operation);
        a.scope = ReservationScope {
            actions: BTreeSet::from([self.scope.action.id.clone()]),
            resources: BTreeSet::from([self.scope.resource.id.clone()]),
        };
        a.parent = self
            .hierarchy
            .as_ref()
            .map(|h| h.parent(g).map(str::to_owned))
            .transpose()?;
        Ok(a)
    }
    pub(crate) fn matches_for(&self, a: &Allocation, op: &str, g: &Grant) -> Result<()> {
        let e = self.allocation_for(op, g)?;
        if a.operation_digest != op
            || a.parent != e.parent
            || a.scope != e.scope
            || a.forward != e.forward
            || a.compensation != e.compensation
            || a.state == ReservationState::Composite
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub(crate) fn allocation(&self, operation: &str) -> Allocation {
        Allocation {
            operation_digest: operation.into(),
            parent: None,
            scope: self.enrollment.scope.clone(),
            forward: self.forward_units,
            compensation: self.compensation_units,
            state: ReservationState::Allocated,
            attempt_id: None,
        }
    }
    pub(crate) fn matches(&self, a: &Allocation, op: &str) -> Result<()> {
        let expected = self.allocation(op);
        if a.operation_digest != op
            || a.parent.is_some()
            || a.scope != expected.scope
            || a.forward != expected.forward
            || a.compensation != expected.compensation
            || a.state == ReservationState::Composite
        {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingPayload {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::saga_forward::deserialize_binding"
    )]
    pub saga: Option<crate::saga_forward::Binding>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_parent"
    )]
    pub parent_grant_digest: Option<String>,
    pub tenant: String,
    pub conflict_domain: String,
    pub root_id: String,
    pub root_generation: u64,
    pub registration_digest: String,
    pub operation_key: String,
    pub grant_digest: String,
    pub certificate_digest: String,
    pub allocation_digest: String,
}
fn present_parent<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationBinding {
    pub profile: String,
    pub kind: String,
    pub key_id: String,
    pub payload: BindingPayload,
    pub signature: String,
}
fn allocation_digest(a: &Allocation) -> Result<String> {
    digest(
        "reserved-leaf-allocation",
        &json!({"operation":a.operation_digest,"parent":a.parent,"scope":a.scope,"forward":a.forward,"compensation":a.compensation}),
    )
}
impl ReservationBinding {
    fn message(&self) -> Result<Vec<u8>> {
        let mut raw = format!("KedgeFlow:{}\0", self.profile).into_bytes();
        raw.extend(canonical(&json!({"profile":self.profile,"kind":self.kind,"key_id":self.key_id,"payload":self.payload}))?);
        Ok(raw)
    }
    pub(crate) fn verify(&self, r: &Registration, g: &Grant, gd: &str) -> Result<()> {
        r.validate()?;
        r.grant(g)?;
        let v = json!(self);
        static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
        let schema = SCHEMA.get_or_init(|| {
            crate::schema::compile(
                &serde_json::from_str(include_str!(
                    "../../../spec/drafts/reserved-leaf-binding-v0.1.schema.json"
                ))
                .expect("embedded reserved binding schema"),
            )
            .expect("valid reserved schema")
        });
        if canonical(&v)?.len() > 16384
            || if r.saga.is_some() {
                crate::saga_forward::validate(&v, "binding").is_err()
            } else if r.hierarchy.is_some() {
                crate::hierarchical_leaf::validate(&v, "binding").is_err()
            } else {
                !schema.is_valid(&v)
            }
        {
            return Err(refuse());
        }
        let keys = crate::control_config::keys(&r.issuer_keys)?;
        let key = keys.get(&self.key_id).ok_or_else(refuse)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| refuse())?;
        let sig = Signature::from_slice(&signature).map_err(|_| refuse())?;
        let p = &self.payload;
        if self.profile != r.binding_profile()
            || self.kind != "reservation_binding"
            || key.verify_strict(&self.message()?, &sig).is_err()
            || p.saga
                != r.saga
                    .as_ref()
                    .map(|plan| plan.binding(&p.operation_key))
                    .transpose()?
            || p.tenant != r.enrollment.tenant
            || p.conflict_domain != r.scope.conflict_domain
            || p.root_id != r.root_id
            || p.root_generation != 1
            || p.registration_digest != r.digest()?
            || p.grant_digest != gd
            || p.certificate_digest != g.certificate_digest
            || p.parent_grant_digest != r.allocation_for(&p.operation_key, g)?.parent
            || p.allocation_digest != allocation_digest(&r.allocation_for(&p.operation_key, g)?)?
        {
            return Err(refuse());
        }
        Ok(())
    }
}
/// Offline signature/context verification only; no live capacity or CAS assertion.
pub fn verify_binding(
    raw: &[u8],
    registration: &Registration,
    signed_grant: &[u8],
) -> Result<BindingPayload> {
    if raw.len() > 16384 {
        return Err(refuse());
    }
    let b: ReservationBinding = serde_json::from_value(strict_value(raw)?)?;
    let g = GrantVerifier {
        keys: crate::control_config::keys(&registration.issuer_keys)?,
        audience: registration.scope.audience.clone(),
    }
    .verify_retained(signed_grant)?;
    b.verify(registration, &g.grant, &g.digest)?;
    Ok(b.payload)
}
pub(crate) fn required_key(ledger: &EtcdLedger, domain: &str) -> String {
    format!(
        "{}/domains/{}/reservation-required",
        ledger.prefix,
        key_part(domain)
    )
}
pub(crate) fn seal_key(ledger: &EtcdLedger, root: &str, op: &str) -> String {
    format!(
        "{}/reservation-seals/{}/{op}",
        ledger.prefix,
        key_part(root)
    )
}
fn binding_key(ledger: &EtcdLedger, gd: &str) -> String {
    format!("{}/reserved-grants/{gd}", ledger.prefix)
}
fn marker(r: &Registration) -> Result<String> {
    record(
        &json!({"profile":r.profile,"root_id":r.root_id,"root_generation":1,"registration_digest":r.digest()?}),
    )
}
pub(crate) struct Change {
    pub compare: Vec<Value>,
    pub writes: Vec<Value>,
    pub newly_allocated: bool,
}
pub(crate) struct Gate {
    pub(crate) r: Registration,
    pub(crate) c: Coordination,
    pub(crate) state: ReservationSnapshot,
    pub(crate) compare: Vec<Value>,
}
impl EtcdLedger {
    pub fn with_reservation(mut self, r: Registration) -> Result<Self> {
        r.validate()?;
        if !self.require_control {
            return Err(refuse());
        }
        self.reservation = Some(std::sync::Arc::new(r));
        Ok(self)
    }
    pub(crate) fn reservation_service(
        &self,
        trust: &crate::admission::AdmissionTrust,
        keys: &BTreeMap<String, ed25519_dalek::VerifyingKey>,
    ) -> bool {
        self.reservation.as_ref().is_none_or(|r| {
            r.enrollment.tenant == trust.tenant
                && r.policy == trust.policy
                && r.ownership_epoch == trust.ownership_epoch
                && r.scope.action.digest == trust.descriptor_digest
                && crate::control_config::keys(&r.issuer_keys).is_ok_and(|k| k == *keys)
                && r.saga.as_ref().is_none_or(|p| {
                    p.distinct(
                        trust
                            .proposal_keys
                            .values()
                            .chain(trust.registry_keys.values())
                            .chain(trust.manifest_keys.values())
                            .chain(trust.evidence.values().flat_map(|e| e.keys.values())),
                    )
                })
                && r.hierarchy.as_ref().is_none_or(|h| {
                    h.distinct(
                        trust
                            .proposal_keys
                            .values()
                            .chain(trust.registry_keys.values())
                            .chain(trust.manifest_keys.values())
                            .chain(trust.evidence.values().flat_map(|e| e.keys.values())),
                    )
                })
        })
    }
    pub async fn enroll_reservation(&self) -> Result<()> {
        let r = self.reservation.as_ref().ok_or_else(refuse)?;
        let c = Coordination::new(self.clone(), &r.root_id)?;
        let state = ReservationSnapshot {
            profile: crate::coordination::PROFILE.into(),
            enrollment: r.enrollment.clone(),
            active: true,
            execution_authority: false,
            allocations: r.initial_allocations()?,
        };
        state.validate()?;
        let (domain, binding) = c.domain_binding(&state.enrollment)?;
        let required = required_key(self, &r.scope.conflict_domain);
        let history = self
            .history_change(
                r,
                None,
                &state,
                crate::reservation_history::EventData::new("enroll", None),
            )
            .await?;
        let mut composite_compare = Vec::new();
        let mut composite_writes = Vec::new();
        if let Some(h) = &r.hierarchy {
            for g in &h.grants {
                let key = crate::hierarchical_leaf::composite_key(self, r, &g.digest()?);
                composite_compare.push(version_zero(&key));
                composite_writes.push(put(&key, &record(g)?));
            }
        }
        if let Some(plan) = &r.saga {
            let key = crate::saga_forward::plan_key(self, r);
            composite_compare.push(version_zero(&key));
            composite_writes.push(put(&key, &record(plan)?));
        }
        if !self
            .txn(
                [
                    composite_compare,
                    vec![
                        version_zero(&c.key),
                        version_zero(&domain),
                        version_zero(&required),
                    ],
                    history.compare,
                ]
                .concat(),
                [
                    composite_writes,
                    vec![
                        put(&c.key, &record(&state)?),
                        put(&domain, &binding),
                        put(&required, &marker(r)?),
                    ],
                    history.writes,
                ]
                .concat(),
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub async fn stop_reservation(&self) -> Result<()> {
        let r = self.reservation.as_ref().ok_or_else(refuse)?;
        // Validate the approved markers before invoking permanent stop. Enrollment
        // is create-only; there is no native replacement/reactivation operation.
        if r.profile == crate::reservation_history::LEAF_PROFILE || r.hierarchy.is_some() {
            let gate = self
                .reservation_gate_for(&r.scope.conflict_domain, false)
                .await?
                .ok_or_else(refuse)?;
            if !gate.state.active {
                if !self
                    .txn(gate.compare, vec![get(&gate.c.key)], Vec::new())
                    .await?
                    .succeeded
                {
                    return Err(refuse());
                }
                return Ok(());
            }
            let mut after = gate.state.clone();
            after.active = false;
            let history = self
                .history_change(
                    r,
                    Some(&gate.state),
                    &after,
                    crate::reservation_history::EventData::new("stop", None),
                )
                .await?;
            let mut compare = gate.compare;
            compare.extend(history.compare);
            let mut writes = history.writes;
            writes.push(put(&gate.c.key, &record(&after)?));
            if !self.txn(compare, writes, Vec::new()).await?.succeeded {
                return Err(refuse());
            }
            return Ok(());
        }
        self.reservation_gate_for(&r.scope.conflict_domain, false)
            .await?
            .ok_or_else(refuse)?
            .c
            .stop()
            .await
    }
    async fn reservation_read(&self, key: &str, bound: usize) -> Result<Option<Vec<u8>>> {
        let t = self.txn(Vec::new(), vec![get(key)], Vec::new()).await?;
        let kv = range_kv(t.responses.first().ok_or_else(refuse)?)?;
        kv.map(|kv| {
            if kv.value.len() > bound {
                Err(refuse())
            } else {
                Ok(kv.value)
            }
        })
        .transpose()
    }
    pub(crate) async fn reservation_gate_for(
        &self,
        domain: &str,
        active: bool,
    ) -> Result<Option<Gate>> {
        let required = required_key(self, domain);
        let raw = self.reservation_read(&required, 16384).await?;
        let Some(r) = &self.reservation else {
            if raw.is_some() {
                return Err(refuse());
            }
            return Ok(None);
        };
        if r.scope.conflict_domain != domain || raw.as_deref() != Some(marker(r)?.as_bytes()) {
            return Err(refuse());
        }
        let c = Coordination::new(self.clone(), &r.root_id)?;
        let state = c.status().await?;
        if state.enrollment != r.enrollment || active && !state.active {
            return Err(refuse());
        }
        let (key, binding) = c.domain_binding(&state.enrollment)?;
        let mut compare = vec![
            value_eq(&required, &marker(r)?),
            value_eq(&c.key, &record(&state)?),
            value_eq(&key, &binding),
        ];
        compare.extend(self.history_guard(r, &state).await?);
        if let Some(h) = &r.hierarchy {
            h.snapshot(r, &state)?;
            for g in &h.grants {
                let key = crate::hierarchical_leaf::composite_key(self, r, &g.digest()?);
                let expected = record(g)?;
                if self.reservation_read(&key, 16384).await?.as_deref() != Some(expected.as_bytes())
                {
                    return Err(refuse());
                }
                compare.push(value_eq(&key, &expected));
            }
        }
        if let Some(plan) = &r.saga {
            let key = crate::saga_forward::plan_key(self, r);
            let expected = record(plan)?;
            if self.reservation_read(&key, 64 << 10).await?.as_deref() != Some(expected.as_bytes())
            {
                return Err(refuse());
            }
            compare.push(value_eq(&key, &expected));
        }
        Ok(Some(Gate {
            r: r.as_ref().clone(),
            c,
            state,
            compare,
        }))
    }
    pub(crate) async fn reservation_candidate(
        &self,
        a: &AdmittedIssuance,
        allocate: bool,
    ) -> Result<Change> {
        let Some(mut gate) = self
            .reservation_gate_for(&a.grant.conflict_domain, true)
            .await?
        else {
            return Ok(Change {
                compare: vec![version_zero(&required_key(self, &a.grant.conflict_domain))],
                writes: Vec::new(),
                newly_allocated: false,
            });
        };
        gate.r.grant(&a.grant)?;
        if gate.r.hierarchy.is_some()
            && (self.authority_clock.now_ms() < a.grant.valid_from
                || self.authority_clock.now_ms() >= a.grant.expires_at)
        {
            return Err(refuse());
        }
        if a.tenant != gate.r.enrollment.tenant {
            return Err(refuse());
        }
        self.saga_dependencies(
            &mut gate,
            &a.key,
            &crate::hierarchical_leaf::Principal::from_grant(&a.grant),
        )
        .await?;
        if let Some(existing) = gate.state.allocations.get(&a.key) {
            gate.r.matches_for(existing, &a.key, &a.grant)?;
            return Ok(Change {
                compare: gate.compare,
                writes: Vec::new(),
                newly_allocated: false,
            });
        }
        let mut writes = Vec::new();
        let compare = gate.compare;
        if allocate {
            gate.state
                .allocations
                .insert(a.key.clone(), gate.r.allocation_for(&a.key, &a.grant)?);
            gate.state.validate()?;
            let value = record(&gate.state)?;
            if value.len() > 128 << 10 {
                return Err(refuse());
            }
            writes.push(put(&gate.c.key, &value));
        }
        Ok(Change {
            compare,
            writes,
            newly_allocated: allocate,
        })
    }
    pub(crate) async fn reservation_allocation_history(
        &self,
        a: &AdmittedIssuance,
        fence: u64,
    ) -> Result<Change> {
        if self
            .reservation
            .as_ref()
            .is_none_or(|r| r.profile != crate::reservation_history::LEAF_PROFILE)
        {
            return Ok(Change {
                compare: Vec::new(),
                writes: Vec::new(),
                newly_allocated: false,
            });
        }
        let gate = self
            .reservation_gate_for(&a.grant.conflict_domain, true)
            .await?
            .ok_or_else(refuse)?;
        if gate.state.allocations.contains_key(&a.key) {
            return Ok(Change {
                compare: gate.compare,
                writes: Vec::new(),
                newly_allocated: false,
            });
        }
        let mut after = gate.state.clone();
        after
            .allocations
            .insert(a.key.clone(), gate.r.allocation_for(&a.key, &a.grant)?);
        let mut data = crate::reservation_history::EventData::new("allocate", Some(&a.key));
        data.fence = Some(fence);
        let mut change = self
            .history_change(&gate.r, Some(&gate.state), &after, data)
            .await?;
        change.compare.extend(gate.compare);
        Ok(change)
    }
    pub(crate) fn sign_reservation(
        &self,
        a: &AdmittedIssuance,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<Option<ReservationBinding>> {
        let Some(r) = &self.reservation else {
            return Ok(None);
        };
        r.grant(&a.grant)?;
        if crate::control_config::keys(&r.issuer_keys)?.get(key_id) != Some(&key.verifying_key())
            || a.tenant != r.enrollment.tenant
        {
            return Err(refuse());
        }
        let mut b = ReservationBinding {
            profile: r.binding_profile().into(),
            kind: "reservation_binding".into(),
            key_id: key_id.into(),
            payload: BindingPayload {
                saga: r
                    .saga
                    .as_ref()
                    .map(|plan| plan.binding(&a.key))
                    .transpose()?,
                parent_grant_digest: r.allocation_for(&a.key, &a.grant)?.parent,
                tenant: a.tenant.clone(),
                conflict_domain: a.grant.conflict_domain.clone(),
                root_id: r.root_id.clone(),
                root_generation: 1,
                registration_digest: r.digest()?,
                operation_key: a.key.clone(),
                grant_digest: a.grant_digest.clone(),
                certificate_digest: a.grant.certificate_digest.clone(),
                allocation_digest: allocation_digest(&r.allocation_for(&a.key, &a.grant)?)?,
            },
            signature: String::new(),
        };
        b.signature = URL_SAFE_NO_PAD.encode(key.sign(&b.message()?).to_bytes());
        b.verify(r, &a.grant, &a.grant_digest)?;
        Ok(Some(b))
    }
    pub(crate) async fn reservation_issue(
        &self,
        a: &AdmittedIssuance,
        b: Option<&ReservationBinding>,
    ) -> Result<Change> {
        let Some(mut gate) = self
            .reservation_gate_for(&a.grant.conflict_domain, true)
            .await?
        else {
            if b.is_some() {
                return Err(refuse());
            }
            return Ok(Change {
                compare: vec![version_zero(&required_key(self, &a.grant.conflict_domain))],
                writes: Vec::new(),
                newly_allocated: false,
            });
        };
        let b = b.ok_or_else(refuse)?;
        b.verify(&gate.r, &a.grant, &a.grant_digest)?;
        self.saga_dependencies(
            &mut gate,
            &a.key,
            &crate::hierarchical_leaf::Principal::from_grant(&a.grant),
        )
        .await?;
        let before = gate.state.clone();
        let mut allocation_writes = Vec::new();
        if gate.r.hierarchy.is_some() && !gate.state.allocations.contains_key(&a.key) {
            gate.state
                .allocations
                .insert(a.key.clone(), gate.r.allocation_for(&a.key, &a.grant)?);
            gate.state.validate()?;
            let value = record(&gate.state)?;
            if value.len() > 128 << 10 {
                return Err(refuse());
            }
            allocation_writes.push(put(&gate.c.key, &value));
        }
        let alloc = gate.state.allocations.get(&a.key).ok_or_else(refuse)?;
        gate.r.matches_for(alloc, &a.key, &a.grant)?;
        if b.payload.operation_key != a.key
            || alloc.state != ReservationState::Allocated
            || b.payload.allocation_digest != allocation_digest(alloc)?
        {
            return Err(refuse());
        }
        let index = binding_key(self, &a.grant_digest);
        let seal = seal_key(self, &gate.c.key, &a.key);
        let value = record(b)?;
        let mut data = crate::reservation_history::EventData::new("issue", Some(&a.key));
        data.grant_digest = Some(a.grant_digest.clone());
        data.binding = Some(b.clone());
        data.signed_grant = Some(a.signed_grant.clone());
        if gate.r.hierarchy.is_some() && crate::reservation_history::audited(&gate.r.profile) {
            data.fence = Some(a.grant.fence);
        }
        let history = self
            .history_change(&gate.r, Some(&before), &gate.state, data)
            .await?;
        let mut compare = gate.compare;
        compare.extend(history.compare);
        compare.extend([version_zero(&index), version_zero(&seal)]);
        Ok(Change {
            compare,
            writes: [
                vec![put(&index, &value), put(&seal, &value)],
                allocation_writes,
                history.writes,
            ]
            .concat(),
            newly_allocated: false,
        })
    }
    pub(crate) async fn reservation_bound(
        &self,
        g: &Grant,
        gd: &str,
        active: bool,
    ) -> Result<Option<(Gate, ReservationBinding)>> {
        let Some(mut gate) = self
            .reservation_gate_for(&g.conflict_domain, active)
            .await?
        else {
            return Ok(None);
        };
        gate.r.grant(g)?;
        if active
            && gate.r.hierarchy.is_some()
            && (self.authority_clock.now_ms() < g.valid_from
                || self.authority_clock.now_ms() >= g.expires_at)
        {
            return Err(refuse());
        }
        let index = binding_key(self, gd);
        let raw = self
            .reservation_read(&index, 16384)
            .await?
            .ok_or_else(refuse)?;
        let b: ReservationBinding = serde_json::from_value(strict_value(&raw)?)?;
        b.verify(&gate.r, g, gd)?;
        let alloc = gate
            .state
            .allocations
            .get(&b.payload.operation_key)
            .ok_or_else(refuse)?;
        gate.r.matches_for(alloc, &b.payload.operation_key, g)?;
        if b.payload.allocation_digest != allocation_digest(alloc)? {
            return Err(refuse());
        }
        let seal = seal_key(self, &gate.c.key, &b.payload.operation_key);
        if self.reservation_read(&seal, 16384).await?.as_deref() != Some(raw.as_slice()) {
            return Err(refuse());
        }
        gate.compare.extend([
            value_eq(&index, std::str::from_utf8(&raw).map_err(|_| refuse())?),
            value_eq(&seal, std::str::from_utf8(&raw).map_err(|_| refuse())?),
        ]);
        Ok(Some((gate, b)))
    }
    pub(crate) async fn reservation_check_issuance(&self, record: &IssuanceRecord) -> Result<()> {
        if self.reservation.is_none() {
            return Ok(());
        }
        let r = self.reservation.as_ref().ok_or_else(refuse)?;
        let g = GrantVerifier {
            keys: crate::control_config::keys(&r.issuer_keys)?,
            audience: r.scope.audience.clone(),
        }
        .verify_retained(record.signed_grant.as_bytes())?;
        let (mut gate, b) = self
            .reservation_bound(&g.grant, &g.digest, true)
            .await?
            .ok_or_else(refuse)?;
        if b.payload.operation_key != record.issuance_key || g.digest != record.grant_digest {
            return Err(refuse());
        }
        self.saga_dependencies(
            &mut gate,
            &b.payload.operation_key,
            &crate::hierarchical_leaf::Principal::from_grant(&g.grant),
        )
        .await?;
        if !self
            .txn(
                gate.compare,
                vec![get(&binding_key(self, &g.digest))],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub(crate) async fn reservation_claim(
        &self,
        g: &Grant,
        gd: &str,
        attempt: &str,
    ) -> Result<Change> {
        let Some((mut gate, b)) = self.reservation_bound(g, gd, true).await? else {
            return Ok(Change {
                compare: vec![version_zero(&required_key(self, &g.conflict_domain))],
                writes: Vec::new(),
                newly_allocated: false,
            });
        };
        self.saga_dependencies(
            &mut gate,
            &b.payload.operation_key,
            &crate::hierarchical_leaf::Principal::from_grant(g),
        )
        .await?;
        if attempt.is_empty() || attempt.len() > 256 {
            return Err(refuse());
        }
        let before = gate.state.clone();
        let a = gate
            .state
            .allocations
            .get_mut(&b.payload.operation_key)
            .ok_or_else(refuse)?;
        if a.state != ReservationState::Allocated || a.attempt_id.is_some() {
            return Err(refuse());
        }
        a.state = ReservationState::Unknown;
        a.attempt_id = Some(attempt.into());
        gate.state.validate()?;
        let raw = record(&gate.state)?;
        if raw.len() > 128 << 10 {
            return Err(refuse());
        }
        let mut data =
            crate::reservation_history::EventData::new("claim", Some(&b.payload.operation_key));
        data.grant_digest = Some(gd.into());
        data.attempt_id = Some(attempt.into());
        let history = self
            .history_change(&gate.r, Some(&before), &gate.state, data)
            .await?;
        Ok(Change {
            compare: [gate.compare, history.compare].concat(),
            writes: [vec![put(&gate.c.key, &raw)], history.writes].concat(),
            newly_allocated: false,
        })
    }
    pub(crate) async fn reservation_dispatch(
        &self,
        g: &Grant,
        gd: &str,
        attempt: &str,
    ) -> Result<Change> {
        let Some((mut gate, b)) = self.reservation_bound(g, gd, true).await? else {
            return Ok(Change {
                compare: vec![version_zero(&required_key(self, &g.conflict_domain))],
                writes: Vec::new(),
                newly_allocated: false,
            });
        };
        self.saga_dependencies(
            &mut gate,
            &b.payload.operation_key,
            &crate::hierarchical_leaf::Principal::from_grant(g),
        )
        .await?;
        let a = gate
            .state
            .allocations
            .get(&b.payload.operation_key)
            .ok_or_else(refuse)?;
        if a.state != ReservationState::Unknown || a.attempt_id.as_deref() != Some(attempt) {
            return Err(refuse());
        }
        let mut data =
            crate::reservation_history::EventData::new("dispatch", Some(&b.payload.operation_key));
        data.grant_digest = Some(gd.into());
        data.attempt_id = Some(attempt.into());
        let history = self
            .history_change(&gate.r, Some(&gate.state), &gate.state, data)
            .await?;
        Ok(Change {
            compare: [gate.compare, history.compare].concat(),
            writes: history.writes,
            newly_allocated: false,
        })
    }
    /// Privileged historical disclosure; no current execution permission implied.
    pub async fn retained_reservation_binding(
        &self,
        g: &Grant,
        gd: &str,
    ) -> Result<ReservationBinding> {
        let (gate, b) = self
            .reservation_bound(g, gd, false)
            .await?
            .ok_or_else(refuse)?;
        if !self
            .txn(gate.compare, vec![get(&binding_key(self, gd))], Vec::new())
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(b)
    }
}
