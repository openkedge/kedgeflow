//! Trusted capacity-state ports only; no grant/target execution authority.
use crate::{
    contracts::{digest, strict_value},
    error::{Error, Result},
    ledger::{EtcdLedger, get, put, range_kv, record, value_eq, version_zero},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const PROFILE: &str = "KF-COORDINATION-0.1-draft";
const MAX: u64 = 9_007_199_254_740_991;
fn refuse() -> Error {
    Error::Refused("coordination scope, budget or transition refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReservationScope {
    #[serde(deserialize_with = "unique_scope")]
    pub actions: BTreeSet<String>,
    #[serde(deserialize_with = "unique_scope")]
    pub resources: BTreeSet<String>,
}
fn unique_scope<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeSet<String>, D::Error> {
    let values = Vec::<String>::deserialize(d)?;
    let set: BTreeSet<_> = values.iter().cloned().collect();
    if set.len() != values.len() {
        return Err(serde::de::Error::custom("duplicate reservation scope"));
    }
    Ok(set)
}
impl ReservationScope {
    pub(crate) fn valid(&self) -> bool {
        [&self.actions, &self.resources].iter().all(|set| {
            !set.is_empty()
                && set.len() <= 64
                && set.iter().all(|s| !s.is_empty() && s.len() <= 256)
        })
    }
    pub(crate) fn narrows(&self, parent: &Self) -> bool {
        self.valid()
            && self.actions.is_subset(&parent.actions)
            && self.resources.is_subset(&parent.resources)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReservationEnrollment {
    pub tenant: String,
    pub conflict_domain: String,
    pub scope: ReservationScope,
    pub forward: u64,
    pub compensation: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Allocated,
    Composite,
    Unknown,
    Committed,
    ProvenNoEffect,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub operation_digest: String,
    pub parent: Option<String>,
    pub scope: ReservationScope,
    pub forward: u64,
    pub compensation: u64,
    pub state: ReservationState,
    pub attempt_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReservationSnapshot {
    pub profile: String,
    pub enrollment: ReservationEnrollment,
    pub active: bool,
    pub execution_authority: bool,
    pub allocations: BTreeMap<String, Allocation>,
}
impl ReservationSnapshot {
    pub(crate) fn validate(&self) -> Result<()> {
        let e = &self.enrollment;
        if self.profile != PROFILE
            || self.execution_authority
            || e.tenant.is_empty()
            || e.tenant.len() > 256
            || e.conflict_domain.is_empty()
            || e.conflict_domain.len() > 256
            || !e.scope.valid()
            || e.forward == 0
            || e.forward > MAX
            || e.compensation > MAX
            || self.allocations.len() > 256
        {
            return Err(refuse());
        }
        let mut sums: BTreeMap<Option<String>, (u64, u64)> = BTreeMap::new();
        for (id, a) in &self.allocations {
            if id != &a.operation_digest
                || !crate::grant_reference::valid_reference(id)
                || a.forward == 0
                || a.forward > MAX
                || a.compensation > MAX
                || !a.scope.valid()
            {
                return Err(refuse());
            }
            match a.state {
                ReservationState::Allocated | ReservationState::Composite => {
                    if a.attempt_id.is_some() {
                        return Err(refuse());
                    }
                }
                _ => {
                    if a.attempt_id
                        .as_ref()
                        .is_none_or(|id| id.is_empty() || id.len() > 256)
                    {
                        return Err(refuse());
                    }
                }
            }
            let parent_scope = if let Some(parent) = &a.parent {
                let parent = self.allocations.get(parent).ok_or_else(refuse)?;
                if parent.state != ReservationState::Composite {
                    return Err(refuse());
                }
                &parent.scope
            } else {
                &e.scope
            };
            if !a.scope.narrows(parent_scope) {
                return Err(refuse());
            }
            let mut chain = BTreeSet::from([id.clone()]);
            let mut parent = a.parent.as_ref();
            while let Some(p) = parent {
                if !chain.insert(p.clone()) || chain.len() > 8 {
                    return Err(refuse());
                }
                parent = self.allocations.get(p).ok_or_else(refuse)?.parent.as_ref();
            }
            let sum = sums.entry(a.parent.clone()).or_default();
            sum.0 = sum.0.checked_add(a.forward).ok_or_else(refuse)?;
            sum.1 = sum.1.checked_add(a.compensation).ok_or_else(refuse)?;
        }
        for (parent, (forward, compensation)) in sums {
            let limit = parent.as_ref().map(|p| &self.allocations[p]);
            if forward > limit.map_or(e.forward, |a| a.forward)
                || compensation > limit.map_or(e.compensation, |a| a.compensation)
            {
                return Err(refuse());
            }
        }
        Ok(())
    }
}
pub struct Coordination {
    pub(crate) ledger: EtcdLedger,
    pub(crate) key: String,
}
impl Coordination {
    pub(crate) fn domain_binding(
        &self,
        enrollment: &ReservationEnrollment,
    ) -> Result<(String, String)> {
        let key = format!(
            "{}/coordination-domains/{}",
            self.ledger.prefix,
            digest(
                "coordination-domain",
                &serde_json::json!({"tenant":enrollment.tenant,"domain":enrollment.conflict_domain})
            )?
        );
        let value = record(&serde_json::json!({"profile":PROFILE,"root":self.key,
            "enrollment_digest":digest("coordination-enrollment", &serde_json::to_value(enrollment)?)?}))?;
        Ok((key, value))
    }
    pub fn new(ledger: EtcdLedger, root_id: &str) -> Result<Self> {
        if root_id.is_empty() || root_id.len() > 256 {
            return Err(refuse());
        }
        let key = format!(
            "{}/coordination/{}",
            ledger.prefix,
            digest("coordination-root", &serde_json::json!(root_id))?
        );
        Ok(Self { ledger, key })
    }
    pub async fn enroll(&self, enrollment: ReservationEnrollment) -> Result<()> {
        let state = ReservationSnapshot {
            profile: PROFILE.into(),
            enrollment,
            active: true,
            execution_authority: false,
            allocations: BTreeMap::new(),
        };
        state.validate()?;
        let (domain, binding) = self.domain_binding(&state.enrollment)?;
        if !self
            .ledger
            .txn(
                vec![version_zero(&self.key), version_zero(&domain)],
                vec![put(&self.key, &record(&state)?), put(&domain, &binding)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub async fn status(&self) -> Result<ReservationSnapshot> {
        let reply = self
            .ledger
            .txn(Vec::new(), vec![get(&self.key)], Vec::new())
            .await?;
        let kv = range_kv(reply.responses.first().ok_or_else(refuse)?)?.ok_or_else(refuse)?;
        if kv.value.len() > 128 << 10 {
            return Err(refuse());
        }
        let state: ReservationSnapshot = serde_json::from_value(strict_value(&kv.value)?)?;
        state.validate()?;
        let (domain, binding) = self.domain_binding(&state.enrollment)?;
        if !self
            .ledger
            .txn(
                vec![value_eq(&domain, &binding)],
                vec![get(&domain)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(state)
    }
    async fn save(&self, old: &str, state: &ReservationSnapshot, seals: &[String]) -> Result<()> {
        state.validate()?;
        let required =
            crate::reserved_leaf::required_key(&self.ledger, &state.enrollment.conflict_domain);
        let marker = self.ledger.read_key(&required).await?;
        if let Some(raw) = &marker {
            let v = strict_value(raw)?;
            if v["profile"] == crate::reservation_history::LEAF_PROFILE
                || v["profile"] == crate::hierarchical_leaf::PROFILE
            {
                return Err(refuse());
            }
        }
        let marker_compare = match &marker {
            None => version_zero(&required),
            Some(raw) => value_eq(&required, std::str::from_utf8(raw).map_err(|_| refuse())?),
        };
        let next = record(state)?;
        if next.len() > 128 << 10 {
            return Err(refuse());
        }
        let (domain, binding) = self.domain_binding(&state.enrollment)?;
        if !self
            .ledger
            .txn(
                std::iter::once(marker_compare)
                    .chain(std::iter::once(value_eq(&self.key, old)))
                    .chain(std::iter::once(value_eq(&domain, &binding)))
                    .chain(seals.iter().map(|s| version_zero(s)))
                    .collect(),
                vec![put(&self.key, &next)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    async fn unsealed(&self, operation: &str) -> Result<()> {
        let key = crate::reserved_leaf::seal_key(&self.ledger, &self.key, operation);
        if !self
            .ledger
            .txn(vec![version_zero(&key)], vec![get(&key)], Vec::new())
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    /// Caller independently verifies admitted operation and narrower delegation.
    pub async fn allocate(
        &self,
        operation_digest: &str,
        parent: Option<&str>,
        scope: ReservationScope,
        forward: u64,
        compensation: u64,
    ) -> Result<Allocation> {
        if !crate::grant_reference::valid_reference(operation_digest) {
            return Err(refuse());
        }
        let mut state = self.status().await?;
        let candidate = Allocation {
            operation_digest: operation_digest.into(),
            parent: parent.map(str::to_owned),
            scope,
            forward,
            compensation,
            state: ReservationState::Allocated,
            attempt_id: None,
        };
        if let Some(existing) = state.allocations.get(operation_digest) {
            if existing.parent == candidate.parent
                && existing.scope == candidate.scope
                && existing.forward == forward
                && existing.compensation == compensation
            {
                return Ok(existing.clone());
            }
            return Err(refuse());
        }
        if !state.active {
            return Err(refuse());
        }
        let old = record(&state)?;
        if let Some(parent) = parent {
            let ancestor = state.allocations.get_mut(parent).ok_or_else(refuse)?;
            if !matches!(
                ancestor.state,
                ReservationState::Allocated | ReservationState::Composite
            ) {
                return Err(refuse());
            }
            ancestor.state = ReservationState::Composite;
        }
        state
            .allocations
            .insert(operation_digest.into(), candidate.clone());
        let seals = parent
            .map(|p| vec![crate::reserved_leaf::seal_key(&self.ledger, &self.key, p)])
            .unwrap_or_default();
        self.save(&old, &state, &seals).await?;
        Ok(candidate)
    }
    /// State-only original-attempt consumption; does not dispatch or mint a grant.
    pub async fn consume(&self, operation_digest: &str, attempt_id: &str) -> Result<Allocation> {
        if attempt_id.is_empty() || attempt_id.len() > 256 {
            return Err(refuse());
        }
        let mut state = self.status().await?;
        let old = record(&state)?;
        let a = state
            .allocations
            .get_mut(operation_digest)
            .ok_or_else(refuse)?;
        if let Some(original) = &a.attempt_id {
            self.unsealed(operation_digest).await?;
            if original == attempt_id {
                return Ok(a.clone());
            }
            return Err(refuse());
        }
        if !state.active || a.state != ReservationState::Allocated {
            return Err(refuse());
        }
        a.state = ReservationState::Unknown;
        a.attempt_id = Some(attempt_id.into());
        let result = a.clone();
        self.save(
            &old,
            &state,
            &[crate::reserved_leaf::seal_key(
                &self.ledger,
                &self.key,
                operation_digest,
            )],
        )
        .await?;
        Ok(result)
    }
    /// Trusted query evidence only. Known no-effect remains held: no refund API.
    pub async fn observe(
        &self,
        operation_digest: &str,
        attempt_id: &str,
        outcome: ReservationState,
    ) -> Result<()> {
        if !matches!(
            outcome,
            ReservationState::Committed | ReservationState::ProvenNoEffect
        ) {
            return Err(refuse());
        }
        let mut state = self.status().await?;
        let old = record(&state)?;
        let a = state
            .allocations
            .get_mut(operation_digest)
            .ok_or_else(refuse)?;
        if a.attempt_id.as_deref() != Some(attempt_id)
            || !matches!(
                a.state,
                ReservationState::Unknown
                    | ReservationState::Committed
                    | ReservationState::ProvenNoEffect
            )
        {
            return Err(refuse());
        }
        if a.state != ReservationState::Unknown && a.state != outcome {
            return Err(refuse());
        }
        a.state = outcome;
        self.save(
            &old,
            &state,
            &[crate::reserved_leaf::seal_key(
                &self.ledger,
                &self.key,
                operation_digest,
            )],
        )
        .await
    }
    pub async fn stop(&self) -> Result<()> {
        let mut state = self.status().await?;
        let old = record(&state)?;
        state.active = false;
        self.save(&old, &state, &[]).await
    }
}
