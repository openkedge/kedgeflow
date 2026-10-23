//! Replayable composition phases. Only native storage/claim adapters may retain
//! these records; an owner intent cannot invent an original inverse claim.
use crate::{
    compensation_execution::Binding,
    contracts::{canonical, digest},
    error::{Error, Result},
    family::Registration,
    family_saga::{
        ForwardState as F, Intent, IntentAction, InverseState as I, MemberSummary, PROFILE, Plan,
        Snapshot,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_EVENTS: usize = 96;
pub const MAX_STATE: usize = 256 << 10;
fn refused() -> Error {
    Error::Refused("global family saga phase, order or original claim refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Forward,
    Quiescing,
    Compensating,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Flight {
    pub child_id: String,
    pub grant_digest: String,
    pub attempt_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Owner {
        at: i64,
        intent: Intent,
        /// Exact family head compared by the native phase CAS. Historical
        /// Observe is read-only with respect to execution authority.
        family_head: Option<String>,
    },
    NativeClaim {
        at: i64,
        child_id: String,
        attempt_id: String,
        binding: Box<Binding>,
    },
}
impl Event {
    fn at(&self) -> i64 {
        match self {
            Self::Owner { at, .. } | Self::NativeClaim { at, .. } => *at,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub profile: String,
    pub registration_digest: String,
    pub phase: Phase,
    pub head: String,
    pub snapshot_digest: Option<String>,
    pub members: BTreeMap<String, MemberSummary>,
    pub in_flight: Option<Flight>,
    pub events: Vec<Event>,
}
impl State {
    pub fn genesis(r: &Registration) -> Result<Self> {
        r.validate()?;
        if r.profile != PROFILE || r.composition.is_none() {
            return Err(refused());
        }
        Ok(Self {
            profile: PROFILE.into(),
            registration_digest: r.digest()?,
            phase: Phase::Forward,
            head: digest(
                "family-saga-genesis",
                &json!({"registration_digest":r.digest()?,"plan_digest":r.composition.as_ref().ok_or_else(refused)?.digest()?}),
            )?,
            snapshot_digest: None,
            members: BTreeMap::new(),
            in_flight: None,
            events: vec![],
        })
    }
    pub fn verify(&self, r: &Registration, proofs: &BTreeMap<String, Snapshot>) -> Result<()> {
        if self.events.len() > MAX_EVENTS || canonical(&json!(self))?.len() > MAX_STATE {
            return Err(refused());
        }
        if &Self::from_events(r, &self.events, proofs)? != self {
            return Err(refused());
        }
        Ok(())
    }
    /// Pure historical phase replay. Native capture seals and actual retained
    /// comparisons must additionally be verified by the aggregate verifier.
    pub fn from_events(
        r: &Registration,
        events: &[Event],
        proofs: &BTreeMap<String, Snapshot>,
    ) -> Result<Self> {
        if events.len() > MAX_EVENTS {
            return Err(refused());
        }
        let mut state = Self::genesis(r)?;
        for event in events {
            state.replay_event(r, event, proofs)?;
        }
        Ok(state)
    }
    pub(crate) fn replay_event(
        &mut self,
        r: &Registration,
        event: &Event,
        proofs: &BTreeMap<String, Snapshot>,
    ) -> Result<()> {
        match event {
            Event::Owner {
                at,
                intent,
                family_head,
            } => {
                let proof = intent
                    .payload
                    .proof_digest
                    .as_ref()
                    .map(|d| proofs.get(d).ok_or_else(refused))
                    .transpose()?;
                if !self.apply_owner(
                    r,
                    intent.clone(),
                    proof,
                    proofs,
                    family_head.as_deref(),
                    *at,
                )? {
                    return Err(refused());
                }
            }
            Event::NativeClaim {
                at,
                child_id,
                attempt_id,
                binding,
            } => self.claim(r, child_id, attempt_id, (**binding).clone(), proofs, *at)?,
        }
        Ok(())
    }
    fn snapshot<'a>(&self, proofs: &'a BTreeMap<String, Snapshot>) -> Result<Option<&'a Snapshot>> {
        self.snapshot_digest
            .as_ref()
            .map(|d| proofs.get(d).ok_or_else(refused))
            .transpose()
    }
    fn clock(&self, r: &Registration, at: i64) -> Result<()> {
        if at < r.valid_from
            || at > crate::contracts::MAX_SAFE_INTEGER as i64
            || self.events.last().is_some_and(|e| at < e.at())
        {
            return Err(refused());
        }
        Ok(())
    }
    fn append(&mut self, r: &Registration, event: Event) -> Result<()> {
        self.clock(r, event.at())?;
        if self.events.len() >= MAX_EVENTS {
            return Err(refused());
        }
        self.head = digest(
            "family-saga-event",
            &json!({"previous":self.head,"sequence":self.events.len()+1,"event":event}),
        )?;
        self.events.push(event);
        if canonical(&json!(self))?.len() > MAX_STATE {
            return Err(refused());
        }
        Ok(())
    }
    fn closure(&self, r: &Registration) -> Result<(usize, usize)> {
        let mut slots = match self.phase {
            Phase::Forward => 3,
            Phase::Quiescing => 2,
            Phase::Compensating => 1,
        };
        let mut bytes = slots * 4096;
        for n in &r.composition.as_ref().ok_or_else(refused)?.nodes {
            if r.child(&n.child_id)?.inverse.is_none() {
                continue;
            }
            let m = self.members.get(&n.child_id);
            if m.is_some_and(|m| {
                m.forward == F::NoEffect
                    || self.phase != Phase::Forward
                        && matches!(m.forward, F::Unissued | F::Unclaimed)
            }) {
                continue;
            }
            match m.map(|m| &m.inverse) {
                Some(I::Committed | I::NoEffect | I::Failed) => {}
                Some(I::Unknown) => {
                    slots += 1;
                    bytes += 4096;
                }
                _ => {
                    slots += 2;
                    bytes += 12288;
                }
            }
        }
        Ok((slots, bytes))
    }
    fn reserve(&self, r: &Registration) -> Result<()> {
        let (slots, bytes) = self.closure(r)?;
        if self.events.len() + slots > MAX_EVENTS
            || canonical(&json!(self))?.len() + bytes > MAX_STATE
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) fn future_state_bytes(&self, r: &Registration) -> Result<usize> {
        canonical(&json!(self))?
            .len()
            .checked_add(self.closure(r)?.1)
            .ok_or_else(refused)
    }
    pub(crate) fn proof_reserve(&self, r: &Registration) -> Result<usize> {
        let mut captures = usize::from(self.phase != Phase::Compensating);
        for n in &r.composition.as_ref().ok_or_else(refused)?.nodes {
            let m = self.members.get(&n.child_id);
            if m.is_none_or(|m| {
                m.forward == F::Unknown
                    || self.phase == Phase::Forward
                        && matches!(m.forward, F::Unissued | F::Unclaimed)
            }) {
                captures += 1;
            }
            if r.child(&n.child_id)?.inverse.is_some()
                && m.is_none_or(|m| {
                    m.forward != F::NoEffect
                        && (self.phase == Phase::Forward || m.forward == F::Committed)
                        && !matches!(m.inverse, I::Committed | I::NoEffect | I::Failed)
                })
            {
                captures += 1;
            }
        }
        captures
            .checked_mul(crate::family_saga::MAX_PROOF + 4096)
            .ok_or_else(refused)
    }
    pub(crate) fn forward_ready(&self, p: &Plan, child: &str) -> Result<()> {
        if self.phase != Phase::Forward {
            return Err(refused());
        }
        let n = p.node(child)?;
        if n.depends_on.iter().any(|d| {
            self.members
                .get(d)
                .is_none_or(|m| m.forward != F::Committed)
        }) {
            return Err(refused());
        }
        if self
            .members
            .get(child)
            .is_some_and(|m| matches!(m.forward, F::Committed | F::NoEffect))
        {
            return Err(refused());
        }
        Ok(())
    }
    fn descendants(p: &Plan, child: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut pending = vec![child.to_owned()];
        while let Some(parent) = pending.pop() {
            for n in &p.nodes {
                if n.depends_on.contains(&parent) && out.insert(n.child_id.clone()) {
                    pending.push(n.child_id.clone());
                }
            }
        }
        out
    }
    pub(crate) fn inverse_ready(&self, p: &Plan, child: &str) -> Result<()> {
        p.node(child)?;
        if self.phase != Phase::Compensating
            || self.members.len() != p.nodes.len()
            || self.members.values().any(|m| m.forward == F::Unknown)
            || self.in_flight.as_ref().is_some_and(|f| f.child_id != child)
        {
            return Err(refused());
        }
        let m = self.members.get(child).ok_or_else(refused)?;
        if m.forward != F::Committed || matches!(m.inverse, I::Committed | I::NoEffect | I::Failed)
        {
            return Err(refused());
        }
        for d in Self::descendants(p, child) {
            let m = self.members.get(&d).ok_or_else(refused)?;
            if m.forward == F::Unknown || m.forward == F::Committed && m.inverse != I::Committed {
                return Err(refused());
            }
        }
        Ok(())
    }
    fn observe(
        &mut self,
        r: &Registration,
        proof: &Snapshot,
        proofs: &BTreeMap<String, Snapshot>,
        at: i64,
    ) -> Result<bool> {
        let plan = r.composition.as_ref().ok_or_else(refused)?;
        if proof.phase_head != self.head || proof.captured_at > at {
            return Err(refused());
        }
        self.clock(r, proof.captured_at)?;
        if let Some(old) = self.snapshot(proofs)? {
            proof.verify_successor(old, r)?;
        }
        let members = proof.verify(r)?;
        // Every actual inverse attempt must have been reserved by the native
        // claim path first. Merely presenting a signed owner snapshot cannot
        // create or clear a different in-flight identity.
        for (id, m) in &members {
            let old = self.members.get(id);
            if m.inverse_attempt.as_ref().is_some_and(|a| {
                old.is_none_or(|o| {
                    o.inverse_attempt.as_ref() != Some(a) || o.inverse_grant != m.inverse_grant
                })
            }) {
                return Err(refused());
            }
            if m.inverse_grant.is_some() && old.is_none_or(|o| o.inverse_grant.is_none()) {
                self.inverse_ready(plan, id)?;
            }
        }
        let mut flight = self.in_flight.clone();
        if let Some(f) = &flight {
            let m = members.get(&f.child_id).ok_or_else(refused)?;
            if m.inverse_grant.as_ref() != Some(&f.grant_digest)
                || m.inverse_attempt.as_ref() != Some(&f.attempt_id)
            {
                return Err(refused());
            }
            if matches!(m.inverse, I::Committed | I::NoEffect | I::Failed) {
                flight = None;
            }
        }
        // Polling can append another original unknown receipt without changing
        // any effect or claim. Do not consume the bounded phase journal for a
        // changed native history head alone; continuity is checked above.
        let semantic = |members: &BTreeMap<String, MemberSummary>| {
            let mut view = members.clone();
            for m in view.values_mut() {
                m.forward_head.clear();
                m.physical_head = None;
                if m.forward == F::Unknown {
                    m.physical_status = None;
                }
            }
            view
        };
        let changed = semantic(&members) != semantic(&self.members) || flight != self.in_flight;
        self.members = members;
        self.in_flight = flight;
        self.snapshot_digest = Some(proof.digest()?);
        Ok(changed)
    }
    pub(crate) fn check_current(
        &self,
        r: &Registration,
        proof: &Snapshot,
        proofs: &BTreeMap<String, Snapshot>,
        at: i64,
    ) -> Result<bool> {
        let mut next = self.clone();
        next.observe(r, proof, proofs, at)
    }
    pub(crate) fn apply_owner(
        &mut self,
        r: &Registration,
        intent: Intent,
        proof: Option<&Snapshot>,
        proofs: &BTreeMap<String, Snapshot>,
        family_head: Option<&str>,
        at: i64,
    ) -> Result<bool> {
        intent.verify_owner(r)?;
        if let Some(old) = self.events.iter().find_map(|e| match e {
            Event::Owner { intent: old, .. }
                if old.payload.operation_key == intent.payload.operation_key =>
            {
                Some(old)
            }
            _ => None,
        }) {
            if old != &intent {
                return Err(refused());
            }
            return Ok(false);
        }
        intent.validate_at(r, at)?;
        if (intent.payload.action == IntentAction::Observe) != family_head.is_none()
            || family_head.is_some_and(|h| !crate::grant_reference::valid_reference(h))
        {
            return Err(refused());
        }
        self.clock(r, at)?;
        if intent.payload.expected_head != self.head
            || proof.map(Snapshot::digest).transpose()? != intent.payload.proof_digest
            || proof.is_some_and(|p| p.captured_at > intent.payload.issued_at)
        {
            return Err(refused());
        }
        let mut next = self.clone();
        let changed = if let Some(p) = proof {
            next.observe(r, p, proofs, at)?
        } else {
            false
        };
        match intent.payload.action {
            IntentAction::Quiesce => {
                if next.phase != Phase::Forward {
                    return Err(refused());
                }
                next.phase = Phase::Quiescing;
            }
            IntentAction::Observe => {
                if !changed {
                    return Err(refused());
                }
            }
            IntentAction::PrepareCompensation => {
                if next.phase != Phase::Quiescing || next.in_flight.is_some() {
                    return Err(refused());
                }
                let p = proof.ok_or_else(refused)?;
                for node in &r.composition.as_ref().ok_or_else(refused)?.nodes {
                    let m = next.members.get(&node.child_id).ok_or_else(refused)?;
                    if m.forward == F::Unknown || m.inverse != I::Absent {
                        return Err(refused());
                    }
                    if m.forward == F::Committed {
                        let t = node.compound()?.ok_or_else(refused)?;
                        let q = p.members[&node.child_id]
                            .compound
                            .as_ref()
                            .ok_or_else(refused)?
                            .evidence
                            .qualifications
                            .last()
                            .ok_or_else(refused)?;
                        let v = crate::compensation::verify(&t.contract, &t.forward, &q.proof, at)?;
                        let mut expected = q.verification.clone();
                        expected.validated_at = at;
                        if v != expected || Some(q.digest()?) != m.qualification {
                            return Err(refused());
                        }
                    }
                }
                next.phase = Phase::Compensating;
            }
        }
        next.append(
            r,
            Event::Owner {
                at,
                intent,
                family_head: family_head.map(str::to_owned),
            },
        )?;
        next.reserve(r)?;
        *self = next;
        Ok(true)
    }
    pub(crate) fn claim(
        &mut self,
        r: &Registration,
        child: &str,
        attempt: &str,
        binding: Binding,
        proofs: &BTreeMap<String, Snapshot>,
        at: i64,
    ) -> Result<()> {
        let p = r.composition.as_ref().ok_or_else(refused)?;
        self.inverse_ready(p, child)?;
        self.clock(r, at)?;
        if self.in_flight.is_some() || attempt.is_empty() || attempt.len() > 256 {
            return Err(refused());
        }
        let n = p.node(child)?;
        let t = n.compound()?.ok_or_else(refused)?;
        binding.verify(&t.inverse.grants.keys)?;
        let b = &binding.payload;
        let snapshot = self.snapshot(proofs)?.ok_or_else(refused)?;
        let q = snapshot
            .members
            .get(child)
            .ok_or_else(refused)?
            .compound
            .as_ref()
            .ok_or_else(refused)?
            .evidence
            .qualifications
            .last()
            .ok_or_else(refused)?;
        let v = crate::compensation::verify(&t.contract, &t.forward, &q.proof, at)?;
        let outcome = digest(
            "compensation-outcome-trust",
            &json!({"source_id":t.inverse.source_id,"keys":t.inverse.outcome_keys.iter().map(|(id,k)|(id.clone(),hex::encode(k.as_bytes()))).collect::<BTreeMap<_,_>>()}),
        )?;
        if b.contract_digest != t.contract.digest()?
            || b.topology_digest != t.topology.digest()?
            || b.outcome_trust_digest != outcome
            || b.qualification_digest != q.digest()?
            || b.forward != v.forward
            || b.inverse_operation_key != t.contract.inverse_operation_key
            || b.parameters_digest != v.parameters_digest
            || b.compensation_units != t.contract.compensation_units
            || at < b.valid_from
            || at >= b.expires_at
            || b.expires_at > v.valid_until
        {
            return Err(refused());
        }
        let mut next = self.clone();
        let m = next.members.get_mut(child).ok_or_else(refused)?;
        if m.inverse_grant
            .as_ref()
            .is_some_and(|g| g != &b.grant_digest)
            || m.inverse_attempt.is_some()
        {
            return Err(refused());
        }
        m.inverse = I::Unknown;
        m.inverse_grant = Some(b.grant_digest.clone());
        m.inverse_attempt = Some(attempt.into());
        next.in_flight = Some(Flight {
            child_id: child.into(),
            grant_digest: b.grant_digest.clone(),
            attempt_id: attempt.into(),
        });
        next.append(
            r,
            Event::NativeClaim {
                at,
                child_id: child.into(),
                attempt_id: attempt.into(),
                binding: Box::new(binding),
            },
        )?;
        next.reserve(r)?;
        *self = next;
        Ok(())
    }
}
