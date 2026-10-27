//! Protected collector and global transitions; no target client or parent grant.
use crate::{
    contracts::canonical,
    control_history::HistoryObserver,
    error::{Error, Result},
    family::{Family, Registration},
    family_saga::{
        Collected, ForwardState, Intent, IntentAction, MAX_HISTORY_BYTES, MemberSnapshot, PROFILE,
        PhaseState, Snapshot,
    },
    family_saga_runtime::{child_ledger, proof_key, retained, state_key},
    ledger::{EtcdLedger, put, record, value_eq, version_zero},
};
use serde_json::json;
use std::collections::BTreeMap;

fn refused() -> Error {
    Error::Refused("native family saga capture or transition refused".into())
}
pub struct MemberObservers {
    pub forward: HistoryObserver,
    pub compound: Option<HistoryObserver>,
}
pub struct Saga {
    family: Family,
    ledger: EtcdLedger,
    members: BTreeMap<String, (EtcdLedger, Option<EtcdLedger>)>,
    observers: BTreeMap<String, MemberObservers>,
    collector: HistoryObserver,
    physical_observers: BTreeMap<String, crate::kube_drain_observer::Observer>,
}
impl Saga {
    pub fn new(
        family: Family,
        observers: BTreeMap<String, MemberObservers>,
        collector: HistoryObserver,
    ) -> Result<Self> {
        let r = family.registration();
        let plan = r.composition.as_ref().ok_or_else(refused)?;
        let key = plan
            .observer
            .keys
            .get(&collector.key_id)
            .ok_or_else(refused)?;
        if collector.id != plan.observer.id
            || crate::config::key(key)? != *collector.key.verifying_key().as_bytes()
            || observers.len() != plan.nodes.len()
        {
            return Err(refused());
        }
        let ledger = family.manager_ledger();
        let mut members = BTreeMap::new();
        for n in &plan.nodes {
            let o = observers.get(&n.child_id).ok_or_else(refused)?;
            let t = n.forward()?;
            if o.forward.id != t.observer_id
                || t.observer_keys.get(&o.forward.key_id) != Some(&o.forward.key.verifying_key())
            {
                return Err(refused());
            }
            let f = child_ledger(&ledger, r, &n.child_id, false)?;
            let inverse = match (n.compound()?, o.compound.as_ref()) {
                (Some(t), Some(o))
                    if o.id == t.observer_id
                        && t.observer_keys.get(&o.key_id) == Some(&o.key.verifying_key()) =>
                {
                    Some(child_ledger(&ledger, r, &n.child_id, true)?)
                }
                (None, None) => None,
                _ => return Err(refused()),
            };
            members.insert(n.child_id.clone(), (f, inverse));
        }
        Ok(Self {
            family,
            ledger,
            members,
            observers,
            collector,
            physical_observers: BTreeMap::new(),
        })
    }
    pub fn with_physical_observer(
        mut self,
        child: String,
        observer: crate::kube_drain_observer::Observer,
    ) -> Result<Self> {
        let plan = self
            .registration()
            .composition
            .as_ref()
            .ok_or_else(refused)?;
        if plan.node(&child)?.physical.as_ref() != Some(observer.trust())
            || self.physical_observers.contains_key(&child)
        {
            return Err(refused());
        }
        self.physical_observers.insert(child, observer);
        Ok(self)
    }
    pub fn registration(&self) -> &Registration {
        self.family.registration()
    }
    pub async fn status(&self) -> Result<PhaseState> {
        Ok(retained(&self.ledger, self.registration()).await?.0)
    }
    /// Query only the exact original owner operation, including after expiry or
    /// root stop. Absence is not permission to choose another operation key.
    pub async fn lookup(&self, intent: &Intent) -> Result<Option<PhaseState>> {
        intent.verify_owner(self.registration())?;
        let state = self.status().await?;
        for event in &state.events {
            if let crate::family_saga::PhaseEvent::Owner { intent: old, .. } = event
                && old.payload.operation_key == intent.payload.operation_key
            {
                if old != intent {
                    return Err(refused());
                }
                return Ok(Some(state));
            }
        }
        Ok(None)
    }
    pub async fn export(
        &self,
        family_observer: &HistoryObserver,
    ) -> Result<crate::family_saga_audit::Bundle> {
        let r = self.registration();
        let current = self.collect().await?;
        let (phase, referenced, mut compare) = retained(&self.ledger, r).await?;
        let epoch = crate::family_saga_epoch::capture(&self.ledger, r).await?;
        if current.snapshot.phase_head != phase.head || current.snapshot.epoch != epoch.token {
            return Err(Error::Refused(
                "family export phase/epoch changed after capture".into(),
            ));
        }
        let family = self
            .family
            .export(family_observer, &crate::family_saga_audit::family_trust(r)?)
            .await?;
        let mut proofs = BTreeMap::new();
        for d in referenced.keys() {
            let raw = self
                .ledger
                .read_key(&proof_key(&self.ledger, d))
                .await?
                .ok_or_else(refused)?;
            let c = Collected::decode(&raw)?;
            c.verify(r)?;
            if c.snapshot.digest()? != *d {
                return Err(refused());
            }
            proofs.insert(d.clone(), c);
        }
        compare.push(epoch.compare);
        if !self.ledger.txn(compare, vec![], vec![]).await?.succeeded {
            return Err(Error::Refused(
                "family export final native comparison raced".into(),
            ));
        }
        crate::family_saga_audit::Bundle::sign(
            crate::family_saga_audit::Evidence {
                family,
                phase,
                proofs,
                current,
            },
            r,
            &self.collector,
            self.ledger.authority_clock.now_ms(),
        )
    }
    pub async fn collect(&self) -> Result<Collected> {
        let started = std::time::Instant::now();
        let r = self.registration();
        let epoch = crate::family_saga_epoch::capture(&self.ledger, r).await?;
        let (phase, proofs, mut compare) = retained(&self.ledger, r).await?;
        compare.extend(crate::family_saga_runtime::enrollment(&self.ledger, r).await?);
        let mut members = BTreeMap::new();
        for n in &r.composition.as_ref().ok_or_else(refused)?.nodes {
            let (f, inverse) = self.members.get(&n.child_id).ok_or_else(refused)?;
            let rr = &r.child(&n.child_id)?.reservation;
            let trust = n.forward()?;
            let observers = &self.observers[&n.child_id];
            let gate = f
                .reservation_gate_for(&rr.scope.conflict_domain, false)
                .await
                .map_err(|e| {
                    Error::Refused(format!(
                        "family capture {} reservation gate: {e}",
                        n.child_id
                    ))
                })?
                .ok_or_else(refused)?;
            let a = gate
                .state
                .allocations
                .get(&n.operation_key)
                .ok_or_else(refused)?;
            let (events, history) = f.read_reservation_history(rr, &gate.state).await?;
            let mut local = gate.compare;
            local.extend(history);
            let issue = format!("{}/issuance/{}", f.namespace(), n.operation_key);
            let mut authorizations = BTreeMap::new();
            let mut executions = BTreeMap::new();
            let auth = if f.read_key(&issue).await?.is_some() {
                Some(f.export_authorization(&n.operation_key).await?)
            } else {
                local.push(version_zero(&issue));
                None
            };
            if let Some(auth) = auth {
                let grant = trust
                    .lineage
                    .grants
                    .verify_retained(auth.issuance.signed_grant.as_bytes())?;
                if let Some(attempt) = &a.attempt_id {
                    let candidate = crate::recovery::Candidate {
                        grant: grant.grant,
                        attempt_id: attempt.clone(),
                    };
                    let b = f
                        .export_reserved_lineage(
                            &candidate,
                            &n.operation_key,
                            &observers.forward,
                            &trust,
                        )
                        .await
                        .map_err(|e| {
                            Error::Refused(format!(
                                "family capture {} reserved lineage: {e}",
                                n.child_id
                            ))
                        })?;
                    if json!(b.events) != json!(events) {
                        return Err(refused());
                    }
                    executions.insert(n.operation_key.clone(), b);
                } else {
                    crate::compensation_lineage::pin_unclaimed(
                        f,
                        &grant.grant,
                        &grant.digest,
                        &mut local,
                    )?;
                }
                authorizations.insert(n.operation_key.clone(), auth);
            } else if a.attempt_id.is_some() {
                return Err(refused());
            }
            let mut qualification_absent = None;
            let qualified = if let Some(c) = &r.child(&n.child_id)?.inverse {
                let q = crate::compensation::Qualifier::new(f.clone(), c.clone(), trust.clone())?;
                let (records, qc) = q.retained_history().await?;
                local.extend(qc);
                if !records.is_empty() {
                    if a.attempt_id.is_none() {
                        return Err(refused());
                    }
                    true
                } else {
                    if a.attempt_id.is_some() {
                        qualification_absent = Some(true);
                    }
                    false
                }
            } else {
                false
            };
            let compound = if a.attempt_id.is_some() && qualified {
                match (inverse, n.compound()?, observers.compound.as_ref()) {
                    (Some(i), Some(t), Some(observer)) => Some(
                        i.export_compensation_lineage(observer, &observers.forward, &t)
                            .await?,
                    ),
                    (None, None, None) => None,
                    _ => return Err(refused()),
                }
            } else {
                if let Some(c) = &r.child(&n.child_id)?.inverse {
                    // Qualify the complete original absence, not merely a
                    // missing target receipt or a missing member in a map.
                    local.extend([
                        version_zero(&format!(
                            "{}/issuance/{}",
                            f.namespace(),
                            c.inverse_operation_key
                        )),
                        version_zero(&format!(
                            "{}/compensation-spends/{}",
                            f.namespace(),
                            c.forward_operation_key
                        )),
                        version_zero(&format!(
                            "{}/compensation-seals/{}",
                            f.namespace(),
                            c.forward_operation_key
                        )),
                    ]);
                }
                None
            };
            if !f.txn(local, vec![], vec![]).await?.succeeded {
                return Err(refused());
            }
            let mut member = MemberSnapshot {
                captured_at: self.ledger.authority_clock.now_ms(),
                events,
                authorizations,
                executions,
                unclaimed: a.attempt_id.is_none(),
                inverse_absent: compound.is_none(),
                compound,
                qualification_absent,
                composition_bindings: None,
                physical: None,
            };
            let mut lanes = vec![("forward".into(), f)];
            if let Some(i) = inverse {
                lanes.push(("inverse".into(), i));
            }
            member.composition_bindings =
                Some(crate::family_saga_bindings::collect(&lanes, r, n, &member).await?);
            if n.physical.is_some() {
                let observer = self
                    .physical_observers
                    .get(&n.child_id)
                    .ok_or_else(refused)?;
                member.physical = Some(
                    observer
                        .collect(
                            f,
                            &n.operation_key,
                            &epoch.token,
                            &trust.lineage.grants,
                            phase
                                .snapshot_digest
                                .as_ref()
                                .and_then(|d| proofs.get(d))
                                .and_then(|p| p.members.get(&n.child_id))
                                .and_then(|m| m.physical.as_ref()),
                        )
                        .await
                        .map_err(|e| {
                            Error::Refused(format!(
                                "family capture {} physical observation: {e}",
                                n.child_id
                            ))
                        })?,
                );
            }
            member.captured_at = self.ledger.authority_clock.now_ms();
            members.insert(n.child_id.clone(), member);
        }
        let snapshot = Snapshot {
            profile: PROFILE.into(),
            registration_digest: r.digest()?,
            phase_head: phase.head.clone(),
            epoch: epoch.token,
            captured_at: self.ledger.authority_clock.now_ms(),
            members,
        };
        snapshot.verify(r).map_err(|e| {
            Error::Refused(format!(
                "family capture snapshot verification after {}ms: {e}",
                started.elapsed().as_millis()
            ))
        })?;
        crate::family_saga_bindings::verify_history(
            r,
            &self.family.status().await?,
            &phase,
            &proofs,
            &snapshot,
        )?;
        compare.push(epoch.compare);
        if !self.ledger.txn(compare, vec![], vec![]).await?.succeeded {
            return Err(Error::Refused(format!(
                "family capture native epoch/head comparison raced after {}ms",
                started.elapsed().as_millis()
            )));
        }
        Collected::sign(snapshot, r, &self.collector)
    }
    pub async fn apply(&self, intent: Intent, capture: Option<Collected>) -> Result<PhaseState> {
        let r = self.registration();
        intent.verify_owner(r)?;
        if let Some(c) = &capture {
            c.verify(r)?;
            if Some(c.snapshot.digest()?) != intent.payload.proof_digest {
                return Err(refused());
            }
        }
        let (mut state, mut proofs, mut compare) = retained(&self.ledger, r).await?;
        if let Some(original) = state.events.iter().find_map(|e| match e {
            crate::family_saga::PhaseEvent::Owner { intent: old, .. }
                if old.payload.operation_key == intent.payload.operation_key =>
            {
                Some(old)
            }
            _ => None,
        }) {
            if original != &intent {
                return Err(refused());
            }
            return Ok(state);
        }
        let family = self.family.status().await?;
        let now = self.ledger.authority_clock.now_ms();
        if intent.payload.action != IntentAction::Observe {
            family.live(r, "root", now)?;
            compare.push(value_eq(
                &format!("{}/family/state", self.ledger.namespace()),
                &record(&family)?,
            ));
        }
        let captured = if intent.payload.proof_digest.is_some() {
            let c = capture.as_ref().ok_or_else(refused)?;
            let epoch = crate::family_saga_epoch::capture(&self.ledger, r).await?;
            if epoch.token != c.snapshot.epoch {
                return Err(refused());
            }
            compare.push(epoch.compare);
            crate::family_saga_bindings::verify_history(r, &family, &state, &proofs, &c.snapshot)?;
            Some(&c.snapshot)
        } else {
            if capture.is_some() {
                return Err(refused());
            }
            None
        };
        state.apply_owner(
            r,
            intent.clone(),
            captured,
            &proofs,
            (intent.payload.action != IntentAction::Observe).then_some(family.head.as_str()),
            now,
        )?;
        let mut writes = Vec::new();
        if intent.payload.action == IntentAction::PrepareCompensation {
            for n in &r.composition.as_ref().ok_or_else(refused)?.nodes {
                if state.members[&n.child_id].forward != ForwardState::Committed {
                    continue;
                }
                let (f, _) = &self.members[&n.child_id];
                let t = n.compound()?.ok_or_else(refused)?;
                let qualifier = crate::compensation::Qualifier::new(
                    f.clone(),
                    t.contract.clone(),
                    t.forward.clone(),
                )?;
                let (q, _) = qualifier.live_qualification().await?;
                if Some(q.digest()?) != state.members[&n.child_id].qualification {
                    return Err(refused());
                }
                // The sealed complete capture's unchanged global epoch covers
                // these native proof reads, avoiding >128 per-member compares.
                let key = crate::compensation_execution::mode_key(f, &t.forward.registration)?;
                let mode = record(
                    &json!({"profile":crate::compensation_execution::PROFILE,"registration_digest":t.forward.registration.digest()?,"topology_digest":t.topology.digest()?,"mode":"compensating"}),
                )?;
                match f.read_key(&key).await? {
                    Some(raw) if raw == mode.as_bytes() => compare.push(value_eq(&key, &mode)),
                    None => {
                        compare.push(version_zero(&key));
                        writes.push(put(&key, &mode));
                    }
                    _ => return Err(refused()),
                }
            }
        }
        if let Some(c) = capture {
            let d = c.snapshot.digest()?;
            let key = proof_key(&self.ledger, &d);
            if let Some(raw) = self.ledger.read_key(&key).await? {
                let old = Collected::decode(&raw)?;
                old.verify(r)?;
                if json!(old.snapshot) != json!(c.snapshot) {
                    return Err(refused());
                }
                compare.push(value_eq(
                    &key,
                    std::str::from_utf8(&raw).map_err(|_| refused())?,
                ));
            } else {
                compare.push(version_zero(&key));
                writes.push(put(&key, &record(&c)?));
            }
            proofs.insert(d, c.snapshot);
        }
        let total = proofs
            .values()
            .try_fold(0usize, |sum, p| -> Result<usize> {
                sum.checked_add(canonical(&json!(p))?.len() + 4096)
                    .ok_or_else(refused)
            })?;
        // Keep room for the remaining original forward observations, one
        // preparation capture and each possible original inverse settlement.
        // Optional qualification refreshes/polling must not consume the proof
        // storage needed to close already reserved native effects.
        let future = state.proof_reserve(r)?;
        if total
            .checked_add(future)
            .is_none_or(|n| n > MAX_HISTORY_BYTES)
        {
            return Err(refused());
        }
        state.verify(r, &proofs)?;
        crate::family_saga_runtime::reserve_wire(r, &family, &state)?;
        intent.validate_at(r, self.ledger.authority_clock.now_ms())?;
        writes.push(put(&state_key(&self.ledger), &record(&state)?));
        if !self.ledger.txn(compare, writes, vec![]).await?.succeeded {
            return Err(refused());
        }
        Ok(state)
    }
}
