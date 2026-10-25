//! Controller-side native operating gate. Pending and send checks retain their
//! original policy/SQL evidence in the same CAS as mechanical authorization.
use crate::{
    clock::Clock,
    current_reservation::Witness,
    current_reservation_client::Querier,
    error::{Error, Result},
    kube_drain_journal::{Authority, State},
    kube_drain_proof::Signed as Mechanical,
    managed_drain_evidence::{Control, ControlKind, ControlProof, Header, Signed},
    managed_drain_journal::{Change, QueryKind},
    managed_drain_store::{Material, Prepared, ReservedQuery, Store},
};
use ed25519_dalek::SigningKey;
use std::sync::Arc;
fn refuse() -> Error {
    Error::Refused("current managed operating authority refused".into())
}
pub struct Guard {
    pub store: Store,
    sql: Arc<dyn Querier>,
    clock: Arc<dyn Clock>,
}
impl Guard {
    pub fn new(store: Store, sql: Arc<dyn Querier>, clock: Arc<dyn Clock>) -> Result<Self> {
        Ok(Self { store, sql, clock })
    }
    pub async fn reserve(&self, kind: QueryKind) -> Result<ReservedQuery> {
        self.store.reserve_query(kind, self.clock.now_ms()).await
    }
    pub async fn current_sql(&self, q: &ReservedQuery) -> Result<Witness> {
        self.sql.query(&self.store.context, q).await
    }
    pub async fn no_action(&self, q: &ReservedQuery) -> Result<()> {
        self.store
            .unavailable(q, self.clock.now_ms(), "refused")
            .await
    }
    #[allow(clippy::too_many_arguments)]
    fn proof(
        &self,
        kind: ControlKind,
        origin: &crate::managed_drain_journal::Origin,
        operating_head_digest: String,
        mechanical: &Mechanical<State>,
        slot: Option<String>,
        sql: Option<Witness>,
        authority: Option<Authority>,
        at: i64,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<ControlProof> {
        let e = &self.store.context.enrollment;
        let sequence = if matches!(kind, ControlKind::Pending | ControlKind::Send) {
            mechanical.body.steps.len() as u64
        } else {
            0
        };
        Signed::sign(
            "controller_cas",
            Control {
                kind,
                origin_digest: origin.digest()?,
                enrollment_digest: e.digest()?,
                policy_digest: e.policy.digest()?,
                operating_head_digest,
                query_slot_digest: slot,
                sequence,
                checked_at: at,
                mechanical_digest: mechanical.digest()?,
                mechanical_header: Header::state(mechanical),
                sql,
                native_authority: authority,
            },
            &self.store.context.physical.controller,
            key_id,
            key,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_control(
        &self,
        q: &ReservedQuery,
        mechanical: &Mechanical<State>,
        sql: Witness,
        kind: ControlKind,
        at: i64,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<Prepared> {
        let s = self.store.tick(at).await?.ok_or_else(refuse)?;
        if s.origin != q.origin || s.state().pending.as_ref() != Some(&q.slot) {
            return Err(refuse());
        }
        let e = &self.store.context.enrollment;
        if crate::managed_drain_journal::add(self.clock.now_ms(), e.clock_uncertainty_ms)?
            >= s.state().deadline
        {
            return Err(refuse());
        }
        if kind == ControlKind::Accepted
            && (!mechanical.body.steps.is_empty() || mechanical.body.accepted.accepted_at != at)
            || kind == ControlKind::Pending
                && mechanical
                    .body
                    .steps
                    .last()
                    .is_none_or(|step| step.pending.authorized_at != at || step.response.is_some())
        {
            return Err(refuse());
        }
        let p = self.proof(
            kind.clone(),
            &s.origin,
            s.head().digest()?,
            mechanical,
            Some(q.slot.reservation_digest.clone()),
            Some(sql),
            None,
            at,
            key_id,
            key,
        )?;
        let proof_digest = p.digest()?;
        let change = match kind {
            ControlKind::Accepted => Change::ControllerAccepted { proof_digest },
            ControlKind::Pending => Change::ControllerPending {
                sequence: mechanical.body.steps.len() as u64,
                proof_digest,
            },
            _ => return Err(refuse()),
        };
        self.store
            .prepare(&s, at, change, Some(Material::Controller(Box::new(p))))
    }
    pub async fn prepare_send(
        &self,
        mechanical: &Mechanical<State>,
        authority: Authority,
        at: i64,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<Prepared> {
        let s = self.store.tick(at).await?.ok_or_else(refuse)?;
        let e = &self.store.context.enrollment;
        if crate::managed_drain_journal::add(self.clock.now_ms(), e.clock_uncertainty_ms)?
            >= s.state().deadline
            || mechanical
                .body
                .steps
                .last()
                .is_none_or(|step| step.response.is_some())
        {
            return Err(refuse());
        }
        let previous = s.state().pending_proof.as_ref().ok_or_else(refuse)?;
        let Some(Material::Controller(p)) = s.materials.get(previous) else {
            return Err(refuse());
        };
        if p.body.mechanical_digest != mechanical.digest()? {
            return Err(refuse());
        }
        let proof = self.proof(
            ControlKind::Send,
            &s.origin,
            s.head().digest()?,
            mechanical,
            p.body.query_slot_digest.clone(),
            p.body.sql.clone(),
            Some(authority),
            at,
            key_id,
            key,
        )?;
        self.store.prepare(
            &s,
            at,
            Change::SendChecked {
                sequence: mechanical.body.steps.len() as u64,
                proof_digest: proof.digest()?,
            },
            Some(Material::Controller(Box::new(proof))),
        )
    }
    pub async fn before_io(&self, pending: &Mechanical<State>, send_checked_at: i64) -> Result<()> {
        let e = &self.store.context.enrollment;
        let s = self.store.load().await?.ok_or_else(refuse)?;
        let now = self.clock.now_ms();
        let authorized_at = pending
            .body
            .steps
            .last()
            .ok_or_else(refuse)?
            .pending
            .authorized_at;
        if now < authorized_at
            || now - authorized_at > e.maximum_authorization_to_send_ms as i64
            || now < send_checked_at
            || now - send_checked_at > e.maximum_authorization_to_send_ms as i64
            || crate::managed_drain_journal::add(now, e.clock_uncertainty_ms)? >= s.state().deadline
            || s.state().stop_required
            || s.state().send_checks != pending.body.steps.len() as u64
        {
            return Err(refuse());
        }
        let reference = s.state().send_proof.as_ref().ok_or_else(refuse)?;
        let Some(Material::Controller(proof)) = s.materials.get(reference) else {
            return Err(refuse());
        };
        if proof.body.mechanical_digest != pending.digest()?
            || proof.body.checked_at != send_checked_at
        {
            return Err(refuse());
        }
        let (_, sql_grant) = self.store.context.validate_origin(&s.origin)?;
        let sql_digest = self
            .store
            .context
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&e.current_sql.forward_child_id)?
            .forward()?
            .lineage
            .grants
            .verify_retained(s.origin.forward_signed_grant.as_bytes())?
            .digest;
        proof
            .body
            .sql
            .as_ref()
            .ok_or_else(refuse)?
            .validate_current(
                e,
                &s.origin,
                proof.body.query_slot_digest.as_deref().ok_or_else(refuse)?,
                now,
                &sql_grant,
                &sql_digest,
            )?;
        // Crypto/replay work above can take time. Sample the protected clock again
        // at the return-to-send boundary rather than reusing a pre-verification time.
        let final_at = self.clock.now_ms();
        let witness = proof.body.sql.as_ref().ok_or_else(refuse)?;
        if final_at < now
            || final_at - authorized_at > e.maximum_authorization_to_send_ms as i64
            || final_at - send_checked_at > e.maximum_authorization_to_send_ms as i64
            || crate::managed_drain_journal::add(final_at, e.clock_uncertainty_ms)?
                >= s.state().deadline
            || final_at >= pending.body.accepted.deferred_until
            || final_at >= self.store.context.selection.registration.expires_at
            || final_at >= witness.body.expires_at
            || final_at >= witness.body.storage_head.body.expires_at
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub async fn may_advance(&self) -> Result<bool> {
        let now = self.clock.now_ms();
        let Some(s) = self.store.tick(now).await? else {
            return Ok(false);
        };
        Ok(s.state().accepted
            && !s.state().stop_required
            && s.state().unresolved()
            && s.state().pending.is_none()
            && now >= s.state().next_query_at)
    }
    pub async fn tick(&self) -> Result<()> {
        self.store.expire_query(self.clock.now_ms()).await?;
        Ok(())
    }
}

impl Guard {
    pub async fn validate_state(&self, state: &Mechanical<State>) -> Result<()> {
        let s = self.store.load().await?.ok_or_else(refuse)?;
        if !s.state().accepted
            || s.origin.original.grant_digest != state.body.accepted.grant_digest
            || s.origin.original.attempt_id != state.body.accepted.attempt_id
            || s.state().pending_steps != state.body.steps.len() as u64
            || s.state().closed != state.body.closed.is_some()
        {
            return Err(refuse());
        }
        Ok(())
    }
}

impl Guard {
    pub async fn prepare_closed(
        &self,
        state: &Mechanical<State>,
        at: i64,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<Prepared> {
        let s = self.store.tick(at).await?.ok_or_else(refuse)?;
        if !state.body.steps.is_empty()
            || state.body.closed.as_ref().is_none_or(|c| c.closed_at != at)
            || state.body.accepted.grant_digest != s.origin.original.grant_digest
            || state.body.accepted.attempt_id != s.origin.original.attempt_id
        {
            return Err(refuse());
        }
        let p = self.proof(
            ControlKind::ClosedNoEffect,
            &s.origin,
            s.head().digest()?,
            state,
            None,
            None,
            None,
            at,
            key_id,
            key,
        )?;
        self.store.prepare(
            &s,
            at,
            Change::ClosedNoEffect {
                proof_digest: p.digest()?,
            },
            Some(Material::Controller(Box::new(p))),
        )
    }
    pub async fn prepare_absent(
        &self,
        gate: &crate::kube_drain_proof::Signed<crate::kube_drain_proof::NoDispatch>,
        at: i64,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<Prepared> {
        let s = self.store.tick(at).await?.ok_or_else(refuse)?;
        let e = &self.store.context.enrollment;
        if gate.body.grant_digest != s.origin.original.grant_digest
            || gate.body.attempt_id != s.origin.original.attempt_id
            || gate.body.closed_at != at
        {
            return Err(refuse());
        }
        let h = Header {
            profile: gate.profile.clone(),
            kind: gate.kind.clone(),
            signer_id: gate.signer_id.clone(),
            key_id: gate.key_id.clone(),
            signature: gate.signature.clone(),
        };
        let p = Signed::sign(
            "controller_cas",
            Control {
                kind: ControlKind::ClosedAbsence,
                origin_digest: s.origin.digest()?,
                enrollment_digest: e.digest()?,
                policy_digest: e.policy.digest()?,
                operating_head_digest: s.head().digest()?,
                query_slot_digest: None,
                sequence: 0,
                checked_at: at,
                mechanical_digest: gate.digest()?,
                mechanical_header: h,
                sql: None,
                native_authority: None,
            },
            &self.store.context.physical.controller,
            key_id,
            key,
        )?;
        self.store.prepare(
            &s,
            at,
            Change::ClosedAbsence {
                proof_digest: p.digest()?,
            },
            Some(Material::Controller(Box::new(p))),
        )
    }
    pub async fn acceptance(
        &self,
        current: &Mechanical<State>,
    ) -> Result<crate::managed_drain_evidence::Acceptance> {
        let s = self.store.load().await?.ok_or_else(refuse)?;
        let key = s.state().accepted_proof.as_ref().ok_or_else(refuse)?;
        let Some(Material::Controller(proof)) = s.materials.get(key) else {
            return Err(refuse());
        };
        if current.body.accepted.grant_digest != s.origin.original.grant_digest
            || current.body.accepted.attempt_id != s.origin.original.attempt_id
        {
            return Err(refuse());
        }
        let h = &proof.body.mechanical_header;
        let controller = Mechanical {
            profile: h.profile.clone(),
            kind: h.kind.clone(),
            signer_id: h.signer_id.clone(),
            key_id: h.key_id.clone(),
            signature: h.signature.clone(),
            body: State {
                accepted: current.body.accepted.clone(),
                steps: vec![],
                closed: None,
            },
        };
        controller.verify("controller_state", &self.store.context.physical.controller)?;
        if controller.digest()? != proof.body.mechanical_digest {
            return Err(refuse());
        }
        let until=s.events.iter().position(|event|matches!(&event.change,Change::ControllerAccepted{proof_digest} if proof_digest==key)).ok_or_else(refuse)?;
        Ok(crate::managed_drain_evidence::Acceptance {
            profile: crate::managed_drain::PROFILE.into(),
            enrollment_digest: self.store.context.enrollment.digest()?,
            origin: s.origin,
            events: s.events[..=until].to_vec(),
            controller,
            proof: (**proof).clone(),
        })
    }
}
