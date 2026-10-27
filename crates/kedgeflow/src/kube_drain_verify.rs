//! Physical member replay supplements native acceptance lineage; it never
//! converts an acceptance receipt into observed completion by itself.
use crate::{
    contracts::{Grant, canonical, digest, strict_value},
    error::{Error, Result},
    family::Registration,
    family_saga::{ForwardState as F, MemberSnapshot, MemberSummary, Node},
    governance::{
        Acknowledgement, EnforcementScope, Installation, Revocation, RevocationTarget,
        trust_digest, validate_ack,
    },
    kube_drain_journal::{Authority, State},
    kube_drain_proof::Capture,
};
use serde_json::json;
fn refuse() -> Error {
    Error::Refused("original physical member, authority prefix or completion refused".into())
}
fn control(
    a: &Authority,
    g: &Grant,
    p: &crate::kube_drain_proof::Trust,
    h: &crate::control_history::ControlHistoryBundle,
    at: i64,
    deadline: i64,
) -> Result<()> {
    let s = &a.control;
    let t = p.control()?;
    let targets = vec![
        RevocationTarget::Domain,
        RevocationTarget::Root {
            id: g.root_id.clone(),
        },
        RevocationTarget::Grant { id: g.gid.clone() },
    ];
    if a.checked_at != s.checked_at
        || s.checked_at < g.valid_from
        || s.checked_at > at
        || s.checked_at >= deadline
        || s.checked_at > h.checkpoint.payload.captured_at
        || s.absent_revocations != targets
    {
        return Err(Error::Refused(
            "physical control clock or revocation targets refused".into(),
        ));
    }
    let head = h
        .events
        .iter()
        .find(|e| e.sequence == s.history_sequence)
        .ok_or_else(refuse)?;
    if head.digest()? != s.history_digest || head.accepted_at > s.checked_at {
        return Err(Error::Refused(
            "physical control head at acceptance refused".into(),
        ));
    }
    let mut installed = None;
    let mut acknowledged = None;
    for e in h.events.iter().take(s.history_sequence as usize) {
        match e.kind.as_str() {
            "install" => {
                installed = Some((
                    e.control.payload::<Installation>("install")?,
                    e.control.digest.clone(),
                ))
            }
            "acknowledge" => {
                acknowledged = Some((
                    e.control.payload::<Acknowledgement>("acknowledge")?,
                    e.control.digest.clone(),
                ))
            }
            "revoke" => {
                let r: Revocation = e.control.payload("revoke")?;
                if targets.contains(&r.target) {
                    return Err(Error::Refused(
                        "physical historical revocation refused".into(),
                    ));
                }
            }
            _ => {}
        }
    }
    let (i, id) = installed.ok_or_else(refuse)?;
    let (ack, ad) = acknowledged.ok_or_else(refuse)?;
    let issuers: std::collections::BTreeMap<_, _> = t
        .operation
        .grants
        .keys
        .iter()
        .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
        .collect();
    if s.installation_digest != id
        || s.acknowledgement_digest != ad
        || i.registration.scope != EnforcementScope::grant(g)?
        || i.registration.policy != g.policy
        || i.registration.ownership_epoch != g.ownership_epoch
        || i.registration.trust_digest
            != trust_digest(
                &t.operation.admission,
                &t.operation.admission_keys,
                &t.operation.grants.keys,
            )?
        || i.registration.issuer_keys != issuers
    {
        return Err(Error::Refused(
            "physical installed registration or acknowledgement refused".into(),
        ));
    }
    validate_ack(&ack, &i, &id, s.checked_at)?;
    Ok(())
}
fn controller(
    n: &Node,
    m: &MemberSnapshot,
    state: &State,
    p: &crate::kube_drain_proof::Trust,
    h: &crate::control_history::ControlHistoryBundle,
) -> Result<Grant> {
    let t = n.forward()?;
    let v = t
        .lineage
        .grants
        .verify_retained(state.accepted.signed_grant.as_bytes())?;
    let g = v.grant;
    state.validate(&p.contract, &g)?;
    let native = m.executions.get(&n.operation_key).ok_or_else(refuse)?;
    let auth = m.authorizations.get(&n.operation_key).ok_or_else(refuse)?;
    if v.digest != state.accepted.grant_digest
        || auth.issuance.grant_digest != v.digest
        || native.lineage.outcomes.attempt_id != state.accepted.attempt_id
        || canonical(&strict_value(auth.issuance.signed_grant.as_bytes())?)?
            != canonical(&strict_value(state.accepted.signed_grant.as_bytes())?)?
        || canonical(&json!(native.lineage))? != canonical(&json!(h.lineage))?
    {
        return Err(Error::Refused(
            "physical original native lineage correlation refused".into(),
        ));
    }
    let descriptor = crate::schema::verify_record(
        auth.packet.descriptor.as_bytes(),
        "ctd",
        &t.lineage.admission.registry_keys,
    )?;
    if descriptor.payload["parameter_schema"] != p.schema()?
        || g.resources != [p.contract.resource()?]
    {
        return Err(Error::Refused(
            "physical protected controller schema or resource refused".into(),
        ));
    }
    let mut last = state.accepted.authority.checked_at;
    let mut sequence = 0;
    for (authority, at, deadline) in std::iter::once((
        &state.accepted.authority,
        state.accepted.accepted_at,
        g.expires_at,
    ))
    .chain(state.steps.iter().map(|s| {
        (
            &s.pending.authority,
            s.pending.authorized_at,
            state.accepted.deferred_until,
        )
    })) {
        native_authority(n, m, state, p, h, authority, at, deadline)?;
        if authority.checked_at < last || authority.control.history_sequence < sequence {
            return Err(refuse());
        }
        last = authority.checked_at;
        sequence = authority.control.history_sequence;
    }
    Ok(g)
}
#[allow(clippy::too_many_arguments)]
fn native_authority(
    n: &Node,
    m: &MemberSnapshot,
    state: &State,
    p: &crate::kube_drain_proof::Trust,
    h: &crate::control_history::ControlHistoryBundle,
    a: &Authority,
    at: i64,
    deadline: i64,
) -> Result<()> {
    let g = n
        .forward()?
        .lineage
        .grants
        .verify_retained(state.accepted.signed_grant.as_bytes())?
        .grant;
    control(a, &g, p, h, at, deadline)?;
    let native = m.executions.get(&n.operation_key).ok_or_else(refuse)?;
    let dispatch = native
        .lineage
        .outcomes
        .journal
        .iter()
        .find(|e| e["phase"] == "dispatch_authorized")
        .ok_or_else(refuse)?;
    let dispatch_digest = digest("kube-drain-native-dispatch", dispatch)?;
    let head = native
        .events
        .iter()
        .find(|e| e.digest().ok().as_ref() == Some(&a.reservation_head))
        .ok_or_else(refuse)?;
    let allocation = head
        .after
        .allocations
        .get(&n.operation_key)
        .ok_or_else(refuse)?;
    if !head.after.active
        || !native.events.iter().take(head.sequence as usize).any(|e| {
            e.data.phase == "issue"
                && e.data.operation_key.as_ref() == Some(&n.operation_key)
                && e.data.grant_digest.as_ref() == Some(&state.accepted.grant_digest)
        })
        || allocation.attempt_id.as_ref() != Some(&state.accepted.attempt_id)
        || a.native_dispatch_digest != dispatch_digest
        || a.checked_at < dispatch["event_time"].as_i64().ok_or_else(refuse)?
    {
        return Err(refuse());
    }
    Ok(())
}
pub(crate) fn member(
    _r: &Registration,
    n: &Node,
    m: &MemberSnapshot,
    s: &mut MemberSummary,
) -> Result<()> {
    let Some(t) = &n.physical else {
        if m.physical.is_some() {
            return Err(Error::Refused(
                "physical unexpected physical member refused".into(),
            ));
        }
        return Ok(());
    };
    let p = m.physical.as_ref().ok_or_else(refuse)?;
    p.verify_sources(t, &n.operation_key, m.captured_at)?;
    let managed = crate::managed_drain_capture::member(_r, n, m, p)?;
    let o = &p.observation.body;
    if let Some(gate) = &p.closed_absence {
        if matches!(s.forward, F::Committed)
            || s.forward_grant.as_ref() != Some(&gate.body.grant_digest)
            || s.forward_attempt.as_ref() != Some(&gate.body.attempt_id)
        {
            return Err(Error::Refused(
                "physical closed physical absence correlation refused".into(),
            ));
        }
        s.forward = F::NoEffect;
        s.physical_status = Some("no_physical_dispatch".into());
        s.physical_head = Some(gate.digest()?);
        return Ok(());
    }
    let Some(current) = &p.controller else {
        if s.forward == F::Committed
            || p.control_history.is_some()
            || p.retained_completion.is_some()
        {
            return Err(Error::Refused(
                "physical missing controller for committed acceptance refused".into(),
            ));
        }
        s.physical_status = Some(
            match s.forward {
                F::Unissued => "unissued",
                F::Unclaimed => "unclaimed",
                F::NoEffect => "no_physical_dispatch",
                _ => "unknown",
            }
            .into(),
        );
        return Ok(());
    };
    let native_forward = s.forward.clone();
    if !matches!(native_forward, F::Committed | F::Unknown) {
        return Err(Error::Refused(
            "physical controller/native forward status refused".into(),
        ));
    }
    let history = p.control_history.as_ref().ok_or_else(refuse)?;
    crate::control_history_verify::verify_history(history, &t.control()?, false)?;
    controller(n, m, &current.body, t, history)?;
    if let Some(prefix) = &p.managed {
        for proof in prefix
            .sources
            .controls
            .values()
            .filter(|v| v.body.kind == crate::managed_drain_evidence::ControlKind::Send)
        {
            let a = proof.body.native_authority.as_ref().ok_or_else(refuse)?;
            native_authority(
                n,
                m,
                &current.body,
                t,
                history,
                a,
                proof.body.checked_at,
                current.body.accepted.deferred_until,
            )?;
            let index = proof.body.sequence.checked_sub(1).ok_or_else(refuse)? as usize;
            let pending = current.body.steps.get(index).ok_or_else(refuse)?;
            if a.checked_at < pending.pending.authority.checked_at
                || a.control.history_sequence < pending.pending.authority.control.history_sequence
                || current.body.steps.get(index + 1).is_some_and(|next| {
                    a.control.history_sequence > next.pending.authority.control.history_sequence
                })
            {
                return Err(refuse());
            }
        }
    }
    if s.forward_grant.as_ref() != Some(&current.body.accepted.grant_digest)
        || s.forward_attempt.as_ref() != Some(&current.body.accepted.attempt_id)
        || current.body.accepted.deferred_until > _r.expires_at
    {
        return Err(Error::Refused(
            "physical original physical grant, attempt or deferred deadline refused".into(),
        ));
    }
    let status = if let Some(closed) = &current.body.closed {
        if closed.closed_at > o.observed_at {
            return Err(Error::Refused(
                "physical physical closure clock refused".into(),
            ));
        }
        "no_physical_effect"
    } else {
        current
            .body
            .physical_status(&t.contract, o.inventory.as_ref().ok_or_else(refuse)?)?
    };
    let mut completed = status == "observed_completed";
    if let Some(old) = &p.retained_completion {
        old.controller.verify("controller_state", &t.controller)?;
        old.observation
            .verify("physical_observation", &t.observer)?;
        let oldo = &old.observation.body;
        if oldo.profile != crate::kube_drain::PROFILE
            || oldo.operation_key != n.operation_key
            || oldo.contract_digest != t.contract.digest()?
            || oldo.controller_digest.as_deref() != Some(old.controller.digest()?.as_str())
            || oldo.gate_digest.is_some()
            || !crate::grant_reference::valid_reference(&oldo.native_epoch)
            || oldo.observed_at > o.observed_at
            || oldo
                .inventory
                .as_ref()
                .is_none_or(|i| i.until > oldo.observed_at)
            || old
                .controller
                .body
                .physical_status(&t.contract, oldo.inventory.as_ref().ok_or_else(refuse)?)?
                != "observed_completed"
        {
            return Err(Error::Refused(
                "physical historical physical completion refused".into(),
            ));
        }
        controller(n, m, &old.controller.body, t, history)?;
        state_successor(&old.controller.body, &current.body)?;
        completed = true;
    }
    if completed
        && managed.as_ref().is_some_and(|core| {
            core.send_checks == 0 || core.send_checks != current.body.steps.len() as u64
        })
    {
        return Err(refuse());
    }
    s.physical_status = Some(
        if completed {
            "observed_completed"
        } else {
            status
        }
        .into(),
    );
    s.physical_head = Some(current.digest()?);
    s.forward = if completed {
        F::Committed
    } else if status == "no_physical_effect" {
        F::NoEffect
    } else {
        F::Unknown
    };
    Ok(())
}
pub(crate) fn state_successor(old: &State, new: &State) -> Result<()> {
    if canonical(&json!(old.accepted))? != canonical(&json!(new.accepted))?
        || new.steps.len() < old.steps.len()
        || old
            .closed
            .as_ref()
            .is_some_and(|c| canonical(&json!(c)).ok() != canonical(&json!(new.closed)).ok())
    {
        return Err(Error::Refused(
            "physical controller journal prefix refused".into(),
        ));
    }
    for (a, b) in old.steps.iter().zip(&new.steps) {
        if canonical(&json!(a.pending))? != canonical(&json!(b.pending))?
            || a.response
                .as_ref()
                .is_some_and(|r| Some(r) != b.response.as_ref())
        {
            return Err(Error::Refused(
                "physical original pending or response prefix refused".into(),
            ));
        }
    }
    Ok(())
}
pub(crate) fn successor(old: Option<&Capture>, new: Option<&Capture>) -> Result<()> {
    match (old, new) {
        (None, None) => Ok(()),
        (Some(a), Some(b)) => {
            if a.observation.body.observed_at > b.observation.body.observed_at {
                return Err(Error::Refused(
                    "physical physical observation clock refused".into(),
                ));
            }
            match (&a.managed, &b.managed) {
                (Some(old), Some(new)) => crate::managed_drain_capture::successor(old, new)?,
                (Some(_), None) => return Err(refuse()),
                _ => (),
            }
            match (&a.controller, &b.controller) {
                (Some(a), Some(b)) => state_successor(&a.body, &b.body)?,
                (Some(_), None) => return Err(refuse()),
                _ => {}
            }
            if a.closed_absence.as_ref().is_some_and(|g| {
                b.closed_absence
                    .as_ref()
                    .is_none_or(|h| g.digest().ok() != h.digest().ok())
            }) {
                return Err(Error::Refused(
                    "physical closed physical gate changed refused".into(),
                ));
            }
            if let Some(c) = &a.retained_completion
                && b.retained_completion
                    .as_ref()
                    .is_none_or(|d| canonical(&json!(c)).ok() != canonical(&json!(d)).ok())
            {
                return Err(Error::Refused(
                    "physical historical completion disappeared refused".into(),
                ));
            }
            Ok(())
        }
        _ => Err(refuse()),
    }
}

pub(crate) fn views(
    r: &Registration,
    n: &Node,
    m: &MemberSnapshot,
    families: &std::collections::BTreeMap<String, crate::family::State>,
    phases: &std::collections::BTreeMap<String, crate::family_saga::PhaseState>,
) -> Result<()> {
    let Some(p) = &m.physical else {
        return Ok(());
    };
    let plan = r.composition.as_ref().ok_or_else(refuse)?;
    let closed = |family: &str, phase: &str, at: i64| -> Result<()> {
        let f = families.get(family).ok_or_else(refuse)?;
        let p = phases.get(phase).ok_or_else(refuse)?;
        if f.active && p.phase == crate::family_saga::Phase::Forward
            || f.events.last().is_some_and(|e| e.at > at)
            || p.events.last().is_some_and(|e| match e {
                crate::family_saga::PhaseEvent::Owner { at: t, .. }
                | crate::family_saga::PhaseEvent::NativeClaim { at: t, .. } => *t > at,
            })
        {
            return Err(Error::Refused(
                "physical closed global phase refused".into(),
            ));
        }
        Ok(())
    };
    for s in p
        .controller
        .iter()
        .map(|s| &s.body)
        .chain(p.retained_completion.iter().map(|c| &c.controller.body))
    {
        for a in std::iter::once(&s.accepted.authority)
            .chain(s.steps.iter().map(|step| &step.pending.authority))
            .chain(
                p.managed
                    .iter()
                    .flat_map(|capture| capture.send_authorities().map(|(a, _)| a)),
            )
        {
            let v = &a.family;
            let f = families.get(&v.family_head).ok_or_else(refuse)?;
            let p = phases.get(&v.phase_head).ok_or_else(refuse)?;
            if v.registration_digest != r.digest()?
                || v.child_id != n.child_id
                || v.lane != "forward"
                || v.qualification_digest.is_some()
                || f.events.last().is_some_and(|e| e.at > a.checked_at)
                || p.events.last().is_some_and(|e| match e {
                    crate::family_saga::PhaseEvent::Owner { at, .. }
                    | crate::family_saga::PhaseEvent::NativeClaim { at, .. } => *at > a.checked_at,
                })
                || p.snapshot_digest.is_none()
                || p.members.len() != plan.nodes.len()
            {
                return Err(Error::Refused(
                    "physical original family phase or dependency authority refused".into(),
                ));
            }
            let attachment = f.attachments.get(&n.child_id).ok_or_else(refuse)?;
            f.live(r, &attachment.parent, a.checked_at)?;
            p.forward_ready(plan, &n.child_id)?;
        }
        if let Some(c) = &s.closed {
            closed(&c.family_head, &c.phase_head, c.closed_at)?;
        }
    }
    if let Some(g) = &p.closed_absence {
        closed(&g.body.family_head, &g.body.phase_head, g.body.closed_at)?;
    }
    Ok(())
}
