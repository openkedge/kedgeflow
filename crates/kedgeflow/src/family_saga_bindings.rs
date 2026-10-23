//! Supplemental global comparisons retained in the original native authority
//! CAS. These are observer-attested ledger records, not consensus proofs.
use crate::{
    contracts::{canonical, strict_value},
    control_bindings::ControlState,
    error::{Error, Result},
    family_saga::PROFILE,
    ledger::{EtcdLedger, get, put, range_kv, record, version_zero},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct View {
    pub registration_digest: String,
    pub family_head: String,
    pub phase_head: String,
    pub child_id: String,
    pub lane: String,
    pub qualification_digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBinding {
    pub profile: String,
    pub control_key: String,
    pub phase: String,
    pub authority_digest: String,
    pub attempt_id: Option<String>,
    pub checked_at: i64,
    pub view: View,
}
pub(crate) fn key(control_key: &str) -> String {
    format!("{control_key}/family-saga")
}
fn refused() -> Error {
    Error::Refused("complete original global authority bindings refused".into())
}
struct Expected {
    control_key: String,
    authority_digest: String,
    attempt: Option<String>,
    earliest: i64,
    expires: i64,
    event_time: Option<i64>,
}
fn expected_lane(
    r: &crate::family::Registration,
    n: &crate::family_saga::Node,
    lane: &str,
    auth: &crate::lineage::AuthorizationBundle,
    execution: Option<&crate::lineage::LineageBundle>,
    out: &mut BTreeMap<String, Expected>,
) -> Result<()> {
    let inverse = lane == "inverse";
    let grant = if inverse {
        n.compound()?.ok_or_else(refused)?.inverse.grants
    } else {
        n.forward()?.lineage.grants
    }
    .verify_retained(auth.issuance.signed_grant.as_bytes())?;
    let op = if inverse {
        &r.child(&n.child_id)?
            .inverse
            .as_ref()
            .ok_or_else(refused)?
            .inverse_operation_key
    } else {
        &n.operation_key
    };
    if auth.issuance.issuance_key != *op {
        return Err(refused());
    }
    out.insert(
        format!("{lane}/admission"),
        Expected {
            control_key: format!("{}/admission-control/{op}", r.namespace),
            authority_digest: auth.admission.certificate_digest.clone(),
            attempt: None,
            earliest: auth.admission.admitted_at,
            expires: auth.admission.expires_at,
            event_time: None,
        },
    );
    let g = &grant.grant;
    out.insert(
        format!("{lane}/issuance"),
        Expected {
            control_key: format!("{}/issuance-control/{op}", r.namespace),
            authority_digest: grant.digest.clone(),
            attempt: None,
            earliest: g.issued_at,
            expires: g.expires_at,
            event_time: None,
        },
    );
    if let Some(e) = execution {
        let mut base = format!(
            "{}/domains/{}",
            r.namespace,
            crate::ledger::key_part(&g.conflict_domain)
        );
        if r.child(&n.child_id)?.topology.is_some() {
            base = format!("{base}/paired/{lane}");
        }
        let attempt = &e.outcomes.attempt_id;
        let root = format!("{base}/roots/{}", crate::ledger::key_part(&g.root_id));
        for phase in ["claim", "dispatch"] {
            let journal = if phase == "claim" {
                "claimed"
            } else {
                "dispatch_authorized"
            };
            if let Some(event) = e.outcomes.journal.iter().find(|e| e["phase"] == journal) {
                let at = event["event_time"].as_i64().ok_or_else(refused)?;
                out.insert(
                    format!("{lane}/{phase}"),
                    Expected {
                        control_key: format!(
                            "{root}/control-bindings/{}/{phase}",
                            crate::ledger::key_part(attempt)
                        ),
                        authority_digest: grant.digest.clone(),
                        attempt: Some(attempt.clone()),
                        earliest: g.valid_from,
                        expires: g.expires_at,
                        event_time: Some(at),
                    },
                );
            } else if phase == "claim" {
                return Err(refused());
            }
        }
    }
    Ok(())
}
fn expected(
    r: &crate::family::Registration,
    n: &crate::family_saga::Node,
    m: &crate::family_saga::MemberSnapshot,
) -> Result<BTreeMap<String, Expected>> {
    let mut out = BTreeMap::new();
    if let Some(a) = m.authorizations.get(&n.operation_key) {
        expected_lane(
            r,
            n,
            "forward",
            a,
            m.executions.get(&n.operation_key).map(|e| &e.lineage),
            &mut out,
        )?;
    }
    if let Some(i) = m
        .compound
        .as_ref()
        .and_then(|c| c.evidence.inverse.as_ref())
    {
        expected_lane(
            r,
            n,
            "inverse",
            &i.authorization,
            i.lineage.as_ref(),
            &mut out,
        )?;
    }
    Ok(out)
}
pub(crate) fn verify_member(
    r: &crate::family::Registration,
    n: &crate::family_saga::Node,
    m: &crate::family_saga::MemberSnapshot,
    bindings: &BTreeMap<String, AuthorityBinding>,
) -> Result<()> {
    let want = expected(r, n, m)?;
    if bindings.len() != want.len() {
        return Err(refused());
    }
    for (id, e) in want {
        let b = bindings.get(&id).ok_or_else(refused)?;
        let (lane, phase) = id.split_once('/').ok_or_else(refused)?;
        let v = &b.view;
        if b.profile != PROFILE
            || b.control_key != e.control_key
            || b.phase != phase
            || b.authority_digest != e.authority_digest
            || b.attempt_id != e.attempt
            || b.checked_at < e.earliest
            || b.checked_at >= e.expires
            || b.checked_at > m.captured_at
            || e.event_time.is_some_and(|at| b.checked_at > at)
            || v.registration_digest != r.digest()?
            || v.child_id != n.child_id
            || v.lane != lane
            || !crate::grant_reference::valid_reference(&v.family_head)
            || !crate::grant_reference::valid_reference(&v.phase_head)
            || canonical(&json!(b))?.len() > 16 << 10
        {
            return Err(refused());
        }
        if lane == "inverse" {
            let c = m.compound.as_ref().ok_or_else(refused)?;
            let q = c
                .evidence
                .qualifications
                .iter()
                .find(|q| q.digest().is_ok_and(|d| Some(d) == v.qualification_digest))
                .ok_or_else(refused)?;
            let t = n.compound()?.ok_or_else(refused)?;
            crate::compensation::verify(&t.contract, &t.forward, &q.proof, b.checked_at)?;
            if phase != "admission"
                && c.evidence
                    .inverse
                    .as_ref()
                    .ok_or_else(refused)?
                    .binding
                    .payload
                    .qualification_digest
                    != q.digest()?
            {
                return Err(refused());
            }
        } else if v.qualification_digest.is_some() {
            return Err(refused());
        }
    }
    Ok(())
}
pub(crate) async fn collect(
    lanes: &[(String, &EtcdLedger)],
    r: &crate::family::Registration,
    n: &crate::family_saga::Node,
    m: &crate::family_saga::MemberSnapshot,
) -> Result<BTreeMap<String, AuthorityBinding>> {
    let want = expected(r, n, m)?;
    // An original no-dispatch inventory also qualifies absence of BOTH the
    // legacy comparison record and its supplemental global comparison.
    for (id, e) in &want {
        if let Some(lane) = id.strip_suffix("/claim")
            && !want.contains_key(&format!("{lane}/dispatch"))
        {
            let l = lanes
                .iter()
                .find(|(name, _)| name == lane)
                .ok_or_else(refused)?
                .1;
            let dispatch = format!(
                "{}/dispatch",
                e.control_key.strip_suffix("/claim").ok_or_else(refused)?
            );
            if !l
                .txn(
                    vec![version_zero(&dispatch), version_zero(&key(&dispatch))],
                    vec![],
                    vec![],
                )
                .await?
                .succeeded
            {
                return Err(refused());
            }
        }
    }
    let mut out = BTreeMap::new();
    for (id, e) in want {
        let lane = id.split_once('/').ok_or_else(refused)?.0;
        let l = lanes
            .iter()
            .find(|(name, _)| name == lane)
            .ok_or_else(refused)?
            .1;
        let t = l
            .txn(
                vec![],
                vec![get(&e.control_key), get(&key(&e.control_key))],
                vec![],
            )
            .await?;
        if !t.succeeded || t.responses.len() != 2 {
            return Err(refused());
        }
        let original = range_kv(&t.responses[0])?.ok_or_else(refused)?;
        let raw = range_kv(&t.responses[1])?.ok_or_else(refused)?;
        if original.value.len() > 16 << 10 || raw.value.len() > 16 << 10 {
            return Err(refused());
        }
        let old: crate::control_bindings::AuthorityControlBinding =
            serde_json::from_value(strict_value(&original.value)?)?;
        let b: AuthorityBinding = serde_json::from_value(strict_value(&raw.value)?)?;
        if record(&b)?.as_bytes() != raw.value
            || b.checked_at != old.control.checked_at
            || b.phase != old.phase
            || b.authority_digest != old.authority_digest
            || b.attempt_id != old.attempt_id
        {
            return Err(refused());
        }
        out.insert(id, b);
    }
    verify_member(r, n, m, &out)?;
    Ok(out)
}

/// Replay the exact retained heads, not a later plausible readiness state. The
/// separate capture observer attests that each supplemental record was retained
/// in its original native CAS; this is not a Byzantine-storage consensus proof.
pub(crate) fn verify_history(
    r: &crate::family::Registration,
    family: &crate::family::State,
    phase: &crate::family_saga::PhaseState,
    proofs: &BTreeMap<String, crate::family_saga::Snapshot>,
    current: &crate::family_saga::Snapshot,
) -> Result<()> {
    use crate::family_saga::{PhaseEvent, PhaseState};
    let plan = r.composition.as_ref().ok_or_else(refused)?;
    family.verify(r)?;
    phase.verify(r, proofs)?;
    let mut fs = r.genesis()?;
    let mut families = BTreeMap::from([(fs.head.clone(), fs.clone())]);
    for e in &family.events {
        fs.apply(r, &e.command, e.at)?;
        families.insert(fs.head.clone(), fs.clone());
    }
    let mut ps = PhaseState::genesis(r)?;
    let mut phases = BTreeMap::from([(ps.head.clone(), ps.clone())]);
    let mut claims = BTreeMap::new();
    for e in &phase.events {
        if let PhaseEvent::Owner {
            at,
            family_head: Some(head),
            ..
        } = e
        {
            let f = families.get(head).ok_or_else(refused)?;
            if f.events.last().is_some_and(|e| e.at > *at) {
                return Err(refused());
            }
            f.live(r, "root", *at)?;
        }
        if let PhaseEvent::NativeClaim {
            at,
            child_id,
            attempt_id,
            binding,
        } = e
            && claims
                .insert(
                    (
                        child_id.clone(),
                        attempt_id.clone(),
                        binding.payload.grant_digest.clone(),
                    ),
                    (ps.head.clone(), *at, binding.as_ref()),
                )
                .is_some()
        {
            return Err(refused());
        }
        ps.replay_event(r, e, proofs)?;
        phases.insert(ps.head.clone(), ps.clone());
    }
    for snapshot in proofs.values().chain(std::iter::once(current)) {
        for (child, member) in &snapshot.members {
            crate::kube_drain_verify::views(r, plan.node(child)?, member, &families, &phases)?;
            for b in member
                .composition_bindings
                .as_ref()
                .ok_or_else(refused)?
                .values()
            {
                let f = families.get(&b.view.family_head).ok_or_else(refused)?;
                if f.attachments.len() != plan.nodes.len()
                    || f.events.last().is_some_and(|e| e.at > b.checked_at)
                {
                    return Err(refused());
                }
                f.live(
                    r,
                    &f.attachments.get(child).ok_or_else(refused)?.parent,
                    b.checked_at,
                )?;
                let p = phases.get(&b.view.phase_head).ok_or_else(refused)?;
                if p.members.len() != plan.nodes.len()
                    || p.snapshot_digest.is_none()
                    || p.events.last().is_some_and(|e| match e {
                        PhaseEvent::Owner { at, .. } | PhaseEvent::NativeClaim { at, .. } => {
                            *at > b.checked_at
                        }
                    })
                {
                    return Err(refused());
                }
                if b.view.lane == "forward" {
                    p.forward_ready(plan, child)?;
                } else {
                    p.inverse_ready(plan, child)?;
                    if p.members[child].qualification != b.view.qualification_digest {
                        return Err(refused());
                    }
                    if b.phase == "claim" {
                        let attempt = b.attempt_id.as_ref().ok_or_else(refused)?;
                        let (head, at, _) = claims
                            .get(&(child.clone(), attempt.clone(), b.authority_digest.clone()))
                            .ok_or_else(refused)?;
                        if head != &b.view.phase_head || b.checked_at > *at {
                            return Err(refused());
                        }
                    }
                    if b.phase == "dispatch" {
                        let flight = p.in_flight.as_ref().ok_or_else(refused)?;
                        if flight.child_id != *child
                            || flight.grant_digest != b.authority_digest
                            || Some(&flight.attempt_id) != b.attempt_id.as_ref()
                        {
                            return Err(refused());
                        }
                    }
                }
            }
        }
    }
    // Every retained native claim must have the complete ORIGINAL current
    // authority/spend and signed outcome lineage. A claim event cannot be
    // invented merely by presenting an owner label or an allocated grant.
    for ((child, attempt, gd), (_, at, binding)) in claims {
        let m = current.members.get(&child).ok_or_else(refused)?;
        let i = m
            .compound
            .as_ref()
            .and_then(|c| c.evidence.inverse.as_ref())
            .ok_or_else(refused)?;
        let execution = i.lineage.as_ref().ok_or_else(refused)?;
        let original = execution
            .outcomes
            .journal
            .iter()
            .find(|e| e["phase"] == "claimed")
            .ok_or_else(refused)?;
        if i.binding != *binding
            || i.spend.attempt_id.as_ref() != Some(&attempt)
            || i.authorization.issuance.grant_digest != gd
            || original["event_time"].as_i64() != Some(at)
        {
            return Err(refused());
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn retain(
    l: &EtcdLedger,
    compare: &mut Vec<Value>,
    writes: &mut Vec<Value>,
    control_key: &str,
    phase: &str,
    authority: &str,
    attempt: Option<&str>,
    control: &Option<ControlState>,
    view: &Option<View>,
) -> Result<()> {
    let refused = || Error::Refused("original global family authority binding refused".into());
    let Some(view) = view else {
        if crate::family_saga_epoch::selected(l) {
            return Err(refused());
        }
        return Ok(());
    };
    let c = control.as_ref().ok_or_else(refused)?;
    if !crate::family_saga_epoch::selected(l)
        || !control_key.starts_with(&format!("{}/", l.namespace()))
        || !["admission", "issuance", "claim", "dispatch"].contains(&phase)
    {
        return Err(refused());
    }
    let b = AuthorityBinding {
        profile: PROFILE.into(),
        control_key: control_key.into(),
        phase: phase.into(),
        authority_digest: authority.into(),
        attempt_id: attempt.map(str::to_owned),
        checked_at: c.checked_at,
        view: view.clone(),
    };
    if canonical(&json!(b))?.len() > 16 << 10 {
        return Err(refused());
    }
    let k = key(control_key);
    compare.push(version_zero(&k));
    writes.push(put(&k, &record(&b)?));
    Ok(())
}
