//! Complete observer-attested native control prefix for a physical capture.
//! Aggregate observation bodies and sink acknowledgements remain in the outer
//! operating audit; they are never recursively embedded in physical captures.
use crate::{
    contracts::{canonical, digest},
    current_reservation::SourceClaim,
    error::{Error, Result},
    kube_drain_journal::State,
    kube_drain_proof::{Capture, NoDispatch, Signed as Mechanical},
    managed_drain::PROFILE,
    managed_drain_evidence::{ControlKind, ControlProof, Header, Signed},
    managed_drain_journal::{Change, Core, Event, MAX_EVENTS, Origin},
    managed_drain_preflight::{Claim, Evidence, MAX_OBSERVATIONS},
    managed_drain_store::{Context, Material, Store},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
fn refuse() -> Error {
    Error::Refused("complete original managed control capture refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCheckpoint {
    pub enrollment_digest: String,
    pub source_digest: String,
    pub event_count: u64,
    pub head_digest: String,
    pub mechanical_digest: Option<String>,
    pub native_epoch: String,
    pub captured_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    pub origin: Origin,
    pub events: Vec<Event>,
    pub controls: BTreeMap<String, ControlProof>,
    pub claims: BTreeMap<String, SourceClaim>,
    pub preflight_claims: Vec<Claim>,
    pub admission: Evidence,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCapture {
    pub profile: String,
    pub sources: Sources,
    pub checkpoint: Signed<NativeCheckpoint>,
}
impl Sources {
    fn digest(&self) -> Result<String> {
        digest("managed-drain-native-control-sources", &json!(self))
    }
}
fn control_reference(c: &Change) -> Option<&str> {
    match c {
        Change::ControllerAccepted { proof_digest }
        | Change::ControllerPending { proof_digest, .. }
        | Change::SendChecked { proof_digest, .. }
        | Change::ClosedNoEffect { proof_digest }
        | Change::ClosedAbsence { proof_digest } => Some(proof_digest),
        _ => None,
    }
}
fn mechanical_digest(
    state: Option<&Mechanical<State>>,
    gate: Option<&Mechanical<NoDispatch>>,
) -> Result<Option<String>> {
    match (state, gate) {
        (Some(s), None) => Ok(Some(s.digest()?)),
        (None, Some(g)) => Ok(Some(g.digest()?)),
        (None, None) => Ok(None),
        _ => Err(refuse()),
    }
}
impl Store {
    /// Called by the separately keyed read-only physical observer. The caller
    /// signs only after its inventory read and a comparison of this exact prefix.
    pub(crate) async fn control_capture(&self) -> Result<(Option<Sources>, Vec<Value>)> {
        use crate::ledger::{record, value_eq, version_zero};
        let base = self.context.base();
        let Some(s) = self.load().await? else {
            return Ok((
                None,
                vec![
                    version_zero(&format!("{base}/origin")),
                    version_zero(&format!("{base}/head")),
                ],
            ));
        };
        let mut compare = vec![
            value_eq(&self.context.marker(), &s.marker_raw),
            value_eq(&format!("{base}/origin"), &s.origin_raw),
            value_eq(&format!("{base}/head"), &s.head_raw),
        ];
        let (grant, _) = self.context.validate_origin(&s.origin)?;
        let (admission, admission_compare) = self.admission_source(&grant, &s.origin).await?;
        compare.extend(admission_compare);
        let mut controls = BTreeMap::new();
        for event in &s.events {
            if let Some(reference) = control_reference(&event.change) {
                let Some(Material::Controller(p)) = s.materials.get(reference) else {
                    return Err(refuse());
                };
                controls.insert(reference.to_owned(), (**p).clone());
                compare.push(value_eq(
                    &format!("{base}/records/{reference}"),
                    &record(&s.materials[reference])?,
                ));
            }
        }
        for (reference, claim) in &s.claims {
            compare.push(value_eq(
                &format!("{base}/source-claims/{reference}"),
                &record(claim)?,
            ));
        }
        // A legitimate new source claim can only use the one current pending
        // slot. Claims do not advance the event head, so compare its absence too.
        if let Some(slot) = &s.state().pending
            && !s.claims.contains_key(&slot.reservation_digest)
        {
            compare.push(version_zero(&format!(
                "{base}/source-claims/{}",
                slot.reservation_digest
            )));
        }
        let sources = Sources {
            origin: s.origin,
            events: s.events,
            controls,
            claims: s.claims,
            preflight_claims: self.preflight_history().await?,
            admission,
        };
        Ok((Some(sources), compare))
    }
}
impl NativeCapture {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        sources: Sources,
        c: &Context,
        state: Option<&Mechanical<State>>,
        gate: Option<&Mechanical<NoDispatch>>,
        epoch: &str,
        at: i64,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<Self> {
        let cp = NativeCheckpoint {
            enrollment_digest: c.enrollment.digest()?,
            source_digest: sources.digest()?,
            event_count: sources.events.len() as u64,
            head_digest: sources.events.last().ok_or_else(refuse)?.digest()?,
            mechanical_digest: mechanical_digest(state, gate)?,
            native_epoch: epoch.into(),
            captured_at: at,
        };
        let native = Self {
            profile: PROFILE.into(),
            sources,
            checkpoint: Signed::sign(
                "native_control_capture",
                cp,
                &c.physical.observer,
                key_id,
                key,
            )?,
        };
        native.verify_sources(c, state, gate, epoch, at)?;
        Ok(native)
    }
    /// Replays transition structure and all mutation-related signed source facts.
    /// Prior aggregate views are attested by the native observer here; the outer
    /// managed audit must replay their complete aggregate and acknowledgement bodies.
    pub(crate) fn verify_sources(
        &self,
        c: &Context,
        state: Option<&Mechanical<State>>,
        gate: Option<&Mechanical<NoDispatch>>,
        epoch: &str,
        at: i64,
    ) -> Result<Core> {
        let s = &self.sources;
        let cp = &self.checkpoint.body;
        self.checkpoint
            .verify("native_control_capture", &c.physical.observer)?;
        c.validate_origin(&s.origin)?;
        if self.profile != PROFILE
            || s.events.is_empty()
            || s.events.len() > MAX_EVENTS
            || s.claims.len() > 64
            || s.controls.len() > 2 * crate::kube_drain::MAX_REQUESTS + 2
            || s.preflight_claims.is_empty()
            || s.preflight_claims.len() > MAX_OBSERVATIONS
            || cp.enrollment_digest != c.enrollment.digest()?
            || cp.source_digest != s.digest()?
            || cp.event_count != s.events.len() as u64
            || cp.head_digest != s.events.last().ok_or_else(refuse)?.digest()?
            || cp.mechanical_digest != mechanical_digest(state, gate)?
            || cp.native_epoch != epoch
            || !crate::grant_reference::valid_reference(epoch)
            || cp.captured_at > at
            || cp.captured_at < s.events.last().ok_or_else(refuse)?.at
            || at > crate::contracts::MAX_SAFE_INTEGER as i64
            || canonical(&json!(self))?.len() > crate::family_saga::MAX_PROOF
        {
            return Err(refuse());
        }
        let mut pd = BTreeSet::new();
        for (i, claim) in s.preflight_claims.iter().enumerate() {
            claim.validate(c)?;
            if claim.sequence != i as u64 + 1
                || !pd.insert(&claim.proposal_digest)
                || claim.previous_digest
                    != if i == 0 {
                        None
                    } else {
                        Some(s.preflight_claims[i - 1].digest()?)
                    }
                || i > 0 && claim.claimed_at < s.preflight_claims[i - 1].claimed_at
                || claim.claimed_at > s.origin.original.dispatched_at
            {
                return Err(refuse());
            }
        }
        let claim = &s.admission.statement.body.claim;
        if s.preflight_claims
            .get(claim.sequence.checked_sub(1).ok_or_else(refuse)? as usize)
            != Some(claim)
            || claim.forward.signed_grant != s.origin.forward_signed_grant
            || claim.forward.attempt_id != s.origin.forward_attempt_id
        {
            return Err(refuse());
        }
        let (grant, _) = c.validate_origin(&s.origin)?;
        s.admission
            .statement
            .validate_admission(c, grant.issued_at)?;
        let mut materials = BTreeMap::new();
        for (reference, proof) in &s.controls {
            if *reference != proof.digest()? {
                return Err(refuse());
            }
            materials.insert(
                reference.clone(),
                Material::Controller(Box::new(proof.clone())),
            );
        }
        let mut core = Core::initial(&c.enrollment, &s.origin)?;
        let mut previous = None;
        let mut used = BTreeSet::new();
        for event in &s.events {
            event.bound()?;
            if let Some(reference) = control_reference(&event.change) {
                if !used.insert(reference.to_owned()) {
                    return Err(refuse());
                }
                let p = s.controls.get(reference).ok_or_else(refuse)?;
                if event.previous_digest.as_deref() != Some(&p.body.operating_head_digest) {
                    return Err(refuse());
                }
                c.validate_material(
                    &s.origin,
                    &core,
                    &event.change,
                    event.at,
                    &materials,
                    &s.claims,
                )?;
                verify_mechanical(c, p, state, gate)?;
            }
            let view = if matches!(event.change, Change::Observed { .. }) {
                event.after.observation.as_ref()
            } else {
                None
            };
            if *event
                != Event::new(
                    previous,
                    &core,
                    &c.enrollment,
                    &s.origin,
                    event.at,
                    event.change.clone(),
                    view,
                )?
            {
                return Err(refuse());
            }
            core = event.after.clone();
            previous = Some(event);
        }
        if used != s.controls.keys().cloned().collect() {
            return Err(refuse());
        }
        for (reference, claim) in &s.claims {
            let head = s
                .events
                .iter()
                .find(|e| e.digest().ok().as_ref() == Some(&claim.operating_head_digest))
                .ok_or_else(refuse)?;
            crate::managed_drain_store::validate_claim_slot(c, &s.origin, head, claim)?;
            if *reference != claim.reservation_digest || claim.claimed_at > cp.captured_at {
                return Err(refuse());
            }
        }
        match (state, gate) {
            (Some(state), None)
                if core.accepted
                    && core.pending_steps == state.body.steps.len() as u64
                    && core.closed == state.body.closed.is_some() =>
            {
                // A response can exist only after the final native send CAS. A
                // lost Pending with no send proof remains unknown and query-only.
                if state
                    .body
                    .steps
                    .iter()
                    .skip(core.send_checks as usize)
                    .any(|step| step.response.is_some())
                {
                    return Err(refuse());
                }
            }
            (None, Some(_)) if !core.accepted && core.closed => (),
            (None, None) if !core.accepted && !core.closed && s.controls.is_empty() => (),
            _ => return Err(refuse()),
        }
        Ok(core)
    }
    pub(crate) fn send_authorities(
        &self,
    ) -> impl Iterator<Item = (&crate::kube_drain_journal::Authority, i64)> {
        self.sources
            .controls
            .values()
            .filter(|p| p.body.kind == ControlKind::Send)
            .filter_map(|p| {
                p.body
                    .native_authority
                    .as_ref()
                    .map(|a| (a, p.body.checked_at))
            })
    }
}
fn verify_mechanical(
    c: &Context,
    p: &ControlProof,
    current: Option<&Mechanical<State>>,
    gate: Option<&Mechanical<NoDispatch>>,
) -> Result<()> {
    let h = &p.body.mechanical_header;
    if p.body.kind == ControlKind::ClosedAbsence {
        let gate = gate.ok_or_else(refuse)?;
        let header = Header {
            profile: gate.profile.clone(),
            kind: gate.kind.clone(),
            signer_id: gate.signer_id.clone(),
            key_id: gate.key_id.clone(),
            signature: gate.signature.clone(),
        };
        if json!(header) != json!(h)
            || gate.digest()? != p.body.mechanical_digest
            || gate.body.closed_at != p.body.checked_at
        {
            return Err(refuse());
        }
        return gate.verify("closed_no_dispatch", &c.physical.controller);
    }
    let current = current.ok_or_else(refuse)?;
    let mut body = current.body.clone();
    match p.body.kind {
        ControlKind::Accepted => {
            body.steps.clear();
            body.closed = None;
        }
        ControlKind::Pending | ControlKind::Send => {
            if p.body.sequence == 0 || p.body.sequence > body.steps.len() as u64 {
                return Err(refuse());
            }
            body.steps.truncate(p.body.sequence as usize);
            body.closed = None;
            body.steps.last_mut().ok_or_else(refuse)?.response = None;
        }
        ControlKind::ClosedNoEffect
            if body.steps.is_empty()
                && body
                    .closed
                    .as_ref()
                    .is_some_and(|v| v.closed_at == p.body.checked_at) => {}
        _ => return Err(refuse()),
    }
    let reconstructed = Mechanical {
        profile: h.profile.clone(),
        kind: h.kind.clone(),
        signer_id: h.signer_id.clone(),
        key_id: h.key_id.clone(),
        signature: h.signature.clone(),
        body,
    };
    reconstructed.verify("controller_state", &c.physical.controller)?;
    if reconstructed.digest()? != p.body.mechanical_digest {
        return Err(refuse());
    }
    Ok(())
}

/// Extra correlation checked against the independently verified original member.
pub(crate) fn member(
    r: &crate::family::Registration,
    n: &crate::family_saga::Node,
    m: &crate::family_saga::MemberSnapshot,
    p: &Capture,
) -> Result<Option<Core>> {
    let trust = n.physical.as_ref().ok_or_else(refuse)?;
    let Some(_) = &trust.operating else {
        if p.managed.is_some() {
            return Err(refuse());
        }
        return Ok(None);
    };
    let original = m.executions.get(&n.operation_key).and_then(|b| {
        b.lineage
            .outcomes
            .journal
            .iter()
            .find(|e| e["phase"] == "dispatch_authorized")
    });
    let Some(dispatch) = original else {
        if p.managed.is_some() || p.controller.is_some() || p.closed_absence.is_some() {
            return Err(refuse());
        }
        return Ok(None);
    };
    let native = p.managed.as_ref().ok_or_else(refuse)?;
    let context = Context::from_selection(crate::family::Selection {
        registration: r.clone(),
        child_id: n.child_id.clone(),
    })?;
    let core = native.verify_sources(
        &context,
        p.controller.as_ref(),
        p.closed_absence.as_ref(),
        &p.observation.body.native_epoch,
        p.observation.body.observed_at,
    )?;
    let s = &native.sources;
    let auth = m.authorizations.get(&n.operation_key).ok_or_else(refuse)?;
    let proposal = crate::contracts::strict_value(auth.packet.proposal.as_bytes())?;
    let proposal: crate::contracts::Envelope = serde_json::from_value(proposal)?;
    let (g, _) = context.validate_origin(&s.origin)?;
    let request = crate::managed_drain_preflight::Request {
        profile: crate::current_reservation::PROFILE.into(),
        enrollment_digest: context.enrollment.digest()?,
        signed_proposal: auth.packet.proposal.clone(),
        requested_at: s.admission.statement.body.claim.requested_at,
    };
    context.admission_proposal(&request, g.issued_at)?;
    s.admission.validate(&context, &proposal, g.issued_at)?;
    if s.origin.original.native_dispatch_digest != digest("kube-drain-native-dispatch", dispatch)?
        || s.origin.signed_grant != auth.issuance.signed_grant
        || s.origin.original.attempt_id
            != m.executions[&n.operation_key].lineage.outcomes.attempt_id
        || !auth.packet.witnesses.iter().any(|raw| {
            crate::contracts::strict_value(raw.as_bytes()).ok() == Some(json!(s.admission.evidence))
        })
    {
        return Err(refuse());
    }
    Ok(Some(core))
}

pub(crate) fn successor(old: &NativeCapture, new: &NativeCapture) -> Result<()> {
    let a = &old.sources;
    let b = &new.sources;
    if a.origin != b.origin
        || a.events.len() > b.events.len()
        || a.events != b.events[..a.events.len()]
        || canonical(&json!(a.admission))? != canonical(&json!(b.admission))?
        || a.preflight_claims != b.preflight_claims
        || old.checkpoint.body.captured_at > new.checkpoint.body.captured_at
        || a.claims.iter().any(|(k, v)| b.claims.get(k) != Some(v))
        || a.controls.iter().any(|(k, v)| {
            b.controls
                .get(k)
                .is_none_or(|n| canonical(&json!(n)).ok() != canonical(&json!(v)).ok())
        })
    {
        return Err(refuse());
    }
    Ok(())
}
