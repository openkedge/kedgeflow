//! Complete bounded family allocation, phase and original native execution
//! evidence. Observer custody and correct native storage are explicit trust
//! assumptions; no checkpoint conveys current execution authority.
use crate::{
    contracts::{canonical, digest, strict_value},
    control_history::HistoryObserver,
    error::{Error, Result},
    family::{self, Registration},
    family_saga::{
        Collected, Flight, ForwardState as F, InverseState as I, MAX_HISTORY_BYTES, MemberSummary,
        PROFILE, Phase, PhaseEvent, PhaseState, Snapshot,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_BUNDLE: usize = 18 << 20;
fn refused() -> Error {
    Error::Refused("complete original family saga aggregate refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub family: family::Bundle,
    pub phase: PhaseState,
    pub proofs: BTreeMap<String, Collected>,
    pub current: Collected,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub profile: String,
    pub observer_id: String,
    pub key_id: String,
    pub namespace: String,
    pub registration_digest: String,
    pub evidence_digest: String,
    pub captured_at: i64,
    pub signature: String,
}
impl Checkpoint {
    fn message(&self) -> Result<Vec<u8>> {
        let mut value = json!(self);
        value
            .as_object_mut()
            .ok_or_else(refused)?
            .remove("signature");
        let mut bytes = format!("KedgeFlow:{PROFILE}:aggregate-history\0").into_bytes();
        bytes.extend(canonical(&value)?);
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub profile: String,
    pub evidence: Evidence,
    pub checkpoint: Checkpoint,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTrust {
    pub registration: Registration,
}
#[derive(Serialize)]
pub struct Verification {
    pub profile: String,
    pub family_id: String,
    pub phase: Phase,
    pub family_active: bool,
    pub status: String,
    pub observation_required: bool,
    pub retained_in_flight: Option<Flight>,
    pub nodes: BTreeMap<String, MemberSummary>,
    pub held_forward: u64,
    pub held_compensation: u64,
    pub complete_evidence: bool,
    pub execution_authority: bool,
    pub fresh_admission_required: bool,
}
impl Bundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BUNDLE {
            return Err(refused());
        }
        let value = strict_value(raw)?;
        let b: Self = serde_json::from_value(value.clone())?;
        if json!(b) != value {
            return Err(refused());
        }
        Ok(b)
    }
    pub(crate) fn sign(
        evidence: Evidence,
        r: &Registration,
        observer: &HistoryObserver,
        at: i64,
    ) -> Result<Self> {
        let mut checkpoint = Checkpoint {
            profile: PROFILE.into(),
            observer_id: observer.id.clone(),
            key_id: observer.key_id.clone(),
            namespace: r.namespace.clone(),
            registration_digest: r.digest()?,
            evidence_digest: digest("family-saga-complete-evidence", &json!(evidence))?,
            captured_at: at,
            signature: String::new(),
        };
        checkpoint.signature =
            URL_SAFE_NO_PAD.encode(observer.key.sign(&checkpoint.message()?).to_bytes());
        let b = Self {
            profile: PROFILE.into(),
            evidence,
            checkpoint,
        };
        verify(
            &b,
            &AuditTrust {
                registration: r.clone(),
            },
        )?;
        Ok(b)
    }
}
impl AuditTrust {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(refused());
        }
        let value = strict_value(raw)?;
        let t: Self = serde_json::from_value(value.clone())?;
        if json!(t) != value {
            return Err(refused());
        }
        t.registration.validate()?;
        if t.registration.composition.is_none() {
            return Err(refused());
        }
        Ok(t)
    }
}
pub fn family_trust(r: &Registration) -> Result<family::AuditTrust> {
    let p = &r.composition.as_ref().ok_or_else(refused)?.family_observer;
    Ok(family::AuditTrust {
        registration: r.clone(),
        namespace: r.namespace.clone(),
        observer_id: p.id.clone(),
        observer_keys: p.keys.clone(),
    })
}
pub fn verify(b: &Bundle, t: &AuditTrust) -> Result<Verification> {
    let r = &t.registration;
    r.validate()?;
    let plan = r.composition.as_ref().ok_or_else(refused)?;
    let e = &b.evidence;
    let cp = &b.checkpoint;
    if b.profile != PROFILE
        || cp.profile != PROFILE
        || cp.observer_id != plan.observer.id
        || cp.namespace != r.namespace
        || cp.registration_digest != r.digest()?
        || cp.evidence_digest != digest("family-saga-complete-evidence", &json!(e))?
        || cp.captured_at < r.valid_from
        || cp.captured_at > crate::contracts::MAX_SAFE_INTEGER as i64
        || canonical(&json!(b))?.len() > MAX_BUNDLE
    {
        return Err(refused());
    }
    let key = crate::control_config::keys(&plan.observer.keys)?
        .remove(&cp.key_id)
        .ok_or_else(refused)?;
    let sig = URL_SAFE_NO_PAD
        .decode(&cp.signature)
        .map_err(|_| refused())?;
    if URL_SAFE_NO_PAD.encode(&sig) != cp.signature {
        return Err(refused());
    }
    key.verify_strict(
        &cp.message()?,
        &Signature::from_slice(&sig).map_err(|_| refused())?,
    )
    .map_err(|_| refused())?;
    family::verify(&e.family, &family_trust(r)?)?;
    if e.family.state.attachments.len() != plan.nodes.len()
        || e.family.checkpoint.captured_at > cp.captured_at
        || e.current.snapshot.captured_at > cp.captured_at
        || e.current.snapshot.phase_head != e.phase.head
    {
        return Err(refused());
    }
    let mut referenced = BTreeSet::new();
    for event in &e.phase.events {
        if let PhaseEvent::Owner { intent, .. } = event
            && let Some(d) = &intent.payload.proof_digest
        {
            referenced.insert(d.clone());
        }
    }
    if e.proofs.keys().cloned().collect::<BTreeSet<_>>() != referenced {
        return Err(refused());
    }
    let mut total = 0usize;
    let mut proofs: BTreeMap<String, Snapshot> = BTreeMap::new();
    for (d, c) in &e.proofs {
        c.verify(r)?;
        if c.snapshot.digest()? != *d || c.snapshot.captured_at > cp.captured_at {
            return Err(refused());
        }
        total = total
            .checked_add(canonical(&json!(c))?.len())
            .ok_or_else(refused)?;
        if total > MAX_HISTORY_BYTES {
            return Err(refused());
        }
        proofs.insert(d.clone(), c.snapshot.clone());
    }
    let nodes = e.current.verify(r)?;
    e.phase.verify(r, &proofs)?;
    let changed = e
        .phase
        .check_current(r, &e.current.snapshot, &proofs, cp.captured_at)?;
    crate::family_saga_bindings::verify_history(
        r,
        &e.family.state,
        &e.phase,
        &proofs,
        &e.current.snapshot,
    )?;
    let status = if nodes
        .values()
        .any(|m| m.forward == F::Unknown || m.inverse == I::Unknown)
    {
        "unresolved"
    } else if e.phase.phase == Phase::Forward {
        if nodes.values().all(|m| m.forward == F::Committed) {
            "forward_completed"
        } else {
            "forward_partial"
        }
    } else if e.phase.phase == Phase::Quiescing {
        if plan.nodes.iter().any(|n| {
            nodes[&n.child_id].forward == F::Committed
                && r.child(&n.child_id).is_ok_and(|c| c.inverse.is_none())
        }) {
            "compensation_blocked"
        } else {
            "quiescing"
        }
    } else if nodes
        .values()
        .any(|m| matches!(m.inverse, I::NoEffect | I::Failed))
    {
        "compensation_failed"
    } else if nodes
        .values()
        .any(|m| m.forward == F::Committed && m.inverse != I::Committed)
    {
        "partial_compensation"
    } else if nodes.values().any(|m| m.forward == F::Committed) {
        "compensated"
    } else {
        "no_forward_effects"
    };
    Ok(Verification {
        profile: PROFILE.into(),
        family_id: r.family_id.clone(),
        phase: e.phase.phase.clone(),
        family_active: e.family.state.active,
        status: status.into(),
        observation_required: changed,
        retained_in_flight: e.phase.in_flight.clone(),
        nodes,
        held_forward: r.forward,
        held_compensation: r.compensation,
        complete_evidence: true,
        execution_authority: false,
        fresh_admission_required: true,
    })
}
