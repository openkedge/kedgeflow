//! Complete bounded operating audit against independent protected enrollment.
//! Checkpoints attest native storage reads; they are not consensus proofs or
//! current execution authority. Every referenced source body is replayed here.
use crate::{
    contracts::{canonical, digest, strict_value},
    error::{Error, Result},
    family::Selection,
    managed_drain::PROFILE,
    managed_drain_capture::Sources,
    managed_drain_evidence::Signed,
    managed_drain_store::{Context, Material, Store},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
pub const MAX_BYTES: usize = 64 << 20;
fn refuse() -> Error {
    Error::Refused("complete managed operating/physical source audit refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub profile: String,
    pub selection: Selection,
}
impl Trust {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 2 << 20 {
            return Err(refuse());
        }
        let t: Self = serde_json::from_value(strict_value(raw)?)?;
        t.context()?;
        Ok(t)
    }
    fn context(&self) -> Result<Context> {
        if self.profile != PROFILE {
            return Err(refuse());
        }
        Context::from_selection(self.selection.clone())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source: Sources,
    pub materials: BTreeMap<String, Material>,
    pub current_aggregate_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub enrollment_digest: String,
    pub evidence_digest: String,
    pub event_count: u64,
    pub head_digest: String,
    pub captured_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub profile: String,
    pub evidence: Evidence,
    pub checkpoint: Signed<Checkpoint>,
}
impl Bundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BYTES {
            return Err(refuse());
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub fn verify(&self, trust: &Trust) -> Result<Value> {
        let c = trust.context()?;
        let e = &self.evidence;
        let s = &e.source;
        let cp = &self.checkpoint.body;
        self.checkpoint
            .verify("complete_operating_audit", &c.enrollment.operating_observer)?;
        if self.profile != PROFILE
            || cp.enrollment_digest != c.enrollment.digest()?
            || cp.evidence_digest != digest("managed-drain-complete-evidence", &json!(e))?
            || cp.event_count != s.events.len() as u64
            || cp.head_digest != s.events.last().ok_or_else(refuse)?.digest()?
            || cp.captured_at < s.events.last().ok_or_else(refuse)?.at
            || cp.captured_at > crate::contracts::MAX_SAFE_INTEGER as i64
            || s.claims
                .values()
                .any(|claim| claim.claimed_at > cp.captured_at)
            || canonical(&json!(self))?.len() > MAX_BYTES
        {
            return Err(refuse());
        }
        let core =
            crate::managed_drain_store::replay(&c, &s.origin, &s.events, &e.materials, &s.claims)?;
        if core
            .observation
            .as_ref()
            .map(|v| v.aggregate_digest.as_str())
            != Some(e.current_aggregate_digest.as_str())
        {
            return Err(refuse());
        }
        let mut controls = BTreeMap::new();
        for (key, material) in &e.materials {
            if let Material::Controller(p) = material {
                controls.insert(key.clone(), (**p).clone());
            }
            if let Material::Aggregate(b) = material {
                let boundary=s.events.iter().filter(|event| matches!(&event.change,
                    crate::managed_drain_journal::Change::Observed { aggregate_digest, .. } if aggregate_digest==key))
                    .map(|event| event.sequence).min().ok_or_else(refuse)? as usize;
                verify_aggregate_prefix(&c, s, b, boundary)?;
            }
        }
        if canonical(&json!(controls))? != canonical(&json!(s.controls))? {
            return Err(refuse());
        }
        let Some(Material::Aggregate(current)) = e.materials.get(&e.current_aggregate_digest)
        else {
            return Err(refuse());
        };
        let native = current
            .evidence
            .current
            .snapshot
            .members
            .get(&c.selection.child_id)
            .and_then(|m| m.physical.as_ref())
            .and_then(|p| p.managed.as_ref())
            .ok_or_else(refuse)?;
        // A later control/closure cannot be hidden behind an older physical capture.
        if canonical(&json!(native.sources.controls))? != canonical(&json!(s.controls))?
            || cp.captured_at < current.checkpoint.captured_at
        {
            return Err(refuse());
        }
        let physical = crate::family_saga::verify_aggregate(
            current,
            &crate::family_saga::AuditTrust {
                registration: c.selection.registration.clone(),
            },
        )?;
        Ok(
            json!({"profile":PROFILE,"verified":"observer_attested_complete_operating_and_physical_prefix",
            "enrollment_digest":c.enrollment.digest()?,"event_count":s.events.len(),"head_digest":cp.head_digest,
            "physical_observed_at":current.checkpoint.captured_at,"captured_at":cp.captured_at,
            "operating":core,"physical":physical.nodes[&c.selection.child_id],
            "held_forward":physical.held_forward,"held_compensation":physical.held_compensation,
            "controller_proofs":s.controls.len(),"source_claims":s.claims.len(),
            "complete_evidence":true,"native_history_verified":true,"execution_authority":false}),
        )
    }
}
fn verify_aggregate_prefix(
    c: &Context,
    source: &Sources,
    b: &crate::family_saga::AggregateBundle,
    boundary: usize,
) -> Result<()> {
    for capture in b
        .evidence
        .proofs
        .values()
        .chain(std::iter::once(&b.evidence.current))
    {
        let member = capture
            .snapshot
            .members
            .get(&c.selection.child_id)
            .ok_or_else(refuse)?;
        let Some(p) = member.physical.as_ref().and_then(|p| p.managed.as_ref()) else {
            continue;
        };
        let s = &p.sources;
        if s.origin != source.origin
            || s.events.len() >= boundary
            || s.events.len() > source.events.len()
            || s.events != source.events[..s.events.len()]
            || s.preflight_claims != source.preflight_claims
            || canonical(&json!(s.admission))? != canonical(&json!(source.admission))?
            || s.claims
                .iter()
                .any(|(k, v)| source.claims.get(k) != Some(v))
            || s.controls.iter().any(|(k, v)| {
                source
                    .controls
                    .get(k)
                    .is_none_or(|p| canonical(&json!(p)).ok() != canonical(&json!(v)).ok())
            })
        {
            return Err(refuse());
        }
    }
    Ok(())
}
pub struct Auditor {
    store: Store,
    clock: Arc<dyn crate::clock::Clock>,
    key_id: String,
    key: ed25519_dalek::SigningKey,
}
impl Auditor {
    pub fn new(
        store: Store,
        clock: Arc<dyn crate::clock::Clock>,
        key_id: String,
        key: ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        if crate::control_config::keys(&store.context.enrollment.operating_observer.keys)?
            .get(&key_id)
            != Some(&key.verifying_key())
        {
            return Err(refuse());
        }
        Ok(Self {
            store,
            clock,
            key_id,
            key,
        })
    }
    /// Serializes retained source material; does not perform a fresh physical
    /// query or bypass its budget. Missing complete evidence refuses export.
    pub async fn export(&self) -> Result<Bundle> {
        self.store.expire_query(self.clock.now_ms()).await?;
        let (source, compare) = self.store.control_capture().await?;
        let source = source.ok_or_else(refuse)?;
        let s = self.store.load().await?.ok_or_else(refuse)?;
        if s.origin != source.origin || s.events != source.events || s.claims != source.claims {
            return Err(refuse());
        }
        let current_aggregate_digest = s
            .state()
            .observation
            .as_ref()
            .ok_or_else(refuse)?
            .aggregate_digest
            .clone();
        let evidence = Evidence {
            source,
            materials: s.materials,
            current_aggregate_digest,
        };
        let checkpoint = Signed::sign(
            "complete_operating_audit",
            Checkpoint {
                enrollment_digest: self.store.context.enrollment.digest()?,
                evidence_digest: digest("managed-drain-complete-evidence", &json!(evidence))?,
                event_count: evidence.source.events.len() as u64,
                head_digest: evidence.source.events.last().ok_or_else(refuse)?.digest()?,
                captured_at: self.clock.now_ms(),
            },
            &self.store.context.enrollment.operating_observer,
            &self.key_id,
            &self.key,
        )?;
        let b = Bundle {
            profile: PROFILE.into(),
            evidence,
            checkpoint,
        };
        b.verify(&Trust {
            profile: PROFILE.into(),
            selection: self.store.context.selection.clone(),
        })?;
        if !self
            .store
            .ledger
            .txn(compare, vec![], vec![])
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(b)
    }
}
