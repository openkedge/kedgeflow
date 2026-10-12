//! Observer-attested governance history, separate from live execution authority.
use crate::{
    clock::Clock,
    contracts::{canonical, digest, strict_value},
    error::{Error, Result},
    governance::StoredControl,
    ledger::EtcdLedger,
    lineage::LineageBundle,
    recovery::Candidate,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const PROFILE: &str = "KF-CONTROL-HISTORY-0.1-draft";
pub const MAX_EVENTS: u64 = 64;
const MAX_BUNDLE: usize = 32 << 20;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEvent {
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub kind: String,
    pub accepted_at: i64,
    pub control: StoredControl,
}
impl HistoryEvent {
    pub fn digest(&self) -> Result<String> {
        digest("control-history-event", &serde_json::to_value(self)?)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoryHead {
    pub sequence: u64,
    pub digest: String,
    pub accepted_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPayload {
    pub observer_id: String,
    pub namespace: String,
    pub tenant: String,
    pub conflict_domain: String,
    pub event_count: u64,
    pub head_digest: String,
    pub captured_at: i64,
    pub lineage_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCheckpoint {
    pub profile: String,
    pub kind: String,
    pub key_id: String,
    pub payload: CheckpointPayload,
    pub signature: String,
}
impl HistoryCheckpoint {
    fn message(&self) -> Result<Vec<u8>> {
        let mut raw = b"KedgeFlow:KF-CONTROL-HISTORY-0.1-draft\0".to_vec();
        raw.extend(canonical(&json!({"profile":self.profile,"kind":self.kind,"key_id":self.key_id,"payload":self.payload}))?);
        Ok(raw)
    }
    pub(crate) fn verify(&self, keys: &BTreeMap<String, VerifyingKey>) -> Result<()> {
        let key = keys
            .get(&self.key_id)
            .ok_or_else(|| Error::Refused("unregistered history observer".into()))?;
        let sig = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| Error::Invalid("checkpoint signature encoding".into()))?;
        let sig = Signature::from_slice(&sig)
            .map_err(|_| Error::Invalid("checkpoint signature length".into()))?;
        if self.profile != PROFILE
            || self.kind != "checkpoint"
            || key.verify_strict(&self.message()?, &sig).is_err()
        {
            return Err(Error::Refused(
                "invalid history checkpoint signature/profile".into(),
            ));
        }
        Ok(())
    }
}
/// Protected operator-side signer. Its attestation depends on authorized ledger
/// access and custody; it is not an etcd signature or a non-revocation proof.
pub struct HistoryObserver {
    id: String,
    key_id: String,
    key: SigningKey,
}
impl HistoryObserver {
    pub fn new(id: String, key_id: String, key: SigningKey) -> Result<Self> {
        if id.is_empty() || key_id.is_empty() {
            return Err(Error::Invalid("missing observer identity/key ID".into()));
        }
        Ok(Self { id, key_id, key })
    }
    fn checkpoint(&self, payload: CheckpointPayload) -> Result<HistoryCheckpoint> {
        let mut c = HistoryCheckpoint {
            profile: PROFILE.into(),
            kind: "checkpoint".into(),
            key_id: self.key_id.clone(),
            payload,
            signature: String::new(),
        };
        c.signature = URL_SAFE_NO_PAD.encode(self.key.sign(&c.message()?).to_bytes());
        Ok(c)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlHistoryBundle {
    pub profile: String,
    pub lineage: LineageBundle,
    pub events: Vec<HistoryEvent>,
    pub checkpoint: HistoryCheckpoint,
}
impl ControlHistoryBundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BUNDLE {
            return Err(Error::Invalid(
                "control history bundle exceeds bound".into(),
            ));
        }
        let value = strict_value(raw)?;
        validate(&value)?;
        let b: Self = serde_json::from_value(value)?;
        b.bound()?;
        Ok(b)
    }
    pub(crate) fn bound(&self) -> Result<()> {
        if self.events.is_empty()
            || self.events.len() > MAX_EVENTS as usize
            || self
                .events
                .iter()
                .any(|e| e.control.record.is_empty() || e.control.record.len() > 1 << 20)
            || canonical(&serde_json::to_value(self)?)?.len() > MAX_BUNDLE
        {
            return Err(Error::Invalid(
                "control history carriage exceeds bound".into(),
            ));
        }
        validate(&serde_json::to_value(self)?)?;
        // Reuse the closed, byte-bounded lineage decoder even for library callers.
        LineageBundle::decode(&canonical(&serde_json::to_value(&self.lineage)?)?)?;
        Ok(())
    }
}
fn validate(value: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let schema = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/control-history-v0.1.schema.json"
            ))
            .expect("embedded history schema"),
        )
        .expect("valid history schema")
    });
    if !schema.is_valid(value) {
        return Err(Error::Invalid(
            "closed control history supplement mismatch".into(),
        ));
    }
    Ok(())
}
impl EtcdLedger {
    /// Privileged operator disclosure, with a separately approved observer key.
    /// Immutable history through a captured head forms a prefix, not a latest-head
    /// or operation-bound control-state assertion.
    pub async fn export_control_history(
        &self,
        c: &Candidate,
        operation_key: &str,
        observer: &HistoryObserver,
        clock: &dyn Clock,
    ) -> Result<ControlHistoryBundle> {
        let (head, events) = self
            .retained_control_history(&c.grant.conflict_domain)
            .await?;
        let lineage = self.export_lineage(c, operation_key).await?;
        let proposal: crate::contracts::Envelope =
            serde_json::from_value(strict_value(lineage.packet.proposal.as_bytes())?)?;
        let captured_at = clock.now_ms();
        if head.accepted_at > captured_at {
            return Err(Error::Refused(
                "history capture precedes accepted event".into(),
            ));
        }
        let checkpoint = observer.checkpoint(CheckpointPayload {
            observer_id: observer.id.clone(),
            namespace: self.namespace().into(),
            tenant: proposal.payload["tenant"]
                .as_str()
                .ok_or_else(|| Error::Invalid("missing signed tenant".into()))?
                .into(),
            conflict_domain: c.grant.conflict_domain.clone(),
            event_count: head.sequence,
            head_digest: head.digest,
            captured_at,
            lineage_digest: digest("control-history-lineage", &serde_json::to_value(&lineage)?)?,
        })?;
        let bundle = ControlHistoryBundle {
            profile: PROFILE.into(),
            lineage,
            events,
            checkpoint,
        };
        bundle.bound()?;
        Ok(bundle)
    }
}
