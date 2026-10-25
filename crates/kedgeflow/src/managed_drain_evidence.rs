//! Closed source/controller/incident statements for the explicit managed profile.
use crate::{
    contracts::{canonical, digest},
    error::{Error, Result},
    family_saga::ObserverPin,
    managed_drain::PROFILE,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
fn refuse() -> Error {
    Error::Refused("managed statement signature or original correlation refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub profile: String,
    pub kind: String,
    pub signer_id: String,
    pub key_id: String,
    pub body: T,
    pub signature: String,
}
impl<T: Serialize> Signed<T> {
    fn message(&self) -> Result<Vec<u8>> {
        let mut b = format!("KedgeFlow:{PROFILE}\0").into_bytes();
        b.extend(canonical(&json!({"profile":self.profile,"kind":self.kind,"signer_id":self.signer_id,"key_id":self.key_id,"body":self.body}))?);
        Ok(b)
    }
    pub fn sign(
        kind: &str,
        body: T,
        pin: &ObserverPin,
        key_id: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::Signer;
        if crate::control_config::keys(&pin.keys)?.get(key_id) != Some(&key.verifying_key()) {
            return Err(refuse());
        }
        let mut s = Self {
            profile: PROFILE.into(),
            kind: kind.into(),
            signer_id: pin.id.clone(),
            key_id: key_id.into(),
            body,
            signature: String::new(),
        };
        s.signature = URL_SAFE_NO_PAD.encode(key.sign(&s.message()?).to_bytes());
        Ok(s)
    }
    pub fn verify(&self, kind: &str, pin: &ObserverPin) -> Result<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        if self.profile != PROFILE || self.kind != kind || self.signer_id != pin.id {
            return Err(refuse());
        }
        let keys = crate::control_config::keys(&pin.keys)?;
        let key = keys.get(&self.key_id).ok_or_else(refuse)?;
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| refuse())?;
        if URL_SAFE_NO_PAD.encode(&raw) != self.signature {
            return Err(refuse());
        }
        let sig = ed25519_dalek::Signature::from_slice(&raw).map_err(|_| refuse())?;
        key.verify_strict(&self.message()?, &sig)
            .map_err(|_| refuse())
    }
    pub fn digest(&self) -> Result<String> {
        digest("managed-drain-statement", &json!(self))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    Accepted,
    Pending,
    Send,
    ClosedNoEffect,
    ClosedAbsence,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub profile: String,
    pub kind: String,
    pub signer_id: String,
    pub key_id: String,
    pub signature: String,
}
impl Header {
    pub fn state(s: &crate::kube_drain_proof::Signed<crate::kube_drain_journal::State>) -> Self {
        Self {
            profile: s.profile.clone(),
            kind: s.kind.clone(),
            signer_id: s.signer_id.clone(),
            key_id: s.key_id.clone(),
            signature: s.signature.clone(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub kind: ControlKind,
    pub origin_digest: String,
    pub enrollment_digest: String,
    pub policy_digest: String,
    pub operating_head_digest: String,
    pub query_slot_digest: Option<String>,
    pub sequence: u64,
    pub checked_at: i64,
    pub mechanical_digest: String,
    pub mechanical_header: Header,
    pub sql: Option<crate::current_reservation::Witness>,
    pub native_authority: Option<crate::kube_drain_journal::Authority>,
}
pub type ControlProof = Signed<Control>;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentReport {
    pub incident_id: String,
    pub event_digest: String,
    pub original: crate::physical_operations::Original,
    pub deadline: i64,
    pub opened_at: i64,
    pub resource_owner_id: String,
    pub on_call_team_id: String,
    pub sink_id: String,
    pub physical_state: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub incident_id: String,
    pub event_digest: String,
    pub received_at: i64,
}
pub type Ack = Signed<Acknowledgement>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub profile: String,
    pub enrollment_digest: String,
    pub origin: crate::managed_drain_journal::Origin,
    pub events: Vec<crate::managed_drain_journal::Event>,
    pub controller: crate::kube_drain_proof::Signed<crate::kube_drain_journal::State>,
    pub proof: ControlProof,
}
