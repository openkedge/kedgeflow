//! Separate controller statements and read-only physical observation signatures.
use crate::{
    contracts::{canonical, digest},
    error::{Error, Result},
    family_saga::ObserverPin,
    kube_drain::{Contract, PROFILE},
    kube_drain_api::Inventory,
    kube_drain_journal::State,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
fn refuse() -> Error {
    Error::Refused("Kubernetes controller/observer proof refused".into())
}
/// A present extension is a closed object; explicit null must not normalize
/// into absence when decoding a legacy registration or snapshot.
pub(crate) fn deserialize_optional<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let v = crate::contracts::strict_deserialize(d)?;
    if !v.is_object() {
        return Err(serde::de::Error::custom(
            "physical extension must be an object",
        ));
    }
    serde_json::from_value(v)
        .map(Some)
        .map_err(serde::de::Error::custom)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub contract: Contract,
    pub controller: ObserverPin,
    pub observer: ObserverPin,
    pub control_trust: serde_json::Value,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional"
    )]
    pub operating: Option<crate::managed_drain::Enrollment>,
}
impl Trust {
    pub fn control(&self) -> Result<crate::control_history_verify::ControlHistoryTrust> {
        crate::control_history_config::ControlHistoryTrustConfig::decode(&canonical(
            &self.control_trust,
        )?)?
        .registration()
    }
    pub fn action(&self) -> &str {
        if self.operating.is_some() {
            crate::managed_drain::ACTION
        } else {
            crate::kube_drain::ACTION
        }
    }
    pub fn version(&self) -> &str {
        if self.operating.is_some() {
            crate::managed_drain::VERSION
        } else {
            "1.0"
        }
    }
    pub fn adapter(&self) -> serde_json::Value {
        if self.operating.is_some() {
            crate::managed_drain::adapter_contract()
        } else {
            crate::kube_drain::adapter_contract()
        }
    }
    pub fn schema(&self) -> Result<serde_json::Value> {
        match &self.operating {
            Some(e) => e.schema(&self.contract),
            None => self.contract.parameter_schema(),
        }
    }
    pub fn signing_keys(&self) -> Result<Vec<ed25519_dalek::VerifyingKey>> {
        let mut out = Vec::new();
        for pin in [&self.controller, &self.observer] {
            out.extend(crate::control_config::keys(&pin.keys)?.values().copied());
        }
        if let Some(e) = &self.operating {
            for pin in [
                &e.operating_observer,
                &e.current_sql.provider,
                &e.current_sql.storage.owner,
            ] {
                out.extend(crate::control_config::keys(&pin.keys)?.values().copied());
            }
            out.extend(
                crate::control_config::keys(&e.policy.incident_sink.acknowledgement_keys)?
                    .values()
                    .copied(),
            );
        }
        Ok(out)
    }
    pub fn audit_signing_keys(&self) -> Result<Vec<ed25519_dalek::VerifyingKey>> {
        let mut keys = self.signing_keys()?;
        if let Some(e) = &self.operating {
            let providers = crate::control_config::keys(&e.current_sql.provider.keys)?;
            keys.retain(|key| !providers.values().any(|p| p == key));
        }
        Ok(keys)
    }
    pub fn validate(&self) -> Result<()> {
        self.contract.validate()?;
        if let Some(e) = &self.operating {
            e.validate(&self.contract)?;
        }

        let mut h = self.control()?;
        if h.historical.iter().any(|entry| {
            entry.registration.scope.action.id != self.action()
                || entry.registration.scope.action.version != self.version()
        }) {
            return Err(refuse());
        }
        if let Some(e) = &self.operating {
            crate::current_reservation::validate_requirement(
                &e.current_sql,
                &h.operation.admission,
            )?;
        }
        let all = self.signing_keys()?;
        if all
            .iter()
            .map(|k| *k.as_bytes())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != all.len()
        {
            return Err(refuse());
        }
        if let Some(e) = &self.operating {
            let ids = [
                &self.controller.id,
                &self.observer.id,
                &e.operating_observer.id,
                &e.current_sql.provider.id,
                &e.current_sql.storage.owner.id,
                &e.policy.incident_sink.id,
            ];
            if ids
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 6
            {
                return Err(refuse());
            }
        }
        if h.observer_id != self.observer.id
            || h.observer_keys != crate::control_config::keys(&self.observer.keys)?
        {
            return Err(refuse());
        }
        if self.operating.is_some() {
            for (i, key) in self.audit_signing_keys()?.iter().enumerate() {
                h.observer_keys.insert(format!("managed-source-{i}"), *key);
            }
        }
        let controller = crate::control_config::keys(&self.controller.keys)?;
        for (id, key) in &controller {
            h.observer_keys
                .insert(format!("physical-controller-{id}"), *key);
        }
        h.validate()?;

        if h.administrative_keys.values().any(|keys| {
            keys.values()
                .any(|key| controller.values().any(|c| c == key))
        }) {
            return Err(refuse());
        }
        if self.controller.id.is_empty()
            || self.observer.id.is_empty()
            || self.controller.id == self.observer.id
            || self.controller.keys.is_empty()
            || self.observer.keys.is_empty()
            || self.controller.keys.len() > 16
            || self.observer.keys.len() > 16
        {
            return Err(refuse());
        }
        let c = crate::control_config::keys(&self.controller.keys)?;
        let o = crate::control_config::keys(&self.observer.keys)?;
        if c.values().any(|k| o.values().any(|v| k == v)) {
            return Err(refuse());
        }
        Ok(())
    }
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
        key: &SigningKey,
    ) -> Result<Self> {
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
        let signature = Signature::from_slice(&raw).map_err(|_| refuse())?;
        key.verify_strict(&self.message()?, &signature)
            .map_err(|_| refuse())
    }
    pub fn digest(&self) -> Result<String> {
        digest("kube-drain-signed-record", &json!(self))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoDispatch {
    pub profile: String,
    pub contract_digest: String,
    pub operation_key: String,
    pub grant_digest: String,
    pub attempt_id: String,
    pub closed_at: i64,
    pub family_head: String,
    pub phase_head: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub profile: String,
    pub contract_digest: String,
    pub operation_key: String,
    pub controller_digest: Option<String>,
    pub gate_digest: Option<String>,
    pub observed_at: i64,
    pub native_epoch: String,
    pub inventory: Option<Inventory>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub controller: Signed<State>,
    pub observation: Signed<Observation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub controller: Option<Signed<State>>,
    pub closed_absence: Option<Signed<NoDispatch>>,
    pub observation: Signed<Observation>,
    pub control_history: Option<Box<crate::control_history::ControlHistoryBundle>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_completion: Option<Box<Completion>>,
}
impl Capture {
    /// Native original grant/attempt correlation and original phase/control-head
    /// replay are mandatory in addition to these source signatures.
    pub fn verify_sources(&self, t: &Trust, operation: &str, captured_at: i64) -> Result<()> {
        t.validate()?;
        self.observation
            .verify("physical_observation", &t.observer)?;
        let o = &self.observation.body;
        if o.profile != PROFILE
            || o.contract_digest != t.contract.digest()?
            || o.operation_key != operation
            || o.observed_at > captured_at
            || o.observed_at < 0
            || !crate::grant_reference::valid_reference(&o.native_epoch)
            || self.controller.is_some() && self.closed_absence.is_some()
            || self.closed_absence.is_some()
                && (self.control_history.is_some() || self.retained_completion.is_some())
        {
            return Err(refuse());
        }
        if let Some(s) = &self.controller {
            s.verify("controller_state", &t.controller)?;
            if o.controller_digest.as_deref() != Some(s.digest()?.as_str())
                || o.gate_digest.is_some()
                || o.inventory.is_none() && s.body.closed.is_none()
            {
                return Err(refuse());
            }
        } else if o.controller_digest.is_some() {
            return Err(refuse());
        }
        if let Some(g) = &self.closed_absence {
            g.verify("closed_no_dispatch", &t.controller)?;
            let p = &g.body;
            if p.profile != PROFILE
                || p.contract_digest != t.contract.digest()?
                || p.operation_key != operation
                || p.closed_at > o.observed_at
                || p.closed_at < 0
                || !crate::grant_reference::valid_reference(&p.grant_digest)
                || !crate::grant_reference::valid_reference(&p.family_head)
                || !crate::grant_reference::valid_reference(&p.phase_head)
                || p.attempt_id.is_empty()
                || p.attempt_id.len() > 256
                || o.gate_digest.as_deref() != Some(g.digest()?.as_str())
            {
                return Err(refuse());
            }
        } else if o.gate_digest.is_some() {
            return Err(refuse());
        }
        if let Some(i) = &o.inventory {
            i.validate(&t.contract)?;
            if i.until > o.observed_at {
                return Err(refuse());
            }
        }
        Ok(())
    }
}
