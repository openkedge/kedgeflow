//! Public, independently approved historical registrations and observer pins.
use crate::{
    contracts::strict_value,
    control_config::keys,
    control_history_verify::{ApprovedHistoryRegistration, ControlHistoryTrust},
    error::{Error, Result},
    governance::ControlRegistration,
    lineage_config::LineageTrustConfig,
};
use serde::Deserialize;
use std::collections::BTreeMap;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRegistrationConfig {
    pub registration: ControlRegistration,
    pub trust: LineageTrustConfig,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlHistoryTrustConfig {
    pub operation: LineageTrustConfig,
    pub historical: Vec<HistoryRegistrationConfig>,
    pub administrative_keys: BTreeMap<String, BTreeMap<String, String>>,
    pub observer_keys: BTreeMap<String, String>,
    pub observer_id: String,
    pub namespace: String,
}
impl ControlHistoryTrustConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 4 << 20 {
            return Err(Error::Invalid("history trust exceeds bound".into()));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub fn registration(&self) -> Result<ControlHistoryTrust> {
        if self.historical.is_empty() || self.historical.len() > 16 {
            return Err(Error::Invalid(
                "historical registration count exceeds bound".into(),
            ));
        }
        let trust = ControlHistoryTrust {
            operation: self.operation.registration()?,
            historical: self
                .historical
                .iter()
                .map(|s| {
                    Ok(ApprovedHistoryRegistration {
                        registration: s.registration.clone(),
                        trust: s.trust.registration()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            administrative_keys: self
                .administrative_keys
                .iter()
                .map(|(id, k)| Ok((id.clone(), keys(k)?)))
                .collect::<Result<BTreeMap<_, _>>>()?,
            observer_keys: keys(&self.observer_keys)?,
            observer_id: self.observer_id.clone(),
            namespace: self.namespace.clone(),
        };
        trust.validate()?;
        Ok(trust)
    }
}
