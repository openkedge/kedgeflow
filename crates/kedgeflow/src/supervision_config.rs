//! Separate operator enrollment for OutcomeService supervision and reporting.
use crate::{
    clock::SystemClock,
    config::{key, read_secret},
    contracts::{GrantVerifier, Subject, strict_value},
    control_config::keys,
    error::{Error, Result},
    outcome_report_client::{CollectorTrust, OutcomeReportClient},
    outcome_report_service::ReporterTrust,
    recovery_config::RecoveryConfig,
    supervision::{IncidentPolicy, OutcomeSupervisor},
    tls,
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryConfig {
    pub collector_id: String,
    pub collector_url: String,
    pub collector_ca: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub token_file: PathBuf,
    pub dpop_signing_key_file: PathBuf,
    pub tenant: String,
    pub conflict_domain: String,
    pub reporter_subject: Subject,
    pub report_scope: String,
    pub outcome_keys: BTreeMap<String, String>,
    pub acknowledgement_keys: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionConfig {
    pub recovery: RecoveryConfig,
    pub delivery: DeliveryConfig,
    pub incident_policy: IncidentPolicy,
    pub receipt_budget: usize,
}
impl SupervisionConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 2 << 20 {
            return Err(Error::Invalid(
                "supervisor configuration exceeds bound".into(),
            ));
        }
        let v = strict_value(raw)?;
        // Preserve the existing recovery bounds and origin checks.
        RecoveryConfig::decode(&crate::contracts::canonical(&v["recovery"])?)?;
        let c: Self = serde_json::from_value(v)?;
        c.incident_policy.validate()?;
        if !(1..=64).contains(&c.receipt_budget) {
            return Err(Error::Invalid("invalid supervisor receipt budget".into()));
        }
        Ok(c)
    }
    pub async fn supervisor(&self) -> Result<OutcomeSupervisor> {
        let r = &self.recovery;
        let d = &self.delivery;
        let outcome = keys(&d.outcome_keys)?;
        let reporter = ReporterTrust {
            tenant: d.tenant.clone(),
            conflict_domain: d.conflict_domain.clone(),
            source_id: r.source_id.clone(),
            subject: d.reporter_subject.clone(),
            required_scope: d.report_scope.clone(),
            grants: GrantVerifier {
                keys: r
                    .grant_keys
                    .iter()
                    .map(|(id, k)| {
                        Ok((
                            id.clone(),
                            ed25519_dalek::VerifyingKey::from_bytes(&key(k)?).map_err(|_| {
                                Error::Invalid("invalid supervisor grant pin".into())
                            })?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?,
                audience: r.gateway_audience.clone(),
            },
            outcome_keys: outcome,
        };
        let transport = tls::pinned_client(
            &d.collector_ca,
            &d.certificate,
            &d.private_key,
            Duration::from_secs(5),
        )?;
        let client = OutcomeReportClient::new(
            transport,
            CollectorTrust {
                reporter,
                collector_id: d.collector_id.clone(),
                collector_url: d.collector_url.clone(),
                acknowledgement_keys: keys(&d.acknowledgement_keys)?,
            },
            read_secret(&d.token_file).await?,
            SigningKey::from_bytes(&key(&read_secret(&d.dpop_signing_key_file).await?)?),
            Arc::new(SystemClock),
        )?;
        OutcomeSupervisor::new(
            r.worker().await?,
            client,
            self.incident_policy.clone(),
            self.receipt_budget,
            Arc::new(SystemClock),
        )
    }
}
