//! Independent collector deployment; no worker or execution credentials required.
use crate::{
    auth::DualAuthenticator,
    clock::SystemClock,
    config::{key, read_secret},
    contracts::{GrantVerifier, Subject, strict_value},
    control_config::keys,
    error::{Error, Result},
    ledger::EtcdLedger,
    outcome_report_service::{OutcomeReportService, ReporterTrust},
    tls,
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeReportConfig {
    #[serde(
        default,
        deserialize_with = "crate::action_domain::deserialize_selection"
    )]
    pub action_domain: Option<crate::action_domain::Selection>,
    #[serde(default)]
    pub shared_auth: Option<crate::shared_auth::SharedAuthConfig>,
    #[serde(default)]
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
    pub listen: std::net::SocketAddr,
    pub external_url: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
    pub oidc_issuer: String,
    pub delegation_audience: String,
    pub oidc_public_key_base64: String,
    pub etcd_endpoint: String,
    pub etcd_prefix: String,
    pub etcd_ca: PathBuf,
    pub etcd_certificate: PathBuf,
    pub etcd_private_key: PathBuf,
    pub etcd_token_file: PathBuf,
    pub tenant: String,
    pub conflict_domain: String,
    pub source_id: String,
    pub reporter_subject: Subject,
    pub report_scope: String,
    pub gateway_audience: String,
    pub grant_keys: BTreeMap<String, String>,
    pub outcome_keys: BTreeMap<String, String>,
    pub collector_id: String,
    pub acknowledgement_key_id: String,
    pub acknowledgement_signing_key_file: PathBuf,
}
impl OutcomeReportConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("outcome configuration exceeds bound".into()));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub async fn service(&self) -> Result<Arc<OutcomeReportService>> {
        let client = tls::pinned_http_client(
            &self.etcd_ca,
            &self.etcd_certificate,
            &self.etcd_private_key,
            Duration::from_secs(5),
        )?;
        let mut ledger = EtcdLedger::new(client, &self.etcd_endpoint, &self.etcd_prefix)?
            .with_auth_token(&read_secret(&self.etcd_token_file).await?)?;
        if let Some(s) = &self.action_domain {
            ledger = ledger.with_action_domain(s.clone())?;
        }
        if let Some(gate) = &self.restore_gate {
            ledger = gate.attach(ledger).await?;
        }
        let mut auth = DualAuthenticator::new(
            &self.oidc_issuer,
            &self.delegation_audience,
            &self.external_url,
            key(&self.oidc_public_key_base64)?,
        )?;
        if let Some(shared) = &self.shared_auth {
            auth = auth.with_shared_replay(ledger.clone(), shared.clone())?;
        }
        let trust = ReporterTrust {
            tenant: self.tenant.clone(),
            conflict_domain: self.conflict_domain.clone(),
            source_id: self.source_id.clone(),
            subject: self.reporter_subject.clone(),
            required_scope: self.report_scope.clone(),
            grants: GrantVerifier {
                keys: keys(&self.grant_keys)?,
                audience: self.gateway_audience.clone(),
            },
            outcome_keys: keys(&self.outcome_keys)?,
        };
        let signer = SigningKey::from_bytes(&key(&read_secret(
            &self.acknowledgement_signing_key_file,
        )
        .await?)?);
        Ok(Arc::new(OutcomeReportService::new(
            trust,
            ledger,
            auth,
            self.collector_id.clone(),
            self.acknowledgement_key_id.clone(),
            signer,
            Arc::new(SystemClock),
        )?))
    }
}
