//! Protected operator configuration; no listener, signing key or target client.
use crate::{
    config::read_secret,
    contracts::strict_value,
    error::{Error, Result},
    grant_reference::fixed_https,
    ledger::EtcdLedger,
    reserved_lineage::TrustConfig,
    saga::{Plan, SagaObserver},
    tls,
};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SagaConfig {
    #[serde(
        default,
        deserialize_with = "crate::action_domain::deserialize_selection"
    )]
    pub action_domain: Option<crate::action_domain::Selection>,
    #[serde(default, deserialize_with = "crate::family::deserialize_selection")]
    pub family: Option<crate::family::Selection>,
    pub plan: Plan,
    pub trust: TrustConfig,
    pub etcd_endpoint: String,
    pub etcd_ca: PathBuf,
    pub etcd_certificate: PathBuf,
    pub etcd_private_key: PathBuf,
    pub etcd_token_file: PathBuf,
    #[serde(default)]
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
}
impl SagaConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("saga configuration exceeds bound".into()));
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        fixed_https(&c.etcd_endpoint)?;
        c.plan.validate(&c.trust.registration()?)?;
        Ok(c)
    }
    pub async fn observer(&self) -> Result<SagaObserver> {
        let trust = self.trust.registration()?;
        let client = tls::pinned_http_client(
            &self.etcd_ca,
            &self.etcd_certificate,
            &self.etcd_private_key,
            Duration::from_secs(5),
        )?;
        let mut ledger = EtcdLedger::new(client, &self.etcd_endpoint, &trust.namespace)?
            .with_auth_token(&read_secret(&self.etcd_token_file).await?)?
            .requiring_control(None)
            .with_reservation(trust.registration.clone())?;
        if let Some(s) = &self.action_domain {
            ledger = ledger.with_action_domain(s.clone())?;
        }
        if let Some(f) = &self.family {
            ledger = f.attach(ledger)?;
        }
        if let Some(g) = &self.restore_gate {
            ledger = g.attach(ledger).await?;
        }
        SagaObserver::new(ledger, self.plan.clone(), trust)
    }
}
