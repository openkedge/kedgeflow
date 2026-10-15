//! Protected operator configuration for evidence only; no signer or target client.
use crate::{
    compensation::{Contract, Qualifier},
    config::read_secret,
    contracts::strict_value,
    error::{Error, Result},
    grant_reference::fixed_https,
    ledger::EtcdLedger,
    reserved_lineage::TrustConfig,
    tls,
};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompensationConfig {
    pub contract: Contract,
    pub trust: TrustConfig,
    pub etcd_endpoint: String,
    pub etcd_ca: PathBuf,
    pub etcd_certificate: PathBuf,
    pub etcd_private_key: PathBuf,
    pub etcd_token_file: PathBuf,
    #[serde(default)]
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
}
impl CompensationConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("inverse configuration exceeds bound".into()));
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        fixed_https(&c.etcd_endpoint)?;
        c.contract.validate(&c.trust.registration()?)?;
        Ok(c)
    }
    pub async fn qualifier(&self) -> Result<Qualifier> {
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
        if let Some(g) = &self.restore_gate {
            ledger = g.attach(ledger).await?;
        }
        Qualifier::new(ledger, self.contract.clone(), trust)
    }
}
