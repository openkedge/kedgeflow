//! Protected enrollment and stop configuration for a fresh paired domain.
use crate::{
    action_domain::Topology,
    config::read_secret,
    contracts::strict_value,
    error::{Error, Result},
    grant_reference::fixed_https,
    ledger::EtcdLedger,
    tls,
};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDomainConfig {
    pub topology: Topology,
    pub etcd_endpoint: String,
    pub etcd_prefix: String,
    pub etcd_ca: PathBuf,
    pub etcd_certificate: PathBuf,
    pub etcd_private_key: PathBuf,
    pub etcd_token_file: PathBuf,
    #[serde(default)]
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
}
impl ActionDomainConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 128 << 10 {
            return Err(Error::Invalid("paired configuration exceeds bound".into()));
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        c.topology.validate()?;
        if fixed_https(&c.etcd_endpoint)?.path() != "/" {
            return Err(Error::Invalid("etcd must be a HTTPS origin".into()));
        }
        Ok(c)
    }
    pub async fn ledger(&self) -> Result<EtcdLedger> {
        let client = tls::pinned_http_client(
            &self.etcd_ca,
            &self.etcd_certificate,
            &self.etcd_private_key,
            Duration::from_secs(5),
        )?;
        let mut ledger = EtcdLedger::new(client, &self.etcd_endpoint, &self.etcd_prefix)?
            .with_auth_token(&read_secret(&self.etcd_token_file).await?)?;
        if let Some(g) = &self.restore_gate {
            ledger = g.attach(ledger).await?;
        }
        Ok(ledger)
    }
}
