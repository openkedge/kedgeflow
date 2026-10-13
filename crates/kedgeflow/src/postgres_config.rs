//! Protected local target configuration; --check loads material without SQL use.
use crate::{
    clock::SystemClock,
    config::read_secret,
    contracts::{GrantVerifier, strict_value},
    control_config::keys,
    error::{Error, Result},
    postgres_store::{PostgresStore, UnixDatabase},
    postgres_target::{Registration, TargetService},
    target_token::TargetTokenVerifier,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresTargetConfig {
    pub listen: std::net::SocketAddr,
    pub dispatch_url: String,
    pub query_url: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
    pub database: UnixDatabase,
    pub gateway_audience: String,
    pub grant_keys: BTreeMap<String, String>,
    pub token_issuer: String,
    pub target_keys: BTreeMap<String, String>,
    pub query_token_file: PathBuf,
    pub registration: Registration,
}
impl PostgresTargetConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("SQL configuration exceeds bound".into()));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub async fn service(&self) -> Result<Arc<TargetService>> {
        Ok(Arc::new(TargetService::new(
            self.registration.clone(),
            GrantVerifier {
                keys: keys(&self.grant_keys)?,
                audience: self.gateway_audience.clone(),
            },
            TargetTokenVerifier::new(self.token_issuer.clone(), keys(&self.target_keys)?)?,
            Arc::new(PostgresStore::new(self.database.clone())?),
            Arc::new(SystemClock),
            &self.dispatch_url,
            &self.query_url,
            &read_secret(&self.query_token_file).await?,
        )?))
    }
}
