//! Explicit protected SQL inverse target and independent evaluator configurations.
use crate::{
    action_domain::Topology,
    clock::SystemClock,
    compensation_execution::ExecutionConfig,
    compensation_target::{PROFILE, TargetTrust},
    compensation_target_http::Service,
    config::{key, read_secret},
    contracts::{GrantVerifier, strict_value},
    control_config::keys,
    error::{Error, Result},
    postgres_compensation::{Database, PostgresCompensationStore},
    postgres_target::Registration,
    target_token::TargetTokenVerifier,
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    pub inverse_execution: ExecutionConfig,
    pub topology: Topology,
    pub registration: Registration,
    pub forward_gateway_workload: String,
}
impl TrustConfig {
    pub fn registration(&self) -> Result<TargetTrust> {
        if self.inverse_execution.profile != crate::compensation_execution::PROFILE {
            return Err(Error::Refused("inverse target profile refused".into()));
        }
        Ok(TargetTrust {
            contract: self.inverse_execution.contract.clone(),
            forward: self.inverse_execution.forward.registration()?,
            topology: self.topology.clone(),
            registration: self.registration.clone(),
            forward_gateway_workload: self.forward_gateway_workload.clone(),
            outcome_keys: keys(&self.inverse_execution.outcome_keys)?,
            outcome_source: self.inverse_execution.source_id.clone(),
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub listen: std::net::SocketAddr,
    pub dispatch_url: String,
    pub query_url: String,
    pub barrier_url: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
    pub database: Database,
    pub trust: TrustConfig,
    pub grant_keys: BTreeMap<String, String>,
    pub gateway_audience: String,
    pub token_issuer: String,
    pub target_keys: BTreeMap<String, String>,
    pub query_token_file: PathBuf,
    pub barrier_token_file: PathBuf,
    pub barrier_workload: String,
    pub barrier_key_id: String,
    pub barrier_signing_key_file: PathBuf,
    pub barrier_lifetime_ms: i64,
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("inverse target config exceeds bound".into()));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub fn store(&self, peer_uid: Option<u32>) -> Result<PostgresCompensationStore> {
        let store = PostgresCompensationStore::new(self.database.clone())?;
        if let Some(uid) = peer_uid {
            store.with_peer_uid(uid)
        } else {
            Ok(store)
        }
    }
    pub async fn service(&self, peer_uid: Option<u32>) -> Result<Arc<Service>> {
        if self.profile != PROFILE {
            return Err(Error::Refused("inverse target profile refused".into()));
        }
        let signer =
            SigningKey::from_bytes(&key(&read_secret(&self.barrier_signing_key_file).await?)?);
        Ok(Arc::new(Service::new(
            self.trust.registration()?,
            GrantVerifier {
                keys: keys(&self.grant_keys)?,
                audience: self.gateway_audience.clone(),
            },
            TargetTokenVerifier::new(self.token_issuer.clone(), keys(&self.target_keys)?)?,
            Arc::new(self.store(peer_uid)?),
            Arc::new(SystemClock),
            [&self.dispatch_url, &self.query_url, &self.barrier_url],
            &read_secret(&self.query_token_file).await?,
            &read_secret(&self.barrier_token_file).await?,
            self.barrier_workload.clone(),
            self.barrier_key_id.clone(),
            signer,
            self.barrier_lifetime_ms,
        )?))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorConfig {
    pub contract: crate::compensation::Contract,
    pub forward: crate::reserved_lineage::TrustConfig,
    pub key_id: String,
    pub signing_key_file: PathBuf,
}
