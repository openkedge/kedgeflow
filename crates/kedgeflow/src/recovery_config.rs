//! Operator-owned recovery deployment. No listener or target mutation API.
use crate::{
    clock::SystemClock,
    config::{key, read_secret},
    contracts::{GrantVerifier, strict_value},
    error::{Error, Result},
    grant_reference::{bounded_response, fixed_https},
    ledger::{AuthoritativeObservation, EtcdLedger, OutcomeQuerier},
    recovery::{PROFILE, RecoveryWorker},
    tls,
};
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

pub struct HttpOutcomeQuerier {
    client: reqwest::Client,
    url: reqwest::Url,
    token: String,
}
impl HttpOutcomeQuerier {
    pub fn new(client: reqwest::Client, url: &str, token: String) -> Result<Self> {
        if token.trim().is_empty() {
            return Err(Error::Invalid("query credential required".into()));
        }
        Ok(Self {
            client,
            url: fixed_https(url)?,
            token,
        })
    }
}
#[async_trait]
impl OutcomeQuerier for HttpOutcomeQuerier {
    async fn query(&self, id: &str) -> Result<AuthoritativeObservation> {
        if id.is_empty() || id.len() > 1024 {
            return Err(Error::Invalid("invalid attempt query".into()));
        }
        let response = self
            .client
            .post(self.url.clone())
            .bearer_auth(&self.token)
            .json(&json!({"profile":PROFILE,"operation":"query","attempt_id":id}))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if response.url() != &self.url || !response.status().is_success() {
            return Err(Error::Unavailable("target query failed".into()));
        }
        let raw = bounded_response(response, 65536).await?;
        let value = strict_value(&raw)?;
        crate::recovery::validate(&value)?;
        let observation: AuthoritativeObservation = serde_json::from_value(value)?;
        if observation.attempt_id != id {
            return Err(Error::Unknown("uncorrelated query response".into()));
        }
        Ok(observation)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfig {
    #[serde(default)]
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
    pub etcd_endpoint: String,
    pub etcd_prefix: String,
    pub etcd_ca: PathBuf,
    pub etcd_certificate: PathBuf,
    pub etcd_private_key: PathBuf,
    pub etcd_token_file: PathBuf,
    pub gateway_audience: String,
    pub grant_keys: BTreeMap<String, String>,
    pub query_url: String,
    pub query_ca: PathBuf,
    pub query_certificate: PathBuf,
    pub query_private_key: PathBuf,
    pub query_token_file: PathBuf,
    pub receipt_key_id: String,
    pub receipt_signing_key_file: PathBuf,
    pub source_id: String,
    pub page_size: usize,
    pub poll_interval_ms: u64,
}
impl RecoveryConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid(
                "recovery configuration exceeds bound".into(),
            ));
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        if !(1..=64).contains(&c.page_size)
            || !(100..=60000).contains(&c.poll_interval_ms)
            || c.grant_keys.is_empty()
        {
            return Err(Error::Invalid("invalid recovery polling bounds".into()));
        }
        fixed_https(&c.etcd_endpoint)?;
        fixed_https(&c.query_url)?;
        fixed_https(&c.gateway_audience)?;
        Ok(c)
    }
    pub async fn worker(&self) -> Result<RecoveryWorker> {
        let client = tls::pinned_http_client(
            &self.etcd_ca,
            &self.etcd_certificate,
            &self.etcd_private_key,
            Duration::from_secs(5),
        )?;
        let mut ledger = EtcdLedger::new(client, &self.etcd_endpoint, &self.etcd_prefix)?
            .with_auth_token(&read_secret(&self.etcd_token_file).await?)?;
        if let Some(gate) = &self.restore_gate {
            ledger = gate.attach(ledger).await?;
        }
        let client = tls::pinned_http_client(
            &self.query_ca,
            &self.query_certificate,
            &self.query_private_key,
            Duration::from_secs(5),
        )?;
        let query = HttpOutcomeQuerier::new(
            client,
            &self.query_url,
            read_secret(&self.query_token_file).await?,
        )?;
        let keys = self
            .grant_keys
            .iter()
            .map(|(id, k)| {
                Ok((
                    id.clone(),
                    VerifyingKey::from_bytes(&key(k)?)
                        .map_err(|_| Error::Invalid("invalid grant key".into()))?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        RecoveryWorker::new(
            ledger,
            GrantVerifier {
                keys,
                audience: self.gateway_audience.clone(),
            },
            Arc::new(query),
            self.receipt_key_id.clone(),
            SigningKey::from_bytes(&key(&read_secret(&self.receipt_signing_key_file).await?)?),
            self.source_id.clone(),
            Arc::new(SystemClock),
        )
    }
}
