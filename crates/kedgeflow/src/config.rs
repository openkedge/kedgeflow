//! Strict operator configuration. Secrets and authority operations are never
//! supplied through agent request metadata.
use crate::{
    adapter::HttpAdapter,
    auth::DualAuthenticator,
    broker::{FileAssertion, Rfc8693Broker},
    clock::SystemClock,
    contracts::{GrantVerifier, strict_value},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    gateway::{Gateway, ToolDescriptor},
    grant_reference::{HttpsGrantResolver, fixed_https},
    ledger::EtcdLedger,
    tls,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: std::net::SocketAddr,
    pub external_url: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
    pub grant_key_id: String,
    pub grant_public_key_base64: String,
    pub oidc_issuer: String,
    pub oidc_public_key_base64: String,
    pub etcd_endpoints: Vec<String>,
    pub etcd_prefix: String,
    pub etcd_ca: PathBuf,
    #[serde(default)]
    pub etcd_token_file: PathBuf,
    pub broker_endpoint: String,
    pub broker_ca: PathBuf,
    #[serde(default)]
    pub grant_resolver_endpoint: String,
    #[serde(default)]
    pub grant_resolver_ca: PathBuf,
    pub target_audience: String,
    pub target_scope: String,
    pub actor_workload: String,
    pub actor_token_file: PathBuf,
    pub target_url: String,
    pub target_ca: PathBuf,
    #[serde(default)]
    pub read_token_file: PathBuf,
    pub tools: Vec<ToolDescriptor>,
}
fn key(value: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(value)
        .map_err(|_| Error::Invalid("invalid public key base64".into()))?
        .try_into()
        .map_err(|_| Error::Invalid("public key must be 32-byte Ed25519".into()))
}
async fn read_secret(path: &PathBuf) -> Result<String> {
    let file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(Error::Invalid("invalid secret file".into()));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes).await?;
    if bytes.len() > 65536 {
        return Err(Error::Invalid("secret exceeds bound".into()));
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Invalid("secret UTF8".into()))?
        .trim();
    if value.is_empty() {
        return Err(Error::Invalid("empty configured secret".into()));
    }
    Ok(value.to_owned())
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub fn validate(&self) -> Result<EndpointPolicy> {
        let endpoint = EndpointPolicy::new(&self.external_url)?;
        // One fixed member endpoint is intentional in this HTTP reference client.
        // No automatic mutation retry across members after ambiguous transport.
        if self.etcd_endpoints.len() != 1
            || self.grant_key_id.is_empty()
            || self.actor_workload.is_empty()
        {
            return Err(Error::Invalid(
                "one pinned etcd endpoint, Grant Authority key and actor workload required".into(),
            ));
        }
        let etcd = fixed_https(&self.etcd_endpoints[0])?;
        if etcd.path() != "/" {
            return Err(Error::Invalid("etcd must be a HTTPS origin".into()));
        }
        fixed_https(&self.target_url)?;
        fixed_https(&self.broker_endpoint)?;
        if self.grant_resolver_endpoint.is_empty() != self.grant_resolver_ca.as_os_str().is_empty()
        {
            return Err(Error::Invalid(
                "grant resolver endpoint and CA must be configured together".into(),
            ));
        }
        if !self.grant_resolver_endpoint.is_empty() {
            fixed_https(&self.grant_resolver_endpoint)?;
        }
        key(&self.grant_public_key_base64)?;
        key(&self.oidc_public_key_base64)?;
        let mut names = std::collections::BTreeSet::new();
        for tool in &self.tools {
            tool.validate()?;
            if !names.insert(&tool.name) {
                return Err(Error::Invalid("duplicate registered tool".into()));
            }
        }
        if self.tools.is_empty() {
            return Err(Error::Invalid("empty tool registration".into()));
        }
        Ok(endpoint)
    }
    pub async fn gateway(&self) -> Result<Gateway> {
        self.validate()?;
        let clock = Arc::new(SystemClock);
        let budget = Duration::from_secs(5);
        let client =
            |ca: &PathBuf| tls::pinned_client(ca, &self.certificate, &self.private_key, budget);
        let mut ledger = EtcdLedger::new(
            client(&self.etcd_ca)?.client().clone(),
            &self.etcd_endpoints[0],
            &self.etcd_prefix,
        )?;
        if !self.etcd_token_file.as_os_str().is_empty() {
            ledger = ledger.with_auth_token(&read_secret(&self.etcd_token_file).await?)?;
        }
        let verifier = GrantVerifier {
            keys: BTreeMap::from([(
                self.grant_key_id.clone(),
                VerifyingKey::from_bytes(&key(&self.grant_public_key_base64)?)
                    .map_err(|_| Error::Invalid("invalid Grant Authority key".into()))?,
            )]),
            audience: self.external_url.clone(),
        };
        let auth = DualAuthenticator::new(
            &self.oidc_issuer,
            &self.external_url,
            &self.external_url,
            key(&self.oidc_public_key_base64)?,
        )?;
        let broker = Rfc8693Broker::new(
            &self.broker_endpoint,
            self.target_audience.clone(),
            self.target_scope.clone(),
            client(&self.broker_ca)?,
            Arc::new(FileAssertion {
                workload_id: self.actor_workload.clone(),
                path: self.actor_token_file.clone(),
            }),
            clock.clone(),
            budget,
        )?;
        let read_token = if self.read_token_file.as_os_str().is_empty() {
            String::new()
        } else {
            read_secret(&self.read_token_file).await?
        };
        let adapter = HttpAdapter::new(
            &self.target_url,
            client(&self.target_ca)?,
            self.target_audience.clone(),
            read_token,
            clock.clone(),
        )?;
        let resolver: Option<Arc<dyn crate::grant_reference::GrantResolver>> =
            if self.grant_resolver_endpoint.is_empty() {
                None
            } else {
                Some(Arc::new(HttpsGrantResolver::new(
                    &self.grant_resolver_endpoint,
                    client(&self.grant_resolver_ca)?,
                )?))
            };
        let gateway = Gateway {
            verifier,
            ledger: Arc::new(ledger),
            auth: Arc::new(auth),
            broker: Arc::new(broker),
            adapter: Arc::new(adapter),
            resolver,
            tools: self
                .tools
                .iter()
                .cloned()
                .map(|t| (t.name.clone(), t))
                .collect(),
            timeout: budget,
            clock,
        };
        gateway.validate()?;
        Ok(gateway)
    }
}
