//! Strict operator configuration. Secrets and authority operations are never
//! supplied through agent request metadata.
use crate::{
    adapter::{HttpAdapter, ResourceAdapter},
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

/// Explicit RFC 0025 opt-in. No SQL endpoint, key or registration is caller selected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlAdapterConfig {
    pub profile: String,
    pub registration: crate::postgres_target::Registration,
    pub token_issuer: String,
    pub target_keys: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(
        default,
        deserialize_with = "crate::compensation_execution::deserialize_execution"
    )]
    pub inverse_execution: Option<crate::compensation_execution::ExecutionConfig>,
    #[serde(
        default,
        deserialize_with = "crate::action_domain::deserialize_selection"
    )]
    pub action_domain: Option<crate::action_domain::Selection>,
    #[serde(default)]
    pub reservation: Option<crate::reserved_leaf::Registration>,
    #[serde(default)]
    pub shared_auth: Option<crate::shared_auth::SharedAuthConfig>,
    #[serde(default)]
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
    #[serde(default)]
    pub require_control: bool,
    #[serde(default)]
    pub enforcement: Option<crate::gateway_control::GatewayControlConfig>,
    pub listen: std::net::SocketAddr,
    pub external_url: String,
    /// Shared leaf-control delegation audience; blank retains the legacy URL.
    #[serde(default)]
    pub delegation_audience: String,
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
    #[serde(default)]
    pub postgres_adapter: Option<SqlAdapterConfig>,
}
pub(crate) fn key(value: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(value)
        .map_err(|_| Error::Invalid("invalid public key base64".into()))?
        .try_into()
        .map_err(|_| Error::Invalid("public key must be 32-byte Ed25519".into()))
}
pub(crate) async fn read_secret(path: &PathBuf) -> Result<String> {
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
        if let Some(shared) = &self.shared_auth {
            shared.validate(&self.oidc_issuer)?;
        }
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
            if tool.inverse_contract.as_ref()
                != self.inverse_execution.as_ref().map(|e| &e.contract)
                && (tool.inverse_contract.is_some() || self.inverse_execution.is_some())
            {
                return Err(Error::Invalid(
                    "inverse tool requires matching execution configuration".into(),
                ));
            }
            if !names.insert(&tool.name) {
                return Err(Error::Invalid("duplicate registered tool".into()));
            }
        }
        if self.tools.is_empty() {
            return Err(Error::Invalid("empty tool registration".into()));
        }
        let sql_tools = self
            .tools
            .iter()
            .filter(|t| {
                t.action
                    .as_ref()
                    .is_some_and(|a| a.id == crate::postgres_action::ACTION)
            })
            .count();
        if let Some(sql) = &self.postgres_adapter {
            let pin = &sql.registration;
            pin.validate()?;
            let tokens = crate::target_token::TargetTokenVerifier::new(
                sql.token_issuer.clone(),
                crate::control_config::keys(&sql.target_keys)?,
            )?;
            let grant_key = VerifyingKey::from_bytes(&key(&self.grant_public_key_base64)?)
                .map_err(|_| Error::Invalid("invalid grant key".into()))?;
            if sql.profile != crate::leaf_action::PROFILE
                || self.tools.len() != 1
                || sql_tools != 1
                || !self.read_token_file.as_os_str().is_empty()
                || tokens.keys().any(|k| k == &grant_key)
                || pin.action.version != "1.0"
                || pin.action.id != crate::postgres_action::ACTION
                || pin.target_audience != self.target_audience
                || pin.target_scope != self.target_scope
            {
                return Err(Error::Invalid("SQL adapter configuration mismatch".into()));
            }
            let tool = &self.tools[0];
            if tool.read_only
                || tool.action.as_ref() != Some(&pin.action)
                || tool.resource.as_ref() != Some(&pin.resource)
                || tool.conflict_domain != pin.conflict_domain
                || tool.adapter_contract != pin.adapter_contract
                || tool.predicate_id != pin.predicate_id
                || tool.predicate_version != pin.predicate_version
            {
                return Err(Error::Invalid(
                    "SQL adapter/tool registration mismatch".into(),
                ));
            }
        } else if sql_tools != 0 {
            return Err(Error::Invalid(
                "SQL tool requires explicit SQL adapter".into(),
            ));
        }
        if let Some(r) = &self.reservation {
            r.validate()?;
            let issuer = BTreeMap::from([(
                self.grant_key_id.clone(),
                VerifyingKey::from_bytes(&key(&self.grant_public_key_base64)?)
                    .map_err(|_| Error::Invalid("invalid issuer key".into()))?,
            )]);
            if !self.require_control
                || self.tools.len() != 1
                || crate::control_config::keys(&r.issuer_keys)? != issuer
            {
                return Err(Error::Invalid(
                    "reserved gateway needs one managed tool and exact issuer role".into(),
                ));
            }
            let t = &self.tools[0];
            if t.read_only
                || t.action.as_ref() != Some(&r.scope.action)
                || t.resource.as_ref() != Some(&r.scope.resource)
                || t.conflict_domain != r.scope.conflict_domain
                || t.adapter_contract != r.scope.adapter_contract
                || r.scope.predicate_descriptor["id"].as_str() != Some(t.predicate_id.as_str())
                || r.scope.predicate_descriptor["version"].as_str()
                    != Some(t.predicate_version.as_str())
                || self.external_url != r.scope.audience
            {
                return Err(Error::Invalid("reserved gateway scope mismatch".into()));
            }
        }
        if let Some(e) = &self.enforcement {
            if !self.require_control
                || self.etcd_token_file.as_os_str().is_empty()
                || e.component_id.is_empty()
                || e.workload_id.is_empty()
                || self
                    .tools
                    .iter()
                    .filter(|t| !t.read_only)
                    .map(|t| &t.conflict_domain)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != 1
            {
                return Err(Error::Invalid(
                    "gateway control requires one managed domain and enrolled component".into(),
                ));
            }
            EndpointPolicy::new(&e.control_url)?;
            crate::control_config::keys(&e.installation_keys)?;
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
        if self.require_control {
            ledger = ledger.requiring_control(None);
        }
        if let Some(r) = &self.reservation {
            ledger = ledger.with_reservation(r.clone())?;
        }
        if let Some(s) = &self.action_domain {
            ledger = ledger.with_action_domain(s.clone())?;
        }
        if let Some(e) = &self.inverse_execution {
            ledger = e.attach(ledger)?;
        }
        if let Some(gate) = &self.restore_gate {
            ledger = gate.attach(ledger).await?;
        }
        let verifier = GrantVerifier {
            keys: BTreeMap::from([(
                self.grant_key_id.clone(),
                VerifyingKey::from_bytes(&key(&self.grant_public_key_base64)?)
                    .map_err(|_| Error::Invalid("invalid Grant Authority key".into()))?,
            )]),
            audience: self.external_url.clone(),
        };
        let mut auth = DualAuthenticator::new(
            &self.oidc_issuer,
            if self.delegation_audience.is_empty() {
                &self.external_url
            } else {
                &self.delegation_audience
            },
            &self.external_url,
            key(&self.oidc_public_key_base64)?,
        )?;
        if let Some(shared) = &self.shared_auth {
            auth = auth.with_shared_replay(ledger.clone(), shared.clone())?;
        }
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
        let adapter: Arc<dyn ResourceAdapter> = if let Some(sql) = &self.postgres_adapter {
            Arc::new(crate::postgres_adapter::PostgresAdapter::new(
                &self.target_url,
                client(&self.target_ca)?,
                sql.registration.clone(),
                verifier.clone(),
                crate::target_token::TargetTokenVerifier::new(
                    sql.token_issuer.clone(),
                    crate::control_config::keys(&sql.target_keys)?,
                )?,
                clock.clone(),
            )?)
        } else {
            Arc::new(HttpAdapter::new(
                &self.target_url,
                client(&self.target_ca)?,
                self.target_audience.clone(),
                read_token,
                clock.clone(),
            )?)
        };
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
            adapter,
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
        if let Some(e) = &self.enforcement {
            key(&read_secret(&e.acknowledgement_key_file).await?)?;
            client(&e.control_ca)?;
        }
        gateway.validate()?;
        Ok(gateway)
    }
}
