//! Protected native broker material. Snapshot refresh and retained epoch custody
//! are operator responsibilities; --check performs no network authority use.
use crate::{
    broker_authorization::{BrokerAuthorizer, BrokerRegistration},
    broker_service::BrokerService,
    clock::SystemClock,
    config::{key, read_secret},
    contracts::{GrantVerifier, strict_value},
    control_config::keys,
    error::{Error, Result},
    exchange_identity::PinnedExchangeIdentityProvider,
    ledger::EtcdLedger,
    target_token::{ReferenceTokenMinter, TargetTokenVerifier},
    tls,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    #[serde(
        default,
        deserialize_with = "crate::compensation_execution::deserialize_execution"
    )]
    pub inverse_execution: Option<crate::compensation_execution::ExecutionConfig>,
    #[serde(default, deserialize_with = "crate::family::deserialize_selection")]
    pub family: Option<crate::family::Selection>,
    #[serde(
        default,
        deserialize_with = "crate::action_domain::deserialize_selection"
    )]
    pub action_domain: Option<crate::action_domain::Selection>,
    pub listen: std::net::SocketAddr,
    pub external_url: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
    pub etcd_endpoint: String,
    pub etcd_prefix: String,
    pub etcd_ca: PathBuf,
    pub etcd_certificate: PathBuf,
    pub etcd_private_key: PathBuf,
    pub etcd_token_file: PathBuf,
    pub gateway_audience: String,
    pub delegation_audience: String,
    pub grant_keys: BTreeMap<String, String>,
    pub registration: BrokerRegistration,
    #[serde(default)]
    pub identity_snapshot_file: Option<PathBuf>,
    #[serde(default)]
    pub identity_epoch_floor_file: Option<PathBuf>,
    #[serde(default)]
    pub identity_refresh: Option<IdentityRefreshConfig>,
    pub target_key_id: String,
    pub target_signing_key_file: PathBuf,
    pub target_verification_keys: BTreeMap<String, String>,
    #[serde(default)]
    pub allow_unmanaged_fixture: bool,
    #[serde(default)]
    pub installed_trust_digest: Option<String>,
    #[serde(default)]
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRefreshConfig {
    pub authority_id: String,
    pub issuer: String,
    pub authority_keys: BTreeMap<String, String>,
    pub signed_snapshot_file: PathBuf,
    pub head_file: PathBuf,
    pub minimum_epoch_file: PathBuf,
}
impl BrokerConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("broker configuration exceeds bound".into()));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub async fn service(&self) -> Result<Arc<BrokerService>> {
        crate::endpoint::EndpointPolicy::new(&self.external_url)?;
        crate::endpoint::EndpointPolicy::new(&self.gateway_audience)?;
        self.registration.validate()?;
        if !self.allow_unmanaged_fixture && !self.etcd_endpoint.starts_with("https://") {
            return Err(Error::Invalid(
                "managed broker requires HTTPS ledger transport".into(),
            ));
        }
        if !self.allow_unmanaged_fixture
            && self.installed_trust_digest.as_ref().is_none_or(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
        {
            return Err(Error::Invalid(
                "managed broker requires installed trust digest".into(),
            ));
        }
        let grant_keys = keys(&self.grant_keys)?;
        let target_keys = keys(&self.target_verification_keys)?;
        let signer =
            SigningKey::from_bytes(&key(&read_secret(&self.target_signing_key_file).await?)?);
        if target_keys.get(&self.target_key_id) != Some(&signer.verifying_key()) {
            return Err(Error::Invalid("unregistered target signing key".into()));
        }
        let provider: Arc<dyn crate::broker_authorization::ExchangeIdentityProvider> = match (
            &self.identity_refresh,
            &self.identity_snapshot_file,
            &self.identity_epoch_floor_file,
        ) {
            (Some(refresh), None, None) => {
                let floor = read_secret(&refresh.minimum_epoch_file)
                    .await?
                    .parse::<u64>()
                    .map_err(|_| {
                        Error::Invalid("invalid independent identity epoch floor".into())
                    })?;
                let forbidden = grant_keys
                    .values()
                    .chain(target_keys.values())
                    .map(|k| k.to_bytes())
                    .collect();
                let provider = crate::identity_refresh::RefreshingIdentityProvider::new(
                    Arc::new(crate::identity_refresh::FileRefreshSource {
                        head_file: refresh.head_file.clone(),
                        signed_snapshot_file: refresh.signed_snapshot_file.clone(),
                    }),
                    crate::identity_refresh::RealmPins {
                        issuer: refresh.issuer.clone(),
                        subject_audience: self.delegation_audience.clone(),
                        actor_audience: self.external_url.clone(),
                    },
                    refresh.authority_id.clone(),
                    keys(&refresh.authority_keys)?,
                    forbidden,
                    floor,
                )?;
                provider.check_material().await?;
                Arc::new(provider)
            }
            (None, Some(snapshot_file), Some(floor_file)) => {
                let mut raw = Vec::new();
                tokio::fs::File::open(snapshot_file)
                    .await?
                    .take((1 << 20) + 1)
                    .read_to_end(&mut raw)
                    .await?;
                let floor = read_secret(floor_file).await?.parse::<u64>().map_err(|_| {
                    Error::Invalid("invalid independent identity epoch floor".into())
                })?;
                let provider = PinnedExchangeIdentityProvider::from_json(&raw, floor)?;
                let snapshot: crate::exchange_identity::TrustSnapshot =
                    serde_json::from_value(strict_value(&raw)?)?;
                if snapshot.actor_audience != self.external_url
                    || snapshot.subject_audience != self.delegation_audience
                {
                    return Err(Error::Invalid("broker snapshot audience mismatch".into()));
                }
                if snapshot.subject_keys.iter().any(|k| {
                    URL_SAFE_NO_PAD.decode(&k.public_key).is_ok_and(|v| {
                        target_keys
                            .values()
                            .chain(grant_keys.values())
                            .any(|t| t.as_bytes().as_slice() == v)
                    })
                }) {
                    return Err(Error::Invalid("overlapping broker key roles".into()));
                }
                Arc::new(provider)
            }
            _ => {
                return Err(Error::Invalid(
                    "select exactly one complete broker identity mode".into(),
                ));
            }
        };
        let client = tls::pinned_http_client(
            &self.etcd_ca,
            &self.etcd_certificate,
            &self.etcd_private_key,
            Duration::from_secs(5),
        )?;
        let mut ledger = EtcdLedger::new(client, &self.etcd_endpoint, &self.etcd_prefix)?
            .with_auth_token(&read_secret(&self.etcd_token_file).await?)?;
        if !self.allow_unmanaged_fixture {
            ledger = ledger.requiring_control(self.installed_trust_digest.clone());
        }
        if let Some(s) = &self.action_domain {
            ledger = ledger.with_action_domain(s.clone())?;
        }
        if let Some(e) = &self.inverse_execution {
            ledger = e.attach(ledger)?;
        }
        if let Some(family) = &self.family {
            ledger = family.attach(ledger)?;
        }
        if let Some(gate) = &self.restore_gate {
            ledger = gate.attach(ledger).await?;
        }
        let clock = Arc::new(SystemClock);
        let authorizer = BrokerAuthorizer::new(
            self.registration.clone(),
            GrantVerifier {
                keys: grant_keys,
                audience: self.gateway_audience.clone(),
            },
            ledger,
            provider,
            clock.clone(),
        )?;
        let minter = ReferenceTokenMinter::new(
            self.external_url.clone(),
            self.target_key_id.clone(),
            signer,
        )?;
        let verifier = TargetTokenVerifier::new(self.external_url.clone(), target_keys)?;
        Ok(Arc::new(BrokerService::new(
            authorizer,
            &self.external_url,
            Arc::new(minter),
            verifier,
            clock,
        )?))
    }
}
