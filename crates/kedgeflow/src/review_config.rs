//! All new review-service material is loaded from checked descriptors, no rereads.
use crate::{
    auth::DualAuthenticator,
    clock::SystemClock,
    config::key,
    error::{Error, Result},
    ledger::EtcdLedger,
    postgres_custody::{Material, Root},
    restore::{RestoreGate, RestoreGateConfig},
    review_evidence::ReviewRegistration,
    review_service::ReviewService,
    tls,
};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewConfig {
    pub listen: std::net::SocketAddr,
    pub url: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
    pub oidc_issuer: String,
    pub oidc_public_key_base64: String,
    pub audience: String,
    pub scope: String,
    pub reviewer_workload: String,
    pub etcd_endpoint: String,
    pub etcd_prefix: String,
    pub etcd_ca: PathBuf,
    pub etcd_certificate: PathBuf,
    pub etcd_private_key: PathBuf,
    pub etcd_token_file: PathBuf,
    pub provider_key_id: String,
    pub provider_signing_key_file: PathBuf,
    pub registration: ReviewRegistration,
    #[serde(default)]
    pub require_control: bool,
    #[serde(default)]
    pub shared_auth: Option<crate::shared_auth::SharedAuthConfig>,
    #[serde(default)]
    pub restore_gate: Option<RestoreGateConfig>,
}
pub struct LoadedReview {
    pub config: ReviewConfig,
    pub tls: Arc<rustls::ServerConfig>,
    pub service: Arc<ReviewService>,
    pub ledger: EtcdLedger,
}
fn secret(root: &Root, path: &Path) -> Result<String> {
    let bytes = root.read(path, Material::Secret, 65536)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Invalid("review secret encoding".into()))?
        .trim();
    if value.is_empty() {
        return Err(Error::Invalid("empty review secret".into()));
    }
    Ok(value.into())
}
fn ledger(
    root: &Root,
    endpoint: &str,
    prefix: &str,
    ca: &Path,
    cert: &Path,
    key: &Path,
    token: &Path,
) -> Result<EtcdLedger> {
    let origin = crate::grant_reference::fixed_https(endpoint)?;
    if origin.path() != "/" {
        return Err(Error::Invalid("review etcd must be a HTTPS origin".into()));
    }
    let client = tls::pinned_http_client_pem(
        &root.read(ca, Material::Public, 1 << 20)?,
        &root.read(cert, Material::Public, 1 << 20)?,
        &root.read(key, Material::Secret, 65536)?,
        Duration::from_secs(5),
    )?;
    EtcdLedger::new(client, endpoint, prefix)?.with_auth_token(&secret(root, token)?)
}
impl LoadedReview {
    pub fn load(root: &Path, path: &Path) -> Result<Self> {
        let root = Root::open(root)?;
        let config: ReviewConfig = serde_json::from_value(crate::contracts::strict_value(
            &root.read(path, Material::Public, 1 << 20)?,
        )?)?;
        let tls = tls::server_config_pem(
            &root.read(&config.certificate, Material::Public, 1 << 20)?,
            &root.read(&config.private_key, Material::Secret, 65536)?,
            &root.read(&config.workload_ca, Material::Public, 1 << 20)?,
        )?;
        let signing = ed25519_dalek::SigningKey::from_bytes(&key(&secret(
            &root,
            &config.provider_signing_key_file,
        )?)?);
        let mut store = ledger(
            &root,
            &config.etcd_endpoint,
            &config.etcd_prefix,
            &config.etcd_ca,
            &config.etcd_certificate,
            &config.etcd_private_key,
            &config.etcd_token_file,
        )?;
        if config.require_control {
            store = store.requiring_control(None);
        }
        if let Some(g) = &config.restore_gate {
            store = store.with_restore_gate(RestoreGate::new(ledger(
                &root,
                &g.endpoint,
                &g.prefix,
                &g.ca,
                &g.certificate,
                &g.private_key,
                &g.token_file,
            )?)?)?;
        }
        let mut auth = DualAuthenticator::new(
            &config.oidc_issuer,
            &config.audience,
            &config.url,
            key(&config.oidc_public_key_base64)?,
        )?;
        if let Some(shared) = &config.shared_auth {
            auth = auth.with_shared_replay(store.clone(), shared.clone())?;
        }
        let service = Arc::new(ReviewService::new(
            config.registration.clone(),
            store.clone(),
            Arc::new(SystemClock),
            auth,
            config.scope.clone(),
            config.reviewer_workload.clone(),
            config.provider_key_id.clone(),
            signing,
        )?);
        Ok(Self {
            config,
            tls,
            service,
            ledger: store,
        })
    }
}
