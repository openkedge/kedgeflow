//! Explicit descriptor/mode custody for SQL target files; no OS isolation claim.
use crate::{
    error::Result, postgres_config::PostgresTargetConfig, postgres_target::TargetService, tls,
};
use std::{path::Path, sync::Arc};
pub const PROFILE: &str = "KF-POSTGRES-CUSTODY-0.1-draft";
pub struct LoadedTarget {
    pub config: PostgresTargetConfig,
    pub tls: Arc<rustls::ServerConfig>,
    pub service: Arc<TargetService>,
    pub effective_uid: u32,
}
// Kept at the original path for SQL target callers.
pub use crate::file_custody::{Material, Root};
impl LoadedTarget {
    pub fn load(root: &Path, config_path: &Path) -> Result<Self> {
        Self::load_with_peer(root, config_path, None)
    }
    pub fn load_with_peer(root: &Path, config_path: &Path, peer_uid: Option<u32>) -> Result<Self> {
        let root = Root::open(root)?;
        let config =
            PostgresTargetConfig::decode(&root.read(config_path, Material::Public, 1 << 20)?)?;
        let cert = root.read(&config.certificate, Material::Public, 1 << 20)?;
        let key = root.read(&config.private_key, Material::Secret, 65536)?;
        let ca = root.read(&config.workload_ca, Material::Public, 1 << 20)?;
        let token = root.read(&config.query_token_file, Material::Secret, 65536)?;
        let token = std::str::from_utf8(&token)
            .map_err(|_| {
                crate::error::Error::Refused("protected SQL file custody rejected".into())
            })?
            .trim();
        let tls = tls::server_config_pem(&cert, &key, &ca)?;
        let service = config.service_with_peer(token, peer_uid)?;
        Ok(Self {
            config,
            tls,
            service,
            effective_uid: root.uid(),
        })
    }
}
