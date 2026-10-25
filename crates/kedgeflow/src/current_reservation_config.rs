//! Protected source service material. This enables a read-only source endpoint,
//! not managed physical execution or a grant/inverse authority.
use crate::{
    clock::{Clock, SystemClock},
    contracts::strict_value,
    current_reservation::PROFILE,
    current_reservation_provider::{FileHead, HeadSource, Provider},
    error::{Error, Result},
    family,
    managed_drain_store::Store,
    postgres_compensation::{CurrentReservationReader, Database},
    postgres_custody::{Material, Root},
};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
fn refuse() -> Error {
    Error::Refused("protected current SQL source configuration refused".into())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub material_root: PathBuf,
    pub family: family::Config,
    pub child_id: String,
    pub database: Database,
    pub postgres_peer_uid: u32,
    pub storage_head_file: PathBuf,
    pub provider_key_id: String,
    pub provider_key_file: PathBuf,
    pub query_token_file: PathBuf,
    pub evidence_token_file: PathBuf,
    pub listen: std::net::SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
}
pub struct Loaded {
    pub config: Config,
    pub provider: Arc<Provider>,
    pub tls: Arc<rustls::ServerConfig>,
    pub query_token: String,
    pub evidence_token: String,
}
fn secret(root: &Root, path: &Path) -> Result<String> {
    String::from_utf8(root.read(path, Material::Secret, 16384)?)
        .map(|v| v.trim().to_owned())
        .map_err(|_| refuse())
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(refuse());
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        c.family.registration.validate()?;
        if c.profile != PROFILE
            || c.family.etcd_prefix != c.family.registration.namespace
            || c.postgres_peer_uid == 0
        {
            return Err(refuse());
        }
        crate::grant_reference::fixed_https(&c.family.etcd_endpoint)?;
        Ok(c)
    }
    pub async fn load(material_root: &Path, path: &Path) -> Result<Loaded> {
        let root = Root::open(material_root)?;
        let c = Self::decode(&root.read(path, Material::Secret, 1 << 20)?)?;
        if c.material_root != material_root {
            return Err(refuse());
        }
        let client = crate::tls::pinned_http_client_pem(
            &root.read(&c.family.etcd_ca, Material::Public, 1 << 20)?,
            &root.read(&c.family.etcd_certificate, Material::Public, 1 << 20)?,
            &root.read(&c.family.etcd_private_key, Material::Secret, 1 << 20)?,
            Duration::from_secs(5),
        )?;
        let mut ledger =
            crate::ledger::EtcdLedger::new(client, &c.family.etcd_endpoint, &c.family.etcd_prefix)?
                .with_auth_token(&secret(&root, &c.family.etcd_token_file)?)?;
        if let Some(gate) = &c.family.restore_gate {
            ledger = gate.attach(ledger).await?;
        }
        let family = family::Family::new(ledger, c.family.registration.clone())?;
        let child = crate::family_saga_runtime::child_ledger(
            &family.manager_ledger(),
            &c.family.registration,
            &c.child_id,
            false,
        )?;
        let store = Store::new(child)?;
        let e = &store.context.enrollment;
        if c.database.connection.database != e.current_sql.storage.identity.database {
            return Err(refuse());
        }
        let key = crate::config::key(&secret(&root, &c.provider_key_file)?)?;
        let reader = CurrentReservationReader::new(c.database.clone())?
            .with_peer_uid(c.postgres_peer_uid)?;
        if reader.identity().await? != e.current_sql.storage.identity {
            return Err(refuse());
        }
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let heads = Arc::new(FileHead::new(material_root, c.storage_head_file.clone())?);
        heads.current(&e.current_sql, clock.now_ms()).await?;
        let provider = Arc::new(Provider::new(
            store,
            reader,
            heads,
            clock,
            c.provider_key_id.clone(),
            ed25519_dalek::SigningKey::from_bytes(&key),
        )?);
        let tls = crate::tls::server_config_pem(
            &root.read(&c.certificate, Material::Public, 1 << 20)?,
            &root.read(&c.private_key, Material::Secret, 1 << 20)?,
            &root.read(&c.workload_ca, Material::Public, 1 << 20)?,
        )?;
        let query_token = secret(&root, &c.query_token_file)?;
        let evidence_token = secret(&root, &c.evidence_token_file)?;
        // Validate the endpoint credential before binding a listener.
        crate::current_reservation_service::Service::new(
            provider.clone(),
            &query_token,
            &evidence_token,
        )?;
        Ok(Loaded {
            config: c,
            provider,
            tls,
            query_token,
            evidence_token,
        })
    }
}
