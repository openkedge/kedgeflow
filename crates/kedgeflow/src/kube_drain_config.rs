//! Explicit protected file snapshots for the Level C controller and read-only
//! observer. These file checks do not establish separate OS administration.
use crate::{
    clock::{Clock, SystemClock},
    contracts::{GrantVerifier, strict_value},
    error::{Error, Result},
    family,
    kube_drain_api::Api,
    kube_drain_observer::Observer,
    kube_drain_runtime::Controller,
    postgres_custody::{Material, Root},
    target_token::TargetTokenVerifier,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
fn refuse() -> Error {
    Error::Refused("protected Kubernetes drain configuration/material refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiFiles {
    pub material_root: PathBuf,
    pub ca_file: PathBuf,
    pub token_file: PathBuf,
}
impl ApiFiles {
    pub fn api(
        &self,
        contract: &crate::kube_drain::Contract,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Api>> {
        let root = Root::open(&self.material_root)?;
        let ca = root.read(&self.ca_file, Material::Public, 1 << 20)?;
        let token = root.read(&self.token_file, Material::Secret, 16384)?;
        Ok(Arc::new(Api::new(
            &contract.api_origin,
            &ca,
            String::from_utf8(token)
                .map_err(|_| refuse())?
                .trim()
                .to_owned(),
            clock,
        )?))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverFiles {
    pub api: ApiFiles,
    pub key_id: String,
    pub signing_key_file: PathBuf,
}
impl ObserverFiles {
    pub fn observer(
        &self,
        trust: crate::kube_drain_proof::Trust,
        clock: Arc<dyn Clock>,
    ) -> Result<Observer> {
        let root = Root::open(&self.api.material_root)?;
        let raw = root.read(&self.signing_key_file, Material::Secret, 16384)?;
        let key = crate::config::key(std::str::from_utf8(&raw).map_err(|_| refuse())?.trim())?;
        let api = self.api.api(&trust.contract, clock.clone())?;
        Observer::new(
            trust,
            api,
            self.key_id.clone(),
            ed25519_dalek::SigningKey::from_bytes(&key),
            clock,
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub material_root: PathBuf,
    pub family: family::Config,
    pub child_id: String,
    pub api: ApiFiles,
    pub controller_key_id: String,
    pub controller_key_file: PathBuf,
    pub token_issuer: String,
    pub target_keys: std::collections::BTreeMap<String, String>,
    pub gateway_workload: String,
    pub query_workload: String,
    pub target_audience: String,
    pub target_scope: String,
    pub query_token_file: PathBuf,
    pub listen: std::net::SocketAddr,
    pub dispatch_url: String,
    pub query_url: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
}
pub struct Loaded {
    pub config: Config,
    pub controller: Arc<Controller>,
    pub tls: Arc<rustls::ServerConfig>,
    pub query_token: String,
}
fn secret(root: &Root, path: &Path, bound: usize) -> Result<String> {
    String::from_utf8(root.read(path, Material::Secret, bound)?)
        .map(|s| s.trim().to_owned())
        .map_err(|_| refuse())
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(refuse());
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        c.family.registration.validate()?;
        if c.family.etcd_prefix != c.family.registration.namespace
            || c.material_root != c.api.material_root
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
        c.build(&root, None).await
    }
    pub(crate) async fn build(
        self,
        root: &Root,
        source: Option<crate::managed_drain_controller_config::SourceFiles>,
    ) -> Result<Loaded> {
        let c = self;
        let node = c
            .family
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&c.child_id)?;
        let trust = node.physical.as_ref().ok_or_else(refuse)?.clone();
        let native = node.forward()?;
        if trust.operating.is_some() != source.is_some() {
            return Err(refuse());
        }
        if !trust.control()?.historical.iter().any(|h| {
            h.registration.scope == native.registration.scope
                && h.registration.acknowledger.workload_id == c.gateway_workload
        }) || c.query_workload != native.lineage.source_id
            || c.gateway_workload == c.query_workload
            || c.target_audience != c.dispatch_url
        {
            return Err(refuse());
        }
        let key = crate::config::key(&secret(root, &c.controller_key_file, 16384)?)?;
        let api = c.api.api(&trust.contract, Arc::new(SystemClock))?;
        let family = if let Some(e) = &trust.operating {
            crate::managed_drain_files::family(root, &c.family, &e.controller_workload).await?
        } else {
            let client = crate::tls::pinned_http_client_pem(
                &root.read(&c.family.etcd_ca, Material::Public, 1 << 20)?,
                &root.read(&c.family.etcd_certificate, Material::Public, 1 << 20)?,
                &root.read(&c.family.etcd_private_key, Material::Secret, 1 << 20)?,
                Duration::from_secs(5),
            )?;
            let mut ledger = crate::ledger::EtcdLedger::new(
                client,
                &c.family.etcd_endpoint,
                &c.family.etcd_prefix,
            )?
            .with_auth_token(&secret(root, &c.family.etcd_token_file, 16384)?)?;
            if let Some(g) = &c.family.restore_gate {
                ledger = g.attach(ledger).await?;
            }
            family::Family::new(ledger, c.family.registration.clone())?
        };
        let ledger = crate::family_saga_runtime::child_ledger(
            &family.manager_ledger(),
            &c.family.registration,
            &c.child_id,
            false,
        )?;
        let grants = GrantVerifier {
            keys: native.lineage.grants.keys,
            audience: native.lineage.grants.audience,
        };
        let tokens = TargetTokenVerifier::new(
            c.token_issuer.clone(),
            crate::control_config::keys(&c.target_keys)?,
        )?;
        if tokens.keys().any(|k| {
            grants.keys.values().any(|v| v == k)
                || trust
                    .controller
                    .keys
                    .values()
                    .chain(trust.observer.keys.values())
                    .any(|v| crate::config::key(v).is_ok_and(|v| v == *k.as_bytes()))
        }) {
            return Err(refuse());
        }
        let sql = match source {
            Some(s) => Some(s.client(root, trust.operating.as_ref().ok_or_else(refuse)?)?),
            None => None,
        };
        let controller = Arc::new(match sql {
            Some(sql) => Controller::new_managed(
                ledger,
                trust,
                api,
                grants,
                tokens,
                c.gateway_workload.clone(),
                c.target_audience.clone(),
                c.target_scope.clone(),
                c.controller_key_id.clone(),
                ed25519_dalek::SigningKey::from_bytes(&key),
                Arc::new(SystemClock),
                sql,
            )?,
            None => Controller::new(
                ledger,
                trust,
                api,
                grants,
                tokens,
                c.gateway_workload.clone(),
                c.target_audience.clone(),
                c.target_scope.clone(),
                c.controller_key_id.clone(),
                ed25519_dalek::SigningKey::from_bytes(&key),
                Arc::new(SystemClock),
            )?,
        });
        let tls = crate::tls::server_config_pem(
            &root.read(&c.certificate, Material::Public, 1 << 20)?,
            &root.read(&c.private_key, Material::Secret, 1 << 20)?,
            &root.read(&c.workload_ca, Material::Public, 1 << 20)?,
        )?;
        let query_token = secret(root, &c.query_token_file, 16384)?;
        if query_token.len() < 32 || query_token.len() > 16384 {
            return Err(refuse());
        }
        Ok(Loaded {
            config: c,
            controller,
            tls,
            query_token,
        })
    }
}
