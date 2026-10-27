//! Explicit managed controller enrollment and protected query credentials. The
//! source destination comes exclusively from the enrolled current SQL contract.
use crate::{
    clock::SystemClock,
    contracts::{canonical, strict_value},
    current_reservation_client::{Client, Querier},
    error::Result,
    kube_drain_config::{Config as ControllerConfig, Loaded},
    managed_drain::{Enrollment, PROFILE},
    managed_drain_files::{refuse, secret, transport},
    managed_drain_store::Context,
    postgres_custody::{Material, Root},
};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFiles {
    pub ca_file: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub token_file: PathBuf,
}
impl SourceFiles {
    pub(crate) fn client(self, root: &Root, e: &Enrollment) -> Result<Arc<dyn Querier>> {
        Ok(Arc::new(Client::new(
            transport(
                root,
                &self.ca_file,
                &self.certificate_file,
                &self.private_key_file,
                &e.controller_workload,
            )?,
            e.current_sql.clone(),
            secret(root, &self.token_file)?,
            Arc::new(SystemClock),
        )?))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub controller: ControllerConfig,
    pub current_sql: SourceFiles,
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(refuse());
        }
        let value = strict_value(raw)?;
        ControllerConfig::decode(&canonical(&value["controller"])?)?;
        let c: Self = serde_json::from_value(value)?;
        let context = Context::from_selection(crate::family::Selection {
            registration: c.controller.family.registration.clone(),
            child_id: c.controller.child_id.clone(),
        })?;
        let e = &context.enrollment;
        let roles = [
            &e.controller_workload,
            &e.supervisor_workload,
            &e.evidence_workload,
        ];
        if c.profile != PROFILE
            || c.controller.target_audience != e.target_audience
            || c.controller.target_scope != e.target_scope
            || roles.contains(&&c.controller.gateway_workload)
            || roles.contains(&&c.controller.query_workload)
        {
            return Err(refuse());
        }
        // A broker credential must not double as an operating, sink, source or
        // storage-owner signing key. Physical/grant key separation is shared.
        let target = crate::control_config::keys(&c.controller.target_keys)?;
        for keys in [
            &e.operating_observer.keys,
            &e.policy.incident_sink.acknowledgement_keys,
            &e.current_sql.provider.keys,
            &e.current_sql.storage.owner.keys,
        ] {
            if crate::control_config::keys(keys)?
                .values()
                .any(|key| target.values().any(|candidate| candidate == key))
            {
                return Err(refuse());
            }
        }
        Ok(c)
    }
    pub async fn load(material_root: &Path, path: &Path) -> Result<Loaded> {
        let root = Root::open(material_root)?;
        let c = Self::decode(&root.read(path, Material::Secret, 1 << 20)?)?;
        if c.controller.material_root != material_root
            || secret(&root, &c.current_sql.token_file)?
                == secret(&root, &c.controller.query_token_file)?
        {
            return Err(refuse());
        }
        let loaded = c.controller.build(&root, Some(c.current_sql)).await?;
        // Validate the exact protected endpoints/roles even for check/state.
        crate::kube_drain_http::Service::new(
            loaded.controller.clone(),
            &loaded.config.dispatch_url,
            &loaded.config.query_url,
            loaded.config.gateway_workload.clone(),
            loaded.config.query_workload.clone(),
            &loaded.query_token,
        )?;
        Ok(loaded)
    }
}
