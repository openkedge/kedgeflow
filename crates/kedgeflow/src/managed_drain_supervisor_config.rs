//! Closed protected supervisor configuration. It selects no mutation adapter or
//! controller. All observer/transport material is read under one protected root.
use crate::{
    clock::{Clock, SystemClock},
    contracts::{canonical, strict_value},
    control_history::HistoryObserver,
    error::Result,
    family_saga::{MemberObservers, Saga},
    family_saga_config::{Config as CollectorConfig, ObserverFile},
    managed_drain::PROFILE,
    managed_drain_delivery::{Client, Worker},
    managed_drain_files::{family, refuse, secret, transport},
    managed_drain_store::{Context, Store},
    managed_drain_supervisor::{SagaCollector, Supervisor},
    postgres_custody::{Material, Root},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkFiles {
    pub ca_file: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub token_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub material_root: PathBuf,
    pub collector: CollectorConfig,
    pub child_id: String,
    pub operating_key_id: String,
    pub operating_key_file: PathBuf,
    pub sink: SinkFiles,
}
pub struct Loaded {
    pub supervisor: Arc<Supervisor>,
    pub delivery: Arc<Worker>,
    pub auditor: crate::managed_drain_audit::Auditor,
}
fn observer(root: &Root, file: &ObserverFile) -> Result<HistoryObserver> {
    HistoryObserver::new(
        file.id.clone(),
        file.key_id.clone(),
        ed25519_dalek::SigningKey::from_bytes(&crate::config::key(&secret(
            root,
            &file.signing_key_file,
        )?)?),
    )
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(refuse());
        }
        let value = strict_value(raw)?;
        CollectorConfig::decode(&canonical(&value["collector"])?)?;
        let c: Self = serde_json::from_value(value)?;
        let context = Context::from_selection(crate::family::Selection {
            registration: c.collector.family.registration.clone(),
            child_id: c.child_id.clone(),
        })?;
        if c.profile != PROFILE
            || c.operating_key_id.is_empty()
            || !context
                .enrollment
                .operating_observer
                .keys
                .contains_key(&c.operating_key_id)
            || c.collector
                .physical_observers
                .values()
                .any(|f| f.api.material_root != c.material_root)
        {
            return Err(refuse());
        }
        Ok(c)
    }
    pub async fn load(material_root: &Path, path: &Path) -> Result<Loaded> {
        let root = Root::open(material_root)?;
        let c = Self::decode(&root.read(path, Material::Secret, 1 << 20)?)?;
        if c.material_root != material_root {
            return Err(refuse());
        }
        let r = &c.collector.family.registration;
        let context = Context::from_selection(crate::family::Selection {
            registration: r.clone(),
            child_id: c.child_id.clone(),
        })?;
        let e = &context.enrollment;
        let family = family(&root, &c.collector.family, &e.supervisor_workload).await?;
        let ledger = crate::family_saga_runtime::child_ledger(
            &family.manager_ledger(),
            r,
            &c.child_id,
            false,
        )?;
        let store = Store::new(ledger)?;
        let mut members = BTreeMap::new();
        for (id, files) in &c.collector.members {
            members.insert(
                id.clone(),
                MemberObservers {
                    forward: observer(&root, &files.forward)?,
                    compound: files
                        .compound
                        .as_ref()
                        .map(|file| observer(&root, file))
                        .transpose()?,
                },
            );
        }
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut saga = Saga::new(family, members, observer(&root, &c.collector.collector)?)?;
        for (child, files) in &c.collector.physical_observers {
            let trust = r
                .composition
                .as_ref()
                .ok_or_else(refuse)?
                .node(child)?
                .physical
                .clone()
                .ok_or_else(refuse)?;
            saga =
                saga.with_physical_observer(child.clone(), files.observer(trust, clock.clone())?)?;
        }
        let family_observer = observer(&root, &c.collector.family_observer)?;
        let pin = &r.composition.as_ref().ok_or_else(refuse)?.family_observer;
        if crate::control_config::keys(&pin.keys)?.get(&family_observer.key_id)
            != Some(&family_observer.key.verifying_key())
        {
            return Err(refuse());
        }
        let sink_transport = transport(
            &root,
            &c.sink.ca_file,
            &c.sink.certificate_file,
            &c.sink.private_key_file,
            &e.supervisor_workload,
        )?;
        let sink = Arc::new(Client::new(
            sink_transport,
            &e.policy.incident_sink,
            secret(&root, &c.sink.token_file)?,
        )?);
        let operating_key = ed25519_dalek::SigningKey::from_bytes(&crate::config::key(&secret(
            &root,
            &c.operating_key_file,
        )?)?);
        let auditor = crate::managed_drain_audit::Auditor::new(
            store.clone(),
            clock.clone(),
            c.operating_key_id.clone(),
            operating_key.clone(),
        )?;
        let delivery = Arc::new(Worker::new(
            store.clone(),
            sink,
            clock.clone(),
            c.operating_key_id,
            operating_key,
        )?);
        let supervisor = Arc::new(Supervisor::new(
            store,
            Arc::new(SagaCollector {
                saga,
                family_observer,
            }),
            clock,
        ));
        Ok(Loaded {
            supervisor,
            delivery,
            auditor,
        })
    }
}
