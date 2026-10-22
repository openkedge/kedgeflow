//! Protected local collector configuration. Command data cannot select endpoints,
//! native members, observer identities or credentials.
use crate::{
    contracts::strict_value,
    error::{Error, Result},
    family::{self, Config as FamilyConfig},
    family_saga::{MemberObservers, Saga},
};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverFile {
    pub id: String,
    pub key_id: String,
    pub signing_key_file: PathBuf,
}
impl ObserverFile {
    pub async fn load(&self) -> Result<crate::control_history::HistoryObserver> {
        family::observer_from_file(self.id.clone(), self.key_id.clone(), &self.signing_key_file)
            .await
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberFiles {
    pub forward: ObserverFile,
    pub compound: Option<ObserverFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub family: FamilyConfig,
    pub members: BTreeMap<String, MemberFiles>,
    pub collector: ObserverFile,
    pub family_observer: ObserverFile,
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("saga configuration exceeds bound".into()));
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        let r = &c.family.registration;
        r.validate()?;
        let p = r
            .composition
            .as_ref()
            .ok_or_else(|| Error::Invalid("explicit family saga registration required".into()))?;
        crate::grant_reference::fixed_https(&c.family.etcd_endpoint)?;
        if c.family.etcd_prefix != r.namespace
            || c.members.len() != p.nodes.len()
            || c.collector.id != p.observer.id
            || !p.observer.keys.contains_key(&c.collector.key_id)
            || c.family_observer.id != p.family_observer.id
            || !p
                .family_observer
                .keys
                .contains_key(&c.family_observer.key_id)
        {
            return Err(Error::Invalid("protected saga catalog/pins differ".into()));
        }
        for n in &p.nodes {
            let m = c.members.get(&n.child_id).ok_or_else(|| {
                Error::Invalid("complete protected saga observer catalog required".into())
            })?;
            let t = n.forward()?;
            if m.forward.id != t.observer_id
                || !t.observer_keys.contains_key(&m.forward.key_id)
                || match (n.compound()?, &m.compound) {
                    (None, None) => false,
                    (Some(t), Some(o)) => {
                        o.id != t.observer_id || !t.observer_keys.contains_key(&o.key_id)
                    }
                    _ => true,
                }
            {
                return Err(Error::Invalid(
                    "protected native observer pins differ".into(),
                ));
            }
        }
        Ok(c)
    }
    pub async fn saga(&self) -> Result<Saga> {
        let mut members = BTreeMap::new();
        for (id, m) in &self.members {
            members.insert(
                id.clone(),
                MemberObservers {
                    forward: m.forward.load().await?,
                    compound: match &m.compound {
                        Some(o) => Some(o.load().await?),
                        None => None,
                    },
                },
            );
        }
        // Validate the family export signer as well, including on --check.
        let observer = self.family_observer.load().await?;
        let pin = &self
            .family
            .registration
            .composition
            .as_ref()
            .unwrap()
            .family_observer;
        if crate::config::key(&pin.keys[&observer.key_id])?
            != *observer.key.verifying_key().as_bytes()
        {
            return Err(Error::Invalid(
                "protected family observer key differs".into(),
            ));
        }
        Saga::new(
            self.family.family().await?,
            members,
            self.collector.load().await?,
        )
    }
}
