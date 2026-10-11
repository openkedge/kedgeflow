//! Public operator registration for a separate administrative listener.
use crate::{
    auth::DualAuthenticator,
    clock::SystemClock,
    config::{key, read_secret},
    contracts::{Subject, strict_value},
    control_config::{ControlConfig, keys},
    error::Result,
    governance::{Acknowledger, ControlRegistration, EnforcementScope, trust_digest},
    governance_service::{AdministrativeRole, GovernanceService, GovernanceTrust},
    ledger::EtcdLedger,
    tls,
};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    pub subject: Subject,
    pub workload_id: String,
    pub scope: String,
    pub keys: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceConfig {
    pub listen: std::net::SocketAddr,
    pub external_url: String,
    pub control: ControlConfig,
    pub scope: EnforcementScope,
    pub admission_keys: BTreeMap<String, String>,
    pub issuer_keys: BTreeMap<String, String>,
    pub acknowledger: Acknowledger,
    pub roles: BTreeMap<String, RoleConfig>,
}
impl GovernanceConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(crate::error::Error::Invalid(
                "governance configuration exceeds bound".into(),
            ));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub fn trust(&self) -> Result<GovernanceTrust> {
        let (admission, definition) = self.control.registration()?;
        let roles = self
            .roles
            .iter()
            .map(|(k, r)| {
                Ok((
                    k.clone(),
                    AdministrativeRole {
                        subject: r.subject.clone(),
                        workload_id: r.workload_id.clone(),
                        scope: r.scope.clone(),
                        keys: if r.keys.is_empty() {
                            BTreeMap::new()
                        } else {
                            keys(&r.keys)?
                        },
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let registration = ControlRegistration {
            tenant: admission.tenant.clone(),
            scope: self.scope.clone(),
            policy: admission.policy.clone(),
            ownership_epoch: admission.ownership_epoch,
            obligation_manifest_digest: admission.obligation_manifest_digest.clone(),
            issuer_keys: keys(&self.issuer_keys)?
                .iter()
                .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                .collect(),
            trust_digest: trust_digest(
                &admission,
                &keys(&self.admission_keys)?,
                &keys(&self.issuer_keys)?,
            )?,
            acknowledger: self.acknowledger.clone(),
        };
        let t = GovernanceTrust {
            registration,
            admission,
            definition,
            admission_keys: keys(&self.admission_keys)?,
            issuer_keys: keys(&self.issuer_keys)?,
            roles,
        };
        t.validate()?;
        Ok(t)
    }
    pub async fn service(&self) -> Result<Arc<GovernanceService>> {
        let c = &self.control;
        let client = tls::pinned_http_client(
            &c.etcd_ca,
            &c.etcd_certificate,
            &c.etcd_private_key,
            Duration::from_secs(5),
        )?;
        let ledger = EtcdLedger::new(client, &c.etcd_endpoint, &c.etcd_prefix)?
            .with_auth_token(&read_secret(&c.etcd_token_file).await?)?;
        let auth = DualAuthenticator::new(
            &c.oidc_issuer,
            &c.delegation_audience,
            &self.external_url,
            key(&c.oidc_public_key_base64)?,
        )?;
        Ok(Arc::new(GovernanceService::new(
            self.trust()?,
            ledger,
            auth,
            Arc::new(SystemClock),
        )?))
    }
}
