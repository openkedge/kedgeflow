//! Running gateway prerequisites; remote monitors use separate enrolled material.
use crate::{
    contracts::GrantVerifier,
    error::{Error, Result},
    gateway::{Gateway, ToolDescriptor},
    governance::{Installation, verify_control},
    ledger::EtcdLedger,
    operations::{Check, Dependency, Probe, Role},
    operations_client::{Remote, RemoteConfig},
    service_files::ServiceFiles,
};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc};
pub struct Pins {
    pub component_id: String,
    pub workload_id: String,
    pub installation_keys: BTreeMap<String, VerifyingKey>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependencies {
    pub broker: RemoteConfig,
    pub target: RemoteConfig,
}
pub struct GatewayProbe {
    gateway: Arc<Gateway>,
    pins: Option<Pins>,
    broker: Option<Remote>,
    target: Option<Remote>,
}
impl GatewayProbe {
    pub fn new(
        gateway: Arc<Gateway>,
        pins: Option<Pins>,
        broker: Option<Remote>,
        target: Option<Remote>,
    ) -> Self {
        Self {
            gateway,
            pins,
            broker,
            target,
        }
    }
    pub async fn load(
        config: &crate::config::Config,
        files: &ServiceFiles,
        gateway: Arc<Gateway>,
    ) -> Result<Self> {
        let pins = config
            .enforcement
            .as_ref()
            .map(|e| {
                Ok::<_, Error>(Pins {
                    component_id: e.component_id.clone(),
                    workload_id: e.workload_id.clone(),
                    installation_keys: crate::control_config::keys(&e.installation_keys)?,
                })
            })
            .transpose()?;
        let (broker, target) = match &config.operations_dependencies {
            Some(d) => (
                Some(d.broker.load(files, &config.broker_endpoint).await?),
                Some(d.target.load(files, &config.target_url).await?),
            ),
            None => (None, None),
        };
        Ok(Self {
            gateway,
            pins,
            broker,
            target,
        })
    }
}
#[async_trait::async_trait]
impl Probe for GatewayProbe {
    async fn check(&self) -> Vec<Check> {
        let gateway = &self.gateway;
        let remote = async {
            let broker = async {
                match &self.broker {
                    Some(r) => Check::result(
                        Dependency::Broker,
                        r.check(Role::Broker, false, gateway.clock.as_ref()).await,
                    ),
                    None => Check::unverified(Dependency::Broker),
                }
            };
            let target = async {
                match &self.target {
                    Some(r) => Check::result(
                        Dependency::Target,
                        r.check(Role::SqlTarget, false, gateway.clock.as_ref())
                            .await,
                    ),
                    None => Check::unverified(Dependency::Target),
                }
            };
            tokio::join!(broker, target)
        };
        let (mut checks, (broker, target)) = tokio::join!(
            gateway
                .ledger
                .gateway_readiness(&gateway.tools, &gateway.verifier, self.pins.as_ref()),
            remote
        );
        checks.extend([broker, target]);
        checks
    }
}
impl EtcdLedger {
    pub(crate) async fn gateway_control_readiness(
        &self,
        tools: &BTreeMap<String, ToolDescriptor>,
        grants: &GrantVerifier,
        pins: &Pins,
    ) -> Result<()> {
        let mut checked = false;
        for tool in tools.values().filter(|t| !t.read_only) {
            let (stored, _) = self.control_snapshot(&tool.conflict_domain).await?;
            let stored = stored.ok_or_else(|| Error::Refused("gateway control missing".into()))?;
            let (installation, verified): (Installation, _) =
                verify_control(&stored.record, "install", &pins.installation_keys)?;
            let r = &installation.registration;
            let issuers: BTreeMap<_, _> = grants
                .keys
                .iter()
                .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                .collect();
            if stored.digest != verified.digest
                || r.issuer_keys != issuers
                || r.acknowledger.component_id != pins.component_id
                || r.acknowledger.workload_id != pins.workload_id
                || r.scope.conflict_domain != tool.conflict_domain
                || r.scope.audience != grants.audience
                || Some(&r.scope.action) != tool.action.as_ref()
                || Some(&r.scope.resource) != tool.resource.as_ref()
                || r.scope.adapter_contract != tool.adapter_contract
                || r.scope.predicate_descriptor["id"] != tool.predicate_id
                || r.scope.predicate_descriptor["version"] != tool.predicate_version
            {
                return Err(Error::Refused(
                    "gateway readiness installation mismatch".into(),
                ));
            }
            self.readiness_control(&r.scope, &r.policy, r.ownership_epoch)
                .await?;
            checked = true;
        }
        if !checked {
            return Err(Error::Refused(
                "gateway has no monitored execution scope".into(),
            ));
        }
        Ok(())
    }
}
