//! Explicit local saved-plan adapter. The gateway owns the original claim,
//! broker exchange and native outcome; the runner owns its one-shot intent.
use crate::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::Identity,
    broker::TargetCredential,
    clock::Clock,
    contracts::{GrantVerifier, canonical},
    error::{Error, Result},
    gateway::{Request, ToolDescriptor, VerifiedCall},
    ledger::EtcdLedger,
    target_token::TargetTokenVerifier,
    terraform_apply::{self as apply, Pins},
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

pub const PROFILE: &str = "KF-TERRAFORM-GATEWAY-0.1-draft";
pub const PAIR_PROFILE: &str = "KF-TERRAFORM-PAIR-GATEWAY-0.1-draft";
pub const PAIR_EXTENSION: &str = "io.kedgeflow/terraform-pair-apply";
pub fn is_action(id: &str) -> bool {
    [apply::ACTION, crate::terraform_pair_apply::ACTION].contains(&id)
}
pub fn extension(p: &Pins) -> &'static str {
    if p.profile == crate::terraform_pair_apply::PROFILE {
        PAIR_EXTENSION
    } else {
        EXTENSION
    }
}
pub fn pinned_capabilities(p: &Pins) -> Value {
    if p.profile == crate::terraform_pair_apply::PROFILE {
        json!({"profile":PAIR_PROFILE,"runner_profile":crate::terraform_pair_apply::PROFILE,"guard_level":"Level_C","target_atomic":false})
    } else {
        capabilities()
    }
}
pub const EXTENSION: &str = "io.kedgeflow/terraform-apply";
fn refused() -> Error {
    Error::Refused("explicit Terraform gateway/plan/token binding required".into())
}
pub fn capabilities() -> Value {
    json!({"profile":PROFILE,"runner_profile":apply::PROFILE,"guard_level":"Level_C","target_atomic":false})
}
pub fn metadata(p: &Pins) -> Value {
    let mut value = pinned_capabilities(p);
    value["manifest_digest"] = json!(p.manifest_digest);
    value["effect_digest"] = json!(p.effect_digest);
    value["inspection_sha256"] = json!(p.inspection_sha256);
    value
}
pub fn same_tool(a: &ToolDescriptor, b: &ToolDescriptor) -> Result<bool> {
    Ok(canonical(&json!(a))? == canonical(&json!(b))?)
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub pins: Pins,
    pub token_issuer: String,
    pub target_keys: BTreeMap<String, String>,
}
impl Config {
    pub fn validate(&self, grants: &GrantVerifier) -> Result<()> {
        let p = &self.pins;
        p.tool.validate()?;
        let resource = p.tool.resource.as_ref().ok_or_else(refused)?;
        let pair = self.profile == PAIR_PROFILE;
        let (profile, action, scope, contract, schema) = if pair {
            use crate::terraform_pair_apply as pair;
            (
                pair::PROFILE,
                pair::ACTION,
                pair::SCOPE,
                pair::adapter_contract(),
                pair::parameter_schema(&p.manifest_digest, &p.effect_digest, &resource.id)?,
            )
        } else {
            (
                apply::PROFILE,
                apply::ACTION,
                "terraform:apply",
                apply::adapter_contract(),
                apply::parameter_schema(&p.manifest_digest, &p.effect_digest, &resource.id)?,
            )
        };
        if ![PROFILE, PAIR_PROFILE].contains(&self.profile.as_str())
            || p.profile != profile
            || !crate::auth::valid_spiffe_id(&p.gateway_workload)
            || p.target_scope != scope
            || p.tool.action.as_ref().is_none_or(|a| a.id != action)
            || p.tool.required_scope != scope
            || p.tool.adapter_contract != contract
            || !crate::grant_reference::valid_reference(&p.inspection_sha256)
            || p.parameter_schema != schema
            || (pair && !crate::grant_reference::valid_reference(&resource.incarnation))
        {
            return Err(refused());
        }
        crate::endpoint::EndpointPolicy::new(&p.target_audience)?;
        let tokens = TargetTokenVerifier::new(
            self.token_issuer.clone(),
            crate::control_config::keys(&self.target_keys)?,
        )?;
        if grants.keys.is_empty() || tokens.keys().any(|t| grants.keys.values().any(|g| g == t)) {
            return Err(refused());
        }
        Ok(())
    }
}
#[cfg(unix)]
pub struct Adapter {
    config: Config,
    runner: apply::Runner,
    clock: Arc<dyn Clock>,
}
#[cfg(unix)]
impl Adapter {
    pub async fn new(
        config: Config,
        grants: GrantVerifier,
        ledger: EtcdLedger,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        config.validate(&grants)?;
        let tokens = TargetTokenVerifier::new(
            config.token_issuer.clone(),
            crate::control_config::keys(&config.target_keys)?,
        )?;
        let runner = if config.profile == PAIR_PROFILE {
            apply::Runner::new_pair(config.pins.clone(), ledger, grants, tokens, clock.clone())
                .await?
        } else {
            apply::Runner::new(config.pins.clone(), ledger, grants, tokens, clock.clone()).await?
        };
        Ok(Self {
            config,
            runner,
            clock,
        })
    }
}
#[cfg(unix)]
#[async_trait]
impl ResourceAdapter for Adapter {
    fn terraform_pins(&self) -> Option<&Pins> {
        Some(&self.config.pins)
    }
    fn outcome_evidence(&self, result: &AdapterResult) -> Result<Value> {
        Ok(
            json!({"kind":if self.config.profile == PAIR_PROFILE {"terraform_pair_original_intent"} else {"terraform_original_intent"},"report":result.result["structuredContent"]["kedgeflow_terraform_report"]}),
        )
    }
    async fn dispatch(
        &self,
        call: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult> {
        if !same_tool(&call.descriptor, &self.config.pins.tool)?
            || credential.audience != self.config.pins.target_audience
            || credential.expires_at_ms > call.grant.expires_at
            || self.clock.now_ms() >= credential.expires_at_ms
        {
            return Err(refused());
        }
        let report = self
            .runner
            .execute_gateway(&apply::Request {
                profile: self.config.pins.profile.clone(),
                signed_grant: String::from_utf8(call.signed_grant.clone())
                    .map_err(|_| refused())?,
                attempt_id: call.attempt_id.clone(),
                parameters: call.request.params.arguments.clone(),
                target_credential: credential.token.clone(),
            })
            .await?;
        if report.status != "committed"
            || report.replayed
            || report.observed_postcondition != Some(true)
        {
            return Err(Error::Unknown(
                "original Terraform intent remains unresolved".into(),
            ));
        }
        Ok(AdapterResult {
            status: "committed".into(),
            result: json!({"resultType":"complete","isError":false,"content":[],
            "structuredContent":{"kedgeflow_terminal_receipt":{"attempt_id":call.attempt_id,"grant_digest":call.grant_digest,"resource":call.grant.resources[0],"fence":call.grant.fence,"status":"committed"},
            "kedgeflow_terraform_report":report,"kedgeflow_terraform_binding":metadata(&self.config.pins)}}),
        })
    }
    async fn read(&self, _: &Request, _: &Identity) -> Result<Value> {
        Err(refused())
    }
}
