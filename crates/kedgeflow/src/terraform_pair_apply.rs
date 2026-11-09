//! Separately admitted compound action for one immutable two-resource plan.
//! Ordinary authority remains held when the retained physical result is partial.
use crate::{
    contracts::{Resource, digest},
    error::{Error, Result},
    terraform_pair,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const PROFILE: &str = "KF-TERRAFORM-PAIR-APPLY-0.1-draft";
pub const ACTION: &str = "terraform.configmap.annotation.pair.apply";
pub const SCOPE: &str = "terraform:pair-apply";
pub fn adapter_contract() -> Value {
    let mut v = crate::terraform_apply::adapter_contract();
    v["commit_point"] =
        json!("KF-TERRAFORM-PAIR-APPLY-0.1-draft:original-native-intent-before-apply");
    v
}
pub fn validate_adapter(version: &str, value: &Value, fence: Option<&str>) -> Result<()> {
    if version != "1.0" || value != &adapter_contract() || fence.is_some_and(|v| !v.is_empty()) {
        return Err(Error::Refused(
            "Terraform pair adapter binding refused".into(),
        ));
    }
    Ok(())
}
pub fn incarnation(m: &terraform_pair::Manifest) -> Result<String> {
    digest(
        "terraform-pair-resource-incarnation",
        &json!({"members":m.members,"workspace_id":m.workspace_id,"backend_state_path":m.backend_state_path}),
    )
}
pub fn parameter_schema(manifest: &str, effect: &str, resource: &str) -> Result<Value> {
    crate::terraform_apply::parameter_schema(manifest, effect, resource)
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemberObservation {
    pub id: String,
    pub target_uid: String,
    pub state: String,
    pub observation_digest: Option<String>,
    pub observed_at: Option<i64>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub tool_succeeded: Option<bool>,
    pub backend_progress: bool,
    pub members: Vec<MemberObservation>,
}
impl Outcome {
    pub fn started(m: &terraform_pair::Manifest) -> Self {
        Self {
            tool_succeeded: None,
            backend_progress: false,
            members: m
                .members
                .iter()
                .map(|m| MemberObservation {
                    id: m.id.clone(),
                    target_uid: m.target.uid.clone(),
                    state: "unresolved".into(),
                    observation_digest: None,
                    observed_at: None,
                })
                .collect(),
        }
    }
    pub fn state(&self) -> &'static str {
        if self.members.len() != 2 {
            return "unknown";
        }
        let desired = self.members.iter().filter(|m| m.state == "desired").count();
        if self.tool_succeeded == Some(true) && self.backend_progress && desired == 2 {
            "applied"
        } else if self.tool_succeeded == Some(false)
            && self.backend_progress
            && desired == 1
            && self.members[0].state == "desired"
            && self.members[1].state == "original_observed"
        {
            "partial_observed"
        } else {
            "unknown"
        }
    }
    pub fn validate(&self, m: &terraform_pair::Manifest, state: &str) -> Result<()> {
        let valid = m.members.len() == 2
            && self.members.len() == 2
            && self.members.iter().zip(&m.members).all(|(o, m)| {
                o.id == m.id
                    && o.target_uid == m.target.uid
                    && ["desired", "original_observed", "unresolved"].contains(&o.state.as_str())
                    && match (&o.observation_digest, o.observed_at) {
                        (Some(d), Some(t)) => crate::grant_reference::valid_reference(d) && t >= 0,
                        (None, None) => o.state == "unresolved",
                        _ => false,
                    }
            });
        if !valid
            || if state == "started" {
                self.tool_succeeded.is_some()
                    || self.backend_progress
                    || self
                        .members
                        .iter()
                        .any(|m| m.state != "unresolved" || m.observation_digest.is_some())
            } else {
                self.state() != state
            }
        {
            return Err(Error::Refused(
                "Terraform pair retained observation refused".into(),
            ));
        }
        Ok(())
    }
}
pub fn resource(m: &terraform_pair::Manifest, manifest_digest: &str) -> Result<Resource> {
    Ok(Resource {
        id: format!("terraform-pair:{manifest_digest}"),
        incarnation: incarnation(m)?,
    })
}
