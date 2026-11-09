//! Named, one-plan native execution. Authority intent is durable before any
//! writer credential is read or Terraform apply starts. Unknown never retries.
use crate::{
    contracts::{Resource, canonical, digest},
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const PROFILE: &str = "KF-TERRAFORM-APPLY-0.1-draft";
pub const ACTION: &str = "terraform.configmap.annotation.apply";
fn backend_advanced(before: &Value, after: &Value) -> bool {
    // A single apply can persist multiple checkpoints (the real fixture moves
    // serial 1 to 3). Serial counts state writes, not execution attempts.
    before["lineage"].as_str().is_some_and(|s| !s.is_empty())
        && before["lineage"] == after["lineage"]
        && before["serial"]
            .as_u64()
            .zip(after["serial"].as_u64())
            .is_some_and(|(a, b)| a < b && b <= crate::contracts::MAX_SAFE_INTEGER)
}
pub fn coverage() -> Value {
    let mut inventory = json!({"coordinated_writers":["protected-terraform-runner"],"uncoordinated_writers":["privileged-administrators","kubernetes-control-plane"]});
    inventory["inventory_digest"] =
        json!(digest("coverage-inventory", &inventory).expect("fixed inventory"));
    inventory
}
fn refused() -> Error {
    Error::Refused("Terraform original plan/authority binding refused".into())
}
pub fn adapter_contract() -> Value {
    json!({"level":"Level_C","guard_primitive":"None","fence_parameter":null,"guard_scope":[],
        "completion_mode":"dispatch_bound","commit_point":"KF-TERRAFORM-APPLY-0.1-draft:original-native-intent-before-apply",
        "idempotency":{"mode":"resource_key","parameter":"attempt_id","retention_ms":86400000}})
}
pub fn validate_adapter(version: &str, value: &Value, fence: Option<&str>) -> Result<()> {
    if version != "1.0" || value != &adapter_contract() || fence.is_some_and(|s| !s.is_empty()) {
        return Err(refused());
    }
    Ok(())
}
pub fn parameter_schema(manifest: &str, effect: &str, resource: &str) -> Result<Value> {
    if !crate::grant_reference::valid_reference(manifest)
        || !crate::grant_reference::valid_reference(effect)
        || resource.is_empty()
    {
        return Err(refused());
    }
    Ok(
        json!({"type":"object","additionalProperties":false,"required":["node","expected_version","manifest_digest","effect_digest"],
        "properties":{"node":{"type":"string","const":resource},"expected_version":{"type":"integer","const":1},
        "manifest_digest":{"type":"string","const":manifest},"effect_digest":{"type":"string","const":effect}}}),
    )
}
pub fn validate_schema(version: &str, schema: &Value) -> Result<()> {
    if version != "1.0"
        || canonical(schema)?
            != canonical(&parameter_schema(
                schema["properties"]["manifest_digest"]["const"]
                    .as_str()
                    .ok_or_else(refused)?,
                schema["properties"]["effect_digest"]["const"]
                    .as_str()
                    .ok_or_else(refused)?,
                schema["properties"]["node"]["const"]
                    .as_str()
                    .ok_or_else(refused)?,
            )?)?
    {
        return Err(refused());
    }
    Ok(())
}
pub fn bind(version: &str, p: &Value, r: &Resource, version_field: &str) -> Result<u64> {
    if version != "1.0"
        || version_field != "expected_version"
        || p["node"] != r.id
        || p["expected_version"] != 1
        || p != &json!({"node":r.id,"expected_version":1,"manifest_digest":p["manifest_digest"],"effect_digest":p["effect_digest"]})
        || !p["manifest_digest"]
            .as_str()
            .is_some_and(crate::grant_reference::valid_reference)
        || !p["effect_digest"]
            .as_str()
            .is_some_and(crate::grant_reference::valid_reference)
    {
        return Err(refused());
    }
    Ok(1)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    pub profile: String,
    pub material_root: PathBuf,
    pub manifest_file: PathBuf,
    pub backend_root: PathBuf,
    pub secret_root: PathBuf,
    pub writer_token_file: PathBuf,
    pub observer_token_file: PathBuf,
    pub manifest_digest: String,
    pub inspection_sha256: String,
    pub effect_digest: String,
    pub tool: crate::gateway::ToolDescriptor,
    pub parameter_schema: Value,
    pub gateway_workload: String,
    pub target_audience: String,
    pub target_scope: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub profile: String,
    pub signed_grant: String,
    pub attempt_id: String,
    pub parameters: Value,
    pub target_credential: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub profile: String,
    pub manifest_digest: String,
    pub effect_digest: String,
    pub grant_digest: String,
    pub root_id: String,
    pub attempt_id: String,
    pub state: String,
    pub initiated_at: i64,
    pub backend_before_sha256: String,
    pub backend_after_sha256: Option<String>,
    pub observed_after_digest: Option<String>,
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair: Option<crate::terraform_pair_apply::Outcome>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub profile: &'static str,
    pub status: &'static str,
    pub intent: Intent,
    pub replayed: bool,
    pub observed_postcondition: Option<bool>,
}
fn decode_intent(raw: &[u8], pair: bool) -> Result<Intent> {
    let value = crate::contracts::strict_value(raw)?;
    if !pair && value.get("pair").is_some() {
        return Err(refused());
    }
    serde_json::from_value(value).map_err(|_| refused())
}

#[cfg(unix)]
mod native {
    use super::*;
    use crate::{
        clock::Clock,
        contracts::{Grant, GrantVerifier, strict_value},
        file_custody::{Material, Root},
        ledger::{
            AuthorityLedger, EtcdLedger, expected_root, get, put, range_kv, record, value_eq,
            version_zero,
        },
        recovery::{Candidate, context_key},
        target_token::{TargetTokenVerifier, TokenBinding},
        terraform_plan::{EXECUTION_PROFILE, Prepared, prepare},
    };
    use sha2::{Digest, Sha256};
    use std::{sync::Arc, time::Duration};
    fn hash(v: &[u8]) -> String {
        hex::encode(Sha256::digest(v))
    }
    pub struct Runner {
        pins: Pins,
        prepared: Prepared,
        ledger: EtcdLedger,
        grants: GrantVerifier,
        tokens: TargetTokenVerifier,
        clock: Arc<dyn Clock>,
        secrets: Root,
        backend: Root,
        client: reqwest::Client,
        urls: Vec<reqwest::Url>,
        pair: Option<crate::terraform_pair::Manifest>,
    }
    impl Runner {
        pub async fn new(
            pins: Pins,
            ledger: EtcdLedger,
            grants: GrantVerifier,
            tokens: TargetTokenVerifier,
            clock: Arc<dyn Clock>,
        ) -> Result<Self> {
            if pins.profile != PROFILE {
                return Err(refused());
            }
            let prepared = prepare(&pins.material_root, &pins.manifest_file).await?;
            Self::from_prepared(pins, prepared, None, ledger, grants, tokens, clock).await
        }
        pub(crate) async fn new_pair(
            pins: Pins,
            ledger: EtcdLedger,
            grants: GrantVerifier,
            tokens: TargetTokenVerifier,
            clock: Arc<dyn Clock>,
        ) -> Result<Self> {
            let p =
                crate::terraform_pair::prepare(&pins.material_root, &pins.manifest_file).await?;
            let i = p.inspection;
            let manifest = p.manifest;
            let prepared = Prepared {
                manifest: manifest.single(0),
                inspection: crate::terraform_plan::Inspection {
                    profile: EXECUTION_PROFILE.into(),
                    status: "inspection_passed",
                    manifest_digest: i.manifest_digest,
                    inspection_sha256: i.inspection_sha256,
                    inputs: i.inputs,
                    workspace_id: i.workspace_id,
                    backend: i.backend,
                    backend_state_path: Some(i.backend_state_path),
                    state_lineage: i.state_lineage,
                    state_serial: i.state_serial,
                    target: manifest.members[0].target.clone(),
                    effect_digest: i.effect_digest,
                    guard_level: "Level_C",
                    execution_enabled: false,
                },
                config: p.config,
                state: p.state,
                stage: p.stage,
            };
            Self::from_prepared(
                pins,
                prepared,
                Some(manifest),
                ledger,
                grants,
                tokens,
                clock,
            )
            .await
        }
        async fn from_prepared(
            pins: Pins,
            prepared: Prepared,
            pair: Option<crate::terraform_pair::Manifest>,
            ledger: EtcdLedger,
            grants: GrantVerifier,
            tokens: TargetTokenVerifier,
            clock: Arc<dyn Clock>,
        ) -> Result<Self> {
            pins.tool.validate()?;
            let (profile, action, scope, contract) = if pair.is_some() {
                (
                    crate::terraform_pair_apply::PROFILE,
                    crate::terraform_pair_apply::ACTION,
                    crate::terraform_pair_apply::SCOPE,
                    crate::terraform_pair_apply::adapter_contract(),
                )
            } else {
                (PROFILE, ACTION, "terraform:apply", adapter_contract())
            };
            if pins.profile != profile
                || !ledger.require_control
                || !crate::auth::valid_spiffe_id(&pins.gateway_workload)
                || pins.target_scope != scope
                || (pair.is_some() && pins.tool.required_scope != scope)
                || pins.target_audience.is_empty()
                || pins.tool.action.as_ref().is_none_or(|a| a.id != action)
                || tokens.keys().any(|t| grants.keys.values().any(|g| g == t))
            {
                return Err(refused());
            }
            crate::endpoint::EndpointPolicy::new(&pins.target_audience)?;
            let i = &prepared.inspection;
            let resource = pins.tool.resource.as_ref().ok_or_else(refused)?;
            let schema =
                parameter_schema(&pins.manifest_digest, &pins.effect_digest, &resource.id)?;
            if prepared.manifest.profile != EXECUTION_PROFILE
                || i.manifest_digest != pins.manifest_digest
                || i.inspection_sha256 != pins.inspection_sha256
                || i.effect_digest != pins.effect_digest
                || if let Some(m) = &pair {
                    resource != &crate::terraform_pair_apply::resource(m, &i.manifest_digest)?
                } else {
                    resource.incarnation != prepared.manifest.target.uid
                }
                || pins.parameter_schema != schema
                || pins.tool.adapter_contract != contract
            {
                return Err(refused());
            }
            let backend = Root::open(&pins.backend_root)?;
            let secrets = Root::open(&pins.secret_root)?;
            let p = &prepared.config["provider"]["kubernetes"];
            let origin = p["host"].as_str().ok_or_else(refused)?;
            let targets = pair
                .as_ref()
                .map(|m| m.members.iter().map(|m| &m.target).collect::<Vec<_>>())
                .unwrap_or_else(|| vec![&prepared.manifest.target]);
            let urls = targets
                .iter()
                .map(|target| {
                    reqwest::Url::parse(&format!(
                        "{}/api/v1/namespaces/{}/configmaps/{}",
                        origin.trim_end_matches('/'),
                        target.namespace,
                        target.name
                    ))
                    .map_err(|_| refused())
                })
                .collect::<Result<Vec<_>>>()?;
            let ca = p["cluster_ca_certificate"].as_str().ok_or_else(refused)?;
            let client = reqwest::Client::builder()
                .no_proxy()
                .tls_built_in_root_certs(false)
                .add_root_certificate(
                    reqwest::Certificate::from_pem(ca.as_bytes()).map_err(|_| refused())?,
                )
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .build()?;
            // Validate the registered path and snapshot custody; later reads may
            // legitimately see a changed backend after the original attempt.
            let path = prepared
                .manifest
                .backend_state_path
                .as_ref()
                .ok_or_else(refused)?;
            backend.read(std::path::Path::new(path), Material::Secret, 2 << 20)?;
            Ok(Self {
                pins,
                prepared,
                ledger,
                grants,
                tokens,
                clock,
                secrets,
                backend,
                client,
                urls,
                pair,
            })
        }
        fn profile(&self) -> &'static str {
            if self.pair.is_some() {
                crate::terraform_pair_apply::PROFILE
            } else {
                PROFILE
            }
        }
        fn contract(&self) -> Value {
            if self.pair.is_some() {
                crate::terraform_pair_apply::adapter_contract()
            } else {
                adapter_contract()
            }
        }
        async fn preflight(&self) -> Result<bool> {
            for index in 0..self.urls.len() {
                if !self.member_matches(&self.observe_member(index).await?, false, index) {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        async fn current_postcondition(&self) -> Option<bool> {
            let mut matched = true;
            for index in 0..self.urls.len() {
                matched &=
                    self.member_matches(&self.observe_member(index).await.ok()?, true, index);
            }
            Some(matched)
        }
        fn validate_pair_intent(&self, i: &Intent) -> Result<()> {
            let m = self.pair.as_ref().ok_or_else(refused)?;
            let outcome = i.pair.as_ref().ok_or_else(refused)?;
            outcome.validate(m, &i.state)?;
            if i.profile != self.profile()
                || i.manifest_digest != self.pins.manifest_digest
                || i.effect_digest != self.pins.effect_digest
                || !crate::grant_reference::valid_reference(&i.grant_digest)
                || !crate::grant_reference::valid_reference(&i.backend_before_sha256)
                || i.backend_before_sha256 != self.prepared.inspection.inputs["state.json"]
                || i.root_id.is_empty()
                || i.attempt_id.is_empty()
                || i.attempt_id.len() > 1024
                || i.initiated_at < 0
                || i.backend_after_sha256
                    .as_deref()
                    .is_some_and(|s| !crate::grant_reference::valid_reference(s))
                || i.observed_after_digest
                    .as_deref()
                    .is_some_and(|s| !crate::grant_reference::valid_reference(s))
                || i.last_error.as_ref().is_some_and(|s| s.len() > 256)
                || outcome
                    .members
                    .iter()
                    .any(|o| o.observed_at.is_some_and(|t| t < i.initiated_at))
                || outcome.backend_progress != i.backend_after_sha256.is_some()
                || i.backend_after_sha256
                    .as_ref()
                    .is_some_and(|h| h == &i.backend_before_sha256)
                || if i.state == "started" {
                    i.last_error.is_some()
                        || i.backend_after_sha256.is_some()
                        || i.observed_after_digest.is_some()
                } else {
                    i.observed_after_digest.is_none()
                        || (i.state == "applied") != i.last_error.is_none()
                }
            {
                return Err(refused());
            }
            if i.state != "started"
                && i.observed_after_digest.as_ref()
                    != Some(&digest("terraform-pair-observation", &json!(outcome))?)
            {
                return Err(refused());
            }
            Ok(())
        }
        async fn apply_pair(
            &self,
            intent: &mut Intent,
            r: &Request,
            permit: &crate::broker_authorization::ExchangePermit,
        ) -> Result<()> {
            let tool = async {
                let now = self.clock.now_ms();
                self.grants.verify(r.signed_grant.as_bytes(), now)?;
                self.tokens
                    .verify(&r.target_credential, &TokenBinding::from(permit), now)?;
                let token = self.credential(&self.pins.writer_token_file)?;
                self.prepared
                    .stage
                    .command_outcome_with_token(
                        &[
                            "apply",
                            "-input=false",
                            "-lock=true",
                            "-lock-timeout=1s",
                            "-no-color",
                            "plan.bin",
                        ],
                        Some(&token),
                    )
                    .await
            }
            .await;
            let mut outcome =
                crate::terraform_pair_apply::Outcome::started(self.pair.as_ref().unwrap());
            outcome.tool_succeeded = tool.as_ref().ok().map(|r| r.success);
            if let Ok(bytes) = self.backend_bytes()
                && let Ok(state) = strict_value(&bytes)
            {
                outcome.backend_progress = backend_advanced(&self.prepared.state, &state);
                if outcome.backend_progress {
                    intent.backend_after_sha256 = Some(hash(&bytes));
                }
            }
            for (index, member) in outcome.members.iter_mut().enumerate() {
                if let Ok(value) = self.observe_member(index).await {
                    member.state = if self.member_matches(&value, true, index)
                        && value["metadata"]["resourceVersion"]
                            != self.pair.as_ref().unwrap().members[index]
                                .target
                                .resource_version
                    {
                        "desired"
                    } else if self.member_matches(&value, false, index) {
                        "original_observed"
                    } else {
                        "unresolved"
                    }
                    .into();
                    member.observation_digest =
                        Some(digest("terraform-pair-member-observation", &value)?);
                    member.observed_at = Some(self.clock.now_ms());
                }
            }
            intent.state = outcome.state().into();
            intent.observed_after_digest =
                Some(digest("terraform-pair-observation", &json!(outcome))?);
            intent.last_error = if intent.state == "applied" {
                None
            } else {
                Some(match tool {
                    Ok(r) if !r.success => format!("Terraform pair: {}", r.failure),
                    Ok(_) => "Terraform pair independent completion remains unresolved".into(),
                    Err(e) => e.to_string().chars().take(256).collect(),
                })
            };
            intent.pair = Some(outcome);
            self.validate_pair_intent(intent)
        }
        fn key(&self) -> String {
            format!(
                "{}/{}/{}/intent",
                self.ledger.namespace(),
                if self.pair.is_some() {
                    "terraform-pair"
                } else {
                    "terraform"
                },
                self.pins.manifest_digest
            )
        }
        fn credential(&self, path: &std::path::Path) -> Result<String> {
            let value = String::from_utf8(self.secrets.read(path, Material::Secret, 16 << 10)?)
                .map_err(|_| refused())?;
            let value = value.trim();
            if value.is_empty() || value.bytes().any(|b| b <= b' ' || b == 127) {
                return Err(refused());
            }
            Ok(value.into())
        }
        fn backend_bytes(&self) -> Result<Vec<u8>> {
            self.backend.read(
                std::path::Path::new(self.prepared.manifest.backend_state_path.as_ref().unwrap()),
                Material::Secret,
                2 << 20,
            )
        }
        async fn observe(&self) -> Result<Value> {
            self.observe_member(0).await
        }
        async fn observe_member(&self, index: usize) -> Result<Value> {
            let token = self.credential(&self.pins.observer_token_file)?;
            let response = self
                .client
                .get(self.urls[index].clone())
                .bearer_auth(token)
                .send()
                .await?;
            if !response.status().is_success() || response.url() != &self.urls[index] {
                return Err(refused());
            }
            let raw = crate::grant_reference::bounded_response(response, 2 << 20).await?;
            strict_value(&raw)
        }
        fn target_matches(&self, v: &Value, post: bool) -> bool {
            self.member_matches(v, post, 0)
        }
        fn member_matches(&self, v: &Value, post: bool, index: usize) -> bool {
            let single = &self.prepared.manifest;
            let pair_member = self.pair.as_ref().map(|m| &m.members[index]);
            let target = pair_member.map(|m| &m.target).unwrap_or(&single.target);
            let after = pair_member
                .map(|m| &m.after_revision)
                .unwrap_or(&single.after_revision);
            let before = &self.prepared.state["resources"][index]["instances"][0]["attributes"];
            let mut annotations = before["metadata"][0]["annotations"].clone();
            if post {
                annotations[crate::terraform_plan::ANNOTATION] = json!(after);
            }
            let empty = json!({});
            v["metadata"]["uid"] == target.uid
                && v["metadata"]["name"] == target.name
                && v["metadata"]["namespace"] == target.namespace
                && (post || v["metadata"]["resourceVersion"] == target.resource_version)
                && v["metadata"].get("annotations").unwrap_or(&empty) == &annotations
                && v["metadata"].get("labels").unwrap_or(&empty) == &before["metadata"][0]["labels"]
                && v.get("data").unwrap_or(&empty) == &before["data"]
                && v.get("binaryData").unwrap_or(&empty) == &before["binary_data"]
                && v.get("immutable").unwrap_or(&json!(false)) == &before["immutable"]
        }
        async fn retained(&self) -> Result<Option<Intent>> {
            let t = self
                .ledger
                .txn(vec![], vec![get(&self.key())], vec![])
                .await?;
            if !t.succeeded || t.responses.len() != 1 {
                return Err(refused());
            }
            let Some(kv) = range_kv(&t.responses[0])? else {
                return Ok(None);
            };
            if kv.value.len() > 16384 {
                return Err(refused());
            }
            let i = decode_intent(&kv.value, self.pair.is_some())?;
            if self.pair.is_some() {
                self.validate_pair_intent(&i)?;
            } else {
                if i.pair.is_some()
                    || i.profile != self.profile()
                    || i.manifest_digest != self.pins.manifest_digest
                    || i.effect_digest != self.pins.effect_digest
                    || !["started", "unknown", "applied"].contains(&i.state.as_str())
                    || !crate::grant_reference::valid_reference(&i.grant_digest)
                    || !crate::grant_reference::valid_reference(&i.backend_before_sha256)
                    || i.root_id.is_empty()
                    || i.attempt_id.is_empty()
                    || i.attempt_id.len() > 1024
                    || i.initiated_at < 0
                    || i.last_error
                        .as_ref()
                        .is_some_and(|e| e.chars().count() > 256)
                    || if i.state == "applied" {
                        i.last_error.is_some()
                            || !i
                                .backend_after_sha256
                                .as_deref()
                                .is_some_and(crate::grant_reference::valid_reference)
                            || !i
                                .observed_after_digest
                                .as_deref()
                                .is_some_and(crate::grant_reference::valid_reference)
                    } else {
                        i.backend_after_sha256.is_some()
                            || i.observed_after_digest.is_some()
                            || (i.state == "started" && i.last_error.is_some())
                    }
                {
                    return Err(refused());
                }
            }
            Ok(Some(i))
        }
        pub async fn status(&self, attempt: &str) -> Result<Report> {
            let intent = self
                .retained()
                .await?
                .filter(|i| i.attempt_id == attempt)
                .ok_or_else(refused)?;
            let observed = self.current_postcondition().await;
            Ok(Report {
                profile: self.profile(),
                status: if intent.state == "applied" {
                    "committed"
                } else {
                    "unknown"
                },
                intent,
                replayed: true,
                observed_postcondition: observed,
            })
        }
        fn bind_grant(&self, g: &Grant, parameters: &Value) -> Result<()> {
            if self.pair.is_some()
                && (g.resources.len() != 1
                    || g.completion_mode != "dispatch_bound"
                    || g.parent_grant_digest.is_some()
                    || !g.saga_budget.is_null())
            {
                return Err(refused());
            }
            if self.pins.tool.action.as_ref() != Some(&g.action)
                || self.pins.tool.resource.as_ref() != g.resources.first()
                || g.adapter_contract != self.contract()
                || g.conflict_domain != self.pins.tool.conflict_domain
                || digest("parameters", parameters)? != g.parameters_digest
                || parameters
                    != &json!({"node":g.resources[0].id,"expected_version":1,"manifest_digest":self.pins.manifest_digest,"effect_digest":self.pins.effect_digest})
                || g.predicate_descriptor
                    != json!({"id":self.pins.tool.predicate_id,"version":self.pins.tool.predicate_version,"language":"kf-conjunction-v1","clauses":[{"kind":"version_eq","resource":g.resources[0],"expected_version":"1"}]})
            {
                return Err(refused());
            }
            Ok(())
        }
        pub async fn execute(&self, r: &Request) -> Result<Report> {
            self.execute_original(r, true).await
        }
        /// The gateway owns ordinary outcome publication for its original claim.
        /// The runner still owns the permanent one-shot execution intent.
        pub(crate) async fn execute_gateway(&self, r: &Request) -> Result<Report> {
            self.execute_original(r, false).await
        }
        async fn execute_original(&self, r: &Request, publish: bool) -> Result<Report> {
            if r.profile != self.profile()
                || r.signed_grant.len() > 1 << 20
                || r.attempt_id.is_empty()
                || r.attempt_id.len() > 1024
            {
                return Err(refused());
            }
            let verified = self.grants.verify_retained(r.signed_grant.as_bytes())?;
            let g = &verified.grant;
            self.bind_grant(g, &r.parameters)?;
            if let Some(i) = self.retained().await? {
                if i.attempt_id != r.attempt_id
                    || i.grant_digest != verified.digest
                    || i.root_id != g.root_id
                {
                    return Err(refused());
                }
                return self.status(&r.attempt_id).await;
            }
            let now = self.clock.now_ms();
            self.grants.verify(r.signed_grant.as_bytes(), now)?;
            let claims = self.tokens.verify(
                &r.target_credential,
                &TokenBinding {
                    grant_digest: verified.digest.clone(),
                    root_id: g.root_id.clone(),
                    attempt_id: r.attempt_id.clone(),
                    gateway_workload: self.pins.gateway_workload.clone(),
                    audience: self.pins.target_audience.clone(),
                    scope: self.pins.target_scope.clone(),
                    max_expires_at: g.expires_at,
                },
                now,
            )?;
            let candidate = Candidate {
                grant: g.clone(),
                attempt_id: r.attempt_id.clone(),
            };
            let snapshot = self.ledger.recovery_snapshot(&candidate).await?;
            snapshot.context.validate(g, &verified.digest)?;
            if snapshot.attempt.status != "claimed"
                || snapshot.outbox != "dispatch_authorized"
                || snapshot.context.signed_grant != r.signed_grant
                || snapshot.context.parameters != r.parameters
                || snapshot.context.tool != self.pins.tool.name
            {
                return Err(refused());
            }
            let permit_key = format!(
                "{}/credential-permit",
                self.ledger.attempt(g, &r.attempt_id)
            );
            let permit_bytes = self
                .ledger
                .read_key(&permit_key)
                .await?
                .ok_or_else(refused)?;
            let permit = String::from_utf8(permit_bytes).map_err(|_| refused())?;
            let p: crate::broker_authorization::ExchangePermit =
                serde_json::from_value(strict_value(permit.as_bytes())?).map_err(|_| refused())?;
            crate::broker_authorization::validate_permit(&json!(p))?;
            if p.permit_id != claims.permit_id
                || p.attempt_id != r.attempt_id
                || p.grant_digest != verified.digest
                || p.root_id != g.root_id
                || p.gateway_workload != self.pins.gateway_workload
                || p.target_audience != self.pins.target_audience
                || p.target_scope != self.pins.target_scope
            {
                return Err(refused());
            }
            let before = self.backend_bytes()?;
            if hash(&before) != self.prepared.inspection.inputs["state.json"]
                || !self.preflight().await?
            {
                return Err(refused());
            }
            let mut root = expected_root(g);
            root.status = "claimed".into();
            let mut compare = vec![
                value_eq(&self.ledger.root(g), &record(&root)?),
                value_eq(&self.ledger.grant_key(g), &verified.digest),
                value_eq(&self.ledger.nonce(g), &r.attempt_id),
                value_eq(
                    &self.ledger.attempt(g, &r.attempt_id),
                    &record(&snapshot.attempt)?,
                ),
                value_eq(&self.ledger.outbox(g, &r.attempt_id), "dispatch_authorized"),
                value_eq(
                    &context_key(&self.ledger, g, &r.attempt_id),
                    &snapshot.context_raw,
                ),
                value_eq(
                    &format!("{}/policy", self.ledger.domain(g)),
                    &record(&g.policy)?,
                ),
                value_eq(
                    &format!("{}/ownership", self.ledger.domain(g)),
                    &g.ownership_epoch.to_string(),
                ),
                value_eq(&permit_key, &permit),
                version_zero(&self.key()),
            ];
            compare.extend(self.ledger.grant_control_compare(g).await?);
            let now = self.clock.now_ms();
            self.grants.verify(r.signed_grant.as_bytes(), now)?;
            self.tokens
                .verify(&r.target_credential, &TokenBinding::from(&p), now)?;
            let mut intent = Intent {
                profile: self.profile().into(),
                manifest_digest: self.pins.manifest_digest.clone(),
                effect_digest: self.pins.effect_digest.clone(),
                grant_digest: verified.digest.clone(),
                root_id: g.root_id.clone(),
                attempt_id: r.attempt_id.clone(),
                state: "started".into(),
                initiated_at: now,
                backend_before_sha256: hash(&before),
                backend_after_sha256: None,
                observed_after_digest: None,
                last_error: None,
                pair: self
                    .pair
                    .as_ref()
                    .map(crate::terraform_pair_apply::Outcome::started),
            };
            let original = record(&intent)?;
            let written = self
                .ledger
                .txn(compare, vec![put(&self.key(), &original)], vec![])
                .await?;
            if !written.succeeded {
                return Err(refused());
            }
            // No path after this durable one-shot intent may retry apply, even if
            // credential access, spawn, native locking or reply delivery fails.
            if self.pair.is_some() {
                self.apply_pair(&mut intent, r, &p).await?;
            } else {
                let applied = async {
                    let now = self.clock.now_ms();
                    self.grants.verify(r.signed_grant.as_bytes(), now)?;
                    self.tokens
                        .verify(&r.target_credential, &TokenBinding::from(&p), now)?;
                    let token = self.credential(&self.pins.writer_token_file)?;
                    self.prepared
                        .stage
                        .command_with_token(
                            &[
                                "apply",
                                "-input=false",
                                "-lock=true",
                                "-lock-timeout=1s",
                                "-no-color",
                                "plan.bin",
                            ],
                            Some(&token),
                        )
                        .await?;
                    let backend = self.backend_bytes()?;
                    let state = strict_value(&backend)?;
                    let observed = self.observe().await?;
                    if !backend_advanced(&self.prepared.state, &state) {
                        return Err(Error::Refused(
                            "Terraform backend lineage/serial transition refused".into(),
                        ));
                    }
                    if !self.target_matches(&observed, true) {
                        return Err(Error::Refused(
                            "Terraform independent target postcondition refused".into(),
                        ));
                    }
                    Ok::<_, Error>((
                        hash(&backend),
                        digest("terraform-target-observation", &observed)?,
                    ))
                }
                .await;
                match applied {
                    Ok((backend, observation)) => {
                        intent.state = "applied".into();
                        intent.backend_after_sha256 = Some(backend);
                        intent.observed_after_digest = Some(observation);
                    }
                    Err(error) => {
                        intent.state = "unknown".into();
                        intent.last_error = Some(error.to_string().chars().take(256).collect());
                    }
                }
            }
            let recorded = self
                .ledger
                .txn(
                    vec![value_eq(&self.key(), &original)],
                    vec![put(&self.key(), &record(&intent)?)],
                    vec![],
                )
                .await?;
            if !recorded.succeeded {
                return Err(Error::Unknown(
                    "Terraform original outcome retention unavailable".into(),
                ));
            }
            if publish {
                self.ledger
                    .finish_recorded(
                        g,
                        &snapshot.attempt,
                        if intent.state == "applied" {
                            "committed"
                        } else {
                            "unknown"
                        },
                        &json!({"kind":if self.pair.is_some() {"terraform_pair_original_intent"}else{"terraform_original_intent"},"intent":intent}),
                    )
                    .await?;
            }
            let observed = self.current_postcondition().await;
            Ok(Report {
                profile: self.profile(),
                status: if intent.state == "applied" {
                    "committed"
                } else {
                    "unknown"
                },
                intent,
                replayed: false,
                observed_postcondition: observed,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn single_intent_still_refuses_pair_field_even_when_null() {
        let base = json!({"profile":PROFILE,"manifest_digest":"a".repeat(64),"effect_digest":"b".repeat(64),"grant_digest":"c".repeat(64),"root_id":"root","attempt_id":"attempt","state":"started","initiated_at":1,"backend_before_sha256":"d".repeat(64),"backend_after_sha256":null,"observed_after_digest":null,"last_error":null});
        assert!(decode_intent(&serde_json::to_vec(&base).unwrap(), false).is_ok());
        let mut bad = base;
        bad["pair"] = Value::Null;
        assert!(decode_intent(&serde_json::to_vec(&bad).unwrap(), false).is_err());
    }
    #[test]
    fn backend_progress_allows_multiple_checkpoints_but_refuses_rollback_or_substitution() {
        let before = json!({"lineage":"original","serial":1});
        for serial in [2, 3] {
            assert!(backend_advanced(
                &before,
                &json!({"lineage":"original","serial":serial})
            ));
        }
        for after in [
            json!({"lineage":"other","serial":3}),
            json!({"lineage":"original","serial":0}),
            json!({"lineage":"original","serial":1}),
            json!({"lineage":"original","serial":"3"}),
            json!({"lineage":"original","serial":crate::contracts::MAX_SAFE_INTEGER+1}),
            json!({"serial":3}),
        ] {
            assert!(!backend_advanced(&before, &after));
        }
    }
}
#[cfg(unix)]
pub use native::Runner;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerConfig {
    pub endpoint: String,
    pub prefix: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub token_file: PathBuf,
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub pins: Pins,
    pub ledger: LedgerConfig,
    pub gateway_audience: String,
    pub grant_keys: std::collections::BTreeMap<String, String>,
    pub token_issuer: String,
    pub target_keys: std::collections::BTreeMap<String, String>,
}
#[cfg(unix)]
impl Config {
    pub async fn load(root: &std::path::Path, path: &std::path::Path) -> Result<Runner> {
        Self::load_mode(root, path, false).await
    }
    pub(crate) async fn load_pair(
        root: &std::path::Path,
        path: &std::path::Path,
    ) -> Result<Runner> {
        Self::load_mode(root, path, true).await
    }
    async fn load_mode(
        root: &std::path::Path,
        path: &std::path::Path,
        pair: bool,
    ) -> Result<Runner> {
        use crate::{
            clock::SystemClock,
            contracts::{GrantVerifier, strict_value},
            file_custody::Material,
            ledger::EtcdLedger,
            service_files::ServiceFiles,
            target_token::TargetTokenVerifier,
        };
        let files = ServiceFiles::protected(root)?;
        let c: Self = serde_json::from_value(strict_value(
            &files.read(path, Material::Secret, 2 << 20).await?,
        )?)?;
        crate::grant_reference::fixed_https(&c.ledger.endpoint)?;
        crate::managed_drain_files::local_role(
            &files
                .read(&c.ledger.certificate, Material::Public, 1 << 20)
                .await?,
            &c.pins.gateway_workload,
        )?;
        let client = files
            .http_client(
                &c.ledger.ca,
                &c.ledger.certificate,
                &c.ledger.private_key,
                std::time::Duration::from_secs(5),
            )
            .await?;
        let mut ledger = EtcdLedger::new(client, &c.ledger.endpoint, &c.ledger.prefix)?
            .with_auth_token_file(&files, &c.ledger.token_file)
            .await?
            .requiring_control(None);
        if let Some(gate) = c.ledger.restore_gate {
            ledger = gate.attach_with_files(ledger, &files).await?;
        }
        let grants = GrantVerifier {
            keys: crate::control_config::keys(&c.grant_keys)?,
            audience: c.gateway_audience,
        };
        let tokens =
            TargetTokenVerifier::new(c.token_issuer, crate::control_config::keys(&c.target_keys)?)?;
        if pair {
            return Runner::new_pair(
                c.pins,
                ledger,
                grants,
                tokens,
                std::sync::Arc::new(SystemClock),
            )
            .await;
        }
        Runner::new(
            c.pins,
            ledger,
            grants,
            tokens,
            std::sync::Arc::new(SystemClock),
        )
        .await
    }
}
