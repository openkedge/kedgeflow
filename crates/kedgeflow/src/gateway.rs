//! Closed governed-MCP dispatch path. Authority services are not agent APIs.
use crate::{
    adapter::ResourceAdapter,
    auth::{Authenticator, Identity, WorkloadIdentity},
    broker::CredentialBroker,
    clock::Clock,
    contracts::{Action, Grant, GrantVerifier, Resource, canonical, digest, strict_value},
    error::{Error, Result},
    grant_reference::{
        GrantResolver, INLINE_HEADER, MAX_INLINE_HEADER, MAX_RESOLVED_BYTES, REFERENCE_HEADER,
        REFERENCE_PROFILE, valid_reference,
    },
    ledger::{Attempt, AuthorityLedger},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::time::Instant;

pub const PROTOCOL_VERSION: &str = "2026-07-28";
pub const MCP_PROFILE: &str = "KF-MCP-0.1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDescriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inverse_contract: Option<crate::compensation::Contract>,
    pub name: String,
    pub read_only: bool,
    pub required_scope: String,
    /// Independent disclosure permission; empty disables draft status lookup.
    #[serde(default)]
    pub status_scope: String,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub resource: Option<Resource>,
    #[serde(default)]
    pub conflict_domain: String,
    #[serde(default)]
    pub adapter_contract: Value,
    #[serde(default)]
    pub predicate_id: String,
    #[serde(default)]
    pub predicate_version: String,
    #[serde(default)]
    pub version_parameter: String,
    #[serde(default)]
    pub fence_parameter: String,
    #[serde(default)]
    pub admission_endpoint: String,
}
impl ToolDescriptor {
    pub fn validate(&self) -> Result<()> {
        let physical = self
            .action
            .as_ref()
            .is_some_and(|a| crate::kube_drain::is_action(&a.id));
        if physical
            && (self.read_only
                || self.inverse_contract.is_some()
                || !self.fence_parameter.is_empty()
                || self.version_parameter != "expected_version")
        {
            return Err(Error::Refused(
                "explicit Level C drain tool binding required".into(),
            ));
        }
        if let Some(c) = &self.inverse_contract
            && (self.read_only
                || self.action.as_ref() != Some(&c.inverse_scope.action)
                || self.resource.as_ref() != Some(&c.inverse_scope.resource)
                || self.conflict_domain != c.inverse_scope.conflict_domain
                || self.adapter_contract != c.inverse_scope.adapter_contract)
        {
            return Err(Error::Invalid(
                "inverse tool differs from protected contract".into(),
            ));
        }
        if let Some(c) = &self.inverse_contract {
            c.digest()?;
        }
        if self.name.is_empty() || self.required_scope.is_empty() {
            return Err(Error::Invalid(
                "registered tool requires name and scope".into(),
            ));
        }
        if !self.status_scope.is_empty()
            && (self.read_only || self.status_scope == self.required_scope)
        {
            return Err(Error::Invalid(
                "status requires a distinct consequential-tool scope".into(),
            ));
        }
        if !self.read_only
            && (self.action.is_none()
                || self.resource.is_none()
                || self.conflict_domain.is_empty()
                || self.predicate_id.is_empty()
                || self.predicate_version.is_empty()
                || self.version_parameter.is_empty()
                || self.fence_parameter.is_empty() && !physical
                || self.version_parameter == "node"
                || self.fence_parameter == "node"
                || self.version_parameter == self.fence_parameter
                || [
                    "kf_attempt_id",
                    "kf_grant_digest",
                    "kf_resource_incarnation",
                ]
                .contains(&self.version_parameter.as_str())
                || [
                    "kf_attempt_id",
                    "kf_grant_digest",
                    "kf_resource_incarnation",
                ]
                .contains(&self.fence_parameter.as_str()))
        {
            return Err(Error::Invalid(
                "incomplete or conflicting consequential tool registration".into(),
            ));
        }
        if !self.read_only {
            crate::grant_reference::fixed_https(&self.admission_endpoint)?;
            let resource = self
                .resource
                .as_ref()
                .ok_or_else(|| Error::Invalid("resource registration required".into()))?;
            let action = self
                .action
                .as_ref()
                .ok_or_else(|| Error::Invalid("action registration required".into()))?;
            if resource.id.is_empty()
                || resource.incarnation.is_empty()
                || action.id.is_empty()
                || action.version.is_empty()
                || !valid_reference(&action.digest)
            {
                return Err(Error::Invalid(
                    "invalid registered action/resource identity".into(),
                ));
            }
            if action.id == crate::postgres_action::ACTION
                && (action.version != "1.0"
                    || self.version_parameter != "expected_version"
                    || self.fence_parameter != "fence")
            {
                return Err(Error::Invalid("unsupported SQL tool binding".into()));
            }
            crate::contracts::validate_action_adapter(
                action,
                &self.adapter_contract,
                resource,
                Some(&self.fence_parameter),
            )?;
        }
        Ok(())
    }
}
fn empty_object() -> Value {
    json!({})
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallParams {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default = "empty_object")]
    pub arguments: Value,
    #[serde(rename = "_meta", default)]
    pub meta: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: CallParams,
}
#[derive(Clone)]
pub struct VerifiedCall {
    pub request: Request,
    pub grant: Grant,
    pub identity: Identity,
    pub attempt_id: String,
    pub descriptor: ToolDescriptor,
    pub grant_digest: String,
    pub signed_grant: Vec<u8>,
}
pub struct Gateway {
    pub verifier: GrantVerifier,
    pub ledger: Arc<dyn AuthorityLedger>,
    pub auth: Arc<dyn Authenticator>,
    pub broker: Arc<dyn CredentialBroker>,
    pub adapter: Arc<dyn ResourceAdapter>,
    pub resolver: Option<Arc<dyn GrantResolver>>,
    pub tools: BTreeMap<String, ToolDescriptor>,
    pub timeout: Duration,
    pub clock: Arc<dyn Clock>,
}
fn response(id: &Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn failure(id: &Value, code: i32, message: &str, data: Option<Value>) -> Value {
    let mut value = json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}});
    if let Some(data) = data {
        value["error"]["data"] = data;
    }
    value
}
fn random_id() -> String {
    let mut bytes = [0; 18];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    identifier(&bytes)
}
fn identifier(entropy: &[u8; 18]) -> String {
    // Raw base64url may start with '-' or '_'; frozen Id and SQL labels require
    // an alphanumeric first character. Keep all 144 random bits, with a prefix.
    format!("kf-{}", URL_SAFE_NO_PAD.encode(entropy))
}
fn extension(meta: &BTreeMap<String, Value>, name: &str, profile: &str) -> bool {
    meta.get("io.modelcontextprotocol/clientCapabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.get(name))
        .is_some_and(|e| {
            e.as_object().is_some_and(|o| o.len() == 1)
                && e.get("profile").and_then(Value::as_str) == Some(profile)
        })
}
fn header_values<'a>(headers: &'a HeaderMap, name: &str) -> Result<Vec<&'a str>> {
    headers
        .get_all(name)
        .iter()
        .map(|v| {
            v.to_str()
                .map_err(|_| Error::Invalid("invalid grant header".into()))
        })
        .collect()
}

pub fn bind_call(
    grant: &Grant,
    identity: &Identity,
    tool: &ToolDescriptor,
    arguments: &Value,
) -> Result<()> {
    if grant.subject != identity.subject
        || grant.workload_id != identity.workload_id
        || grant.dpop_jkt != identity.dpop_jkt
        || grant.delegation_digest != identity.delegation_digest
        || grant.parameters_digest != digest("parameters", arguments)?
        || Some(&grant.action) != tool.action.as_ref()
        || grant.resources.len() != 1
        || Some(&grant.resources[0]) != tool.resource.as_ref()
        || grant.conflict_domain != tool.conflict_domain
        || canonical(&grant.adapter_contract)? != canonical(&tool.adapter_contract)?
        || if crate::kube_drain::is_action(&grant.action.id) {
            !tool.fence_parameter.is_empty()
                || grant.adapter_contract != crate::kube_drain::action_adapter(&grant.action.id)?
        } else {
            grant
                .adapter_contract
                .get("fence_parameter")
                .and_then(Value::as_str)
                != Some(tool.fence_parameter.as_str())
        }
    {
        return Err(Error::Refused("grant scope mismatch".into()));
    }
    let version = crate::leaf_action::bind_inverse(
        &grant.action.id,
        &grant.action.version,
        arguments,
        &grant.resources[0],
        &tool.version_parameter,
        tool.inverse_contract.as_ref(),
    )?;
    let predicate = json!({"id":tool.predicate_id,"version":tool.predicate_version,"language":"kf-conjunction-v1",
        "clauses":[{"kind":"version_eq","resource":grant.resources[0],"expected_version":version.to_string()}]});
    if canonical(&grant.predicate_descriptor)? != canonical(&predicate)? {
        return Err(Error::Refused("unsupported or mismatched predicate".into()));
    }
    Ok(())
}
impl Gateway {
    pub fn validate(&self) -> Result<()> {
        if self.timeout.is_zero() || self.verifier.keys.is_empty() || self.tools.is_empty() {
            return Err(Error::Invalid("incomplete gateway configuration".into()));
        }
        if self.adapter.managed_drain_context().is_some()
            && (self.tools.len() != 1
                || !self.tools.values().all(|tool| {
                    tool.action
                        .as_ref()
                        .is_some_and(|a| a.id == crate::managed_drain::ACTION)
                }))
        {
            return Err(Error::Refused(
                "managed adapter requires one named managed tool".into(),
            ));
        }
        for (name, tool) in &self.tools {
            tool.validate()?;
            if tool
                .action
                .as_ref()
                .is_some_and(|action| action.id == crate::managed_drain::ACTION)
            {
                let context = self.adapter.managed_drain_context().ok_or_else(|| Error::Refused("managed gateway adapter and complete independent proof integration required before discovery".into()))?;
                let pinned =
                    crate::managed_drain_store::Context::from_selection(context.selection.clone())?;
                let native = context
                    .selection
                    .registration
                    .composition
                    .as_ref()
                    .ok_or_else(|| Error::Refused("managed family plan required".into()))?
                    .node(&context.selection.child_id)?
                    .forward()?;
                if context.enrollment != pinned.enrollment
                    || context.physical != pinned.physical
                    || self.ledger.managed_drain_selection() != Some(&context.selection)
                    || self.verifier.keys != native.lineage.grants.keys
                    || self.verifier.audience != native.lineage.grants.audience
                    || tool.action.as_ref() != Some(&native.registration.scope.action)
                    || tool.resource.as_ref() != Some(&context.physical.contract.resource()?)
                    || tool.conflict_domain != native.registration.scope.conflict_domain
                    || tool.adapter_contract != crate::managed_drain::adapter_contract()
                    || tool.required_scope != native.lineage.admission.required_scope
                    || native.registration.scope.predicate_descriptor["id"].as_str()
                        != Some(tool.predicate_id.as_str())
                    || native.registration.scope.predicate_descriptor["version"].as_str()
                        != Some(tool.predicate_version.as_str())
                {
                    return Err(Error::Refused(
                        "managed adapter/native/tool context mismatch".into(),
                    ));
                }
            }
            if tool
                .action
                .as_ref()
                .is_some_and(|a| a.id == crate::kube_drain::ACTION)
            {
                let contract = self.adapter.kube_drain_contract().ok_or_else(|| {
                    Error::Refused("protected physical adapter required for drain discovery".into())
                })?;
                if tool.resource.as_ref() != Some(&contract.resource()?) {
                    return Err(Error::Refused(
                        "physical discovery resource differs from adapter".into(),
                    ));
                }
                contract.validate()?;
            }
            if name != &tool.name {
                return Err(Error::Invalid("tool registration name mismatch".into()));
            }
        }
        Ok(())
    }
    async fn finish(&self, grant: &Grant, attempt: &Attempt, status: &str) -> Result<()> {
        // Completion recording outlives the signed dispatch budget. It never
        // releases root/nonce authority, including after an unknown outcome.
        tokio::time::timeout(
            Duration::from_secs(5),
            self.ledger.finish(grant, attempt, status),
        )
        .await
        .map_err(|_| Error::Unavailable("completion recording timed out".into()))?
    }
    async fn finish_recorded(
        &self,
        grant: &Grant,
        attempt: &Attempt,
        status: &str,
        evidence: &Value,
    ) -> Result<()> {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.ledger
                .finish_recorded(grant, attempt, status, evidence),
        )
        .await
        .map_err(|_| Error::Unavailable("completion evidence recording timed out".into()))?
    }
    pub async fn handle(
        &self,
        headers: &HeaderMap,
        workload: &WorkloadIdentity,
        raw: &[u8],
    ) -> Value {
        let null = Value::Null;
        if raw.len() > 1 << 20 {
            return failure(&null, -32600, "INVALID_REQUEST", None);
        }
        let req: Request = match strict_value(raw)
            .and_then(|v| serde_json::from_value::<Request>(v).map_err(Into::into))
        {
            Ok(req)
                if req.jsonrpc == "2.0"
                    && (req.id.is_string() || req.id.is_i64() || req.id.is_u64()) =>
            {
                req
            }
            _ => return failure(&null, -32600, "INVALID_REQUEST", None),
        };
        let id = &req.id;
        if ![
            "tools/call",
            "tools/list",
            "server/discover",
            crate::execution_status::METHOD,
        ]
        .contains(&req.method.as_str())
        {
            return failure(id, -32601, "METHOD_NOT_SUPPORTED", None);
        }
        let version = req
            .params
            .meta
            .get("io.modelcontextprotocol/protocolVersion")
            .and_then(Value::as_str);
        if version.is_none()
            || !req
                .params
                .meta
                .get("io.modelcontextprotocol/clientCapabilities")
                .is_some_and(Value::is_object)
        {
            return failure(id, -32602, "REQUIRED_PROTOCOL_METADATA", None);
        }
        if version != Some(PROTOCOL_VERSION) {
            return failure(id, -32022, "UNSUPPORTED_PROTOCOL_VERSION", None);
        }
        let identity = match self.auth.authenticate(headers, workload).await {
            Ok(id) => id,
            Err(_) => return failure(id, -32003, "IDENTITY_CONFLICT", None),
        };
        if req.method == "server/discover" {
            let mut extensions = json!({"io.kedgeflow/governed-mcp":{"profile":MCP_PROFILE,"max_inline_grant_header_bytes":MAX_INLINE_HEADER}});
            if self
                .tools
                .values()
                .any(|t| !t.status_scope.is_empty() && identity.scopes.contains(&t.status_scope))
            {
                extensions[crate::execution_status::EXTENSION] = json!({"profile":crate::execution_status::PROFILE,"method":crate::execution_status::METHOD});
            }
            if self.tools.values().any(|t| {
                t.action
                    .as_ref()
                    .is_some_and(|a| a.id == crate::postgres_action::ACTION)
            }) {
                extensions[crate::leaf_action::EXTENSION] =
                    json!({"profile":crate::leaf_action::PROFILE});
            }
            if self.tools.values().any(|t| t.inverse_contract.is_some()) {
                extensions[crate::compensation_execution::EXTENSION] =
                    json!({"profile":crate::compensation_execution::PROFILE});
            }
            if self.adapter.kube_drain_contract().is_some() {
                extensions[crate::kube_drain::EXTENSION] = json!({"profile":crate::kube_drain::PROFILE,"commit_point":"controller_acceptance","physical_completion":"separate_observation"});
            }
            if self.adapter.managed_drain_context().is_some() {
                extensions[crate::managed_drain::EXTENSION] = json!({"profile":crate::managed_drain::PROFILE,
                    "acceptance_proof_profile":crate::managed_drain_acceptance::PROFILE,
                    "commit_point":"controller_acceptance","physical_completion":"separate_observation"});
            }
            if self.resolver.is_some() {
                extensions["io.kedgeflow/grant-reference"] = json!({"profile":REFERENCE_PROFILE,"header":REFERENCE_HEADER,"max_resolved_grant_bytes":MAX_RESOLVED_BYTES});
            }
            return response(
                id,
                json!({"resultType":"complete","supportedVersions":[PROTOCOL_VERSION],"capabilities":{"tools":{},"extensions":extensions},
                "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"KedgeFlow Rust reference gateway","version":"0.9.0-alpha.1"}}}),
            );
        }
        if req.method == "tools/list" {
            let tools: Vec<Value> = self.tools.values().filter(|t| identity.scopes.contains(&t.required_scope)).map(|t| {
                let mut schema = json!({"type":"object","properties":{},"additionalProperties":false});
                if t.action.as_ref().is_some_and(|a| a.id == crate::postgres_action::ACTION) {
                    schema = crate::leaf_action::sql_schema();
                } else if t.action.as_ref().is_some_and(|a| a.id == crate::managed_drain::ACTION) {
                    let c = self.adapter.managed_drain_context().expect("validated managed adapter");
                    schema = c.enrollment.schema(&c.physical.contract).expect("validated managed schema");
                } else if t.action.as_ref().is_some_and(|a| a.id == crate::kube_drain::ACTION) {
                    schema = self.adapter.kube_drain_contract().expect("validated physical adapter").parameter_schema().expect("validated physical contract");
                } else if t.inverse_contract.is_some() {
                    schema = crate::compensation::parameter_schema();
                } else if !t.read_only {
                    schema["properties"]["node"] = json!({"type":"string","const":t.resource.as_ref().map(|r|r.id.as_str()).unwrap_or("")});
                    schema["properties"][&t.version_parameter] = json!({"type":"integer","minimum":1,"maximum":crate::contracts::MAX_SAFE_INTEGER});
                    schema["required"] = json!(["node",t.version_parameter]);
                }
                let mut wire = json!({"name":t.name,"description":"Registered KedgeFlow protected tool","inputSchema":schema,"annotations":{"readOnlyHint":t.read_only}});
                if let Some(c)=&t.inverse_contract {
                    wire["_meta"]=json!({crate::compensation_execution::EXTENSION:{"profile":crate::compensation_execution::PROFILE,"contract_digest":c.digest().expect("validated contract")}});
                }
                if t.action.as_ref().is_some_and(|a| a.id == crate::kube_drain::ACTION) {
                    let c = self.adapter.kube_drain_contract().expect("validated physical adapter");
                    wire["_meta"] = json!({crate::kube_drain::EXTENSION:{"profile":crate::kube_drain::PROFILE,"contract_digest":c.digest().expect("validated physical contract"),"commit_point":"controller_acceptance","physical_completion":"separate_observation"}});
                }
                if t.action.as_ref().is_some_and(|a| a.id == crate::managed_drain::ACTION) {
                    let c = self.adapter.managed_drain_context().expect("validated managed adapter");
                    wire["_meta"] = json!({crate::managed_drain::EXTENSION:{"profile":crate::managed_drain::PROFILE,
                        "acceptance_proof_profile":crate::managed_drain_acceptance::PROFILE,
                        "enrollment_digest":c.enrollment.digest().expect("validated enrollment"),
                        "policy_digest":c.enrollment.policy.digest().expect("validated policy"),
                        "family_registration_digest":c.selection.registration.digest().expect("validated family"),
                        "child_id":c.selection.child_id,"operation_key":c.enrollment.operation_key,
                        "contract_digest":c.physical.contract.digest().expect("validated contract"),
                        "commit_point":"controller_acceptance","physical_completion":"separate_observation"}});
                }
                wire
            }).collect();
            return response(
                id,
                json!({"resultType":"complete","tools":tools,"ttlMs":0,"cacheScope":"private"}),
            );
        }
        let tool = match self.tools.get(&req.params.name) {
            Some(t) => t,
            None => return failure(id, -32004, "UNREGISTERED_TOOL", None),
        };
        if tool.required_scope.is_empty() {
            return failure(id, -32004, "UNREGISTERED_AUTHORIZATION", None);
        }
        if req.method == crate::execution_status::METHOD {
            if !extension(
                &req.params.meta,
                crate::execution_status::EXTENSION,
                crate::execution_status::PROFILE,
            ) {
                return failure(id, -32002, "KF_STATUS_NOT_NEGOTIATED", None);
            }
            if tool.status_scope.is_empty() || !identity.scopes.contains(&tool.status_scope) {
                return failure(id, -32003, "INSUFFICIENT_STATUS_SCOPE", None);
            }
            if headers.contains_key(INLINE_HEADER) || headers.contains_key(REFERENCE_HEADER) {
                return failure(id, -32602, "UNEXPECTED_GRANT_HEADER", None);
            }
            return match tokio::time::timeout(
                Duration::from_secs(5),
                self.query_execution(&req.params.arguments, &identity, tool),
            )
            .await
            {
                Ok(Ok(status)) => response(id, status),
                Ok(Err(Error::Invalid(_))) => failure(id, -32602, "INVALID_STATUS_PARAMS", None),
                Ok(Err(Error::Refused(_))) => failure(id, -32003, "STATUS_FORBIDDEN", None),
                _ => failure(id, -32009, "STATUS_UNAVAILABLE", None),
            };
        }
        if !identity.scopes.contains(&tool.required_scope) {
            return failure(id, -32003, "INSUFFICIENT_SCOPE", None);
        }
        if let Some(action) = &tool.action
            && action.id == crate::postgres_action::ACTION
            && tool.resource.as_ref().is_none_or(|resource| {
                crate::leaf_action::bind(
                    &action.id,
                    &action.version,
                    &req.params.arguments,
                    resource,
                    &tool.version_parameter,
                )
                .is_err()
            })
        {
            return failure(id, -32602, "INVALID_SQL_PARAMS", None);
        }
        if let Some(c) = &tool.inverse_contract {
            if !extension(
                &req.params.meta,
                crate::compensation_execution::EXTENSION,
                crate::compensation_execution::PROFILE,
            ) {
                return failure(id, -32004, "UNSUPPORTED_COMPENSATION_PROFILE", None);
            }
            if tool
                .action
                .as_ref()
                .zip(tool.resource.as_ref())
                .is_none_or(|(a, r)| {
                    crate::leaf_action::bind_inverse(
                        &a.id,
                        &a.version,
                        &req.params.arguments,
                        r,
                        &tool.version_parameter,
                        Some(c),
                    )
                    .is_err()
                })
            {
                return failure(id, -32602, "INVALID_COMPENSATION_PARAMS", None);
            }
        }
        let deadline = Instant::now() + self.timeout;
        let inline = header_values(headers, INLINE_HEADER);
        let references = header_values(headers, REFERENCE_HEADER);
        let (inline, references) = match (inline, references) {
            (Ok(i), Ok(r)) if i.len() <= 1 && r.len() <= 1 && (i.is_empty() || r.is_empty()) => {
                (i, r)
            }
            _ => return failure(id, -32005, "GRANT_MISMATCH", None),
        };
        if tool.read_only {
            if !req
                .params
                .arguments
                .as_object()
                .is_some_and(|o| o.is_empty())
            {
                return failure(id, -32602, "INVALID_READ_PARAMS", None);
            }
            if !inline.is_empty() || !references.is_empty() {
                return failure(id, -32005, "UNEXPECTED_GRANT", None);
            }
            return match tokio::time::timeout_at(deadline, self.adapter.read(&req, &identity)).await
            {
                Ok(Ok(result)) => response(id, result),
                _ => failure(id, -32006, "READ_FAILED", None),
            };
        }
        if !extension(&req.params.meta, "io.kedgeflow/governed-mcp", MCP_PROFILE) {
            return failure(id, -32002, "KF_EXTENSION_NOT_NEGOTIATED", None);
        }
        let parameters_digest = match digest("parameters", &req.params.arguments) {
            Ok(d) => d,
            Err(_) => return failure(id, -32602, "INVALID_PARAMS", None),
        };
        if inline.is_empty() && references.is_empty() {
            return failure(
                id,
                -32001,
                "NEEDS_EVIDENCE",
                Some(self.remediation(tool, &parameters_digest)),
            );
        }
        let raw = if let Some(reference) = references.first() {
            let resolver = match self.resolver.as_ref() {
                Some(r)
                    if extension(
                        &req.params.meta,
                        "io.kedgeflow/grant-reference",
                        REFERENCE_PROFILE,
                    ) =>
                {
                    r
                }
                _ => return failure(id, -32002, "KF_REFERENCE_NOT_NEGOTIATED", None),
            };
            if !valid_reference(reference) {
                return failure(id, -32005, "GRANT_MISMATCH", None);
            }
            match tokio::time::timeout_at(
                deadline.min(Instant::now() + Duration::from_secs(2)),
                resolver.resolve(&identity, reference),
            )
            .await
            {
                Ok(Ok(raw)) if !raw.is_empty() && raw.len() <= MAX_RESOLVED_BYTES => raw,
                _ => return failure(id, -32005, "GRANT_REFERENCE_UNAVAILABLE", None),
            }
        } else {
            if inline[0].len() > MAX_INLINE_HEADER {
                return failure(id, -32005, "GRANT_HEADER_TOO_LARGE", None);
            }
            match URL_SAFE_NO_PAD.decode(inline[0]) {
                Ok(r) => r,
                Err(_) => return failure(id, -32005, "GRANT_MISMATCH", None),
            }
        };
        let verified = match self.verifier.verify(&raw, self.clock.now_ms()) {
            Ok(g) if references.first().is_none_or(|r| *r == g.digest) => g,
            _ => return failure(id, -32005, "GRANT_MISMATCH", None),
        };
        if bind_call(&verified.grant, &identity, tool, &req.params.arguments).is_err() {
            return failure(id, -32005, "GRANT_MISMATCH", None);
        }
        let attempt_id = random_id();
        let correlation = || Some(json!({"attempt_id":attempt_id}));
        let claim_started = self.clock.now_ms();
        let attempt = match tokio::time::timeout_at(
            deadline,
            self.ledger.claim_recorded(
                &verified.grant,
                &verified.digest,
                &attempt_id,
                &crate::recovery::ExecutionRecord {
                    signed_grant: String::from_utf8(raw.clone()).expect("verified JSON grant"),
                    tool: tool.name.clone(),
                    parameters: req.params.arguments.clone(),
                },
            ),
        )
        .await
        {
            Ok(Ok(a)) => a,
            Ok(Err(Error::NonceConsumed)) => {
                return failure(
                    id,
                    -32007,
                    "NONCE_CONSUMED",
                    Some(self.resolve_claim(&verified.grant, &verified.digest).await),
                );
            }
            _ => {
                return failure(
                    id,
                    -32007,
                    "ROOT_UNAVAILABLE_OR_CONSUMED",
                    Some(self.resolve_claim(&verified.grant, &verified.digest).await),
                );
            }
        };
        let claimed_at = self.clock.now_ms();
        let call = VerifiedCall {
            request: req.clone(),
            grant: verified.grant,
            identity,
            attempt_id: attempt_id.clone(),
            descriptor: tool.clone(),
            grant_digest: verified.digest,
            signed_grant: raw,
        };
        let remaining = call
            .grant
            .expires_at
            .saturating_sub(self.clock.now_ms())
            .max(0) as u64;
        let deadline = deadline.min(Instant::now() + Duration::from_millis(remaining));
        let credential =
            match tokio::time::timeout_at(deadline, self.broker.exchange(&call, deadline)).await {
                Ok(Ok(c))
                    if !c.token.is_empty()
                        && self.clock.now_ms() < c.expires_at_ms
                        && c.expires_at_ms <= call.grant.expires_at =>
                {
                    c
                }
                _ => {
                    let _ = self.finish(&call.grant, &attempt, "not_dispatched").await;
                    return failure(id, -32008, "CREDENTIAL_UNAVAILABLE", correlation());
                }
            };
        let broker_returned_at = self.clock.now_ms();
        if self
            .verifier
            .verify(&call.signed_grant, self.clock.now_ms())
            .is_err()
            || Instant::now() >= deadline
        {
            let _ = self.finish(&call.grant, &attempt, "not_dispatched").await;
            return failure(id, -32005, "GRANT_EXPIRED_AFTER_CLAIM", correlation());
        }
        if !matches!(
            tokio::time::timeout_at(
                deadline,
                self.ledger
                    .authorize_dispatch(&call.grant, &call.grant_digest, &attempt_id)
            )
            .await,
            Ok(Ok(()))
        ) {
            let _ = self.finish(&call.grant, &attempt, "not_dispatched").await;
            return failure(
                id,
                -32007,
                "AUTHORITY_CHANGED_BEFORE_DISPATCH",
                correlation(),
            );
        }
        if self
            .verifier
            .verify(&call.signed_grant, self.clock.now_ms())
            .is_err()
            || Instant::now() >= deadline
            || self.clock.now_ms() >= credential.expires_at_ms
        {
            if self.adapter.managed_drain_context().is_some() {
                eprintln!(
                    "managed validity exhausted before original dispatch; claim_ms={}; broker_ms={}; authority_ms={}; grant_remaining_ms={}; credential_remaining_ms={}",
                    claimed_at - claim_started,
                    broker_returned_at - claimed_at,
                    self.clock.now_ms() - broker_returned_at,
                    call.grant.expires_at - self.clock.now_ms(),
                    credential.expires_at_ms - self.clock.now_ms()
                );
            }
            let _ = self.finish(&call.grant, &attempt, "not_dispatched").await;
            return failure(id, -32005, "DISPATCH_VALIDITY_EXPIRED", correlation());
        }
        let dispatch_started = self.clock.now_ms();
        let outcome =
            tokio::time::timeout_at(deadline, self.adapter.dispatch(&call, &credential)).await;
        let outcome = match outcome {
            Ok(Ok(result))
                if ["committed", "state_guard_violation"].contains(&result.status.as_str()) =>
            {
                result
            }
            other => {
                if self.adapter.managed_drain_context().is_some() {
                    let diagnostic = match other {
                        Ok(Err(error)) => error.to_string(),
                        Err(_) => "original dispatch deadline elapsed".into(),
                        Ok(Ok(_)) => "unsupported original adapter outcome".into(),
                    };
                    eprintln!(
                        "managed dispatch of retained attempt {:?} unresolved: {:?}; elapsed_ms={}; grant_remaining_ms={}; token_remaining_ms={}; claim_ms={}; broker_ms={}; authority_ms={}",
                        attempt_id,
                        diagnostic,
                        self.clock.now_ms() - dispatch_started,
                        call.grant.expires_at - self.clock.now_ms(),
                        credential.expires_at_ms - self.clock.now_ms(),
                        claimed_at - claim_started,
                        broker_returned_at - claimed_at,
                        dispatch_started - broker_returned_at
                    );
                }
                let _ = self.finish(&call.grant, &attempt, "unknown").await;
                return failure(id, -32009, "OUTCOME_UNKNOWN", correlation());
            }
        };
        let evidence = match self.adapter.outcome_evidence(&outcome) {
            Ok(evidence) => evidence,
            Err(_) => {
                let _ = self.finish(&call.grant, &attempt, "unknown").await;
                return failure(id, -32009, "OUTCOME_UNKNOWN", correlation());
            }
        };
        if self
            .finish_recorded(&call.grant, &attempt, &outcome.status, &evidence)
            .await
            .is_err()
        {
            return failure(id, -32009, "OUTCOME_UNKNOWN", correlation());
        }
        if outcome.status == "state_guard_violation" {
            return failure(id, -32010, "STATE_GUARD_VIOLATION", correlation());
        }
        response(id, outcome.result)
    }
    fn remediation(&self, tool: &ToolDescriptor, parameters_digest: &str) -> Value {
        let action = tool
            .action
            .as_ref()
            .expect("validated consequential registration");
        json!({"remediation_id":random_id(),"code":"NEEDS_EVIDENCE","proposal_digest":null,"action":action,"parameters_digest":parameters_digest,
            "obligations":[{"obligation_id":"exact-admission","kind":"policy","stage":"static","accepted_provider_classes":["AdmissionController"],
                "question_ref":{"id":action.id,"schema":"https://kedgeflow.dev/spec/v0.9/questions/admission","digest":action.digest},"max_age_ms":0,
                "instruction":"Freeze an exact proposal and obtain admission under the current policy"},
                {"obligation_id":"state-witness","kind":"state","stage":"jit","accepted_provider_classes":["ResourceAdapter"],
                "question_ref":{"id":tool.predicate_id,"schema":"https://kedgeflow.dev/spec/v0.9/questions/resource-version","digest":action.digest},"max_age_ms":1000,
                "instruction":"Acquire the required fresh resource-version witness"}],
            "admission_endpoint":tool.admission_endpoint,"profile":"KF-JSON-0.2","grant_carriage":INLINE_HEADER,
            "expires_at":self.clock.now_ms()+60000,"retry_after_admission":true})
    }
}

#[cfg(test)]
mod identifier_tests {
    use super::*;

    #[test]
    fn every_leading_entropy_byte_produces_receipt_and_sql_compatible_ids() {
        let frozen: Value =
            serde_json::from_str(include_str!("../../../spec/kedgeflow.schema.json")).unwrap();
        let id_schema =
            crate::schema::compile(&json!({"$ref":"#/$defs/Id","$defs":frozen["$defs"]})).unwrap();
        // Negative controls reproduce the old generator's two invalid prefixes.
        for byte in [0xfb, 0xff] {
            assert!(!id_schema.is_valid(&json!(URL_SAFE_NO_PAD.encode([byte; 18]))));
        }
        for byte in 0..=255 {
            let id = identifier(&[byte; 18]);
            assert!(id_schema.is_valid(&json!(id)), "leading byte {byte}");
            let request = json!({"profile":crate::postgres_action::PROFILE,"action":crate::postgres_action::ACTION,
                "tenant":"test","conflict_domain":"test","attempt_id":id,"grant_digest":"a".repeat(64),
                "root_id":"root","resource":{"id":"resource","incarnation":"incarnation"},
                "expected_version":1,"fence":1,"reservation":"booking","gateway_workload":"spiffe://test/gateway","expires_at":1});
            crate::postgres_action::validate(&request).unwrap();
        }
    }
}
