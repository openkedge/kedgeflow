//! A2A v1 JSON-RPC coordination tasks backed by retained signed family events.
//! Completed tasks describe delegation/allocation, never physical target effects.
use crate::{
    auth::{DualAuthenticator, WorkloadIdentity},
    clock::Clock,
    contracts::{digest, strict_value},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    family::{Action, Command, Event, Family, Registration, State},
    hierarchical_leaf::Principal,
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State as AppState},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
pub const PROFILE: &str = "KF-A2A-FAMILY-TASKS-0.1-draft";
pub const EXTENSION: &str = "https://kedgeflow.dev/extensions/family-tasks/v0.1";
const MAX_REQUEST: usize = 32 << 10;
#[derive(Debug)]
struct Fault {
    code: i32,
    message: &'static str,
}
type RpcResult<T> = std::result::Result<T, Fault>;
fn fault(code: i32, message: &'static str) -> Fault {
    Fault { code, message }
}
fn params() -> Fault {
    fault(-32602, "unsupported or invalid coordination parameters")
}
fn unavailable() -> Fault {
    fault(
        -32603,
        "family authority unavailable; query the original task",
    )
}
fn app_error(e: Error) -> Fault {
    match e {
        Error::Refused(_) | Error::Invalid(_) => {
            fault(-32602, "family command refused; query original operation")
        }
        _ => unavailable(),
    }
}
fn empty(v: &Option<Value>) -> bool {
    v.as_ref()
        .is_none_or(|v| v.as_object().is_some_and(|m| m.is_empty()))
}
fn parse<T: for<'a> Deserialize<'a>>(v: Value) -> RpcResult<T> {
    serde_json::from_value(v).map_err(|_| params())
}
fn bounded(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rpc {
    jsonrpc: String,
    id: Value,
    method: String,
    params: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Send {
    message: Message,
    #[serde(default)]
    configuration: Option<Configuration>,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default)]
    tenant: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Configuration {
    #[serde(default)]
    accepted_output_modes: Vec<String>,
    #[serde(default)]
    history_length: Option<u64>,
    #[serde(default)]
    return_immediately: bool,
    #[serde(default)]
    task_push_notification_config: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Message {
    message_id: String,
    role: String,
    parts: Vec<Part>,
    #[serde(default)]
    context_id: String,
    #[serde(default)]
    task_id: String,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    reference_task_ids: Vec<String>,
    #[serde(default)]
    metadata: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Part {
    data: Value,
    #[serde(default)]
    media_type: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    metadata: Option<Value>,
}
enum Data {
    Command(Box<Command>),
    View(View),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct View {
    profile: String,
    operation: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Get {
    id: String,
    #[serde(default)]
    history_length: Option<u64>,
    #[serde(default)]
    tenant: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Cancel {
    id: String,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default)]
    tenant: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct List {
    #[serde(default)]
    context_id: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    page_size: Option<usize>,
    #[serde(default)]
    page_token: String,
    #[serde(default)]
    history_length: Option<u64>,
    #[serde(default)]
    include_artifacts: bool,
    #[serde(default)]
    status_timestamp_after: Option<String>,
    #[serde(default)]
    tenant: String,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Page {
    head: String,
    index: usize,
    query: String,
}
pub struct Peer {
    family: Arc<Family>,
    registration: Registration,
    context: String,
    auth: DualAuthenticator,
    endpoint: EndpointPolicy,
    card_endpoint: EndpointPolicy,
    clock: Arc<dyn Clock>,
    scope: String,
    slots: Arc<tokio::sync::Semaphore>,
    url: String,
}
impl Peer {
    pub fn new(
        family: Family,
        auth: DualAuthenticator,
        url: &str,
        scope: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let registration = family.registration().clone();
        registration.validate()?;
        let endpoint = EndpointPolicy::new(url)?;
        let card_endpoint = EndpointPolicy::new(&format!(
            "https://{}/.well-known/agent-card.json",
            endpoint.authority()
        ))?;
        if scope != "kf.family.coordinate"
            || auth.external_url() != url
            || registration.signers.values().any(|s| {
                s.principal.subject.iss != auth.issuer()
                    || crate::config::key(&s.public_key)
                        .is_ok_and(|key| key == *auth.pinned_issuer_key().as_bytes())
            })
        {
            return Err(Error::Invalid(
                "invalid family peer identity/endpoint pins".into(),
            ));
        }
        let context = digest(
            "family-task-context",
            &json!({"namespace":registration.namespace,"registration":registration.digest()?}),
        )?;
        Ok(Self {
            family: Arc::new(family),
            registration,
            context,
            auth,
            endpoint,
            card_endpoint,
            clock,
            scope,
            slots: Arc::new(tokio::sync::Semaphore::new(32)),
            url: url.into(),
        })
    }
    fn task_id(&self, event: &Event) -> Result<String> {
        digest(
            "family-task-id",
            &json!({"context":self.context,"operation":event.command.payload.operation_key}),
        )
    }
    fn reader(&self, p: &Principal, e: &Event) -> bool {
        p == &self.registration.owner
            || e.command
                .principal(&self.registration)
                .is_ok_and(|s| s == p)
            || matches!(&e.command.payload.action,Action::Delegate {branch,..} if &branch.owner==p)
    }
    fn tenant(&self, s: &str) -> RpcResult<()> {
        if s.is_empty() || s == self.registration.tenant {
            Ok(())
        } else {
            Err(params())
        }
    }
    fn task(&self, event: &Event) -> RpcResult<Value> {
        let id = self.task_id(event).map_err(|_| unavailable())?;
        let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(event.at)
            .ok_or_else(unavailable)?
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        Ok(
            json!({"id":id,"contextId":self.context,"status":{"state":"TASK_STATE_COMPLETED","timestamp":at},
            "artifacts":[{"artifactId":"family-command-receipt","name":"Retained coordination command","extensions":[EXTENSION],
                "parts":[{"mediaType":"application/json","data":{"profile":PROFILE,"familyDigest":self.registration.digest().map_err(|_|unavailable())?,
                    "operationKey":event.command.payload.operation_key,"command":event.command,"appliedAt":event.at,
                    "executionAuthority":false,"targetEffectVerified":false}}]}]}),
        )
    }
    fn selected<'a>(&self, state: &'a State, p: &Principal, id: &str) -> RpcResult<&'a Event> {
        state
            .events
            .iter()
            .find(|e| self.task_id(e).is_ok_and(|t| t == id) && self.reader(p, e))
            .ok_or_else(|| fault(-32001, "task not found"))
    }
    async fn execute(&self, p: &Principal, method: &str, value: Value) -> RpcResult<Value> {
        match method {
            "SendMessage" => {
                let s: Send = parse(value)?;
                self.tenant(&s.tenant)?;
                if !empty(&s.metadata)
                    || !bounded(&s.message.message_id)
                    || s.message.role != "ROLE_USER"
                    || s.message.parts.len() != 1
                    || !empty(&s.message.metadata)
                    || !s.message.reference_task_ids.is_empty()
                    || s.message.extensions != [EXTENSION]
                    || (!s.message.context_id.is_empty() && s.message.context_id != self.context)
                {
                    return Err(params());
                }
                if let Some(c) = s.configuration {
                    let _immediate = c.return_immediately;
                    let _history = c.history_length;
                    if c.task_push_notification_config.is_some() {
                        return Err(fault(-32003, "push notifications are not supported"));
                    }
                    if !c.accepted_output_modes.is_empty()
                        && !c
                            .accepted_output_modes
                            .iter()
                            .any(|m| m == "application/json")
                    {
                        return Err(fault(-32005, "coordination results require JSON output"));
                    }
                }
                let part = s.message.parts.into_iter().next().ok_or_else(params)?;
                if !part.filename.is_empty()
                    || (!part.media_type.is_empty() && part.media_type != "application/json")
                    || !empty(&part.metadata)
                {
                    return Err(fault(-32005, "only signed coordination JSON is supported"));
                }
                // Decode the signed command with its own exact round-trip
                // parser; serde set normalization must not make wire variants
                // of a signed request acceptable.
                let data = if part.data.get("profile").and_then(Value::as_str) == Some(PROFILE) {
                    Data::View(parse(part.data)?)
                } else {
                    Data::Command(Box::new(
                        Command::decode(&serde_json::to_vec(&part.data).map_err(|_| params())?)
                            .map_err(|_| params())?,
                    ))
                };
                let command = match data {
                    Data::Command(c) => *c,
                    Data::View(v) => {
                        if v.profile != PROFILE
                            || v.operation != "status"
                            || !s.message.task_id.is_empty()
                        {
                            return Err(params());
                        }
                        let state = self.family.status().await.map_err(app_error)?;
                        let message_id = digest(
                            "family-status-message",
                            &json!({"context":self.context,"head":state.head}),
                        )
                        .map_err(|_| unavailable())?;
                        return Ok(
                            json!({"message":{"messageId":message_id,"contextId":self.context,"role":"ROLE_AGENT",
                            "extensions":[EXTENSION],"parts":[{"mediaType":"application/json","data":{"profile":PROFILE,"operation":"status",
                                "familyDigest":self.registration.digest().map_err(|_|unavailable())?,"familyHead":state.head,
                                "active":state.active,"executionAuthority":false}}]}}),
                        );
                    }
                };
                if command
                    .principal(&self.registration)
                    .map_err(|_| params())?
                    != p
                {
                    return Err(params());
                }
                if !s.message.task_id.is_empty() {
                    let old = self.family.status().await.map_err(app_error)?;
                    let original = self.selected(&old, p, &s.message.task_id)?;
                    if original.command != command {
                        return Err(params());
                    }
                }
                let operation = command.payload.operation_key.clone();
                let state = self.family.apply(command).await.map_err(app_error)?;
                let event = state
                    .events
                    .iter()
                    .find(|e| e.command.payload.operation_key == operation)
                    .ok_or_else(unavailable)?;
                Ok(json!({"task":self.task(event)?}))
            }
            "GetTask" => {
                let g: Get = parse(value)?;
                self.tenant(&g.tenant)?;
                let _history = g.history_length;
                if !bounded(&g.id) {
                    return Err(params());
                }
                let state = self.family.status().await.map_err(app_error)?;
                self.task(self.selected(&state, p, &g.id)?)
            }
            "CancelTask" => {
                let c: Cancel = parse(value)?;
                self.tenant(&c.tenant)?;
                if !bounded(&c.id) || !empty(&c.metadata) {
                    return Err(params());
                }
                let state = self.family.status().await.map_err(app_error)?;
                self.selected(&state, p, &c.id)?;
                Err(fault(
                    -32002,
                    "completed coordination task cannot be canceled; allowances remain held",
                ))
            }
            "ListTasks" => {
                let q: List = parse(value)?;
                self.tenant(&q.tenant)?;
                let page = q.page_size.unwrap_or(50);
                if !(1..=100).contains(&page)
                    || ![
                        "",
                        "TASK_STATE_UNSPECIFIED",
                        "TASK_STATE_COMPLETED",
                        "TASK_STATE_SUBMITTED",
                        "TASK_STATE_WORKING",
                        "TASK_STATE_FAILED",
                        "TASK_STATE_CANCELED",
                        "TASK_STATE_REJECTED",
                        "TASK_STATE_INPUT_REQUIRED",
                        "TASK_STATE_AUTH_REQUIRED",
                    ]
                    .contains(&q.status.as_str())
                {
                    return Err(params());
                }
                let query = digest("family-task-page-query", &json!({"principal":p,"context":q.context_id,"status":q.status,"after":q.status_timestamp_after,"artifacts":q.include_artifacts})).map_err(|_|unavailable())?;
                let _history = q.history_length;
                let after = q
                    .status_timestamp_after
                    .map(|s| chrono::DateTime::parse_from_rfc3339(&s).map_err(|_| params()))
                    .transpose()?;
                let state = self.family.status().await.map_err(app_error)?;
                let mut events: Vec<_> = state
                    .events
                    .iter()
                    .filter(|e| {
                        self.reader(p, e)
                            && after.is_none_or(|after| {
                                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(e.at)
                                    .is_some_and(|at| at >= after)
                            })
                    })
                    .collect();
                // Applied times are monotonic in the retained signed history;
                // newest event first gives stable descending timestamp order.
                events.reverse();
                if (!q.context_id.is_empty() && q.context_id != self.context)
                    || !["", "TASK_STATE_UNSPECIFIED", "TASK_STATE_COMPLETED"]
                        .contains(&q.status.as_str())
                {
                    events.clear();
                }
                let index = if q.page_token.is_empty() {
                    0
                } else {
                    use base64::Engine;
                    if q.page_token.len() > 256 {
                        return Err(params());
                    }
                    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(&q.page_token)
                        .map_err(|_| params())?;
                    let token: Page = parse(strict_value(&raw).map_err(|_| params())?)?;
                    if token.head != state.head || token.query != query {
                        return Err(params());
                    }
                    token.index
                };
                if index > events.len() {
                    return Err(params());
                }
                let end = (index + page).min(events.len());
                let mut tasks = Vec::new();
                for e in &events[index..end] {
                    let mut t = self.task(e)?;
                    if !q.include_artifacts {
                        t.as_object_mut().unwrap().remove("artifacts");
                    }
                    tasks.push(t);
                }
                let next = if end == events.len() {
                    String::new()
                } else {
                    use base64::Engine;
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                        serde_json::to_vec(&Page {
                            head: state.head,
                            index: end,
                            query,
                        })
                        .map_err(|_| unavailable())?,
                    )
                };
                Ok(
                    json!({"tasks":tasks,"pageSize":page,"totalSize":events.len(),"nextPageToken":next}),
                )
            }
            "SendStreamingMessage" | "SubscribeToTask" => {
                Err(fault(-32004, "streaming is not supported"))
            }
            "GetExtendedAgentCard" => Err(fault(-32007, "extended card is not configured")),
            "CreateTaskPushNotificationConfig"
            | "GetTaskPushNotificationConfig"
            | "ListTaskPushNotificationConfigs"
            | "DeleteTaskPushNotificationConfig" => {
                Err(fault(-32003, "push notifications are not supported"))
            }
            _ => Err(fault(-32601, "method not found")),
        }
    }
}
impl Peer {
    pub fn card(&self) -> Result<Value> {
        Ok(
            json!({"name":"KedgeFlow family coordinator","description":"Signed narrowed delegation and held native child capacity. Coordination completion is not a target effect.",
            "version":"0.1.0-draft","supportedInterfaces":[{"url":self.url,"protocolBinding":"JSONRPC","protocolVersion":"1.0"}],
            "capabilities":{"streaming":false,"pushNotifications":false,"extendedAgentCard":false,
                "extensions":[{"uri":EXTENSION,"required":true,"description":"Protected signed family commands; no execution authority from tasks",
                    "params":{"profile":PROFILE,"familyDigest":self.registration.digest()?,"contextId":self.context,"maxRetainedTasks":64}}]},
            "securitySchemes":{"workload":{"mtlsSecurityScheme":{"description":"Verified approved SPIFFE workload certificate"}},
                "subject":{"httpAuthSecurityScheme":{"scheme":"DPoP","description":"OIDC subject token and endpoint-bound DPoP; independent of workload identity"}}},
            "securityRequirements":[{"schemes":{"workload":{"list":[]},"subject":{"list":[self.scope]}}}],
            "defaultInputModes":["application/json"],"defaultOutputModes":["application/json"],
            "skills":[{"id":"family-coordinate","name":"Coordinate protected child authority","description":"Delegate, attach or stop signed family branches. Separate fresh native admission and execution remain required for each child.","tags":["coordination","capacity","delegation"],"inputModes":["application/json"],"outputModes":["application/json"]}]}),
        )
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    async fn rpc(&self, p: &Principal, raw: &[u8], headers: &HeaderMap) -> Value {
        let (id, result) = match strict_value(raw) {
            Err(_) => (Value::Null, Err(fault(-32700, "invalid integer-only JSON"))),
            Ok(v) => match serde_json::from_value::<Rpc>(v) {
                Err(_) => (Value::Null, Err(fault(-32600, "invalid JSON-RPC request"))),
                Ok(r) => {
                    let valid_id = r.id.as_i64().is_some() || r.id.as_str().is_some_and(bounded);
                    if r.jsonrpc != "2.0" || !valid_id {
                        (Value::Null, Err(fault(-32600, "invalid JSON-RPC request")))
                    } else if one(headers, "a2a-version") != Some("1.0") {
                        (
                            r.id,
                            Err(fault(-32009, "A2A protocol version 1.0 is required")),
                        )
                    } else if one(headers, "a2a-extensions").is_none_or(|s| s.trim() != EXTENSION) {
                        (
                            r.id,
                            Err(fault(
                                -32008,
                                "the signed family task extension is required",
                            )),
                        )
                    } else {
                        (r.id, self.execute(p, &r.method, r.params).await)
                    }
                }
            },
        };
        match result {
            Ok(value) => json!({"jsonrpc":"2.0","id":id,"result":value}),
            Err(e) => json!({"jsonrpc":"2.0","id":id,"error":{"code":e.code,"message":e.message}}),
        }
    }
}
fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}
fn json_content_type(value: Option<&str>) -> bool {
    let Some(value) = value else { return false };
    let mut parts = value.split(';').map(str::trim);
    if !matches!(
        parts.next(),
        Some("application/json" | "application/a2a+json")
    ) {
        return false;
    }
    let rest: Vec<_> = parts.collect();
    rest.is_empty() || rest.len() == 1 && rest[0].eq_ignore_ascii_case("charset=utf-8")
}
fn response(status: StatusCode, value: Value) -> Response {
    (
        status,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
            ("a2a-version", "1.0"),
            ("a2a-extensions", EXTENSION),
        ],
        Json(value),
    )
        .into_response()
}
async fn handle(
    AppState(service): AppState<Arc<Peer>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    if request.method() == Method::GET && request.uri().path() == service.card_endpoint.path() {
        if let Some(code) = service
            .card_endpoint
            .rejection_status(request.headers(), request.uri())
        {
            return response(code, json!({"error":"endpoint refused"}));
        }
        return match service.card() {
            Ok(card) => response(StatusCode::OK, card),
            Err(_) => response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"card unavailable"}),
            ),
        };
    }
    if request.method() != Method::POST {
        return response(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error":"POST required"}),
        );
    }
    if let Some(code) = service
        .endpoint
        .rejection_status(request.headers(), request.uri())
    {
        return response(code, json!({"error":"endpoint refused"}));
    }
    let content = one(request.headers(), "content-type");
    if !json_content_type(content) || request.headers().contains_key("content-encoding") {
        return response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({"error":"uncompressed JSON required"}),
        );
    }
    let Ok(_slot) = service.slots.clone().try_acquire_owned() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"peer busy"}),
        );
    };
    let identity = match service
        .auth
        .authenticate_shared_at(request.headers(), &workload, service.clock.now_ms() / 1000)
        .await
    {
        Ok(i) => i,
        Err(Error::Unavailable(_)) => {
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"identity authority unavailable"}),
            );
        }
        Err(_) => {
            return response(
                StatusCode::UNAUTHORIZED,
                json!({"error":"identity refused"}),
            );
        }
    };
    let principal = Principal {
        subject: identity.subject.clone(),
        workload_id: identity.workload_id.clone(),
    };
    if !identity.scopes.contains(&service.scope)
        || !service
            .registration
            .signers
            .values()
            .any(|s| s.principal == principal)
    {
        return response(
            StatusCode::FORBIDDEN,
            json!({"error":"coordination role required"}),
        );
    }
    let headers = request.headers().clone();
    let raw = match to_bytes(request.into_body(), MAX_REQUEST).await {
        Ok(v) => v,
        Err(_) => {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error":"bounded request required"}),
            );
        }
    };
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        service.rpc(&principal, &raw, &headers),
    )
    .await
    {
        Ok(value) => response(StatusCode::OK, value),
        Err(_) => response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"reply unavailable; query original task"}),
        ),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub authority: crate::family::Config,
    pub listen: std::net::SocketAddr,
    pub external_url: String,
    pub certificate: std::path::PathBuf,
    pub private_key: std::path::PathBuf,
    pub workload_ca: std::path::PathBuf,
    pub oidc_issuer: String,
    pub oidc_public_key_base64: String,
    pub delegation_audience: String,
    #[serde(default)]
    pub shared_auth: Option<crate::shared_auth::SharedAuthConfig>,
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid(
                "family peer configuration exceeds bound".into(),
            ));
        }
        let c: Self = serde_json::from_value(strict_value(raw)?)?;
        c.authority.registration.validate()?;
        EndpointPolicy::new(&c.external_url)?;
        Ok(c)
    }
    pub async fn service(&self) -> Result<Arc<Peer>> {
        let clock: Arc<dyn Clock> = Arc::new(crate::clock::SystemClock);
        let family = Family::new(
            self.authority.ledger().await?.with_clock(clock.clone()),
            self.authority.registration.clone(),
        )?;
        let mut auth = DualAuthenticator::new(
            &self.oidc_issuer,
            &self.delegation_audience,
            &self.external_url,
            crate::config::key(&self.oidc_public_key_base64)?,
        )?;
        if let Some(s) = &self.shared_auth {
            auth = auth.with_shared_replay(family.manager_ledger(), s.clone())?;
        }
        Ok(Arc::new(Peer::new(
            family,
            auth,
            &self.external_url,
            "kf.family.coordinate".into(),
            clock,
        )?))
    }
}
