//! Authenticated reservation views only. References and views carry no authority.
use crate::{
    auth::Identity,
    contracts::{Subject, digest, strict_value},
    coordination::{
        Coordination, ReservationEnrollment, ReservationScope, ReservationSnapshot,
        ReservationState,
    },
    endpoint::EndpointPolicy,
    error::{Error, Result},
    ledger::{EtcdLedger, get, put, range_kv, record, value_eq, version_zero},
    tls::PinnedClient,
};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::OnceLock, time::Duration};
pub const PROFILE: &str = "KF-A2A-ROOT-RESOLUTION-0.1-draft";
pub const EXTENSION: &str = "urn:kedgeflow:a2a:root-resolution:0.1-draft";
pub const PATH: &str = "/a2a/root:resolve";
pub const MAX_BYTES: usize = 64 << 10;
fn refuse() -> Error {
    Error::Refused("root reference, reader or scope refused".into())
}
pub(crate) fn validate(value: &Value, kind: &str) -> Result<()> {
    static PIN: OnceLock<
        std::result::Result<std::collections::BTreeMap<String, jsonschema::Validator>, String>,
    > = OnceLock::new();
    let pin = PIN.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!("../../../spec/drafts/a2a-root-resolution-v0.1.schema.json")).map_err(|e| e.to_string())?;
        ["registration","request","response","scope"].into_iter().map(|kind| {
            let selected = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":format!("#/$defs/{kind}"),"$defs":schema["$defs"]});
            Ok((kind.to_owned(),crate::schema::compile(&selected).map_err(|e|e.to_string())?))
        }).collect()
    });
    let pins = pin.as_ref().map_err(|e| Error::Unavailable(e.clone()))?;
    if !pins.get(kind).is_some_and(|p| p.is_valid(value)) {
        return Err(Error::Invalid(
            "invalid closed root-resolution record".into(),
        ));
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reader {
    pub subject: Subject,
    pub workload_id: String,
    pub scope: ReservationScope,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub profile: String,
    pub root_id: String,
    pub root_generation: u64,
    pub enrollment: ReservationEnrollment,
    pub delegation_id: String,
    pub authority_endpoint: String,
    pub required_scope: String,
    pub readers: Vec<Reader>,
}
impl Registration {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BYTES {
            return Err(refuse());
        }
        let value = strict_value(raw)?;
        validate(&value, "registration")?;
        let r: Self = serde_json::from_value(value)?;
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        let value = serde_json::to_value(self)?;
        if serde_json::to_vec(&value)?.len() > MAX_BYTES {
            return Err(refuse());
        }
        validate(&value, "registration")?;
        let endpoint = EndpointPolicy::new(&self.authority_endpoint)?;
        let state = ReservationSnapshot {
            profile: crate::coordination::PROFILE.into(),
            enrollment: self.enrollment.clone(),
            active: true,
            execution_authority: false,
            allocations: Default::default(),
        };
        state.validate()?;
        let mut identities = BTreeSet::new();
        if endpoint.path() != PATH || self.required_scope.split_whitespace().count() != 1 {
            return Err(refuse());
        }
        for r in &self.readers {
            if !crate::auth::valid_spiffe_id(&r.workload_id)
                || !r.scope.narrows(&self.enrollment.scope)
                || !identities.insert((&r.subject.iss, &r.subject.sub, &r.workload_id))
            {
                return Err(refuse());
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        digest(
            "a2a-root-resolution-registration",
            &serde_json::to_value(self)?,
        )
    }
    /// Insert this fragment into an existing A2A peer's capabilities.extensions.
    /// This resolver implements no core A2A messaging or task operations.
    pub fn agent_extension(&self) -> Result<Value> {
        self.validate()?;
        Ok(
            json!({"uri":EXTENSION,"description":"Authenticated non-authorizing reservation-root views","required":true,"params":{"assuranceProfiles":[crate::coordination::PROFILE],"resolutionProfile":PROFILE,"authorityEndpoint":self.authority_endpoint,"executionAuthority":false,"childGrants":false}}),
        )
    }
    pub fn reference_part(&self) -> Part {
        Part {
            media_type: "application/json".into(),
            data: RootReference {
                kind: "urn:kedgeflow:root-reference:1.0".into(),
                root_id: self.root_id.clone(),
                root_generation: self.root_generation,
                delegation_id: self.delegation_id.clone(),
                assurance_profile: crate::coordination::PROFILE.into(),
                cryptographic_profile: "KF-JSON-0.2".into(),
                authority_endpoint: self.authority_endpoint.clone(),
                saga_budget: Value::Null,
            },
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootReference {
    #[serde(rename = "type")]
    pub kind: String,
    pub root_id: String,
    pub root_generation: u64,
    pub delegation_id: String,
    pub assurance_profile: String,
    pub cryptographic_profile: String,
    pub authority_endpoint: String,
    pub saga_budget: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Part {
    pub data: RootReference,
    #[serde(rename = "mediaType")]
    pub media_type: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub profile: String,
    pub request_id: String,
    pub part: Part,
    pub scope: ReservationScope,
    pub parent_operation: Option<String>,
    pub task_id: Option<String>,
    pub context_id: Option<String>,
}
impl ResolveRequest {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BYTES {
            return Err(refuse());
        }
        let v = strict_value(raw)?;
        validate(&v, "request")?;
        Ok(serde_json::from_value(v)?)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub profile: String,
    pub request_id: String,
    pub root_id: String,
    pub root_generation: u64,
    pub delegation_id: String,
    pub tenant: String,
    pub conflict_domain: String,
    pub scope: ReservationScope,
    pub parent_operation: Option<String>,
    pub parent_state: Option<ReservationState>,
    pub root_active: bool,
    pub snapshot_digest: String,
    pub execution_authority: bool,
    pub child_grants_supported: bool,
    pub task_id: Option<String>,
    pub context_id: Option<String>,
}
/// Protected logical ACL key does not change with reader/endpoint/configuration changes.
fn acl_key(c: &Coordination, r: &Registration) -> Result<String> {
    Ok(format!(
        "{}/a2a-root-resolvers/{}",
        c.ledger.prefix,
        digest(
            "a2a-root-resolution-key",
            &json!({"root_id":r.root_id,"delegation_id":r.delegation_id})
        )?
    ))
}
fn marker(r: &Registration, active: bool) -> Result<String> {
    record(&json!({"profile":PROFILE,"registration_digest":r.digest()?,"active":active}))
}
#[derive(Clone)]
pub struct RootResolver {
    ledger: EtcdLedger,
    registration: Registration,
}
impl RootResolver {
    pub fn new(ledger: EtcdLedger, registration: Registration) -> Result<Self> {
        registration.validate()?;
        Ok(Self {
            ledger,
            registration,
        })
    }
    pub fn registration(&self) -> &Registration {
        &self.registration
    }
    fn coordination(&self) -> Result<Coordination> {
        Coordination::new(self.ledger.clone(), &self.registration.root_id)
    }
    /// Privileged create-only ACL installation. Does not enroll a root or grant.
    pub async fn enroll(&self) -> Result<()> {
        let c = self.coordination()?;
        let state = c.status().await?;
        if state.enrollment != self.registration.enrollment {
            return Err(refuse());
        }
        let (domain, binding) = c.domain_binding(&state.enrollment)?;
        if !self
            .ledger
            .txn(
                vec![
                    value_eq(&c.key, &record(&state)?),
                    value_eq(&domain, &binding),
                    version_zero(&acl_key(&c, &self.registration)?),
                ],
                vec![put(
                    &acl_key(&c, &self.registration)?,
                    &marker(&self.registration, true)?,
                )],
                vec![],
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    /// Permanent ACL withdrawal; capacity and independently issued authority unchanged.
    pub async fn withdraw(&self) -> Result<()> {
        let c = self.coordination()?;
        let key = acl_key(&c, &self.registration)?;
        let inactive = marker(&self.registration, false)?;
        let raw = self.ledger.read_key(&key).await?.ok_or_else(refuse)?;
        if raw == inactive.as_bytes() {
            return Ok(());
        }
        if raw != marker(&self.registration, true)?.as_bytes() {
            return Err(refuse());
        }
        if !self
            .ledger
            .txn(
                vec![value_eq(&key, &marker(&self.registration, true)?)],
                vec![put(&key, &inactive)],
                vec![],
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub async fn resolve(
        &self,
        identity: &Identity,
        request: &ResolveRequest,
    ) -> Result<Resolution> {
        validate(&serde_json::to_value(request)?, "request")?;
        let r = &self.registration;
        if request.part != r.reference_part() || !identity.scopes.contains(&r.required_scope) {
            return Err(refuse());
        }
        let reader = r
            .readers
            .iter()
            .find(|p| p.subject == identity.subject && p.workload_id == identity.workload_id)
            .ok_or_else(refuse)?;
        if !request.scope.narrows(&reader.scope) {
            return Err(refuse());
        }
        let c = self.coordination()?;
        let (domain, binding) = c.domain_binding(&r.enrollment)?;
        let reply = self
            .ledger
            .txn(
                vec![],
                vec![get(&acl_key(&c, r)?), get(&c.key), get(&domain)],
                vec![],
            )
            .await?;
        if !reply.succeeded || reply.responses.len() != 3 {
            return Err(Error::Unavailable(
                "root resolution snapshot unavailable".into(),
            ));
        }
        let raws = reply
            .responses
            .iter()
            .map(|v| range_kv(v)?.ok_or_else(refuse))
            .collect::<Result<Vec<_>>>()?;
        if raws[0].value != marker(r, true)?.as_bytes()
            || raws[2].value != binding.as_bytes()
            || raws[1].value.len() > 128 << 10
        {
            return Err(refuse());
        }
        let value = strict_value(&raws[1].value)?;
        validate(&value["enrollment"]["scope"], "scope")?;
        for allocation in value["allocations"]
            .as_object()
            .ok_or_else(refuse)?
            .values()
        {
            validate(&allocation["scope"], "scope")?;
        }
        let state: ReservationSnapshot = serde_json::from_value(value)?;
        state.validate()?;
        if state.enrollment != r.enrollment {
            return Err(refuse());
        }
        let (scope, parent_state) = match &request.parent_operation {
            Some(op) => {
                let p = state.allocations.get(op).ok_or_else(refuse)?;
                (&p.scope, Some(p.state.clone()))
            }
            None => (&state.enrollment.scope, None),
        };
        if !request.scope.narrows(scope) {
            return Err(refuse());
        }
        Ok(Resolution {
            profile: PROFILE.into(),
            request_id: request.request_id.clone(),
            root_id: r.root_id.clone(),
            root_generation: r.root_generation,
            delegation_id: r.delegation_id.clone(),
            tenant: r.enrollment.tenant.clone(),
            conflict_domain: r.enrollment.conflict_domain.clone(),
            scope: request.scope.clone(),
            parent_operation: request.parent_operation.clone(),
            parent_state,
            root_active: state.active,
            snapshot_digest: digest(
                "a2a-root-resolution-snapshot",
                &serde_json::to_value(state)?,
            )?,
            execution_authority: false,
            child_grants_supported: false,
            task_id: request.task_id.clone(),
            context_id: request.context_id.clone(),
        })
    }
}
fn one_header<'a>(h: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = h.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(refuse)?
        .to_str()
        .map_err(|_| refuse())?;
    if values.next().is_some() {
        return Err(refuse());
    }
    Ok(value)
}
pub fn activation(headers: &HeaderMap) -> Result<()> {
    if one_header(headers, "a2a-version")? != "1.0" {
        return Err(refuse());
    }
    let values = one_header(headers, "a2a-extensions")?;
    if values.len() > 4096 {
        return Err(refuse());
    }
    let mut seen = BTreeSet::new();
    for uri in values.split(',').map(str::trim) {
        if uri.is_empty()
            || !seen.insert(uri)
            || url::Url::parse(uri).is_err()
            || (uri.starts_with("urn:kedgeflow:a2a:root-resolution:") && uri != EXTENSION)
        {
            return Err(refuse());
        }
    }
    if !seen.contains(EXTENSION) {
        return Err(refuse());
    }
    Ok(())
}
/// Fixed independently configured destination, no reference-directed credentials.
pub struct HttpsRootResolver {
    registration: Registration,
    endpoint: String,
    client: PinnedClient,
}
impl HttpsRootResolver {
    pub fn new(registration: Registration, client: PinnedClient) -> Result<Self> {
        registration.validate()?;
        Ok(Self {
            endpoint: registration.authority_endpoint.clone(),
            registration,
            client,
        })
    }
    pub async fn resolve(
        &self,
        request: &ResolveRequest,
        headers: &HeaderMap,
    ) -> Result<Resolution> {
        let raw = serde_json::to_vec(request)?;
        ResolveRequest::decode(&raw)?;
        if request.part != self.registration.reference_part()
            || !request.scope.narrows(&self.registration.enrollment.scope)
        {
            return Err(refuse());
        }
        let authorization = one_header(headers, "authorization")?;
        let dpop = one_header(headers, "dpop")?;
        tokio::time::timeout(Duration::from_secs(5), async {
            let response = self
                .client
                .client()
                .post(&self.endpoint)
                .header("authorization", authorization)
                .header("dpop", dpop)
                .header("a2a-version", "1.0")
                .header("a2a-extensions", EXTENSION)
                .header("content-type", "application/json")
                .header("accept-encoding", "identity")
                .body(raw)
                .send()
                .await?;
            if response.url().as_str() != self.endpoint
                || response.status() != reqwest::StatusCode::OK
                || response.headers().contains_key("content-encoding")
                || response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    != Some("application/json")
            {
                return Err(Error::Unavailable(
                    "root reference resolution unavailable".into(),
                ));
            }
            let v = strict_value(
                &crate::grant_reference::bounded_response(response, MAX_BYTES).await?,
            )?;
            validate(&v, "response")?;
            let result: Resolution = serde_json::from_value(v)?;
            let reference = &request.part.data;
            if result.tenant != self.registration.enrollment.tenant
                || result.conflict_domain != self.registration.enrollment.conflict_domain
                || result.request_id != request.request_id
                || result.root_id != reference.root_id
                || result.root_generation != reference.root_generation
                || result.delegation_id != reference.delegation_id
                || result.scope != request.scope
                || result.parent_operation != request.parent_operation
                || result.task_id != request.task_id
                || result.context_id != request.context_id
                || result.parent_operation.is_some() != result.parent_state.is_some()
            {
                return Err(refuse());
            }
            Ok(result)
        })
        .await
        .map_err(|_| Error::Unavailable("root reference resolution timeout".into()))?
    }
}
