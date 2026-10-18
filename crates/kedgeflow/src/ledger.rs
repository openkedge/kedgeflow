//! Durable authority transactions over the real etcd v3 JSON gateway.
//!
//! These methods are trusted authority-side operations. The HTTP execution
//! gateway must never expose policy publication, issuance, or replacement to an
//! agent. An unavailable or refused transaction has no in-memory fallback.

use crate::contracts::{Grant, Policy, canonical};
use crate::error::{Error, Result};
use async_trait::async_trait;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{SecondsFormat, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Root {
    pub generation: u64,
    pub fence: u64,
    pub active_gid: String,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Attempt {
    pub id: String,
    pub grant_digest: String,
    pub root_id: String,
    pub status: String,
    pub claimed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStatus {
    pub state: String,
    pub attempt_id: Option<String>,
    pub grant_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeObservation {
    #[serde(rename = "AttemptID")]
    pub attempt_id: String,
    #[serde(rename = "RootID")]
    pub root_id: String,
    #[serde(rename = "GrantDigest")]
    pub grant_digest: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "TargetReference")]
    pub target_reference: String,
}

#[async_trait]
pub trait OutcomeQuerier: Send + Sync {
    /// Implementations authenticate their target and validate target correlation.
    /// This contract deliberately offers no dispatch or retry operation.
    async fn query(&self, attempt_id: &str) -> Result<AuthoritativeObservation>;
}

#[async_trait]
pub trait AuthorityLedger: Send + Sync {
    /// Query-only original-attempt resolution; never creates execution authority.
    async fn execution_status(&self, _: &Grant, _: &str) -> Result<ExecutionStatus> {
        Err(Error::Unavailable("execution status unsupported".into()))
    }
    async fn publish_policy(&self, grant: &Grant) -> Result<()>;
    async fn issue(&self, grant: &Grant, digest: &str) -> Result<()>;
    async fn claim(&self, grant: &Grant, digest: &str, attempt_id: &str) -> Result<Attempt>;
    async fn claim_recorded(
        &self,
        grant: &Grant,
        digest: &str,
        attempt_id: &str,
        _context: &crate::recovery::ExecutionRecord,
    ) -> Result<Attempt> {
        let _ = (grant, digest, attempt_id);
        Err(Error::Unavailable("recorded claims unsupported".into()))
    }
    async fn finish_recorded(
        &self,
        grant: &Grant,
        attempt: &Attempt,
        status: &str,
        _evidence: &Value,
    ) -> Result<()> {
        let _ = (grant, attempt, status);
        Err(Error::Unavailable("recorded outcomes unsupported".into()))
    }
    async fn replace(&self, old: &Grant, next: &Grant, next_digest: &str) -> Result<()>;
    async fn authorize_dispatch(&self, grant: &Grant, digest: &str, attempt_id: &str)
    -> Result<()>;
    async fn finish(&self, grant: &Grant, attempt: &Attempt, status: &str) -> Result<()>;
    async fn status(&self, grant: &Grant, attempt_id: &str) -> Result<Attempt>;
    async fn reconcile(
        &self,
        grant: &Grant,
        attempt_id: &str,
        query: &dyn OutcomeQuerier,
    ) -> Result<Attempt>;
}

#[derive(Clone)]
pub struct EtcdLedger {
    pub(crate) family: Option<std::sync::Arc<crate::family::Access>>,
    pub(crate) inverse_execution: Option<std::sync::Arc<crate::compensation_execution::Execution>>,
    pub(crate) action_domain: Option<std::sync::Arc<crate::action_domain::Selection>>,
    client: Client,
    pub(crate) endpoint: String,
    pub(crate) prefix: String,
    pub(crate) require_control: bool,
    pub(crate) required_trust_digest: Option<String>,
    pub(crate) authority_clock: std::sync::Arc<dyn crate::clock::Clock>,
    auth_token: Option<reqwest::header::HeaderValue>,
    pub(crate) reservation: Option<std::sync::Arc<crate::reserved_leaf::Registration>>,
    pub(crate) restore_gate: Option<crate::restore::RestoreGate>,
}

#[derive(Debug)]
pub(crate) struct Txn {
    pub(crate) succeeded: bool,
    pub(crate) responses: Vec<Value>,
}

#[derive(Debug)]
pub(crate) struct Kv {
    pub(crate) value: Vec<u8>,
    pub(crate) mod_revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuanceRecord {
    pub issuance_key: String,
    pub binding_digest: String,
    pub grant_digest: String,
    pub signed_grant: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceResult {
    pub record: IssuanceRecord,
    pub reused: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    pub admission_key: String,
    pub binding_digest: String,
    pub certificate_digest: String,
    pub signed_certificate: String,
    pub admitted_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionResult {
    pub record: AdmissionRecord,
    pub reused: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionChain {
    admission_key: String,
    certificate_digest: String,
    packet: crate::admission::StoredAdmissionPacket,
}

pub struct AdmissionBundle {
    pub record: AdmissionRecord,
    pub packet: crate::admission::StoredAdmissionPacket,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceRecord {
    issuance_key: String,
    binding_digest: String,
    resource_digest: String,
    fence: u64,
}

/// Only the durable allocator constructs this proof. It confers no allowance.
pub struct FenceReservation {
    record: FenceRecord,
}

impl FenceReservation {
    pub fn fence(&self) -> u64 {
        self.record.fence
    }
}

impl EtcdLedger {
    pub fn namespace(&self) -> &str {
        &self.prefix
    }
    /// `client` supplies the independently trusted TLS/authorization configuration.
    /// HTTP is accepted only for a disposable loopback test cluster. Production
    /// endpoints must use HTTPS. Callers must disable redirects in the client;
    /// responses from redirected requests are never accepted as authority. There is no mutation retry or local fallback.
    pub fn new(
        client: Client,
        endpoint: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Result<Self> {
        let endpoint = endpoint.into();
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|_| Error::Invalid("invalid etcd endpoint".into()))?;
        let local = url.host_str().is_some_and(|h| {
            h == "localhost" || h.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback())
        });
        if (url.scheme() != "https" && !(url.scheme() == "http" && local))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(Error::Invalid(
                "etcd endpoint must be a trusted HTTPS origin (loopback HTTP is test-only)".into(),
            ));
        }
        let prefix = prefix.into();
        if prefix.is_empty() || !prefix.starts_with('/') || prefix.ends_with('/') {
            return Err(Error::Invalid(
                "etcd prefix must be a nonempty absolute namespace without a trailing slash".into(),
            ));
        }
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            prefix,
            auth_token: None,
            family: None,
            restore_gate: None,
            reservation: None,
            action_domain: None,
            inverse_execution: None,
            require_control: false,
            required_trust_digest: None,
            authority_clock: std::sync::Arc::new(crate::clock::SystemClock),
        })
    }

    /// The JSON gateway cannot authenticate an etcd RBAC user by TLS Common
    /// Name. Supply a separately acquired, namespace-scoped etcd auth token.
    /// Expired/revoked tokens fail closed; replacement is an operator operation.
    pub fn with_auth_token(mut self, token: &str) -> Result<Self> {
        if token.is_empty() || token.len() > 16384 {
            return Err(Error::Invalid("invalid etcd auth token".into()));
        }
        let mut value = reqwest::header::HeaderValue::from_str(token)
            .map_err(|_| Error::Invalid("invalid etcd auth token carriage".into()))?;
        value.set_sensitive(true);
        self.auth_token = Some(value);
        Ok(self)
    }

    /// Managed deployments refuse before their first installation as well as
    /// after it. Existing unmanaged fixture callers remain explicitly supported.
    pub fn requiring_control(mut self, trust_digest: Option<String>) -> Self {
        self.require_control = true;
        self.required_trust_digest = trust_digest;
        self
    }
    pub fn with_clock(mut self, clock: std::sync::Arc<dyn crate::clock::Clock>) -> Self {
        self.authority_clock = clock;
        self
    }
    async fn grant_control_check(
        &self,
        grant: &Grant,
    ) -> Result<crate::control_bindings::ControlCheck> {
        self.control_check(
            &crate::governance::EnforcementScope::grant(grant)?,
            &grant.policy,
            grant.ownership_epoch,
            Some(&grant.root_id),
            Some(&grant.gid),
        )
        .await
    }
    pub(crate) async fn grant_control_compare(&self, grant: &Grant) -> Result<Vec<Value>> {
        self.control_compare(
            &crate::governance::EnforcementScope::grant(grant)?,
            &grant.policy,
            grant.ownership_epoch,
            Some(&grant.root_id),
            Some(&grant.gid),
        )
        .await
    }

    async fn check_retained_issuance_control(&self, issuance: &IssuanceRecord) -> Result<()> {
        let envelope = crate::contracts::strict_value(issuance.signed_grant.as_bytes())?;
        let grant: Grant = serde_json::from_value(envelope["payload"].clone())?;
        // Candidate IDs differ across replicas. Revocation must check the
        // ORIGINAL persisted grant/root, including on a duplicate response.
        let mut compare = self.grant_control_compare(&grant).await?;
        compare.push(value_eq(
            &format!("{}/issuance/{}", self.prefix, issuance.issuance_key),
            &record(issuance)?,
        ));
        require_success(self.txn(compare, Vec::new(), Vec::new()).await?)
    }

    pub(crate) fn domain(&self, grant: &Grant) -> String {
        self.domain_base(&grant.conflict_domain)
    }
    pub(crate) fn root(&self, grant: &Grant) -> String {
        format!("{}/roots/{}", self.domain(grant), key_part(&grant.root_id))
    }
    pub(crate) fn grant_key(&self, grant: &Grant) -> String {
        format!("{}/grants/{}", self.root(grant), key_part(&grant.gid))
    }
    pub(crate) fn nonce(&self, grant: &Grant) -> String {
        format!("{}/nonces/{}", self.root(grant), key_part(&grant.nonce))
    }
    pub(crate) fn attempt(&self, grant: &Grant, attempt_id: &str) -> String {
        format!("{}/attempts/{}", self.root(grant), key_part(attempt_id))
    }
    pub(crate) fn outbox(&self, grant: &Grant, attempt_id: &str) -> String {
        format!("{}/outbox/{}", self.root(grant), key_part(attempt_id))
    }

    pub(crate) async fn txn(
        &self,
        compare: Vec<Value>,
        success: Vec<Value>,
        failure: Vec<Value>,
    ) -> Result<Txn> {
        let mut compare = compare;
        compare.extend(self.action_domain_compares()?);
        compare.extend(self.family_compares(false).await?);
        if self.inverse_execution.is_some() || self.family.is_some() {
            let mut seen = std::collections::BTreeSet::new();
            compare.retain(|v| seen.insert(v.to_string()));
        }
        if self.inverse_execution.is_some()
            && (compare.len() > 127
                || canonical(&json!({"compare":compare,"success":success,"failure":failure}))?
                    .len()
                    > 1 << 20)
        {
            return Err(Error::Refused(
                "compensation transaction exceeds bounded profile".into(),
            ));
        }
        if let Some(gate) = &self.restore_gate {
            return gate.transaction(self, compare, success, failure).await;
        }
        // Removing a configured gate cannot bypass an enrolled namespace. The
        // absence comparison also closes enrollment versus unguarded writes.
        let marker = crate::restore::marker_key(self);
        let mut marker_reads = vec![get(&marker)];
        if self.family.is_none() {
            marker_reads.extend([
                get(&crate::family::marker(self)),
                get(&format!("{}/family/state", self.prefix)),
            ]);
        }
        let check = self.raw_txn(Vec::new(), marker_reads, Vec::new()).await?;
        if self.family.is_none() {
            for response in check.responses.iter().skip(1) {
                if range_kv(response)?.is_some() {
                    return Err(Error::Refused(
                        "family selection required for enrolled namespace".into(),
                    ));
                }
            }
            if check.responses.len() != 3 {
                return Err(Error::Unavailable("missing family absence response".into()));
            }
        }
        if range_kv(
            check
                .responses
                .first()
                .ok_or_else(|| Error::Unavailable("missing restore marker response".into()))?,
        )?
        .is_some()
        {
            return Err(Error::Refused(
                "restore quarantine: witness required".into(),
            ));
        }
        if failure.iter().any(|op| op.get("request_range").is_none()) {
            return Err(Error::Invalid(
                "unguarded failure branch must be read-only".into(),
            ));
        }
        let mut compare = compare;
        compare.push(version_zero(&marker));
        self.raw_txn(compare, success, failure).await
    }

    pub(crate) async fn raw_txn(
        &self,
        compare: Vec<Value>,
        success: Vec<Value>,
        failure: Vec<Value>,
    ) -> Result<Txn> {
        let mut request = self
            .client
            .post(format!("{}/v3/kv/txn", self.endpoint))
            .timeout(Duration::from_secs(5))
            .json(&json!({ "compare": compare, "success": success, "failure": failure }));
        if let Some(token) = &self.auth_token {
            request = request.header(reqwest::header::AUTHORIZATION, token.clone());
        }
        let response = request
            .send()
            .await
            .map_err(|_| Error::Unavailable("etcd transaction transport failed".into()))?;
        // A configured reqwest client can have redirects enabled. Never accept a
        // transaction response from another origin as authority evidence.
        if response.url().as_str() != format!("{}/v3/kv/txn", self.endpoint) {
            return Err(Error::Unavailable("etcd transaction redirected".into()));
        }
        if !response.status().is_success() {
            return Err(Error::Unavailable(format!(
                "etcd transaction HTTP {}",
                response.status()
            )));
        }
        let bytes = crate::grant_reference::bounded_response(response, 4 * 1024 * 1024).await?;
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Unavailable("invalid etcd transaction JSON".into()))?;
        if body.get("error").is_some() || !body.is_object() || body.get("header").is_none() {
            return Err(Error::Unavailable(
                "invalid etcd transaction response".into(),
            ));
        }
        // ProtoJSON omits the default `succeeded:false` scalar.
        let succeeded = match body.get("succeeded") {
            Some(Value::Bool(value)) => *value,
            None => false,
            _ => return Err(Error::Unavailable("invalid etcd transaction result".into())),
        };
        let responses = match body.get("responses") {
            Some(Value::Array(values)) => values.clone(),
            None => Vec::new(),
            _ => {
                return Err(Error::Unavailable(
                    "invalid etcd operation responses".into(),
                ));
            }
        };
        Ok(Txn {
            succeeded,
            responses,
        })
    }

    /// Read-only diagnostic access, useful for verifying retained roots/outboxes.
    /// Production ACLs still limit which scopes the client is allowed to read.
    pub async fn read_key(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if !key.starts_with(&format!("{}/", self.prefix)) {
            return Err(Error::Invalid(
                "read is outside the ledger namespace".into(),
            ));
        }
        let txn = self.txn(Vec::new(), vec![get(key)], Vec::new()).await?;
        if !txn.succeeded || txn.responses.len() != 1 {
            return Err(Error::Unavailable("invalid etcd read transaction".into()));
        }
        Ok(range_kv(&txn.responses[0])?.map(|kv| kv.value))
    }

    /// Atomically retain the first Cedar-produced certificate per operation.
    /// Retry never refreshes its time bounds or creates execution authority.
    /// Policy/ownership are compared on both creation and duplicate lookup.
    pub async fn admit(
        &self,
        prepared: &crate::policy::PreparedAdmission,
        clock: &dyn crate::clock::Clock,
    ) -> Result<AdmissionResult> {
        let now = clock.now_ms();
        if now < prepared.admitted_at || now >= prepared.expires_at {
            return Err(Error::Refused("admission candidate no longer valid".into()));
        }
        let c = &prepared.context;
        if self
            .action_domain
            .as_ref()
            .is_some_and(|s| s.registration().tenant != c.tenant)
        {
            return Err(Error::Refused(
                "admission tenant differs from paired domain".into(),
            ));
        }
        let key = format!("{}/admission/{}", self.prefix, prepared.key);
        let chain_key = format!("{}/admission-chain/{}", self.prefix, prepared.key);
        let domain = self.domain_base(&c.conflict_domain);
        let policy_key = format!("{domain}/policy");
        let ownership_key = format!("{domain}/ownership");
        let policy = record(&c.policy)?;
        let ownership = c.ownership_epoch.to_string();
        let mut compare = vec![
            value_eq(&policy_key, &policy),
            value_eq(&ownership_key, &ownership),
        ];
        let control = self
            .control_check(
                &prepared.control_scope,
                &c.policy,
                c.ownership_epoch,
                None,
                None,
            )
            .await?;
        compare.extend(self.inverse_operation_compare(&prepared.key).await?);
        compare.extend(self.saga_admission(prepared, now).await?);
        compare.extend(self.inverse_admission(prepared).await?);
        compare.extend(control.compare.clone());
        compare.extend(self.review_compares(&prepared.review_facts, now).await?);
        let lease = self
            .lease_authority_check(&prepared.lease_check, now)
            .await?;
        compare.extend(lease.compare);
        let result = AdmissionRecord {
            admission_key: prepared.key.clone(),
            binding_digest: prepared.binding.clone(),
            certificate_digest: prepared.certificate_digest.clone(),
            signed_certificate: prepared.signed_certificate.clone(),
            admitted_at: prepared.admitted_at,
            expires_at: prepared.expires_at,
        };
        let mut create = compare.clone();
        create.push(version_zero(&key));
        create.push(version_zero(&chain_key));
        let chain = AdmissionChain {
            admission_key: prepared.key.clone(),
            certificate_digest: prepared.certificate_digest.clone(),
            packet: prepared.packet.clone(),
        };
        let mut writes = vec![
            put(&key, &record(&result)?),
            put(&chain_key, &record(&chain)?),
        ];
        self.retain_control_binding(
            &mut create,
            &mut writes,
            &self.admission_control_key(&prepared.key),
            "admission",
            &prepared.certificate_digest,
            None,
            &control.state,
        )?;
        self.retain_lease_binding(
            &mut create,
            &mut writes,
            &prepared.key,
            "admission",
            &prepared.certificate_digest,
            &lease.state,
        )?;
        let txn = self.txn(create, writes, Vec::new()).await?;
        if txn.succeeded {
            return Ok(AdmissionResult {
                record: result,
                reused: false,
            });
        }
        let read = self.txn(compare, vec![get(&key)], Vec::new()).await?;
        if !read.succeeded {
            return Err(Error::Refused("stale admission authority".into()));
        }
        if read.responses.len() != 1 {
            return Err(Error::Unavailable(
                "invalid admission lookup response".into(),
            ));
        }
        let stored = range_kv(&read.responses[0])?
            .ok_or_else(|| Error::Refused("admission transaction refused".into()))?;
        let existing: AdmissionRecord = serde_json::from_slice(&stored.value)
            .map_err(|_| Error::Unavailable("invalid stored admission".into()))?;
        if existing.admission_key != prepared.key || existing.binding_digest != prepared.binding {
            return Err(Error::Refused("admission identity binding conflict".into()));
        }
        // The persisted record stays retained after expiry; it cannot be replaced
        // by the newer certificate candidate prepared for an unchanged retry.
        if now < existing.admitted_at || now >= existing.expires_at {
            return Err(Error::Refused("original admission expired".into()));
        }
        Ok(AdmissionResult {
            record: existing,
            reused: true,
        })
    }

    /// Trusted read after cryptographic caller/proposal authorization. The issuer
    /// revalidates the retained raw chain; no cached verified context is loaded.
    pub async fn admission_bundle(
        &self,
        key: &str,
        clock: &dyn crate::clock::Clock,
    ) -> Result<AdmissionBundle> {
        if !crate::grant_reference::valid_reference(key) {
            return Err(Error::Invalid("invalid admission lookup key".into()));
        }
        let read = self
            .txn(
                Vec::new(),
                vec![
                    get(&format!("{}/admission/{key}", self.prefix)),
                    get(&format!("{}/admission-chain/{key}", self.prefix)),
                ],
                Vec::new(),
            )
            .await?;
        if !read.succeeded || read.responses.len() != 2 {
            return Err(Error::Unavailable("invalid admission bundle lookup".into()));
        }
        let retained = range_kv(&read.responses[0])?
            .ok_or_else(|| Error::Refused("admission is not retained".into()))?;
        let raw_chain = range_kv(&read.responses[1])?
            .ok_or_else(|| Error::Refused("admission chain is not retained".into()))?;
        let retained: AdmissionRecord = serde_json::from_slice(&retained.value)
            .map_err(|_| Error::Unavailable("invalid retained admission".into()))?;
        let chain: AdmissionChain = serde_json::from_slice(&raw_chain.value)
            .map_err(|_| Error::Unavailable("invalid retained chain".into()))?;
        let now = clock.now_ms();
        if retained.admission_key != key
            || chain.admission_key != key
            || chain.certificate_digest != retained.certificate_digest
            || now < retained.admitted_at
            || now >= retained.expires_at
        {
            return Err(Error::Refused(
                "retained admission correlation or validity mismatch".into(),
            ));
        }
        Ok(AdmissionBundle {
            record: retained,
            packet: chain.packet,
        })
    }

    /// Linearizable historical read. Callers must authorize the signed operation
    /// first. Absence is a snapshot, never permission to retry issuance/execution.
    pub(crate) async fn retained_operation(
        &self,
        key: &str,
    ) -> Result<Option<(IssuanceRecord, AdmissionBundle)>> {
        if !crate::grant_reference::valid_reference(key) {
            return Err(Error::Invalid("invalid operation key".into()));
        }
        let read = self
            .txn(
                Vec::new(),
                vec![
                    get(&format!("{}/issuance/{key}", self.prefix)),
                    get(&format!("{}/admission/{key}", self.prefix)),
                    get(&format!("{}/admission-chain/{key}", self.prefix)),
                ],
                Vec::new(),
            )
            .await?;
        if !read.succeeded || read.responses.len() != 3 {
            return Err(Error::Unavailable("invalid operation snapshot".into()));
        }
        let Some(issued) = range_kv(&read.responses[0])? else {
            return Ok(None);
        };
        let retained = range_kv(&read.responses[1])?
            .ok_or_else(|| Error::Unavailable("missing historical admission".into()))?;
        let chain = range_kv(&read.responses[2])?
            .ok_or_else(|| Error::Unavailable("missing historical chain".into()))?;
        let decode = |message: &str| Error::Unavailable(message.into());
        let issued: IssuanceRecord = serde_json::from_slice(&issued.value)
            .map_err(|_| decode("invalid historical issuance"))?;
        let retained: AdmissionRecord = serde_json::from_slice(&retained.value)
            .map_err(|_| decode("invalid historical admission"))?;
        let chain: AdmissionChain =
            serde_json::from_slice(&chain.value).map_err(|_| decode("invalid historical chain"))?;
        if issued.issuance_key != key
            || retained.admission_key != key
            || chain.admission_key != key
            || chain.certificate_digest != retained.certificate_digest
        {
            return Err(decode("historical operation correlation mismatch"));
        }
        Ok(Some((
            issued,
            AdmissionBundle {
                record: retained,
                packet: chain.packet,
            },
        )))
    }

    pub async fn lookup_issuance(
        &self,
        admitted: &crate::issuance::AdmittedIssuance,
    ) -> Result<Option<IssuanceRecord>> {
        let grant = &admitted.grant;
        let control = self.grant_control_compare(grant).await?;
        let read = self
            .txn(
                {
                    let mut compare = vec![
                        value_eq(
                            &format!("{}/policy", self.domain(grant)),
                            &record(&grant.policy)?,
                        ),
                        value_eq(
                            &format!("{}/ownership", self.domain(grant)),
                            &grant.ownership_epoch.to_string(),
                        ),
                    ];
                    compare.extend(control);
                    compare.extend(self.inverse_operation_compare(&admitted.key).await?);
                    compare.extend(self.inverse_candidate(admitted).await?);
                    compare.extend(self.reservation_candidate(admitted, false).await?.compare);
                    compare.extend(
                        self.lease_compares(&admitted.lease_check, self.authority_clock.now_ms())
                            .await?,
                    );
                    compare.extend(
                        self.review_compares(&admitted.review_facts, self.authority_clock.now_ms())
                            .await?,
                    );
                    compare
                },
                vec![get(&format!("{}/issuance/{}", self.prefix, admitted.key))],
                Vec::new(),
            )
            .await?;
        if !read.succeeded {
            return Err(Error::Refused("stale issuance authority".into()));
        }
        if read.responses.len() != 1 {
            return Err(Error::Unavailable("invalid issuance lookup".into()));
        }
        let Some(kv) = range_kv(&read.responses[0])? else {
            return Ok(None);
        };
        let stored: IssuanceRecord = serde_json::from_slice(&kv.value)
            .map_err(|_| Error::Unavailable("invalid stored issuance".into()))?;
        if stored.issuance_key != admitted.key || stored.binding_digest != admitted.binding {
            return Err(Error::Refused("issuance identity binding conflict".into()));
        }
        self.check_retained_issuance_control(&stored).await?;
        self.reservation_check_issuance(&stored).await?;
        self.inverse_check_issuance(&stored).await?;
        Ok(Some(stored))
    }

    /// Monotonic per tenant/resource/incarnation within this authority namespace,
    /// including across conflict domains. One retained allocation per operation;
    /// gaps after failures confer no authority and are never recycled.
    pub async fn reserve_fence(
        &self,
        admitted: &crate::issuance::AdmittedIssuance,
        clock: &dyn crate::clock::Clock,
    ) -> Result<FenceReservation> {
        let g = &admitted.grant;
        if g.resources.len() != 1 {
            return Err(Error::Refused(
                "fence allocation requires one resource".into(),
            ));
        }
        let resource_digest = crate::contracts::digest(
            "fence-resource",
            &json!({"tenant":admitted.tenant,"resource":g.resources[0]}),
        )?;
        let allocation_key = format!("{}/fence-allocation/{}", self.prefix, admitted.key);
        let counter_key = format!("{}/fence-counter/{resource_digest}", self.prefix);
        let issuance_key = format!("{}/issuance/{}", self.prefix, admitted.key);
        let control = vec![
            value_eq(&format!("{}/policy", self.domain(g)), &record(&g.policy)?),
            value_eq(
                &format!("{}/ownership", self.domain(g)),
                &g.ownership_epoch.to_string(),
            ),
        ];
        for _ in 0..64 {
            let now = clock.now_ms();
            if now < g.valid_from || now >= g.expires_at {
                return Err(Error::Refused("fence candidate expired".into()));
            }
            let mut current_control = control.clone();
            current_control.extend(self.inverse_operation_compare(&admitted.key).await?);
            current_control.extend(self.grant_control_compare(g).await?);
            current_control.extend(self.inverse_candidate(admitted).await?);
            current_control.extend(self.review_compares(&admitted.review_facts, now).await?);
            current_control.extend(self.lease_compares(&admitted.lease_check, now).await?);
            // A hierarchical fence holds no capacity. The later native issuance
            // atomically writes child cost, grant, binding and consumption root.
            let allocate = self
                .reservation
                .as_ref()
                .is_none_or(|r| r.hierarchy.is_none());
            let reservation = self.reservation_candidate(admitted, allocate).await?;
            current_control.extend(reservation.compare);
            let read = self
                .txn(
                    current_control.clone(),
                    vec![get(&allocation_key), get(&counter_key), get(&issuance_key)],
                    Vec::new(),
                )
                .await?;
            if !read.succeeded {
                return Err(Error::Refused("stale fence authority".into()));
            }
            if read.responses.len() != 3 {
                return Err(Error::Unavailable("invalid fence read".into()));
            }
            if let Some(kv) = range_kv(&read.responses[0])? {
                if reservation.newly_allocated {
                    return Err(Error::Refused(
                        "fence lacks original reservation allocation".into(),
                    ));
                }
                let r: FenceRecord = serde_json::from_slice(&kv.value)
                    .map_err(|_| Error::Unavailable("invalid fence allocation".into()))?;
                if r.issuance_key != admitted.key
                    || r.binding_digest != admitted.binding
                    || r.resource_digest != resource_digest
                    || r.fence == 0
                    || r.fence > crate::contracts::MAX_SAFE_INTEGER
                {
                    return Err(Error::Refused("fence allocation binding conflict".into()));
                }
                return Ok(FenceReservation { record: r });
            }
            if range_kv(&read.responses[2])?.is_some() {
                return Err(Error::Refused(
                    "issuance exists without fence allocation".into(),
                ));
            }
            let counter = range_kv(&read.responses[1])?;
            let (previous, counter_compare) = match counter {
                None => (0, version_zero(&counter_key)),
                Some(kv) => {
                    let previous = std::str::from_utf8(&kv.value)
                        .ok()
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or_else(|| Error::Refused("invalid fence counter".into()))?;
                    (previous, mod_revision(&counter_key, &kv.mod_revision))
                }
            };
            let fence = previous
                .checked_add(1)
                .filter(|v| *v <= crate::contracts::MAX_SAFE_INTEGER)
                .ok_or_else(|| Error::Refused("fence counter exhausted".into()))?;
            let r = FenceRecord {
                issuance_key: admitted.key.clone(),
                binding_digest: admitted.binding.clone(),
                resource_digest: resource_digest.clone(),
                fence,
            };
            let mut compare = current_control;
            compare.extend([
                version_zero(&allocation_key),
                version_zero(&issuance_key),
                counter_compare,
            ]);
            let mut writes = reservation.writes;
            if reservation.newly_allocated {
                let history = self.reservation_allocation_history(admitted, fence).await?;
                compare.extend(history.compare);
                writes.extend(history.writes);
            }
            writes.extend([
                put(&counter_key, &fence.to_string()),
                put(&allocation_key, &record(&r)?),
            ]);
            let write = self.txn(compare, writes, Vec::new()).await?;
            if write.succeeded {
                return Ok(FenceReservation { record: r });
            }
            // Retry only a confirmed failed comparison, never an ambiguous send.
        }
        Err(Error::Unavailable(
            "fence allocation contention bound reached".into(),
        ))
    }

    pub async fn issue_allocated(
        &self,
        admitted: &crate::issuance::AdmittedIssuance,
        fence: &FenceReservation,
        clock: &dyn crate::clock::Clock,
    ) -> Result<IssuanceResult> {
        if admitted.key != fence.record.issuance_key
            || admitted.binding != fence.record.binding_digest
            || admitted.grant.fence != fence.record.fence
        {
            return Err(Error::Refused(
                "issuer candidate lacks matching fence allocation".into(),
            ));
        }
        self.issue_with_allocation(admitted, Some(&fence.record), None, None, clock)
            .await
    }

    pub(crate) async fn issue_reserved(
        &self,
        admitted: &crate::issuance::AdmittedIssuance,
        fence: &FenceReservation,
        binding: Option<&crate::reserved_leaf::ReservationBinding>,
        inverse: Option<&crate::compensation_execution::Binding>,
        clock: &dyn crate::clock::Clock,
    ) -> Result<IssuanceResult> {
        if admitted.key != fence.record.issuance_key
            || admitted.binding != fence.record.binding_digest
            || admitted.grant.fence != fence.record.fence
        {
            return Err(Error::Refused("issuer lacks matching fence".into()));
        }
        self.issue_with_allocation(admitted, Some(&fence.record), binding, inverse, clock)
            .await
    }

    /// Trusted issuer prerequisite. Validation cannot be bypassed by constructing
    /// an AdmittedIssuance. The authenticated producer uses issue_allocated to
    /// additionally compare its durable resource fence allocation.
    /// The global operation key survives consumption and is never expiry-deleted.
    pub async fn issue_admitted(
        &self,
        admitted: &crate::issuance::AdmittedIssuance,
        clock: &dyn crate::clock::Clock,
    ) -> Result<IssuanceResult> {
        self.issue_with_allocation(admitted, None, None, None, clock)
            .await
    }

    async fn issue_with_allocation(
        &self,
        admitted: &crate::issuance::AdmittedIssuance,
        allocation: Option<&FenceRecord>,
        binding: Option<&crate::reserved_leaf::ReservationBinding>,
        inverse: Option<&crate::compensation_execution::Binding>,
        clock: &dyn crate::clock::Clock,
    ) -> Result<IssuanceResult> {
        let grant = &admitted.grant;
        // An opaque candidate may have waited since validation. Use authority
        // time again at the persistence boundary, never request-selected time.
        let now_ms = clock.now_ms();
        if now_ms < grant.valid_from || now_ms >= grant.expires_at {
            return Err(Error::Refused("issuance candidate no longer valid".into()));
        }
        let issuance_key = format!("{}/issuance/{}", self.prefix, admitted.key);
        let policy_key = format!("{}/policy", self.domain(grant));
        let ownership_key = format!("{}/ownership", self.domain(grant));
        let policy = record(&grant.policy)?;
        let ownership = grant.ownership_epoch.to_string();
        let result = IssuanceRecord {
            issuance_key: admitted.key.clone(),
            binding_digest: admitted.binding.clone(),
            grant_digest: admitted.grant_digest.clone(),
            signed_grant: admitted.signed_grant.clone(),
        };
        let mut allocation_compare = Vec::new();
        if let Some(allocation) = allocation {
            allocation_compare.push(value_eq(
                &format!("{}/fence-allocation/{}", self.prefix, admitted.key),
                &record(allocation)?,
            ));
        }
        if allocation.is_none() {
            allocation_compare.push(version_zero(&format!(
                "{}/control-required",
                self.domain(grant)
            )));
        }
        let mut compare = vec![
            version_zero(&issuance_key),
            version_zero(&self.root(grant)),
            version_zero(&self.grant_key(grant)),
            version_zero(&self.nonce(grant)),
            value_eq(&policy_key, &policy),
            value_eq(&ownership_key, &ownership),
        ];
        compare.extend(self.inverse_operation_compare(&admitted.key).await?);
        let reservation = self.reservation_issue(admitted, binding).await?;
        let compensation = self.inverse_issue(admitted, inverse).await?;
        let control = self.grant_control_check(grant).await?;
        let installed_control = control.compare;
        allocation_compare.extend(self.review_compares(&admitted.review_facts, now_ms).await?);
        let lease = self
            .lease_authority_check(&admitted.lease_check, now_ms)
            .await?;
        allocation_compare.extend(lease.compare);
        compare.extend(installed_control.clone());
        compare.extend(allocation_compare.clone());
        compare.extend(reservation.compare.clone());
        compare.extend(compensation.compare);
        let mut writes = vec![
            put(&issuance_key, &record(&result)?),
            put(&self.root(grant), &record(&expected_root(grant))?),
            put(&self.grant_key(grant), &admitted.grant_digest),
        ];
        writes.extend(reservation.writes);
        writes.extend(compensation.writes);
        self.retain_control_binding(
            &mut compare,
            &mut writes,
            &self.issuance_control_key(&admitted.key),
            "issuance",
            &admitted.grant_digest,
            None,
            &control.state,
        )?;
        self.retain_lease_binding(
            &mut compare,
            &mut writes,
            &admitted.key,
            "issuance",
            &admitted.grant_digest,
            &lease.state,
        )?;
        let txn = self.txn(compare, writes, Vec::new()).await?;
        if txn.succeeded {
            return Ok(IssuanceResult {
                record: result,
                reused: false,
            });
        }
        // A separate linearizable read transaction compares CURRENT authority;
        // a policy/ownership update after the failed create must block reuse.
        let mut lookup_compare = vec![
            value_eq(&policy_key, &policy),
            value_eq(&ownership_key, &ownership),
        ];
        lookup_compare.extend(installed_control);
        lookup_compare.extend(allocation_compare);
        lookup_compare.extend(self.reservation_candidate(admitted, false).await?.compare);
        lookup_compare.extend(self.inverse_candidate(admitted).await?);
        let lookup = self
            .txn(lookup_compare, vec![get(&issuance_key)], Vec::new())
            .await?;
        if !lookup.succeeded {
            return Err(Error::Refused("stale issuance authority".into()));
        }
        if lookup.responses.len() != 1 {
            return Err(Error::Unavailable(
                "invalid issuance lookup response".into(),
            ));
        }
        let kv = range_kv(&lookup.responses[0])?
            .ok_or_else(|| Error::Refused("issuance transaction refused".into()))?;
        let existing: IssuanceRecord = serde_json::from_slice(&kv.value)
            .map_err(|_| Error::Unavailable("invalid stored issuance".into()))?;
        if existing.issuance_key != admitted.key || existing.binding_digest != admitted.binding {
            return Err(Error::Refused("issuance identity binding conflict".into()));
        }
        self.check_retained_issuance_control(&existing).await?;
        self.reservation_check_issuance(&existing).await?;
        self.inverse_check_issuance(&existing).await?;
        Ok(IssuanceResult {
            record: existing,
            reused: true,
        })
    }
}

impl EtcdLedger {
    async fn finish_internal(
        &self,
        grant: &Grant,
        attempt: &Attempt,
        status: &str,
        evidence: Option<&Value>,
    ) -> Result<()> {
        if !matches!(
            status,
            "committed" | "not_dispatched" | "unknown" | "state_guard_violation"
        ) {
            return Err(Error::Invalid("invalid outcome".into()));
        }
        let outbox_key = self.outbox(grant, &attempt.id);
        let outbox = self
            .read_key(&outbox_key)
            .await?
            .ok_or_else(|| Error::Unavailable("missing dispatch record".into()))?;
        let outbox = String::from_utf8(outbox)
            .map_err(|_| Error::Unavailable("invalid dispatch record".into()))?;
        if attempt.status != "claimed"
            || !["claimed_not_dispatched", "dispatch_authorized"].contains(&outbox.as_str())
        {
            return Err(Error::Refused("terminal transition refused".into()));
        }
        let before = record(attempt)?;
        let mut after = attempt.clone();
        after.status = status.to_owned();
        let mut writes = vec![
            put(&self.attempt(grant, &attempt.id), &record(&after)?),
            put(&outbox_key, status),
            put(
                &crate::recovery::journal_key(self, grant, &attempt.id, status),
                &crate::recovery::transition(grant, &after, status, self.authority_clock.now_ms())?,
            ),
        ];
        if let Some(evidence) = evidence {
            let evidence = record(evidence)?;
            if evidence.len() > 1 << 20 {
                return Err(Error::Invalid("outcome evidence exceeds bound".into()));
            }
            writes.push(put(
                &crate::recovery::evidence_key(self, grant, &attempt.id),
                &evidence,
            ));
        }
        require_success(
            self.txn(
                vec![
                    value_eq(&self.attempt(grant, &attempt.id), &before),
                    value_eq(&outbox_key, &outbox),
                    version_zero(&crate::recovery::journal_key(
                        self,
                        grant,
                        &attempt.id,
                        status,
                    )),
                ],
                writes,
                Vec::new(),
            )
            .await?,
        )
    }

    async fn claim_internal(
        &self,
        grant: &Grant,
        digest: &str,
        attempt_id: &str,
        context: Option<&crate::recovery::ExecutionRecord>,
    ) -> Result<Attempt> {
        let attempt = Attempt {
            id: attempt_id.to_owned(),
            grant_digest: digest.to_owned(),
            root_id: grant.root_id.clone(),
            status: "claimed".into(),
            claimed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true),
        };
        let mut claimed = expected_root(grant);
        claimed.status = "claimed".into();
        let mut compare = vec![
            value_eq(&self.root(grant), &record(&expected_root(grant))?),
            value_eq(&self.grant_key(grant), digest),
            version_zero(&self.nonce(grant)),
            version_zero(&self.attempt(grant, attempt_id)),
            version_zero(&self.outbox(grant, attempt_id)),
            value_eq(
                &format!("{}/policy", self.domain(grant)),
                &record(&grant.policy)?,
            ),
            value_eq(
                &format!("{}/ownership", self.domain(grant)),
                &grant.ownership_epoch.to_string(),
            ),
        ];
        let control = self.grant_control_check(grant).await?;
        compare.extend(control.compare);
        let journal_key = crate::recovery::journal_key(self, grant, attempt_id, "claimed");
        compare.push(version_zero(&journal_key));
        let mut writes = vec![
            put(&self.root(grant), &record(&claimed)?),
            put(&self.nonce(grant), attempt_id),
            put(&self.attempt(grant, attempt_id), &record(&attempt)?),
            put(&self.outbox(grant, attempt_id), "claimed_not_dispatched"),
            put(
                &journal_key,
                &crate::recovery::transition(
                    grant,
                    &attempt,
                    "claimed",
                    self.authority_clock.now_ms(),
                )?,
            ),
        ];
        self.retain_control_binding(
            &mut compare,
            &mut writes,
            &self.execution_control_key(grant, attempt_id, "claim"),
            "claim",
            digest,
            Some(attempt_id),
            &control.state,
        )?;
        if let Some(context) = context {
            context.validate(grant, digest)?;
            let context_key = crate::recovery::context_key(self, grant, attempt_id);
            let index = crate::recovery::index_key(self, digest, attempt_id)?;
            compare.extend([version_zero(&context_key), version_zero(&index)]);
            writes.extend([
                put(&context_key, &record(context)?),
                put(
                    &index,
                    &record(&crate::recovery::Candidate {
                        grant: grant.clone(),
                        attempt_id: attempt_id.into(),
                    })?,
                ),
            ]);
        }
        let compensation = self.inverse_claim(grant, digest, attempt_id).await?;
        compare.extend(compensation.compare);
        writes.extend(compensation.writes);
        let reservation = self.reservation_claim(grant, digest, attempt_id).await?;
        compare.extend(reservation.compare);
        writes.extend(reservation.writes);
        let txn = self
            .txn(compare, writes, vec![get(&self.nonce(grant))])
            .await?;
        if !txn.succeeded {
            if txn.responses.len() != 1 {
                return Err(Error::Unavailable(
                    "missing failed-claim nonce observation".into(),
                ));
            }
            if range_kv(&txn.responses[0])?.is_some() {
                return Err(Error::NonceConsumed);
            }
            return Err(Error::Refused("authority transaction refused".into()));
        }
        Ok(attempt)
    }
}

#[async_trait]
impl AuthorityLedger for EtcdLedger {
    async fn execution_status(&self, grant: &Grant, digest: &str) -> Result<ExecutionStatus> {
        let root_key = self.root(grant);
        let grant_key = self.grant_key(grant);
        let nonce_key = self.nonce(grant);
        let read = self
            .txn(
                vec![],
                vec![get(&root_key), get(&grant_key), get(&nonce_key)],
                vec![],
            )
            .await?;
        if !read.succeeded || read.responses.len() != 3 {
            return Err(Error::Unavailable("invalid execution status read".into()));
        }
        let root = range_kv(&read.responses[0])?
            .ok_or_else(|| Error::Unknown("retained root missing".into()))?;
        let stored_grant = range_kv(&read.responses[1])?
            .ok_or_else(|| Error::Unknown("retained grant missing".into()))?;
        if stored_grant.value != digest.as_bytes() {
            return Err(Error::Refused("retained grant mismatch".into()));
        }
        let nonce = range_kv(&read.responses[2])?;
        let mut expected = expected_root(grant);
        expected.status = if nonce.is_some() {
            "claimed"
        } else {
            "unclaimed"
        }
        .into();
        if root.value != record(&expected)?.as_bytes() {
            return Err(Error::Refused("retained root mismatch".into()));
        }
        let Some(nonce) = nonce else {
            return Ok(ExecutionStatus {
                state: "unclaimed".into(),
                attempt_id: None,
                grant_digest: digest.into(),
            });
        };
        let id = String::from_utf8(nonce.value)
            .map_err(|_| Error::Unavailable("invalid retained nonce".into()))?;
        if id.is_empty() || id.len() > 1024 {
            return Err(Error::Unavailable(
                "invalid retained attempt identity".into(),
            ));
        }
        // The first read discovers the durable original ID. A second snapshot
        // correlates it with immutable authority and the latest attempt/outbox.
        let snapshot = self
            .txn(
                vec![
                    value_eq(&root_key, &record(&expected)?),
                    value_eq(&grant_key, digest),
                    value_eq(&nonce_key, &id),
                ],
                vec![
                    get(&self.attempt(grant, &id)),
                    get(&self.outbox(grant, &id)),
                ],
                vec![],
            )
            .await?;
        if !snapshot.succeeded || snapshot.responses.len() != 2 {
            return Err(Error::Unavailable(
                "execution status correlation changed".into(),
            ));
        }
        let a = range_kv(&snapshot.responses[0])?
            .ok_or_else(|| Error::Unavailable("retained attempt missing".into()))?;
        let attempt: Attempt = serde_json::from_slice(&a.value)
            .map_err(|_| Error::Unavailable("invalid retained attempt".into()))?;
        let outbox = range_kv(&snapshot.responses[1])?
            .ok_or_else(|| Error::Unavailable("retained dispatch state missing".into()))?;
        if attempt.id != id || attempt.root_id != grant.root_id || attempt.grant_digest != digest {
            return Err(Error::Unavailable(
                "retained attempt correlation mismatch".into(),
            ));
        }
        let state = match (attempt.status.as_str(), outbox.value.as_slice()) {
            ("claimed", b"claimed_not_dispatched") => "claimed",
            ("claimed", b"dispatch_authorized") => "dispatch_authorized",
            (s @ ("committed" | "not_dispatched" | "state_guard_violation" | "unknown"), value)
                if s.as_bytes() == value =>
            {
                s
            }
            _ => {
                return Err(Error::Unavailable(
                    "inconsistent retained execution state".into(),
                ));
            }
        };
        Ok(ExecutionStatus {
            state: state.into(),
            attempt_id: Some(id),
            grant_digest: digest.into(),
        })
    }
    async fn publish_policy(&self, grant: &Grant) -> Result<()> {
        if self.action_domain.is_some() {
            return Err(Error::Refused(
                "paired domains require signed control publication".into(),
            ));
        }
        let policy_key = format!("{}/policy", self.domain(grant));
        let ownership_key = format!("{}/ownership", self.domain(grant));
        let read = self
            .txn(
                Vec::new(),
                vec![get(&policy_key), get(&ownership_key)],
                Vec::new(),
            )
            .await?;
        if !read.succeeded || read.responses.len() != 2 {
            return Err(Error::Unavailable("invalid policy read transaction".into()));
        }
        let mut compare = vec![version_zero(&format!(
            "{}/control-required",
            self.domain(grant)
        ))];
        match range_kv(&read.responses[0])? {
            None => compare.push(version_zero(&policy_key)),
            Some(kv) => {
                let old: Policy = serde_json::from_slice(&kv.value)
                    .map_err(|_| Error::Refused("invalid stored policy".into()))?;
                if grant.policy.id != old.id
                    || grant.policy.epoch < old.epoch
                    || (grant.policy.epoch == old.epoch && grant.policy.digest != old.digest)
                {
                    return Err(Error::Refused(
                        "policy rollback or conflicting epoch".into(),
                    ));
                }
                compare.push(mod_revision(&policy_key, &kv.mod_revision));
            }
        }
        match range_kv(&read.responses[1])? {
            None => compare.push(version_zero(&ownership_key)),
            Some(kv) => {
                let old: u64 = std::str::from_utf8(&kv.value)
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| Error::Refused("invalid stored ownership epoch".into()))?;
                if grant.ownership_epoch < old {
                    return Err(Error::Refused("ownership epoch rollback".into()));
                }
                compare.push(mod_revision(&ownership_key, &kv.mod_revision));
            }
        }
        require_success(
            self.txn(
                compare,
                vec![
                    put(&policy_key, &record(&grant.policy)?),
                    put(&ownership_key, &grant.ownership_epoch.to_string()),
                ],
                Vec::new(),
            )
            .await?,
        )
    }

    async fn issue(&self, grant: &Grant, digest: &str) -> Result<()> {
        let mut compare = vec![
            version_zero(&crate::reserved_leaf::required_key(
                self,
                &grant.conflict_domain,
            )),
            version_zero(&self.root(grant)),
            version_zero(&self.grant_key(grant)),
            version_zero(&self.nonce(grant)),
            value_eq(
                &format!("{}/policy", self.domain(grant)),
                &record(&grant.policy)?,
            ),
            value_eq(
                &format!("{}/ownership", self.domain(grant)),
                &grant.ownership_epoch.to_string(),
            ),
        ];
        compare.push(version_zero(&format!(
            "{}/control-required",
            self.domain(grant)
        )));
        compare.extend(self.grant_control_compare(grant).await?);
        require_success(
            self.txn(
                compare,
                vec![
                    put(&self.root(grant), &record(&expected_root(grant))?),
                    put(&self.grant_key(grant), digest),
                ],
                Vec::new(),
            )
            .await?,
        )
    }

    async fn claim(&self, grant: &Grant, digest: &str, attempt_id: &str) -> Result<Attempt> {
        self.claim_internal(grant, digest, attempt_id, None).await
    }
    async fn claim_recorded(
        &self,
        grant: &Grant,
        digest: &str,
        attempt_id: &str,
        context: &crate::recovery::ExecutionRecord,
    ) -> Result<Attempt> {
        self.claim_internal(grant, digest, attempt_id, Some(context))
            .await
    }
    async fn finish_recorded(
        &self,
        grant: &Grant,
        attempt: &Attempt,
        status: &str,
        evidence: &Value,
    ) -> Result<()> {
        self.finish_internal(grant, attempt, status, Some(evidence))
            .await
    }

    async fn replace(&self, old: &Grant, next: &Grant, next_digest: &str) -> Result<()> {
        if old.root_id != next.root_id
            || old.conflict_domain != next.conflict_domain
            || old.root_generation.checked_add(1) != Some(next.root_generation)
            || next.fence <= old.fence
        {
            return Err(Error::Invalid("invalid generation transition".into()));
        }
        let mut compare = vec![
            value_eq(&self.root(old), &record(&expected_root(old))?),
            version_zero(&self.nonce(old)),
            version_zero(&self.grant_key(next)),
            version_zero(&self.nonce(next)),
            value_eq(
                &format!("{}/policy", self.domain(next)),
                &record(&next.policy)?,
            ),
            value_eq(
                &format!("{}/ownership", self.domain(next)),
                &next.ownership_epoch.to_string(),
            ),
        ];
        compare.push(version_zero(&format!(
            "{}/control-required",
            self.domain(next)
        )));
        compare.push(version_zero(&crate::reserved_leaf::required_key(
            self,
            &next.conflict_domain,
        )));
        compare.extend(self.grant_control_compare(next).await?);
        require_success(
            self.txn(
                compare,
                vec![
                    put(&self.root(old), &record(&expected_root(next))?),
                    put(&self.grant_key(next), next_digest),
                ],
                Vec::new(),
            )
            .await?,
        )
    }

    async fn authorize_dispatch(
        &self,
        grant: &Grant,
        digest: &str,
        attempt_id: &str,
    ) -> Result<()> {
        let mut claimed = expected_root(grant);
        claimed.status = "claimed".into();
        let mut compare = vec![
            value_eq(&self.root(grant), &record(&claimed)?),
            value_eq(&self.grant_key(grant), digest),
            value_eq(&self.nonce(grant), attempt_id),
            value_eq(
                &format!("{}/policy", self.domain(grant)),
                &record(&grant.policy)?,
            ),
            value_eq(
                &format!("{}/ownership", self.domain(grant)),
                &grant.ownership_epoch.to_string(),
            ),
            value_eq(&self.outbox(grant, attempt_id), "claimed_not_dispatched"),
        ];
        compare.push(version_zero(&crate::recovery::journal_key(
            self,
            grant,
            attempt_id,
            "dispatch_authorized",
        )));
        let control = self.grant_control_check(grant).await?;
        compare.extend(control.compare);
        let mut writes = vec![
            put(&self.outbox(grant, attempt_id), "dispatch_authorized"),
            put(
                &crate::recovery::journal_key(self, grant, attempt_id, "dispatch_authorized"),
                &record(
                    &json!({"profile":crate::recovery::PROFILE,"attempt_id":attempt_id,"root_id":grant.root_id,"grant_digest":digest,"phase":"dispatch_authorized","event_time":self.authority_clock.now_ms()}),
                )?,
            ),
        ];
        self.retain_control_binding(
            &mut compare,
            &mut writes,
            &self.execution_control_key(grant, attempt_id, "dispatch"),
            "dispatch",
            digest,
            Some(attempt_id),
            &control.state,
        )?;
        let compensation = self.inverse_dispatch(grant, digest, attempt_id).await?;
        compare.extend(compensation.compare);
        writes.extend(compensation.writes);
        let reservation = self.reservation_dispatch(grant, digest, attempt_id).await?;
        compare.extend(reservation.compare);
        writes.extend(reservation.writes);
        require_success(self.txn(compare, writes, Vec::new()).await?)
    }

    async fn finish(&self, grant: &Grant, attempt: &Attempt, status: &str) -> Result<()> {
        self.finish_internal(grant, attempt, status, None).await
    }

    async fn status(&self, grant: &Grant, attempt_id: &str) -> Result<Attempt> {
        let key = self.attempt(grant, attempt_id);
        let value = self
            .read_key(&key)
            .await?
            .ok_or_else(|| Error::Unknown("unknown attempt".into()))?;
        serde_json::from_slice(&value)
            .map_err(|_| Error::Unavailable("invalid durable attempt record".into()))
    }

    async fn reconcile(
        &self,
        grant: &Grant,
        attempt_id: &str,
        query: &dyn OutcomeQuerier,
    ) -> Result<Attempt> {
        let mut attempt = self.status(grant, attempt_id).await?;
        if attempt.status != "unknown" {
            return Err(Error::Invalid(
                "only unknown attempts need reconciliation".into(),
            ));
        }
        let observation = query.query(attempt_id).await?;
        if observation.attempt_id != attempt.id
            || observation.root_id != attempt.root_id
            || observation.grant_digest != attempt.grant_digest
            || observation.target_reference.is_empty()
            || observation.target_reference.len() > 1024
            || record(&observation)?.len() > 65536
        {
            return Err(Error::Invalid("uncorrelated target observation".into()));
        }
        if observation.status != "committed" {
            return Ok(attempt);
        }
        let key = self.attempt(grant, attempt_id);
        let before = record(&attempt)?;
        attempt.status = "committed".into();
        require_success(
            self.txn(
                vec![
                    value_eq(&key, &before),
                    value_eq(&self.outbox(grant, attempt_id), "unknown"),
                    version_zero(&crate::recovery::journal_key(
                        self,
                        grant,
                        attempt_id,
                        "committed",
                    )),
                ],
                vec![
                    put(&key, &record(&attempt)?),
                    put(&format!("{key}/observation"), &record(&observation)?),
                    put(
                        &crate::recovery::evidence_key(self, grant, attempt_id),
                        &record(&json!({"kind":"authoritative_query","observation":observation}))?,
                    ),
                    put(&self.outbox(grant, attempt_id), "committed"),
                    put(
                        &crate::recovery::journal_key(self, grant, attempt_id, "committed"),
                        &crate::recovery::transition(
                            grant,
                            &attempt,
                            "committed",
                            self.authority_clock.now_ms(),
                        )?,
                    ),
                ],
                Vec::new(),
            )
            .await?,
        )?;
        Ok(attempt)
    }
}

pub(crate) fn expected_root(grant: &Grant) -> Root {
    Root {
        generation: grant.root_generation,
        fence: grant.fence,
        active_gid: grant.gid.clone(),
        status: "unclaimed".into(),
    }
}

pub(crate) fn key_part(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}
pub(crate) fn wire(value: &str) -> String {
    STANDARD.encode(value.as_bytes())
}
pub(crate) fn version_zero(key: &str) -> Value {
    json!({ "key": wire(key), "target": "VERSION", "result": "EQUAL", "version": "0" })
}
pub(crate) fn mod_revision(key: &str, revision: &str) -> Value {
    json!({ "key": wire(key), "target": "MOD", "result": "EQUAL", "mod_revision": revision })
}
pub(crate) fn value_eq(key: &str, value: &str) -> Value {
    json!({ "key": wire(key), "target": "VALUE", "result": "EQUAL", "value": wire(value) })
}
pub(crate) fn put(key: &str, value: &str) -> Value {
    json!({ "request_put": { "key": wire(key), "value": wire(value) } })
}
pub(crate) fn get(key: &str) -> Value {
    json!({ "request_range": { "key": wire(key) } })
}
fn require_success(txn: Txn) -> Result<()> {
    if txn.succeeded {
        Ok(())
    } else {
        Err(Error::Refused("authority transaction refused".into()))
    }
}

pub(crate) fn range_kv(response: &Value) -> Result<Option<Kv>> {
    let range = response
        .get("response_range")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Unavailable("missing etcd range response".into()))?;
    let kvs = match range.get("kvs") {
        None => return Ok(None),
        Some(Value::Array(kvs)) => kvs,
        _ => return Err(Error::Unavailable("invalid etcd range records".into())),
    };
    if kvs.is_empty() {
        return Ok(None);
    }
    if kvs.len() != 1 {
        return Err(Error::Unavailable(
            "unexpected multiple etcd range records".into(),
        ));
    }
    let kv = &kvs[0];
    let encoded = kv.get("value").and_then(Value::as_str).unwrap_or("");
    let value = STANDARD
        .decode(encoded)
        .map_err(|_| Error::Unavailable("invalid etcd value encoding".into()))?;
    let revision = kv
        .get("mod_revision")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Unavailable("missing etcd record revision".into()))?;
    revision
        .parse::<u64>()
        .map_err(|_| Error::Unavailable("invalid etcd record revision".into()))?;
    Ok(Some(Kv {
        value,
        mod_revision: revision.to_owned(),
    }))
}

/// Use the shared restricted RFC 8785 profile for byte-compatible Go records.
pub(crate) fn record<T: Serialize>(record: &T) -> Result<String> {
    let value = serde_json::to_value(record)?;
    String::from_utf8(canonical(&value)?)
        .map_err(|_| Error::Invalid("canonical record is not UTF-8".into()))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn fixed_records_match_go_canonical_keys() {
        let root = Root {
            generation: 1,
            fence: 7,
            active_gid: "grant-a".into(),
            status: "unclaimed".into(),
        };
        assert_eq!(
            record(&root).unwrap(),
            r#"{"active_gid":"grant-a","fence":7,"generation":1,"status":"unclaimed"}"#
        );
        assert_eq!(key_part("domain/π"), "ZG9tYWluL8-A");
    }

    #[test]
    fn unsafe_numbers_and_untrusted_endpoints_are_rejected() {
        assert!(record(&json!({"generation": 9_007_199_254_740_992_u64})).is_err());
        assert!(record(&json!({"epoch": 1.5})).is_err());
        assert!(EtcdLedger::new(Client::new(), "http://example.org:2379", "/kf").is_err());
        assert!(EtcdLedger::new(Client::new(), "https://example.org:2379?x=1", "/kf").is_err());
    }
}
