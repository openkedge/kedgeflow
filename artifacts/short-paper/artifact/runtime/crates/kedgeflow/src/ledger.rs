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
    async fn publish_policy(&self, grant: &Grant) -> Result<()>;
    async fn issue(&self, grant: &Grant, digest: &str) -> Result<()>;
    async fn claim(&self, grant: &Grant, digest: &str, attempt_id: &str) -> Result<Attempt>;
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
    client: Client,
    endpoint: String,
    prefix: String,
    auth_token: Option<reqwest::header::HeaderValue>,
}

#[derive(Debug)]
struct Txn {
    succeeded: bool,
    responses: Vec<Value>,
}

#[derive(Debug)]
struct Kv {
    value: Vec<u8>,
    mod_revision: String,
}

impl EtcdLedger {
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

    fn domain(&self, grant: &Grant) -> String {
        format!(
            "{}/domains/{}",
            self.prefix,
            key_part(&grant.conflict_domain)
        )
    }
    fn root(&self, grant: &Grant) -> String {
        format!("{}/roots/{}", self.domain(grant), key_part(&grant.root_id))
    }
    fn grant_key(&self, grant: &Grant) -> String {
        format!("{}/grants/{}", self.root(grant), key_part(&grant.gid))
    }
    fn nonce(&self, grant: &Grant) -> String {
        format!("{}/nonces/{}", self.root(grant), key_part(&grant.nonce))
    }
    fn attempt(&self, grant: &Grant, attempt_id: &str) -> String {
        format!("{}/attempts/{}", self.root(grant), key_part(attempt_id))
    }
    fn outbox(&self, grant: &Grant, attempt_id: &str) -> String {
        format!("{}/outbox/{}", self.root(grant), key_part(attempt_id))
    }

    async fn txn(
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
}

#[async_trait]
impl AuthorityLedger for EtcdLedger {
    async fn publish_policy(&self, grant: &Grant) -> Result<()> {
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
        let mut compare = Vec::new();
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
        let compare = vec![
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
        let attempt = Attempt {
            id: attempt_id.to_owned(),
            grant_digest: digest.to_owned(),
            root_id: grant.root_id.clone(),
            status: "claimed".into(),
            claimed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true),
        };
        let mut claimed = expected_root(grant);
        claimed.status = "claimed".into();
        let compare = vec![
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
        let txn = self
            .txn(
                compare,
                vec![
                    put(&self.root(grant), &record(&claimed)?),
                    put(&self.nonce(grant), attempt_id),
                    put(&self.attempt(grant, attempt_id), &record(&attempt)?),
                    put(&self.outbox(grant, attempt_id), "claimed_not_dispatched"),
                ],
                vec![get(&self.nonce(grant))],
            )
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

    async fn replace(&self, old: &Grant, next: &Grant, next_digest: &str) -> Result<()> {
        if old.root_id != next.root_id
            || old.conflict_domain != next.conflict_domain
            || old.root_generation.checked_add(1) != Some(next.root_generation)
            || next.fence <= old.fence
        {
            return Err(Error::Invalid("invalid generation transition".into()));
        }
        let compare = vec![
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
        let compare = vec![
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
        require_success(
            self.txn(
                compare,
                vec![put(&self.outbox(grant, attempt_id), "dispatch_authorized")],
                Vec::new(),
            )
            .await?,
        )
    }

    async fn finish(&self, grant: &Grant, attempt: &Attempt, status: &str) -> Result<()> {
        if !matches!(
            status,
            "committed" | "not_dispatched" | "unknown" | "state_guard_violation"
        ) {
            return Err(Error::Invalid("invalid outcome".into()));
        }
        let before = record(attempt)?;
        let mut after = attempt.clone();
        after.status = status.to_owned();
        require_success(
            self.txn(
                vec![value_eq(&self.attempt(grant, &attempt.id), &before)],
                vec![
                    put(&self.attempt(grant, &attempt.id), &record(&after)?),
                    put(&self.outbox(grant, &attempt.id), status),
                ],
                Vec::new(),
            )
            .await?,
        )
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
                vec![value_eq(&key, &before)],
                vec![
                    put(&key, &record(&attempt)?),
                    put(&format!("{key}/observation"), &record(&observation)?),
                    put(&self.outbox(grant, attempt_id), "committed"),
                ],
                Vec::new(),
            )
            .await?,
        )?;
        Ok(attempt)
    }
}

fn expected_root(grant: &Grant) -> Root {
    Root {
        generation: grant.root_generation,
        fence: grant.fence,
        active_gid: grant.gid.clone(),
        status: "unclaimed".into(),
    }
}

fn key_part(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}
fn wire(value: &str) -> String {
    STANDARD.encode(value.as_bytes())
}
fn version_zero(key: &str) -> Value {
    json!({ "key": wire(key), "target": "VERSION", "result": "EQUAL", "version": "0" })
}
fn mod_revision(key: &str, revision: &str) -> Value {
    json!({ "key": wire(key), "target": "MOD", "result": "EQUAL", "mod_revision": revision })
}
fn value_eq(key: &str, value: &str) -> Value {
    json!({ "key": wire(key), "target": "VALUE", "result": "EQUAL", "value": wire(value) })
}
fn put(key: &str, value: &str) -> Value {
    json!({ "request_put": { "key": wire(key), "value": wire(value) } })
}
fn get(key: &str) -> Value {
    json!({ "request_range": { "key": wire(key) } })
}
fn require_success(txn: Txn) -> Result<()> {
    if txn.succeeded {
        Ok(())
    } else {
        Err(Error::Refused("authority transaction refused".into()))
    }
}

fn range_kv(response: &Value) -> Result<Option<Kv>> {
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
fn record<T: Serialize>(record: &T) -> Result<String> {
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
