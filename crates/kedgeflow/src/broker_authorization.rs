//! Trusted broker-side integration prerequisite. No token minting or HTTP
//! authorization-server endpoint is implemented by this module.
use crate::{
    auth::{Identity, WorkloadIdentity},
    clock::Clock,
    contracts::{GrantVerifier, digest},
    error::{Error, Result},
    gateway::{ToolDescriptor, bind_call},
    ledger::{EtcdLedger, expected_root, get, put, range_kv, record, value_eq, version_zero},
    recovery::{Candidate, journal_key},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

pub const PROFILE: &str = "KF-BROKER-AUTHORIZATION-0.1-draft";
const SAFE_MS: i64 = 9_007_199_254_740_991;

/// The implementation is an independently trusted provider boundary. It must
/// cryptographically verify the subject and actor tokens, including audience,
/// expiry, revocation and canonical delegation; caller fields are insufficient.
#[async_trait]
pub trait ExchangeIdentityProvider: Send + Sync {
    async fn verify(
        &self,
        subject_token: &str,
        actor_token: &str,
        now_ms: i64,
    ) -> Result<VerifiedExchangeIdentity>;
}
pub struct VerifiedExchangeIdentity {
    pub identity: Identity,
    pub subject_valid_until: i64,
    pub actor_valid_until: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRegistration {
    pub gateway_workload: String,
    pub target_audience: String,
    pub target_scope: String,
    pub max_lifetime_ms: i64,
    pub tool: ToolDescriptor,
}
impl BrokerRegistration {
    pub fn validate(&self) -> Result<()> {
        self.tool.validate()?;
        if self.tool.read_only
            || !crate::auth::valid_spiffe_id(&self.gateway_workload)
            || self.target_audience.is_empty()
            || self.target_audience.len() > 2048
            || self.target_audience.bytes().any(|c| c <= b' ' || c == 127)
            || self.target_scope.is_empty()
            || self.target_scope.len() > 256
            || !self.target_scope.is_ascii()
            || self
                .target_scope
                .bytes()
                .any(|c| c <= b' ' || c == b'"' || c == b'\\' || c == 127)
            || !(1000..=300000).contains(&self.max_lifetime_ms)
        {
            return Err(Error::Invalid("invalid broker target registration".into()));
        }
        Ok(())
    }
}
/// Internal trusted library input; mapping the RFC 8693 form and authenticating
/// the actual provider endpoint are integration responsibilities.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRequest {
    pub subject_token: String,
    pub actor_token: String,
    pub signed_grant: String,
    pub grant_digest: String,
    pub attempt_id: String,
    pub audience: String,
    pub scope: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangePermit {
    pub profile: String,
    pub permit_id: String,
    pub registration_digest: String,
    pub grant_digest: String,
    pub root_id: String,
    pub attempt_id: String,
    pub gateway_workload: String,
    pub target_audience: String,
    pub target_scope: String,
    pub authorized_at: i64,
    pub expires_at: i64,
}
pub fn validate_permit(v: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let s = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/broker-authorization-v0.1.schema.json"
            ))
            .expect("embedded broker schema"),
        )
        .expect("valid broker schema")
    });
    if !s.is_valid(v) {
        return Err(Error::Invalid("closed broker permit mismatch".into()));
    }
    Ok(())
}
pub struct BrokerAuthorizer {
    registration: BrokerRegistration,
    registration_digest: String,
    grants: GrantVerifier,
    ledger: EtcdLedger,
    provider: Arc<dyn ExchangeIdentityProvider>,
    clock: Arc<dyn Clock>,
}
impl BrokerAuthorizer {
    pub(crate) async fn prepare_native_history(&self) -> Result<()> {
        self.ledger.prepare_selected_family_history().await
    }
    pub(crate) fn managed_drain(&self) -> bool {
        crate::ledger::AuthorityLedger::managed_drain_selection(&self.ledger).is_some()
    }
    pub fn new(
        registration: BrokerRegistration,
        grants: GrantVerifier,
        ledger: EtcdLedger,
        provider: Arc<dyn ExchangeIdentityProvider>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        registration.validate()?;
        if grants.keys.is_empty() || grants.audience.is_empty() {
            return Err(Error::Invalid(
                "missing independent broker grant pins".into(),
            ));
        }
        let registration_digest =
            digest("broker-registration", &serde_json::to_value(&registration)?)?;
        Ok(Self {
            registration,
            registration_digest,
            grants,
            ledger,
            provider,
            clock,
        })
    }
    pub(crate) fn gateway_workload(&self) -> &str {
        &self.registration.gateway_workload
    }
    pub(crate) fn grant_keys(&self) -> impl Iterator<Item = &ed25519_dalek::VerifyingKey> {
        self.grants.keys.values()
    }
    /// Only the winning CAS returns a local authorization. A duplicate or lost
    /// reply never authorizes another mint invocation; no remote permit accepts.
    pub async fn authorize(
        &self,
        request: &ExchangeRequest,
        gateway: &WorkloadIdentity,
    ) -> Result<ExchangePermit> {
        if gateway.as_str() != self.registration.gateway_workload
            || request.audience != self.registration.target_audience
            || request.scope != self.registration.target_scope
            || request.attempt_id.is_empty()
            || request.attempt_id.len() > 1024
            || request.signed_grant.is_empty()
            || request.signed_grant.len() > 1 << 20
            || request.subject_token.is_empty()
            || request.subject_token.len() > 65536
            || request.actor_token.is_empty()
            || request.actor_token.len() > 65536
        {
            return Err(Error::Refused(
                "broker exchange identity/target/input mismatch".into(),
            ));
        }
        let started = self.clock.now_ms();
        if !(0..=SAFE_MS).contains(&started) {
            return Err(Error::Refused("invalid broker clock".into()));
        }
        let grant = self
            .grants
            .verify(request.signed_grant.as_bytes(), started)?;
        if grant.digest != request.grant_digest {
            return Err(Error::Refused("broker grant digest mismatch".into()));
        }
        let verified = tokio::time::timeout(
            Duration::from_secs(5),
            self.provider
                .verify(&request.subject_token, &request.actor_token, started),
        )
        .await
        .map_err(|_| Error::Unavailable("broker identity verification timed out".into()))??;
        let candidate = Candidate {
            grant: grant.grant.clone(),
            attempt_id: request.attempt_id.clone(),
        };
        let snapshot = self.ledger.recovery_snapshot(&candidate).await?;
        snapshot.context.validate(&candidate.grant, &grant.digest)?;
        if snapshot.attempt.status != "claimed"
            || snapshot.outbox != "claimed_not_dispatched"
            || snapshot.attempt.grant_digest != grant.digest
            || snapshot.context.signed_grant != request.signed_grant
            || snapshot.context.tool != self.registration.tool.name
            || verified.identity.access_token != request.subject_token
            || !verified
                .identity
                .scopes
                .contains(&self.registration.tool.required_scope)
        {
            return Err(Error::Refused(
                "broker requires original undispatched execution".into(),
            ));
        }
        bind_call(
            &candidate.grant,
            &verified.identity,
            &self.registration.tool,
            &snapshot.context.parameters,
        )?;
        let journal = journal_key(
            &self.ledger,
            &candidate.grant,
            &candidate.attempt_id,
            "claimed",
        );
        let read = self.ledger.txn(vec![], vec![get(&journal)], vec![]).await?;
        if !read.succeeded || read.responses.len() != 1 {
            return Err(Error::Unavailable(
                "broker claim journal unavailable".into(),
            ));
        }
        let journal_raw = String::from_utf8(
            range_kv(&read.responses[0])?
                .ok_or_else(|| Error::Unavailable("missing broker claim journal".into()))?
                .value,
        )
        .map_err(|_| Error::Unavailable("invalid claim journal".into()))?;
        let journal_value = crate::contracts::strict_value(journal_raw.as_bytes())?;
        crate::recovery::validate(&journal_value)?;
        if journal_value["phase"] != "claimed"
            || journal_value["root_id"] != candidate.grant.root_id
            || journal_value["attempt_id"] != candidate.attempt_id
            || journal_value["grant_digest"] != grant.digest
        {
            return Err(Error::Refused("broker claim journal changed".into()));
        }
        let mut claimed = expected_root(&candidate.grant);
        claimed.status = "claimed".into();
        let g = &candidate.grant;
        let mut compare = vec![
            value_eq(&self.ledger.root(g), &record(&claimed)?),
            value_eq(&self.ledger.grant_key(g), &grant.digest),
            value_eq(&self.ledger.nonce(g), &candidate.attempt_id),
            value_eq(
                &self.ledger.attempt(g, &candidate.attempt_id),
                &record(&snapshot.attempt)?,
            ),
            value_eq(
                &self.ledger.outbox(g, &candidate.attempt_id),
                &snapshot.outbox,
            ),
            value_eq(
                &crate::recovery::context_key(&self.ledger, g, &candidate.attempt_id),
                &snapshot.context_raw,
            ),
            value_eq(&journal, &journal_raw),
            value_eq(
                &format!("{}/policy", self.ledger.domain(g)),
                &record(&g.policy)?,
            ),
            value_eq(
                &format!("{}/ownership", self.ledger.domain(g)),
                &g.ownership_epoch.to_string(),
            ),
        ];
        compare.extend(self.ledger.grant_control_compare(g).await?);
        compare.extend(
            self.ledger
                .inverse_dispatch(g, &grant.digest, &candidate.attempt_id)
                .await?
                .compare,
        );
        let now = self.clock.now_ms();
        if now < started
            || now > SAFE_MS
            || !(0..=SAFE_MS).contains(&verified.subject_valid_until)
            || !(0..=SAFE_MS).contains(&verified.actor_valid_until)
        {
            return Err(Error::Refused("broker identity/clock exceeds bound".into()));
        }
        self.grants.verify(request.signed_grant.as_bytes(), now)?;
        let expires_at = [
            g.expires_at,
            verified.subject_valid_until,
            verified.actor_valid_until,
            now.checked_add(self.registration.max_lifetime_ms)
                .ok_or_else(|| Error::Refused("broker expiry overflow".into()))?,
        ]
        .into_iter()
        .min()
        .expect("bounded lifetimes");
        if expires_at - now < 1000 {
            return Err(Error::Refused(
                "broker identity/grant lifetime exhausted".into(),
            ));
        }
        let mut v = json!({
            "profile":PROFILE,"registration_digest":self.registration_digest,
            "grant_digest":grant.digest,"root_id":g.root_id,"attempt_id":candidate.attempt_id,
            "gateway_workload":gateway.as_str(),"target_audience":self.registration.target_audience,
            "target_scope":self.registration.target_scope,"authorized_at":now,"expires_at":expires_at
        });
        v["permit_id"] = json!(digest("broker-permit", &v)?);
        validate_permit(&v)?;
        let key = format!(
            "{}/credential-permit",
            self.ledger.attempt(g, &candidate.attempt_id)
        );
        compare.push(version_zero(&key));
        let written = self
            .ledger
            .txn(compare, vec![put(&key, &record(&v)?)], vec![])
            .await?;
        if !written.succeeded {
            return Err(Error::Refused(
                "broker permit already consumed or authority changed".into(),
            ));
        }
        let returned_at = self.clock.now_ms();
        if returned_at < now || returned_at >= expires_at {
            return Err(Error::Refused(
                "broker permit validity exhausted after write".into(),
            ));
        }
        Ok(serde_json::from_value(v)?)
    }
}
