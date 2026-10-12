//! Optional durable replay protection. Protected operator configuration is not
//! request metadata; application authorization remains independently required.
use crate::{
    auth::Identity,
    contracts::{Subject, digest, strict_value},
    error::{Error, Result},
    ledger::{EtcdLedger, get, put, range_kv, value_eq, version_zero},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &str = "KF-SHARED-AUTH-0.1-draft";
const MAX_SECONDS: i64 = 9_007_199_254_740;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectWorkload {
    pub subject: Subject,
    pub workload_id: String,
    #[serde(deserialize_with = "unique_scopes")]
    pub allowed_scopes: BTreeSet<String>,
}
fn unique_scopes<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeSet<String>, D::Error> {
    let values = Vec::<String>::deserialize(d)?;
    let set: BTreeSet<_> = values.iter().cloned().collect();
    if set.len() != values.len() {
        return Err(serde::de::Error::custom("duplicate registered scope"));
    }
    Ok(set)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedAuthConfig {
    pub capacity: usize,
    pub registrations: Vec<SubjectWorkload>,
}
impl SharedAuthConfig {
    pub fn validate(&self, issuer: &str) -> Result<()> {
        if !(1..=4096).contains(&self.capacity) || !(1..=256).contains(&self.registrations.len()) {
            return Err(Error::Invalid(
                "invalid shared authentication bounds".into(),
            ));
        }
        let mut pairs = BTreeSet::new();
        for r in &self.registrations {
            if r.subject.iss != issuer
                || r.subject.sub.trim().is_empty()
                || r.subject.sub.len() > 1024
                || !crate::auth::valid_spiffe_id(&r.workload_id)
                || !(1..=128).contains(&r.allowed_scopes.len())
                || r.allowed_scopes.iter().any(|s| {
                    s.is_empty()
                        || s.len() > 256
                        || !s.is_ascii()
                        || s.bytes()
                            .any(|c| c <= b' ' || c == b'"' || c == b'\\' || c == 127)
                })
                || !pairs.insert((r.subject.sub.clone(), r.workload_id.clone()))
            {
                return Err(Error::Invalid(
                    "invalid subject/workload registration".into(),
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct SharedAuthentication {
    ledger: EtcdLedger,
    config: SharedAuthConfig,
    key: String,
    registration_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayState {
    profile: String,
    registration_digest: String,
    last_seen: i64,
    entries: BTreeMap<String, i64>,
}
pub fn validate_state(v: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let s = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/shared-authentication-v0.1.schema.json"
            ))
            .expect("embedded authentication schema"),
        )
        .expect("valid authentication schema")
    });
    if !s.is_valid(v) {
        return Err(Error::Unavailable(
            "invalid shared authentication state".into(),
        ));
    }
    Ok(())
}
impl SharedAuthentication {
    pub(crate) fn new(
        ledger: EtcdLedger,
        mut config: SharedAuthConfig,
        issuer: &str,
        audience: &str,
        external_url: &str,
    ) -> Result<Self> {
        config.validate(issuer)?;
        config.registrations.sort_by(|a, b| {
            (&a.subject.sub, &a.workload_id).cmp(&(&b.subject.sub, &b.workload_id))
        });
        let realm = digest(
            "authentication-realm",
            &json!({
                "profile":PROFILE,"issuer":issuer,"audience":audience,"external_url":external_url
            }),
        )?;
        let registration_digest = digest(
            "authentication-registration",
            &json!({
                "realm":realm,"config":config
            }),
        )?;
        let key = format!("{}/authentication/replay/{realm}", ledger.namespace());
        Ok(Self {
            ledger,
            config,
            key,
            registration_digest,
        })
    }
    pub(crate) async fn consume(
        &self,
        identity: &Identity,
        jti: &str,
        proof_iat: i64,
        now: i64,
    ) -> Result<()> {
        if !self.config.registrations.iter().any(|r| {
            r.subject == identity.subject
                && r.workload_id == identity.workload_id
                && identity.scopes.is_subset(&r.allowed_scopes)
        }) {
            return Err(Error::Refused(
                "subject/workload/scope is not registered".into(),
            ));
        }
        let expires_at = proof_iat
            .checked_add(66)
            .filter(|v| *v <= MAX_SECONDS)
            .ok_or_else(|| Error::Refused("proof retention exceeds clock bound".into()))?;
        let proof = digest(
            "authentication-proof",
            &json!({
                "jkt":identity.dpop_jkt,"jti":jti
            }),
        )?;
        for _ in 0..4 {
            let read = self
                .ledger
                .txn(vec![], vec![get(&self.key)], vec![])
                .await?;
            if !read.succeeded || read.responses.len() != 1 {
                return Err(Error::Unavailable(
                    "shared authentication read failed".into(),
                ));
            }
            let raw = range_kv(&read.responses[0])?
                .map(|kv| {
                    String::from_utf8(kv.value)
                        .map_err(|_| Error::Unavailable("invalid replay UTF8".into()))
                })
                .transpose()?;
            let mut state = match &raw {
                Some(raw) => {
                    if raw.len() > 1 << 20 {
                        return Err(Error::Unavailable(
                            "shared authentication state exceeds bound".into(),
                        ));
                    }
                    let v = strict_value(raw.as_bytes())?;
                    validate_state(&v)?;
                    serde_json::from_value::<ReplayState>(v)?
                }
                None => ReplayState {
                    profile: PROFILE.into(),
                    registration_digest: self.registration_digest.clone(),
                    last_seen: now,
                    entries: BTreeMap::new(),
                },
            };
            if state.registration_digest != self.registration_digest
                || state.entries.len() > self.config.capacity
                || state
                    .entries
                    .values()
                    .any(|expiry| *expiry > state.last_seen + 71)
            {
                return Err(Error::Unavailable(
                    "shared authentication registration/state mismatch".into(),
                ));
            }
            if now < state.last_seen {
                return Err(Error::Refused(
                    "shared authentication clock regressed".into(),
                ));
            }
            state.entries.retain(|_, expiry| *expiry > now);
            if state.entries.contains_key(&proof) {
                return Err(Error::Refused("DPoP proof already consumed".into()));
            }
            if state.entries.len() >= self.config.capacity {
                return Err(Error::Unavailable(
                    "shared authentication at capacity".into(),
                ));
            }
            state.last_seen = now;
            state.entries.insert(proof.clone(), expires_at);
            let v = serde_json::to_value(&state)?;
            validate_state(&v)?;
            let compares = match &raw {
                Some(raw) => vec![value_eq(&self.key, raw)],
                None => vec![version_zero(&self.key)],
            };
            let write = self
                .ledger
                .txn(
                    compares,
                    vec![put(&self.key, &serde_json::to_string(&v)?)],
                    vec![],
                )
                .await?;
            if write.succeeded {
                return Ok(());
            }
        }
        Err(Error::Unavailable(
            "shared authentication CAS contention".into(),
        ))
    }
}
