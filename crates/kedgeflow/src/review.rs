//! Narrow WebAuthn assertion/state prerequisite, not hardware or admission proof.
use crate::{
    clock::Clock,
    contracts::{Subject, canonical, digest, strict_value},
    error::{Error, Result},
    ledger::{EtcdLedger, get, put, range_kv, record, value_eq, version_zero},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROFILE: &str = "KF-REVIEW-0.1-draft";
fn refuse() -> Error {
    Error::Refused("review binding, enrollment or consumption refused".into())
}
fn encoded(value: &str, bound: usize) -> Result<Vec<u8>> {
    if value.len() > bound * 2 {
        return Err(refuse());
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| refuse())?;
    if bytes.is_empty() || bytes.len() > bound || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(refuse());
    }
    Ok(bytes)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewEnrollment {
    pub credential_id: String,
    pub reviewer: Subject,
    pub rp_id: String,
    pub origin: String,
    pub public_key_sec1: String,
    pub user_handle: String,
    pub hardware_bound_required: bool,
}
impl ReviewEnrollment {
    fn validate(&self) -> Result<()> {
        let origin = url::Url::parse(&self.origin).map_err(|_| refuse())?;
        let key = encoded(&self.public_key_sec1, 65)?;
        let rp = &self.rp_id;
        if self.hardware_bound_required
            || key.len() != 65
            || key[0] != 4
            || rp.is_empty()
            || rp.len() > 253
            || !rp
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || origin.scheme() != "https"
            || origin.origin().ascii_serialization() != self.origin
            || !origin
                .host_str()
                .is_some_and(|host| host == rp || host.ends_with(&format!(".{rp}")))
            || self.reviewer.iss.is_empty()
            || self.reviewer.sub.is_empty()
            || self.reviewer.iss.len() > 1024
            || self.reviewer.sub.len() > 1024
        {
            return Err(refuse());
        }
        encoded(&self.credential_id, 1024)?;
        encoded(&self.user_handle, 64)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub proposal_digest: String,
    pub policy_epoch: u64,
    pub reviewer: Subject,
    pub rendering_template_digest: String,
    pub rendered_digest: String,
    pub parameters_digest: String,
    pub reviewed_at: i64,
    pub expires_at: i64,
    pub verdict: String,
    pub nonce: String,
    pub rp_id: String,
}
impl Approval {
    pub fn challenge(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&serde_json::to_value(self)?)?)))
    }
    fn validate(&self, enrollment: &ReviewEnrollment, now: i64) -> Result<()> {
        if self.reviewer != enrollment.reviewer
            || self.rp_id != enrollment.rp_id
            || !["approve", "reject"].contains(&self.verdict.as_str())
            || self.policy_epoch == 0
            || self.policy_epoch > 9_007_199_254_740_991
            || self.reviewed_at < 0
            || self.reviewed_at > now
            || self.expires_at <= now
            || self
                .expires_at
                .checked_sub(self.reviewed_at)
                .is_none_or(|v| v > 300_000)
            || [
                &self.proposal_digest,
                &self.parameters_digest,
                &self.rendering_template_digest,
                &self.rendered_digest,
            ]
            .iter()
            .any(|d| !crate::grant_reference::valid_reference(d))
        {
            return Err(refuse());
        }
        if encoded(&self.nonce, 32)?.len() != 32 {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAssertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
}
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
    #[serde(rename = "topOrigin")]
    top_origin: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    enrollment: ReviewEnrollment,
    active: bool,
    counter: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    approval: Approval,
    enrollment_digest: String,
    consumed: bool,
    assertion_digest: Option<String>,
}
pub struct VerifiedReview {
    approval: Approval,
    assertion_digest: String,
    sign_count: u32,
}
impl VerifiedReview {
    pub fn approval(&self) -> &Approval {
        &self.approval
    }
    pub fn assertion_digest(&self) -> &str {
        &self.assertion_digest
    }
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }
}
fn credential_key(ledger: &EtcdLedger, id: &str) -> Result<String> {
    Ok(format!(
        "{}/review/credentials/{}",
        ledger.prefix,
        digest("review-credential", &serde_json::json!(id))?
    ))
}
fn challenge_key(ledger: &EtcdLedger, nonce: &str) -> Result<String> {
    Ok(format!(
        "{}/review/challenges/{}",
        ledger.prefix,
        digest("review-nonce", &serde_json::json!(nonce))?
    ))
}
impl EtcdLedger {
    async fn review_read<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        let reply = self.txn(Vec::new(), vec![get(key)], Vec::new()).await?;
        let kv = range_kv(reply.responses.first().ok_or_else(refuse)?)?.ok_or_else(refuse)?;
        if kv.value.len() > 16384 {
            return Err(refuse());
        }
        Ok(serde_json::from_value(strict_value(&kv.value)?)?)
    }
    /// Trusted operator enrollment; registration/attestation provenance is external.
    pub async fn enroll_review(&self, enrollment: ReviewEnrollment) -> Result<()> {
        enrollment.validate()?;
        let key = credential_key(self, &enrollment.credential_id)?;
        let state = Credential {
            enrollment,
            active: true,
            counter: 0,
        };
        if !self
            .txn(
                vec![version_zero(&key)],
                vec![put(&key, &record(&state)?)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub async fn revoke_review(&self, id: &str) -> Result<()> {
        let key = credential_key(self, id)?;
        let mut state: Credential = self.review_read(&key).await?;
        let old = record(&state)?;
        state.active = false;
        if !self
            .txn(
                vec![value_eq(&key, &old)],
                vec![put(&key, &record(&state)?)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    /// Trusted server constructs binding fields and random nonce; callers supply no nonce/time.
    pub async fn issue_review(
        &self,
        id: &str,
        mut approval: Approval,
        clock: &dyn Clock,
    ) -> Result<Approval> {
        let ck = credential_key(self, id)?;
        let state: Credential = self.review_read(&ck).await?;
        state.enrollment.validate()?;
        if !state.active {
            return Err(refuse());
        }
        approval.nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        approval.reviewed_at = clock.now_ms();
        approval.validate(&state.enrollment, clock.now_ms())?;
        let key = challenge_key(self, &approval.nonce)?;
        let challenge = Challenge {
            approval: approval.clone(),
            enrollment_digest: digest(
                "review-enrollment",
                &serde_json::to_value(&state.enrollment)?,
            )?,
            consumed: false,
            assertion_digest: None,
        };
        if !self
            .txn(
                vec![value_eq(&ck, &record(&state)?), version_zero(&key)],
                vec![put(&key, &record(&challenge)?)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(approval)
    }
    pub async fn consume_review(
        &self,
        approval: &Approval,
        assertion: &ReviewAssertion,
        clock: &dyn Clock,
    ) -> Result<VerifiedReview> {
        let key = challenge_key(self, &approval.nonce)?;
        let mut pending: Challenge = self.review_read(&key).await?;
        let ck = credential_key(self, &assertion.credential_id)?;
        let mut state: Credential = self.review_read(&ck).await?;
        state.enrollment.validate()?;
        approval.validate(&state.enrollment, clock.now_ms())?;
        if pending.consumed
            || pending.approval != *approval
            || !state.active
            || pending.enrollment_digest
                != digest(
                    "review-enrollment",
                    &serde_json::to_value(&state.enrollment)?,
                )?
            || assertion
                .user_handle
                .as_ref()
                .is_some_and(|handle| *handle != state.enrollment.user_handle)
        {
            return Err(refuse());
        }
        let client = encoded(&assertion.client_data_json, 8192)?;
        let data: ClientData = serde_json::from_value(strict_value(&client)?)?;
        if data.kind != "webauthn.get"
            || data.challenge != approval.challenge()?
            || data.origin != state.enrollment.origin
            || data.cross_origin
            || data.top_origin.is_some()
        {
            return Err(refuse());
        }
        let auth = encoded(&assertion.authenticator_data, 37)?;
        if auth.len() != 37
            || auth[0..32] != Sha256::digest(approval.rp_id.as_bytes())[..]
            || auth[32] != 0x05
        {
            return Err(refuse());
        }
        let counter = u32::from_be_bytes(auth[33..37].try_into().map_err(|_| refuse())?);
        if counter == 0 || counter <= state.counter {
            return Err(refuse());
        }
        let mut signed = auth;
        signed.extend_from_slice(&Sha256::digest(&client));
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            encoded(&state.enrollment.public_key_sec1, 65)?,
        )
        .verify(&signed, &encoded(&assertion.signature, 80)?)
        .map_err(|_| refuse())?;
        let old_pending = record(&pending)?;
        let old_state = record(&state)?;
        let assertion_digest = digest("review-assertion", &serde_json::to_value(assertion)?)?;
        pending.consumed = true;
        pending.assertion_digest = Some(assertion_digest.clone());
        state.counter = counter;
        if !self
            .txn(
                vec![value_eq(&key, &old_pending), value_eq(&ck, &old_state)],
                vec![put(&key, &record(&pending)?), put(&ck, &record(&state)?)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        // A delayed/ambiguous response never publishes expired approval facts;
        // consumption stays durable even when this final freshness check refuses.
        approval.validate(&state.enrollment, clock.now_ms())?;
        Ok(VerifiedReview {
            approval: approval.clone(),
            assertion_digest,
            sign_count: counter,
        })
    }
}
