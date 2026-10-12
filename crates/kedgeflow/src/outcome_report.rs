//! Closed retained-outcome delivery contract and independently signed acknowledgements.
use crate::{
    contracts::{Envelope, canonical, digest, record_digest, strict_value},
    error::{Error, Result},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const PROFILE: &str = "KF-OUTCOME-REPORT-0.1-draft";
pub fn validate(value: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let schema = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/outcome-report-v0.1.schema.json"
            ))
            .expect("embedded outcome report schema"),
        )
        .expect("valid outcome report schema")
    });
    if !schema.is_valid(value) {
        return Err(Error::Invalid("closed outcome report mismatch".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub report_id: String,
    pub tenant: String,
    pub grant_digest: String,
    pub attempt_id: String,
    pub receipt_digest: String,
    pub evidence_digest: String,
    pub source_id: String,
    pub collector_id: String,
    pub collector_url: String,
    pub previous_receipt_digest: Option<String>,
    pub accepted_at: i64,
}
impl Acknowledgement {
    pub(crate) fn expected(e: &Envelope, collector: &str, url: &str, tenant: &str) -> Result<Self> {
        let p = &e.payload;
        let field = |name: &str| -> Result<String> {
            p[name]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::Invalid("missing receipt correlation".into()))
        };
        let receipt_digest = record_digest(e)?;
        let grant_digest = field("grant_digest")?;
        let attempt_id = field("attempt_id")?;
        Ok(Self {
            report_id: digest(
                "outcome-delivery",
                &json!({"collector_id":collector,"collector_url":url,"tenant":tenant,"grant_digest":grant_digest,"attempt_id":attempt_id,"receipt_digest":receipt_digest}),
            )?,
            tenant: tenant.into(),
            grant_digest,
            attempt_id,
            receipt_digest,
            evidence_digest: p["resolution_evidence"][0]["digest"]
                .as_str()
                .ok_or_else(|| Error::Invalid("missing receipt evidence".into()))?
                .into(),
            source_id: field("source_id")?,
            collector_id: collector.into(),
            collector_url: url.into(),
            previous_receipt_digest: p["previous_receipt_digest"].as_str().map(str::to_owned),
            accepted_at: 0,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAck {
    profile: String,
    kind: String,
    key_id: String,
    payload: Acknowledgement,
    signature: String,
}
fn message(r: &SignedAck) -> Result<Vec<u8>> {
    let mut bytes = b"KedgeFlow:KF-OUTCOME-REPORT-0.1-draft\0".to_vec();
    bytes.extend(canonical(
        &json!({"profile":r.profile,"kind":r.kind,"key_id":r.key_id,"payload":r.payload}),
    )?);
    Ok(bytes)
}
pub(crate) fn sign_ack(payload: Acknowledgement, id: &str, key: &SigningKey) -> Result<String> {
    let mut r = SignedAck {
        profile: PROFILE.into(),
        kind: "acknowledgement".into(),
        key_id: id.into(),
        payload,
        signature: String::new(),
    };
    r.signature = URL_SAFE_NO_PAD.encode(key.sign(&message(&r)?).to_bytes());
    let value = serde_json::to_value(&r)?;
    validate(&value)?;
    String::from_utf8(canonical(&value)?)
        .map_err(|_| Error::Invalid("acknowledgement encoding".into()))
}
pub fn verify_ack(
    raw: &str,
    keys: &BTreeMap<String, VerifyingKey>,
    expected: &Acknowledgement,
) -> Result<Acknowledgement> {
    if raw.len() > 1 << 20 {
        return Err(Error::Invalid("acknowledgement exceeds bound".into()));
    }
    let value = strict_value(raw.as_bytes())?;
    validate(&value)?;
    let r: SignedAck = serde_json::from_value(value)?;
    let key = keys
        .get(&r.key_id)
        .ok_or_else(|| Error::Refused("untrusted collector key".into()))?;
    let sig = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&r.signature)
            .map_err(|_| Error::Invalid("ack signature encoding".into()))?,
    )
    .map_err(|_| Error::Invalid("ack signature length".into()))?;
    key.verify_strict(&message(&r)?, &sig)
        .map_err(|_| Error::Refused("ack signature mismatch".into()))?;
    let mut actual = r.payload.clone();
    actual.accepted_at = 0;
    let mut expected = expected.clone();
    expected.accepted_at = 0;
    if actual != expected {
        return Err(Error::Refused(
            "acknowledgement correlation mismatch".into(),
        ));
    }
    Ok(r.payload)
}
