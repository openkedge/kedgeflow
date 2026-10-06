//! KF-JSON-0.2 records and the deliberately restricted executable grant profile.
//!
//! JSON canonicalization covers the profile's safe-integer subset of RFC 8785.
//! Signature verification authenticates a statement; it does not discharge
//! admission obligations, establish evidence truth, or reserve an allowance.

use crate::error::{Error, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

pub const PROFILE: &str = "KF-JSON-0.2";
pub const GRANT_SCHEMA: &str =
    "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/ExecutionGrant";
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub iss: String,
    pub sub: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub id: String,
    pub incarnation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub epoch: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub gid: String,
    pub proposal_digest: String,
    pub certificate_digest: String,
    pub delegation_digest: String,
    pub subject: Subject,
    pub workload_id: String,
    pub dpop_jkt: String,
    pub action: Action,
    pub resources: Vec<Resource>,
    pub parameters_digest: String,
    pub policy: Policy,
    pub evidence_manifest_digest: String,
    pub constraint_digest: String,
    pub ownership_epoch: u64,
    pub predicate_descriptor: Value,
    pub adapter_contract: Value,
    pub root_id: String,
    pub root_generation: u64,
    pub parent_grant_digest: Option<String>,
    pub saga_budget: Value,
    pub conflict_domain: String,
    pub nonce: String,
    pub fence: u64,
    pub audience: String,
    pub issued_at: i64,
    pub valid_from: i64,
    pub expires_at: i64,
    pub completion_mode: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub profile: String,
    pub kind: String,
    pub schema: String,
    pub key_id: String,
    pub payload: Value,
    pub signature: String,
}

const ENVELOPE_FIELDS: &[&str] = &[
    "profile",
    "kind",
    "schema",
    "key_id",
    "payload",
    "signature",
];
const GRANT_FIELDS: &[&str] = &[
    "gid",
    "proposal_digest",
    "certificate_digest",
    "delegation_digest",
    "subject",
    "workload_id",
    "dpop_jkt",
    "action",
    "resources",
    "parameters_digest",
    "policy",
    "evidence_manifest_digest",
    "constraint_digest",
    "ownership_epoch",
    "predicate_descriptor",
    "adapter_contract",
    "root_id",
    "root_generation",
    "parent_grant_digest",
    "saga_budget",
    "conflict_domain",
    "nonce",
    "fence",
    "audience",
    "issued_at",
    "valid_from",
    "expires_at",
    "completion_mode",
];

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

fn exact_fields(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("record must be an object"))?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid("required or closed record fields mismatch"));
    }
    Ok(())
}

// Check the lexical number form before serde converts -0 to a floating value.
// The profile accepts -0 as integer zero, but rejects 0.0, 1e0, and all other
// floating/exponent tokens even when their mathematical value is an integer.
fn integer_tokens_only(raw: &[u8]) -> Result<()> {
    let mut i = 0;
    let mut quoted = false;
    while i < raw.len() {
        match raw[i] {
            b'\\' if quoted => {
                i += 2;
                continue;
            }
            b'"' => quoted = !quoted,
            b'-' | b'0'..=b'9' if !quoted => {
                if raw[i] == b'-' {
                    i += 1;
                }
                while i < raw.len() && raw[i].is_ascii_digit() {
                    i += 1;
                }
                if i < raw.len() && matches!(raw[i], b'.' | b'e' | b'E') {
                    return Err(invalid("non-integer JSON number"));
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

struct StrictValue(Value);
struct StrictVisitor;

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Self)
    }
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict safe-integer JSON")
    }

    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        if !(-(MAX_SAFE_INTEGER as i64)..=MAX_SAFE_INTEGER as i64).contains(&value) {
            return Err(E::custom("integer exceeds exact JSON safe range"));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        if value > MAX_SAFE_INTEGER {
            return Err(E::custom("integer exceeds exact JSON safe range"));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        // integer_tokens_only already excluded every decimal/exponent token.
        if value == 0.0 && value.is_sign_negative() {
            return Ok(Value::Number(Number::from(0)));
        }
        Err(E::custom("non-integer or out-of-range JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = seq.next_element::<StrictValue>()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON property"));
            }
            let StrictValue(value) = map.next_value::<StrictValue>()?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

/// Parse one complete UTF-8 JSON value, rejecting duplicate keys at every depth,
/// unpaired Unicode surrogates, floating/exponent numbers, and unsafe integers.
pub fn strict_value(raw: &[u8]) -> Result<Value> {
    std::str::from_utf8(raw).map_err(|_| invalid("non-UTF8 JSON"))?;
    integer_tokens_only(raw)?;
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let StrictValue(value) =
        StrictValue::deserialize(&mut decoder).map_err(|e| invalid(e.to_string()))?;
    decoder.end().map_err(|e| invalid(e.to_string()))?;
    Ok(value)
}

/// RFC 8785 property ordering uses UTF-16 code units, not UTF-8 byte order or
/// Unicode scalar values. No Unicode normalization is performed.
#[derive(Debug, Eq, PartialEq)]
pub struct UTF16Key<'a>(pub &'a str);

impl Ord for UTF16Key<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.encode_utf16().cmp(other.0.encode_utf16())
    }
}
impl PartialOrd for UTF16Key<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            let text = if let Some(n) = number.as_i64() {
                if !(-(MAX_SAFE_INTEGER as i64)..=MAX_SAFE_INTEGER as i64).contains(&n) {
                    return Err(invalid("integer exceeds exact JSON safe range"));
                }
                n.to_string()
            } else if let Some(n) = number.as_u64() {
                if n > MAX_SAFE_INTEGER {
                    return Err(invalid("integer exceeds exact JSON safe range"));
                }
                n.to_string()
            } else {
                return Err(invalid("non-integer JSON number"));
            };
            out.extend_from_slice(text.as_bytes());
        }
        Value::String(text) => {
            out.extend_from_slice(&serde_json::to_vec(text).map_err(|e| invalid(e.to_string()))?);
        }
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_by(|a, b| UTF16Key(a).cmp(&UTF16Key(b)));
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_canonical(&Value::String(key.clone()), out)?;
                out.push(b':');
                write_canonical(&values[key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

pub fn digest(kind: &str, value: &Value) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(format!("KedgeFlow/{PROFILE}/{kind}\0").as_bytes());
    hash.update(canonical(value)?);
    Ok(hex::encode(hash.finalize()))
}

pub fn signature_input(envelope: &Envelope) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct UnsignedEnvelope<'a> {
        profile: &'a str,
        kind: &'a str,
        schema: &'a str,
        key_id: &'a str,
        payload: &'a Value,
    }
    let unsigned = UnsignedEnvelope {
        profile: &envelope.profile,
        kind: &envelope.kind,
        schema: &envelope.schema,
        key_id: &envelope.key_id,
        payload: &envelope.payload,
    };
    let value = serde_json::to_value(unsigned).map_err(|e| invalid(e.to_string()))?;
    let mut bytes = format!("KedgeFlow/{PROFILE}\0").into_bytes();
    bytes.extend(canonical(&value)?);
    Ok(bytes)
}

fn kind_schema(kind: &str) -> Option<&'static str> {
    match kind {
        "proposal" => Some("Proposal"),
        "certificate" => Some("AdmissionCertificate"),
        "grant" => Some("ExecutionGrant"),
        "ctd" => Some("ConsequentialToolDescriptor"),
        "hitl_witness" => Some("HitlWitness"),
        "evidence" => Some("Evidence"),
        "manifest" => Some("WitnessManifest"),
        "lease" => Some("AdmissionLease"),
        "saga_root" => Some("SagaExecutionRoot"),
        "remediation" => Some("RemediationContract"),
        "receipt" => Some("Receipt"),
        "delegation" => Some("DelegationRequest"),
        "token_exchange" => Some("TokenExchangeBinding"),
        _ => None,
    }
}

/// Authenticate a closed envelope for one of the thirteen declared record kinds.
/// This helper does not implement every payload schema, cross-record admission
/// binding, signer-role policy, or that kind's runtime authorization semantics.
pub fn verify_envelope(raw: &[u8], keys: &BTreeMap<String, VerifyingKey>) -> Result<Envelope> {
    let value = strict_value(raw)?;
    exact_fields(&value, ENVELOPE_FIELDS)?;
    let envelope: Envelope = serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
    let definition =
        kind_schema(&envelope.kind).ok_or_else(|| invalid("unsupported envelope kind"))?;
    let schema =
        format!("https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/{definition}");
    if envelope.profile != PROFILE || envelope.schema != schema {
        return Err(invalid("unsupported envelope profile or schema"));
    }
    let key = keys
        .get(&envelope.key_id)
        .ok_or_else(|| invalid("untrusted signing key"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(&envelope.signature)
        .map_err(|_| invalid("invalid signature encoding"))?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| invalid("invalid signature length"))?;
    key.verify_strict(&signature_input(&envelope)?, &signature)
        .map_err(|_| invalid("bad signature"))?;
    Ok(envelope)
}

/// Proposal identity excludes the transport signer/signature; other record
/// digests bind the complete signed envelope, matching the published vectors.
pub fn record_digest(envelope: &Envelope) -> Result<String> {
    let value = if envelope.kind == "proposal" {
        serde_json::json!({"schema": envelope.schema, "payload": envelope.payload})
    } else {
        serde_json::to_value(envelope).map_err(|e| invalid(e.to_string()))?
    };
    digest(&envelope.kind, &value)
}

pub fn sign_grant(grant: &Grant, key_id: &str, key: &SigningKey) -> Result<Vec<u8>> {
    let mut envelope = Envelope {
        profile: PROFILE.to_owned(),
        kind: "grant".to_owned(),
        schema: GRANT_SCHEMA.to_owned(),
        key_id: key_id.to_owned(),
        payload: serde_json::to_value(grant).map_err(|e| invalid(e.to_string()))?,
        signature: String::new(),
    };
    envelope.signature = URL_SAFE_NO_PAD.encode(key.sign(&signature_input(&envelope)?).to_bytes());
    canonical(&serde_json::to_value(envelope).map_err(|e| invalid(e.to_string()))?)
}

#[derive(Clone, Debug)]
pub struct VerifiedGrant {
    pub grant: Grant,
    pub digest: String,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct GrantVerifier {
    /// This is the trusted Grant Authority key set, not every evidence signer.
    pub keys: BTreeMap<String, VerifyingKey>,
    pub audience: String,
}

impl GrantVerifier {
    pub fn verify(&self, raw: &[u8], now_ms: i64) -> Result<VerifiedGrant> {
        let envelope = verify_envelope(raw, &self.keys)?;
        if envelope.kind != "grant" || envelope.schema != GRANT_SCHEMA {
            return Err(invalid("not an execution grant"));
        }
        // serde accepts an omitted Option field as None; the wire contract does
        // not. Null-valued parent_grant_digest and saga_budget remain required.
        exact_fields(&envelope.payload, GRANT_FIELDS)?;
        let grant: Grant =
            serde_json::from_value(envelope.payload.clone()).map_err(|e| invalid(e.to_string()))?;
        if grant.issued_at < 0
            || grant.valid_from < 0
            || grant.expires_at <= grant.valid_from
            || grant.issued_at > grant.valid_from
            || now_ms < grant.valid_from
            || now_ms >= grant.expires_at
        {
            return Err(Error::Refused("grant expired or not yet valid".into()));
        }
        if grant.audience != self.audience
            || grant.gid.is_empty()
            || grant.root_id.is_empty()
            || grant.nonce.is_empty()
            || grant.conflict_domain.is_empty()
            || grant.root_generation == 0
            || grant.fence == 0
            || grant.ownership_epoch == 0
            || grant.policy.epoch == 0
        {
            return Err(invalid("invalid grant scope"));
        }
        if grant.parent_grant_digest.is_some()
            || !grant.saga_budget.is_null()
            || grant.resources.len() != 1
            || grant.completion_mode != "dispatch_bound"
        {
            return Err(invalid("unsupported execution profile"));
        }
        if grant.subject.iss.is_empty()
            || grant.subject.sub.is_empty()
            || grant.workload_id.is_empty()
            || grant.dpop_jkt.is_empty()
            || grant.resources[0].id.is_empty()
            || grant.resources[0].incarnation.is_empty()
            || grant.action.id.is_empty()
            || grant.action.version.is_empty()
            || grant.policy.id.is_empty()
        {
            return Err(invalid("missing dual identity"));
        }
        for value in [
            &grant.proposal_digest,
            &grant.certificate_digest,
            &grant.delegation_digest,
            &grant.action.digest,
            &grant.parameters_digest,
            &grant.policy.digest,
            &grant.evidence_manifest_digest,
            &grant.constraint_digest,
        ] {
            if !crate::grant_reference::valid_reference(value) {
                return Err(invalid("invalid grant digest"));
            }
        }
        validate_executable_contract(&grant)?;
        let digest = digest("grant", &strict_value(raw)?)?;
        Ok(VerifiedGrant {
            grant,
            digest,
            raw: raw.to_vec(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Predicate {
    id: String,
    version: String,
    language: String,
    clauses: Vec<VersionClause>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionClause {
    kind: String,
    resource: Resource,
    expected_version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterContract {
    level: String,
    guard_primitive: String,
    fence_parameter: String,
    guard_scope: Vec<String>,
    completion_mode: String,
    commit_point: String,
    idempotency: Idempotency,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Idempotency {
    mode: String,
    parameter: String,
    retention_ms: u64,
}

/// Enforce the mock-resource profile accepted by the Go gateway's bindCall:
/// one version predicate and a Level A fenced, single-resource dispatch path.
pub fn validate_executable_contract(grant: &Grant) -> Result<()> {
    let predicate: Predicate = serde_json::from_value(grant.predicate_descriptor.clone())
        .map_err(|e| invalid(e.to_string()))?;
    if predicate.id.is_empty()
        || predicate.version.is_empty()
        || predicate.language != "kf-conjunction-v1"
        || predicate.clauses.len() != 1
    {
        return Err(invalid("unsupported predicate"));
    }
    let clause = &predicate.clauses[0];
    let expected = clause
        .expected_version
        .parse::<u64>()
        .map_err(|_| invalid("invalid expected resource version"))?;
    if clause.kind != "version_eq"
        || grant.resources.len() != 1
        || clause.resource != grant.resources[0]
        || expected == 0
        || expected > MAX_SAFE_INTEGER
        || clause.expected_version != expected.to_string()
    {
        return Err(invalid("unsupported or mismatched predicate"));
    }
    validate_adapter_contract(&grant.adapter_contract, &grant.resources[0], None)
}

/// Supported fenced mock mapping, checked both at registration and redemption.
pub fn validate_adapter_contract(
    value: &Value,
    resource: &Resource,
    fence_parameter: Option<&str>,
) -> Result<()> {
    let adapter: AdapterContract =
        serde_json::from_value(value.clone()).map_err(|e| invalid(e.to_string()))?;
    if adapter.level != "Level_A"
        || adapter.guard_primitive != "FencingToken"
        || adapter.fence_parameter.is_empty()
        || adapter.guard_scope != [resource.id.clone()]
        || fence_parameter.is_some_and(|p| p != adapter.fence_parameter)
        || adapter.completion_mode != "dispatch_bound"
        || adapter.commit_point.is_empty()
        || adapter.idempotency.mode != "resource_key"
        || adapter.idempotency.parameter != "kf_attempt_id"
        || adapter.idempotency.retention_ms == 0
        || adapter.idempotency.retention_ms > MAX_SAFE_INTEGER
    {
        return Err(invalid("unsupported adapter contract"));
    }
    Ok(())
}
