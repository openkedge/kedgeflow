//! Separate draft signed records for the bounded administrative control plane.
use crate::{
    admission::AdmissionTrust,
    contracts::{Action, Policy, Resource, canonical, digest, strict_value},
    error::{Error, Result},
    policy::CedarPolicyDefinition,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const PROFILE: &str = "KF-ENFORCEMENT-CONTROL-0.1-draft";
pub fn validate_control(value: &Value) -> Result<()> {
    static PIN: std::sync::OnceLock<std::result::Result<jsonschema::Validator, String>> =
        std::sync::OnceLock::new();
    let pin = PIN.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../spec/drafts/enforcement-control-v0.1.schema.json"
        ))
        .map_err(|_| "invalid embedded control schema".to_owned())?;
        crate::schema::compile(&schema).map_err(|_| "invalid local control schema".to_owned())
    });
    let validator = pin.as_ref().map_err(|v| Error::Unavailable(v.clone()))?;
    if !validator.is_valid(value) {
        return Err(Error::Invalid(
            "record violates draft control schema".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnforcementScope {
    pub conflict_domain: String,
    pub action: Action,
    pub resource: Resource,
    pub audience: String,
    pub adapter_contract: Value,
    pub predicate_descriptor: Value,
}
impl EnforcementScope {
    pub(crate) fn grant(g: &crate::contracts::Grant) -> Result<Self> {
        if g.resources.len() != 1 {
            return Err(Error::Refused("control requires one resource".into()));
        }
        Ok(Self {
            conflict_domain: g.conflict_domain.clone(),
            action: g.action.clone(),
            resource: g.resources[0].clone(),
            audience: g.audience.clone(),
            adapter_contract: g.adapter_contract.clone(),
            predicate_descriptor: g.predicate_descriptor.clone(),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Acknowledger {
    pub component_id: String,
    pub workload_id: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub max_lifetime_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ControlRegistration {
    pub tenant: String,
    pub scope: EnforcementScope,
    pub policy: Policy,
    pub ownership_epoch: u64,
    pub obligation_manifest_digest: String,
    pub trust_digest: String,
    pub issuer_keys: BTreeMap<String, String>,
    pub acknowledger: Acknowledger,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPublication {
    pub registration: ControlRegistration,
    pub definition: CedarPolicyDefinition,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorPublication {
    pub registration: ControlRegistration,
    pub descriptor: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub registration: ControlRegistration,
    pub revision: u64,
    pub expected_revision: u64,
    pub policy_publication_digest: String,
    pub descriptor_publication_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub installation_digest: String,
    pub revision: u64,
    pub component_id: String,
    pub workload_id: String,
    pub coverage: String,
    pub installed_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationTarget {
    Domain,
    Root { id: String },
    Grant { id: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub tenant: String,
    pub conflict_domain: String,
    pub target: RevocationTarget,
    pub revision: u64,
    pub reason_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedControl {
    profile: String,
    kind: String,
    key_id: String,
    payload: Value,
    signature: String,
}
fn message(r: &SignedControl) -> Result<Vec<u8>> {
    let mut bytes = b"KedgeFlow:KF-ENFORCEMENT-CONTROL-0.1-draft\0".to_vec();
    bytes.extend(canonical(
        &json!({"profile":r.profile,"kind":r.kind,"key_id":r.key_id,"payload":r.payload}),
    )?);
    Ok(bytes)
}
pub fn sign_control<T: Serialize>(
    kind: &str,
    payload: &T,
    key_id: &str,
    key: &SigningKey,
) -> Result<String> {
    let mut r = SignedControl {
        profile: PROFILE.into(),
        kind: kind.into(),
        key_id: key_id.into(),
        payload: serde_json::to_value(payload)?,
        signature: String::new(),
    };
    r.signature = URL_SAFE_NO_PAD.encode(key.sign(&message(&r)?).to_bytes());
    String::from_utf8(canonical(&serde_json::to_value(r)?)?)
        .map_err(|_| Error::Invalid("control UTF8".into()))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredControl {
    pub digest: String,
    pub record: String,
}
impl StoredControl {
    pub fn payload<T: DeserializeOwned>(&self, kind: &str) -> Result<T> {
        let r: SignedControl = serde_json::from_value(strict_value(self.record.as_bytes())?)?;
        if r.profile != PROFILE
            || r.kind != kind
            || digest("enforcement-record", &serde_json::to_value(&r)?)? != self.digest
        {
            return Err(Error::Refused("stored control correlation mismatch".into()));
        }
        Ok(serde_json::from_value(r.payload)?)
    }
}
pub fn verify_control<T: DeserializeOwned>(
    raw: &str,
    kind: &str,
    keys: &BTreeMap<String, VerifyingKey>,
) -> Result<(T, StoredControl)> {
    let value = strict_value(raw.as_bytes())?;
    validate_control(&value)?;
    let r: SignedControl = serde_json::from_value(value.clone())?;
    let key = keys
        .get(&r.key_id)
        .ok_or_else(|| Error::Refused("unregistered control signer".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&r.signature)
        .map_err(|_| Error::Invalid("control signature encoding".into()))?;
    let signature = Signature::from_slice(&bytes)
        .map_err(|_| Error::Invalid("control signature length".into()))?;
    if r.profile != PROFILE
        || r.kind != kind
        || key.verify_strict(&message(&r)?, &signature).is_err()
    {
        return Err(Error::Refused(
            "wrong control profile, role or signature".into(),
        ));
    }
    let stored = StoredControl {
        digest: digest("enforcement-record", &value)?,
        record: String::from_utf8(canonical(&value)?)
            .map_err(|_| Error::Invalid("control UTF8".into()))?,
    };
    Ok((serde_json::from_value(r.payload)?, stored))
}
pub(crate) fn control_kind(raw: &str) -> Result<String> {
    let r: SignedControl = serde_json::from_value(strict_value(raw.as_bytes())?)?;
    Ok(r.kind)
}
pub fn trust_digest(
    trust: &AdmissionTrust,
    admission_keys: &BTreeMap<String, VerifyingKey>,
    issuer_keys: &BTreeMap<String, VerifyingKey>,
) -> Result<String> {
    let encode = |keys: &BTreeMap<String, VerifyingKey>| {
        keys.iter()
            .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
            .collect::<BTreeMap<_, _>>()
    };
    let mut v = json!({"tenant":trust.tenant,"proposal_keys":encode(&trust.proposal_keys),"registry_keys":encode(&trust.registry_keys),"manifest_keys":encode(&trust.manifest_keys),"obligation_manifest_digest":trust.obligation_manifest_digest,"admission_keys":encode(admission_keys),"issuer_keys":encode(issuer_keys)});
    if let Some(c) = &trust.inverse_contract {
        v["inverse_contract_digest"] = json!(c.digest()?);
    }
    digest("enforcement-trust", &v)
}
pub(crate) fn acknowledgement_keys(a: &Acknowledger) -> Result<BTreeMap<String, VerifyingKey>> {
    let bytes: [u8; 32] = hex::decode(&a.public_key_hex)
        .map_err(|_| Error::Invalid("ack key hex".into()))?
        .try_into()
        .map_err(|_| Error::Invalid("ack key length".into()))?;
    Ok(BTreeMap::from([(
        a.key_id.clone(),
        VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Invalid("ack public key".into()))?,
    )]))
}
pub(crate) fn validate_ack(
    a: &Acknowledgement,
    i: &Installation,
    installation_digest: &str,
    now: i64,
) -> Result<()> {
    let expected = &i.registration.acknowledger;
    if a.installation_digest != installation_digest
        || a.revision != i.revision
        || a.component_id != expected.component_id
        || a.workload_id != expected.workload_id
        || a.coverage != "gateway_control_checks"
        || a.installed_at > now
        || a.expires_at <= now
        || a.expires_at
            .checked_sub(a.installed_at)
            .is_none_or(|v| v <= 0 || v > expected.max_lifetime_ms)
    {
        return Err(Error::Refused(
            "stale or unsupported installation acknowledgement".into(),
        ));
    }
    Ok(())
}
/// Produce only gateway configuration coverage, never target/writer coverage.
pub fn acknowledge_gateway(
    i: &Installation,
    installation_digest: &str,
    tools: &[crate::gateway::ToolDescriptor],
    verifier: &crate::contracts::GrantVerifier,
    workload_id: &str,
    key: &SigningKey,
    now: i64,
) -> Result<String> {
    let r = &i.registration;
    let s = &r.scope;
    let expected = acknowledgement_keys(&r.acknowledger)?;
    let installed_keys = verifier
        .keys
        .iter()
        .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    if verifier.audience != s.audience
        || installed_keys != r.issuer_keys
        || workload_id != r.acknowledger.workload_id
        || expected.get(&r.acknowledger.key_id) != Some(&key.verifying_key())
        || !tools.iter().any(|t| {
            t.validate().is_ok()
                && !t.read_only
                && t.action.as_ref() == Some(&s.action)
                && t.resource.as_ref() == Some(&s.resource)
                && t.conflict_domain == s.conflict_domain
                && t.adapter_contract == s.adapter_contract
                && s.predicate_descriptor["id"].as_str() == Some(t.predicate_id.as_str())
                && s.predicate_descriptor["version"].as_str() == Some(t.predicate_version.as_str())
        })
    {
        return Err(Error::Refused(
            "gateway has not installed the declared scope".into(),
        ));
    }
    let a = Acknowledgement {
        installation_digest: installation_digest.into(),
        revision: i.revision,
        component_id: r.acknowledger.component_id.clone(),
        workload_id: workload_id.into(),
        coverage: "gateway_control_checks".into(),
        installed_at: now,
        expires_at: now
            .checked_add(r.acknowledger.max_lifetime_ms)
            .ok_or_else(|| Error::Invalid("ack expiry overflow".into()))?,
    };
    sign_control("acknowledge", &a, &r.acknowledger.key_id, key)
}
