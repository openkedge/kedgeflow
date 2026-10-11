//! Pinned local schemas. Schema references cannot read files or use the network.
use crate::{
    contracts::{Envelope, verify_envelope},
    error::{Error, Result},
};
use ed25519_dalek::VerifyingKey;
use jsonschema::{Retrieve, Uri, Validator};
use serde_json::Value;
use std::{collections::BTreeMap, sync::OnceLock};

struct NoRetrieval;
impl Retrieve for NoRetrieval {
    fn retrieve(
        &self,
        _: &Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("external schema retrieval is disabled".into())
    }
}

pub(crate) fn compile(schema: &Value) -> Result<Validator> {
    jsonschema::draft202012::options()
        .with_retriever(NoRetrieval)
        .should_validate_formats(true)
        .should_ignore_unknown_formats(false)
        .build(schema)
        .map_err(|_| Error::Invalid("invalid or nonlocal registered schema".into()))
}

/// Verify a specific kind under caller-supplied role-scoped keys, then validate
/// every frozen payload field, including nested formats, against the local pin.
pub fn verify_record(
    raw: &[u8],
    kind: &str,
    keys: &BTreeMap<String, VerifyingKey>,
) -> Result<Envelope> {
    static PIN: OnceLock<std::result::Result<Validator, String>> = OnceLock::new();
    let pin = PIN.get_or_init(|| {
        let schema: Value =
            serde_json::from_str(include_str!("../../../spec/kedgeflow.schema.json"))
                .map_err(|_| "invalid embedded record schema".to_owned())?;
        compile(&schema).map_err(|_| "cannot compile embedded record schema".to_owned())
    });
    let validator = pin
        .as_ref()
        .map_err(|message| Error::Unavailable(message.clone()))?;
    let envelope = verify_envelope(raw, keys)?;
    if envelope.kind != kind || !validator.is_valid(&serde_json::to_value(&envelope)?) {
        return Err(Error::Invalid(
            "record differs from pinned kind/schema".into(),
        ));
    }
    Ok(envelope)
}

/// A schema obtained from trusted registry/configuration, not a request URI.
pub struct ClosedObjectSchema(Validator);
impl ClosedObjectSchema {
    pub fn new(schema: &Value) -> Result<Self> {
        if schema.get("type").and_then(Value::as_str) != Some("object")
            || schema.get("additionalProperties") != Some(&Value::Bool(false))
        {
            return Err(Error::Invalid(
                "registered application schema must close its object".into(),
            ));
        }
        Ok(Self(compile(schema)?))
    }

    pub fn validate(&self, value: &Value) -> Result<()> {
        if !self.0.is_valid(value) {
            return Err(Error::Refused(
                "application data violates registered schema".into(),
            ));
        }
        Ok(())
    }
}
