//! RFC 0025 named SQL leaf binding. Legacy action names retain the mock binding.
use crate::{
    contracts::{MAX_SAFE_INTEGER, Resource, canonical},
    error::{Error, Result},
    postgres_action::{ACTION, Parameters},
};
use serde_json::Value;

pub const PROFILE: &str = "KF-POSTGRES-LEAF-0.1-draft";
pub const EXTENSION: &str = "io.kedgeflow/postgres-leaf";

pub fn sql_schema() -> Value {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../spec/drafts/postgres-reservation-v0.1.schema.json"
    ))
    .expect("embedded SQL schema");
    schema["$defs"]["Parameters"].clone()
}

pub fn validate_schema(action: &str, version: &str, schema: &Value) -> Result<()> {
    if action == ACTION && (version != "1.0" || canonical(schema)? != canonical(&sql_schema())?) {
        return Err(Error::Refused("SQL action version/schema mismatch".into()));
    }
    Ok(())
}

/// Bind only application arguments. Fence/attempt/grant metadata never comes
/// from the agent. Return the version that must equal the signed predicate.
pub fn bind(
    action: &str,
    version: &str,
    parameters: &Value,
    resource: &Resource,
    version_field: &str,
) -> Result<u64> {
    if action == ACTION {
        if version != "1.0" || version_field != "expected_version" {
            return Err(Error::Refused("unsupported SQL leaf binding".into()));
        }
        let p = Parameters::decode(&serde_json::to_vec(parameters)?)?;
        if p.resource_id != resource.id {
            return Err(Error::Refused("SQL resource parameter mismatch".into()));
        }
        return Ok(p.expected_version);
    }
    let fields = parameters
        .as_object()
        .ok_or_else(|| Error::Invalid("arguments must be an object".into()))?;
    if fields.len() != 2 || fields.get("node").and_then(Value::as_str) != Some(resource.id.as_str())
    {
        return Err(Error::Refused("resource parameter mismatch".into()));
    }
    fields
        .get(version_field)
        .and_then(Value::as_u64)
        .filter(|v| *v > 0 && *v <= MAX_SAFE_INTEGER)
        .ok_or_else(|| Error::Invalid("version required".into()))
}
