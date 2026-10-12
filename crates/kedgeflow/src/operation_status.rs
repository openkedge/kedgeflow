//! Closed proposal-addressed historical disclosure; never execution authority.
use crate::error::{Error, Result};
use serde::Deserialize;
use std::sync::OnceLock;
pub const PROFILE: &str = "KF-OPERATION-STATUS-0.1-draft";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lookup {
    pub request_id: String,
    pub proposal: String,
    #[serde(rename = "profile")]
    pub _profile: String,
    #[serde(rename = "operation")]
    pub _operation: String,
}
pub fn validate(raw: &[u8]) -> Result<()> {
    static SCHEMA: OnceLock<jsonschema::Validator> = OnceLock::new();
    let schema = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/operation-status-v0.1.schema.json"
            ))
            .expect("embedded operation status schema"),
        )
        .expect("valid operation status schema")
    });
    if !schema.is_valid(&crate::contracts::strict_value(raw)?) {
        return Err(Error::Invalid(
            "closed operation status schema mismatch".into(),
        ));
    }
    Ok(())
}
