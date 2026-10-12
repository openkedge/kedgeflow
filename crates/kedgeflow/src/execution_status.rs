//! Query-only retained grant/attempt correlation under current disclosure scope.
use crate::{
    auth::Identity,
    contracts::{Grant, canonical},
    error::{Error, Result},
    gateway::{Gateway, ToolDescriptor},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::OnceLock, time::Duration};

pub const PROFILE: &str = "KF-EXECUTION-STATUS-0.1-draft";
pub const EXTENSION: &str = "io.kedgeflow/execution-status";
pub const METHOD: &str = "kedgeflow/status";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    profile: String,
    grant: String,
    #[serde(default)]
    attempt_id: Option<String>,
}

pub fn validate(value: &Value) -> Result<()> {
    static SCHEMA: OnceLock<jsonschema::Validator> = OnceLock::new();
    let schema = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/execution-status-v0.1.schema.json"
            ))
            .expect("embedded status schema"),
        )
        .expect("valid embedded status schema")
    });
    if !schema.is_valid(value) {
        return Err(Error::Invalid(
            "closed execution status schema mismatch".into(),
        ));
    }
    Ok(())
}

impl Gateway {
    pub(crate) async fn query_execution(
        &self,
        args: &Value,
        identity: &Identity,
        tool: &ToolDescriptor,
    ) -> Result<Value> {
        validate(args)?;
        let lookup: Lookup = serde_json::from_value(args.clone())?;
        if lookup.profile != PROFILE {
            return Err(Error::Invalid("unsupported status profile".into()));
        }
        let verified = self.verifier.verify_retained(lookup.grant.as_bytes())?;
        let g = &verified.grant;
        // A fresh token may replace the expired execution delegation. Disclosure
        // still binds the enrolled subject, workload, PoP key and registered tool.
        if g.subject != identity.subject
            || g.workload_id != identity.workload_id
            || g.dpop_jkt != identity.dpop_jkt
            || Some(&g.action) != tool.action.as_ref()
            || Some(&g.resources[0]) != tool.resource.as_ref()
            || g.conflict_domain != tool.conflict_domain
            || canonical(&g.adapter_contract)? != canonical(&tool.adapter_contract)?
            || g.predicate_descriptor["id"] != tool.predicate_id
            || g.predicate_descriptor["version"] != tool.predicate_version
        {
            return Err(Error::Refused("status identity/tool mismatch".into()));
        }
        let status = self.ledger.execution_status(g, &verified.digest).await?;
        if status.grant_digest != verified.digest {
            return Err(Error::Unavailable("ledger status grant mismatch".into()));
        }
        if lookup
            .attempt_id
            .as_ref()
            .is_some_and(|id| Some(id) != status.attempt_id.as_ref())
        {
            return Err(Error::Refused("status attempt mismatch".into()));
        }
        let value = json!({"resultType":"complete","profile":PROFILE,"state":status.state,"attempt_id":status.attempt_id,"grant_digest":status.grant_digest});
        validate(&value)?;
        Ok(value)
    }

    pub(crate) async fn resolve_claim(&self, grant: &Grant, digest: &str) -> Value {
        match tokio::time::timeout(
            Duration::from_secs(5),
            self.ledger.execution_status(grant, digest),
        )
        .await
        {
            Ok(Ok(status)) if status.grant_digest == digest && validate(&json!({"resultType":"complete","profile":PROFILE,"state":status.state,"attempt_id":status.attempt_id,"grant_digest":status.grant_digest})).is_ok() => {
                json!({"profile":PROFILE,"state":status.state,"attempt_id":status.attempt_id,"grant_digest":status.grant_digest})
            }
            _ => {
                json!({"profile":PROFILE,"state":"unavailable","attempt_id":null,"grant_digest":digest})
            }
        }
    }
}
