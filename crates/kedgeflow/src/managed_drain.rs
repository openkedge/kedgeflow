//! Explicit RFC0056 managed-action enrollment. No nullable legacy mode switch.
use crate::{
    contracts::{Resource, canonical, digest},
    error::{Error, Result},
    family_saga::ObserverPin,
    grant_reference::{fixed_https, valid_reference},
    kube_drain::Contract,
    physical_operations::Policy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub const PROFILE: &str = "KF-MANAGED-KUBE-DRAIN-0.2-draft";
pub const VERSION: &str = "1.1";
pub const ACTION: &str = "kubernetes.node.drain.managed";
pub const EXTENSION: &str = "io.kedgeflow/managed-kubernetes-drain";
fn refuse() -> Error {
    Error::Refused("explicit managed drain enrollment refused".into())
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/@".contains(&b))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub profile: String,
    pub namespace: String,
    pub child_id: String,
    pub operation_key: String,
    pub mechanical_contract_digest: String,
    pub target_audience: String,
    pub target_scope: String,
    pub controller_workload: String,
    pub supervisor_workload: String,
    pub evidence_workload: String,
    pub operating_observer: ObserverPin,
    pub policy: Policy,
    pub current_sql: crate::current_reservation::Registration,
    pub clock_uncertainty_ms: u64,
    pub maximum_authorization_to_send_ms: u64,
}
impl Enrollment {
    pub fn validate(&self, c: &Contract) -> Result<()> {
        c.validate()?;
        self.policy.validate()?;
        self.current_sql.validate()?;
        if self.clock_uncertainty_ms > 1000
            || !(1..=1000).contains(&self.maximum_authorization_to_send_ms)
            || self.profile != PROFILE
            || !self.namespace.starts_with('/')
            || self.namespace.ends_with('/')
            || self.namespace.len() > 512
            || self.namespace[1..].split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            })
            || !id(&self.target_scope)
            || !id(&self.child_id)
            || !valid_reference(&self.operation_key)
            || self.mechanical_contract_digest != c.digest()?
            || !crate::auth::valid_spiffe_id(&self.controller_workload)
            || !crate::auth::valid_spiffe_id(&self.supervisor_workload)
            || !crate::auth::valid_spiffe_id(&self.evidence_workload)
            || [
                &self.controller_workload,
                &self.supervisor_workload,
                &self.evidence_workload,
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
                != 3
            || self.operating_observer.keys.is_empty()
            || self.operating_observer.keys.len() > 16
            || !id(&self.operating_observer.id)
            || self.operating_observer.keys.keys().any(|s| !id(s))
            || self.current_sql.tenant != self.policy.tenant
            || self.current_sql.forward_child_id == self.child_id
        {
            return Err(refuse());
        }
        let keys = crate::control_config::keys(&self.operating_observer.keys)?;
        let others = crate::control_config::keys(&self.current_sql.provider.keys)?;
        let sink = crate::control_config::keys(&self.policy.incident_sink.acknowledgement_keys)?;
        let storage = crate::control_config::keys(&self.current_sql.storage.owner.keys)?;
        let all: Vec<_> = keys
            .values()
            .chain(others.values())
            .chain(sink.values())
            .chain(storage.values())
            .collect();
        let ids = [
            &self.operating_observer.id,
            &self.current_sql.provider.id,
            &self.current_sql.storage.owner.id,
            &self.policy.incident_sink.id,
        ];
        if ids
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 4
            || all
                .iter()
                .map(|k| *k.as_bytes())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != all.len()
            || fixed_https(&self.target_audience)?.as_str() != self.target_audience
            || canonical(&json!(self))?.len() > 128 << 10
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub fn decode(raw: &[u8], contract: &Contract) -> Result<Self> {
        if raw.len() > 128 << 10 {
            return Err(refuse());
        }
        let e: Self = serde_json::from_value(crate::contracts::strict_value(raw)?)?;
        e.validate(contract)?;
        Ok(e)
    }
    pub fn digest(&self) -> Result<String> {
        digest("managed-kube-drain-enrollment", &json!(self))
    }
    pub fn schema(&self, c: &Contract) -> Result<Value> {
        self.validate(c)?;
        parameter_schema(&self.digest()?, &c.digest()?, &c.node.name, c.generation)
    }
    pub fn validate_child(
        &self,
        r: &crate::family::Registration,
        child: &str,
        c: &Contract,
    ) -> Result<()> {
        self.validate(c)?;
        if self.namespace != r.namespace || self.policy.tenant != r.tenant || self.child_id != child
        {
            return Err(refuse());
        }
        let plan = r.composition.as_ref().ok_or_else(refuse)?;
        let node = plan.node(child)?;
        let sql = plan.node(&self.current_sql.forward_child_id)?;
        let sql_child = r.child(&sql.child_id)?;
        if node.operation_key != self.operation_key
            || node.depends_on != [sql.child_id.clone()]
            || sql.operation_key != self.current_sql.forward_operation_key
            || sql.physical.is_some()
            || sql_child.reservation.scope.action.id != crate::postgres_action::ACTION
            || sql_child.reservation.scope.resource != self.current_sql.resource
            || sql_child.reservation.root_id != self.current_sql.forward_reservation_root_id
            || sql_child.inverse.as_ref().ok_or_else(refuse)?.digest()?
                != self.current_sql.compensation_contract_digest
        {
            return Err(refuse());
        }
        Ok(())
    }
}
pub fn adapter_contract() -> Value {
    let mut v = crate::kube_drain::adapter_contract();
    v["commit_point"] = json!(format!("{PROFILE}:durable-controller-acceptance"));
    v
}
pub fn parameter_schema(
    enrollment: &str,
    mechanical: &str,
    node: &str,
    generation: u64,
) -> Result<Value> {
    if !valid_reference(enrollment) || !valid_reference(mechanical) {
        return Err(refuse());
    }
    let mut v = crate::kube_drain::parameter_schema(mechanical, node, generation)?;
    v["$comment"] = json!(format!(
        "{PROFILE} enrollment={enrollment} mechanical={mechanical}"
    ));
    Ok(v)
}
pub fn validate_schema(version: &str, schema: &Value) -> Result<()> {
    let text = schema["$comment"].as_str().ok_or_else(refuse)?;
    let part = text
        .strip_prefix(&format!("{PROFILE} enrollment="))
        .ok_or_else(refuse)?;
    let (enrollment, mechanical) = part.split_once(" mechanical=").ok_or_else(refuse)?;
    let node = schema["properties"]["node"]["const"]
        .as_str()
        .ok_or_else(refuse)?;
    let generation = schema["properties"]["expected_version"]["const"]
        .as_u64()
        .ok_or_else(refuse)?;
    if version != VERSION || *schema != parameter_schema(enrollment, mechanical, node, generation)?
    {
        return Err(refuse());
    }
    Ok(())
}
pub fn bind(version: &str, parameters: &Value, resource: &Resource, field: &str) -> Result<u64> {
    if version != VERSION {
        return Err(refuse());
    }
    crate::kube_drain::bind("1.0", parameters, resource, field)
}
pub fn validate_adapter(version: &str, v: &Value, fence: Option<&str>) -> Result<()> {
    if version != VERSION || *v != adapter_contract() || fence.is_some_and(|s| !s.is_empty()) {
        return Err(refuse());
    }
    Ok(())
}
pub fn coverage() -> Value {
    let mut v = crate::kube_drain::coverage();
    v["coordinated_writers"] = json!(["kedgeflow-managed-drain-controller"]);
    v.as_object_mut()
        .expect("object")
        .remove("inventory_digest");
    v["inventory_digest"] = json!(digest("coverage-inventory", &v).expect("fixed coverage"));
    v
}
