//! Explicit Level C controller contract. This module supplies no native authority.
use crate::{
    contracts::{MAX_SAFE_INTEGER, Resource, canonical, digest, strict_value},
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const PROFILE: &str = "KF-KUBE-DRAIN-0.1-draft";
pub const ACTION: &str = "kubernetes.node.drain";
pub const EXTENSION: &str = "io.kedgeflow/kubernetes-drain";
pub const MAX_PODS: usize = 32;
pub const MAX_REQUESTS: usize = 96;
pub const MAX_CONTRACT: usize = 64 << 10;
fn refuse() -> Error {
    Error::Refused("protected Kubernetes drain contract refused".into())
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
}
fn uid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectPin {
    pub name: String,
    pub uid: String,
}
impl ObjectPin {
    pub(crate) fn validate(&self) -> Result<()> {
        if name(&self.name) && uid(&self.uid) {
            Ok(())
        } else {
            Err(refuse())
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespacedPin {
    pub namespace: String,
    pub object: ObjectPin,
}
impl NamespacedPin {
    pub(crate) fn validate(&self) -> Result<()> {
        self.object.validate()?;
        if name(&self.namespace) && self.namespace.len() <= 63 && !self.namespace.contains('.') {
            Ok(())
        } else {
            Err(refuse())
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub deployment: NamespacedPin,
    pub generation: u64,
    pub replica_set: ObjectPin,
    pub pdb: ObjectPin,
    pub pdb_generation: u64,
    pub pdb_min_available: u64,
    pub minimum_available: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub profile: String,
    pub cluster_uid: String,
    pub api_origin: String,
    pub ca_sha256: String,
    pub node: ObjectPin,
    pub generation: u64,
    pub availability_nodes: Vec<ObjectPin>,
    pub minimum_ready_nodes: u64,
    pub workload: Workload,
    pub allowed_daemon_sets: Vec<NamespacedPin>,
    pub allowed_mirror_pods: Vec<NamespacedPin>,
    pub maximum_pods: u64,
    pub maximum_requests: u64,
    pub maximum_deferred_ms: u64,
    pub grace_period_seconds: u64,
}
impl Contract {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_CONTRACT {
            return Err(refuse());
        }
        let value = strict_value(raw)?;
        let c: Self = serde_json::from_value(value.clone())?;
        if json!(c) != value {
            return Err(refuse());
        }
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        let origin = crate::grant_reference::fixed_https(&self.api_origin)?;
        if origin.path() != "/"
            || origin.as_str() != self.api_origin
            || !crate::grant_reference::valid_reference(&self.ca_sha256)
        {
            return Err(refuse());
        }
        self.node.validate()?;
        self.workload.deployment.validate()?;
        self.workload.replica_set.validate()?;
        self.workload.pdb.validate()?;
        if self.profile != PROFILE
            || !uid(&self.cluster_uid)
            || self.generation == 0
            || self.generation > MAX_SAFE_INTEGER
            || !(2..=16).contains(&self.availability_nodes.len())
            || self.minimum_ready_nodes == 0
            || self.minimum_ready_nodes as usize >= self.availability_nodes.len()
            || self.workload.generation == 0
            || self.workload.generation > MAX_SAFE_INTEGER
            || self.workload.pdb_generation == 0
            || self.workload.pdb_generation > MAX_SAFE_INTEGER
            || self.workload.minimum_available == 0
            || self.workload.minimum_available > MAX_PODS as u64
            || self.workload.pdb_min_available != self.workload.minimum_available
            || self.maximum_pods == 0
            || self.maximum_pods > MAX_PODS as u64
            || self.maximum_requests < self.maximum_pods + 1
            || self.maximum_requests > MAX_REQUESTS as u64
            || self.maximum_deferred_ms == 0
            || self.maximum_deferred_ms > 3600000
            || self.grace_period_seconds > 120
            || self.allowed_daemon_sets.len() > 32
            || self.allowed_mirror_pods.len() > 32
        {
            return Err(refuse());
        }
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for p in &self.availability_nodes {
            p.validate()?;
            if !names.insert(&p.name) || !ids.insert(&p.uid) {
                return Err(refuse());
            }
        }
        if !self.availability_nodes.contains(&self.node) {
            return Err(refuse());
        }
        let mut exclusions = BTreeSet::new();
        for p in self
            .allowed_daemon_sets
            .iter()
            .chain(&self.allowed_mirror_pods)
        {
            p.validate()?;
            if !exclusions.insert((&p.namespace, &p.object.name, &p.object.uid)) {
                return Err(refuse());
            }
        }
        if canonical(&json!(self))?.len() > MAX_CONTRACT {
            return Err(refuse());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("kube-drain-contract", &json!(self))
    }
    pub fn resource(&self) -> Result<Resource> {
        self.validate()?;
        Ok(Resource {
            id: self.node.name.clone(),
            incarnation: digest(
                "kube-drain-incarnation",
                &json!({"cluster_uid":self.cluster_uid,"node_uid":self.node.uid}),
            )?,
        })
    }
    pub fn parameter_schema(&self) -> Result<Value> {
        parameter_schema(&self.digest()?, &self.node.name, self.generation)
    }
}
/// Native commit is controller acceptance. Physical completion needs the
/// separately verified original operation and independent observed outcomes.
pub fn adapter_contract() -> Value {
    json!({"level":"Level_C","guard_primitive":"None","fence_parameter":null,"guard_scope":[],"completion_mode":"dispatch_bound","commit_point":"KF-KUBE-DRAIN-0.1-draft:durable-controller-acceptance","idempotency":{"mode":"resource_key","parameter":"attempt_id","retention_ms":86400000}})
}

pub fn parameter_schema(contract_digest: &str, node: &str, generation: u64) -> Result<Value> {
    if !crate::grant_reference::valid_reference(contract_digest)
        || !name(node)
        || generation == 0
        || generation > MAX_SAFE_INTEGER
    {
        return Err(refuse());
    }
    Ok(
        json!({"$comment":format!("{PROFILE} contract={contract_digest}"),"type":"object","properties":{"node":{"type":"string","const":node},"expected_version":{"type":"integer","const":generation}},"required":["node","expected_version"],"additionalProperties":false}),
    )
}
pub fn validate_schema(version: &str, schema: &Value) -> Result<()> {
    let comment = schema["$comment"].as_str().ok_or_else(refuse)?;
    let digest = comment
        .strip_prefix(&format!("{PROFILE} contract="))
        .ok_or_else(refuse)?;
    let node = schema["properties"]["node"]["const"]
        .as_str()
        .ok_or_else(refuse)?;
    let generation = schema["properties"]["expected_version"]["const"]
        .as_u64()
        .ok_or_else(refuse)?;
    if version != "1.0"
        || canonical(schema)? != canonical(&parameter_schema(digest, node, generation)?)?
    {
        return Err(refuse());
    }
    Ok(())
}
pub fn bind(
    version: &str,
    parameters: &Value,
    resource: &Resource,
    version_field: &str,
) -> Result<u64> {
    let node = parameters["node"].as_str().ok_or_else(refuse)?;
    let generation = parameters["expected_version"].as_u64().ok_or_else(refuse)?;
    if version != "1.0"
        || version_field != "expected_version"
        || node != resource.id
        || !name(node)
        || generation == 0
        || generation > MAX_SAFE_INTEGER
        || parameters != &json!({"node":node,"expected_version":generation})
    {
        return Err(refuse());
    }
    Ok(generation)
}
/// The generic legacy adapter validator stays Level A. Only the named action
/// may select this exact contract; a signature check is not target redemption.
pub fn validate_adapter(version: &str, value: &Value, fence_parameter: Option<&str>) -> Result<()> {
    if version != "1.0"
        || value != &adapter_contract()
        || fence_parameter.is_some_and(|s| !s.is_empty())
    {
        return Err(refuse());
    }
    Ok(())
}

pub fn coverage() -> Value {
    let mut inventory = json!({"coordinated_writers":["kedgeflow-drain-controller"],"uncoordinated_writers":["kubernetes-control-plane","node-runtime","privileged-administrators"]});
    inventory["inventory_digest"] = json!(
        crate::contracts::digest("coverage-inventory", &inventory,)
            .expect("fixed coverage inventory is canonical")
    );
    inventory
}
