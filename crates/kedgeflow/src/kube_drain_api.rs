//! Bounded API access for the explicitly protected Level C controller.
//! Kubernetes response observations are not an atomic availability guard.
use crate::{
    clock::Clock,
    contracts::strict_value,
    error::{Error, Result},
    grant_reference::{bounded_response, fixed_https},
    kube_drain::{Contract, NamespacedPin, ObjectPin},
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
fn refuse() -> Error {
    Error::Refused("Kubernetes realm, inventory or original object refused".into())
}
fn text(v: &Value) -> Result<String> {
    v.as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .map(str::to_owned)
        .ok_or_else(refuse)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeView {
    pub object: ObjectPin,
    pub resource_version: String,
    pub ready: bool,
    pub unschedulable: bool,
    pub operation: Option<String>,
    pub annotations_present: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PodView {
    pub object: NamespacedPin,
    pub resource_version: String,
    pub owner_kind: String,
    pub owner_api_version: String,
    pub owner: ObjectPin,
    pub ready: bool,
    pub deleting: bool,
    pub mirror: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub profile: String,
    pub contract_digest: String,
    pub from: i64,
    pub until: i64,
    pub cluster_uid: String,
    pub nodes: Vec<NodeView>,
    pub target_pods: Vec<PodView>,
    pub deployment_uid: String,
    pub deployment_generation: u64,
    pub observed_generation: u64,
    pub available: u64,
    pub replica_set_uid: String,
    pub pdb_uid: String,
    pub pdb_generation: u64,
    pub pdb_min_available: u64,
    pub pdb_disruptions_allowed: u64,
}
impl Inventory {
    pub fn validate(&self, c: &Contract) -> Result<()> {
        c.validate()?;
        if self.profile != crate::kube_drain::PROFILE
            || self.contract_digest != c.digest()?
            || self.cluster_uid != c.cluster_uid
            || self.from < 0
            || self.until < self.from
            || self.until - self.from > 10000
            || self.nodes.len() != c.availability_nodes.len()
            || crate::contracts::canonical(&json!(self))?.len() > (128 << 10)
            || self.target_pods.len() > 96
            || self.deployment_uid != c.workload.deployment.object.uid
            || self.deployment_generation != c.workload.generation
            || self.observed_generation < self.deployment_generation
            || self.replica_set_uid != c.workload.replica_set.uid
            || self.pdb_uid != c.workload.pdb.uid
            || self.pdb_generation != c.workload.pdb_generation
            || self.pdb_min_available != c.workload.pdb_min_available
        {
            return Err(refuse());
        }
        for p in &c.availability_nodes {
            if self
                .nodes
                .iter()
                .filter(|n| {
                    n.object == *p
                        && !n.resource_version.is_empty()
                        && n.resource_version.len() <= 256
                })
                .count()
                != 1
            {
                return Err(refuse());
            }
        }
        let mut identities = std::collections::BTreeSet::new();
        for p in &self.target_pods {
            p.object.validate()?;
            if p.object.object.name.is_empty()
                || p.object.object.uid.is_empty()
                || p.resource_version.is_empty()
                || !identities.insert((&p.object.namespace, &p.object.object.name))
            {
                return Err(refuse());
            }
            if !self.ignored(c, p)
                && (p.object.namespace != c.workload.deployment.namespace
                    || p.owner_kind != "ReplicaSet"
                    || p.owner_api_version != "apps/v1"
                    || p.owner != c.workload.replica_set)
            {
                return Err(refuse());
            }
        }
        if self
            .target_pods
            .iter()
            .filter(|p| !self.ignored(c, p))
            .count()
            > c.maximum_pods as usize
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub fn ignored(&self, c: &Contract, p: &PodView) -> bool {
        p.mirror && c.allowed_mirror_pods.contains(&p.object)
            || !p.mirror
                && p.owner_kind == "DaemonSet"
                && p.owner_api_version == "apps/v1"
                && c.allowed_daemon_sets
                    .iter()
                    .any(|d| d.namespace == p.object.namespace && d.object == p.owner)
    }
    pub fn target(&self, c: &Contract) -> Result<&NodeView> {
        self.nodes
            .iter()
            .find(|n| n.object == c.node)
            .ok_or_else(refuse)
    }
    pub fn availability(&self, c: &Contract) -> Result<()> {
        self.validate(c)?;
        if self.available < c.workload.minimum_available
            || self
                .nodes
                .iter()
                .filter(|n| n.object != c.node && n.ready && !n.unschedulable)
                .count()
                < (c.minimum_ready_nodes as usize)
        {
            return Err(refuse());
        }
        Ok(())
    }
}
pub struct Api {
    origin: reqwest::Url,
    client: reqwest::Client,
    token: String,
    ca_sha256: String,
    clock: Arc<dyn Clock>,
}
impl Api {
    pub fn new(origin: &str, ca: &[u8], token: String, clock: Arc<dyn Clock>) -> Result<Self> {
        let origin = fixed_https(origin)?;
        if origin.path() != "/"
            || token.len() < 32
            || token.len() > 16384
            || token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(refuse());
        }
        let ca_sha256 = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(ca))
        };
        let ca = reqwest::Certificate::from_pem(ca).map_err(|_| refuse())?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2))
            .build()?;
        Ok(Self {
            origin,
            client,
            token,
            ca_sha256,
            clock,
        })
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        patch: bool,
    ) -> Result<(StatusCode, Value)> {
        let mut url = self.origin.clone();
        url.set_path(path);
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v)));
        }
        let mut r = self.client.request(method, url).bearer_auth(&self.token);
        if let Some(b) = body {
            if patch {
                r = r.header("content-type", "application/json-patch+json");
            }
            r = r.json(b);
        }
        let r = r.send().await?;
        let status = r.status();
        let raw = bounded_response(r, 4 << 20).await?;
        let value = strict_value(&raw)?;
        Ok((status, value))
    }
    async fn get(&self, path: &str) -> Result<Value> {
        let (s, v) = self.request(Method::GET, path, &[], None, false).await?;
        if s != StatusCode::OK {
            return Err(refuse());
        }
        Ok(v)
    }
    pub async fn inventory(&self, c: &Contract) -> Result<Inventory> {
        c.validate()?;
        if self.origin.as_str() != c.api_origin || self.ca_sha256 != c.ca_sha256 {
            return Err(refuse());
        }
        let from = self.clock.now_ms();
        let realm = self.get("/api/v1/namespaces/kube-system").await?;
        let mut nodes = Vec::new();
        for p in &c.availability_nodes {
            let v = self.get(&format!("/api/v1/nodes/{}", p.name)).await?;
            let m = &v["metadata"];
            let object = ObjectPin {
                name: text(&m["name"])?,
                uid: text(&m["uid"])?,
            };
            if object != *p {
                return Err(refuse());
            }
            nodes.push(NodeView {
                object,
                resource_version: text(&m["resourceVersion"])?,
                ready: v["status"]["conditions"].as_array().is_some_and(|a| {
                    a.iter()
                        .any(|x| x["type"] == "Ready" && x["status"] == "True")
                }),
                unschedulable: v["spec"]["unschedulable"].as_bool().unwrap_or(false),
                operation: m["annotations"]["kedgeflow.dev/drain-operation"]
                    .as_str()
                    .map(str::to_owned),
                annotations_present: m.get("annotations").is_some(),
            });
        }
        let (s, list) = self
            .request(
                Method::GET,
                "/api/v1/pods",
                &[
                    ("fieldSelector", format!("spec.nodeName={}", c.node.name)),
                    ("limit", "97".into()),
                ],
                None,
                false,
            )
            .await?;
        if s != StatusCode::OK
            || list["metadata"]["continue"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        {
            return Err(refuse());
        }
        let mut target_pods = Vec::new();
        for v in list["items"]
            .as_array()
            .filter(|a| a.len() <= 96)
            .ok_or_else(refuse)?
        {
            let m = &v["metadata"];
            if v["spec"]["nodeName"] != c.node.name {
                return Err(refuse());
            }
            let owners = m["ownerReferences"].as_array();
            let owner = owners
                .into_iter()
                .flatten()
                .filter(|o| o["controller"] == true)
                .collect::<Vec<_>>();
            let mirror = m["annotations"]
                .get("kubernetes.io/config.mirror")
                .is_some();
            let owner_api_version = if mirror {
                String::new()
            } else {
                text(&owner.first().ok_or_else(refuse)?["apiVersion"])?
            };
            let (owner_kind, owner) = if mirror {
                (
                    String::new(),
                    ObjectPin {
                        name: String::new(),
                        uid: String::new(),
                    },
                )
            } else {
                if owner.len() != 1 {
                    return Err(refuse());
                }
                (
                    text(&owner[0]["kind"])?,
                    ObjectPin {
                        name: text(&owner[0]["name"])?,
                        uid: text(&owner[0]["uid"])?,
                    },
                )
            };
            target_pods.push(PodView {
                object: NamespacedPin {
                    namespace: text(&m["namespace"])?,
                    object: ObjectPin {
                        name: text(&m["name"])?,
                        uid: text(&m["uid"])?,
                    },
                },
                resource_version: text(&m["resourceVersion"])?,
                owner_kind,
                owner_api_version,
                owner,
                ready: v["status"]["conditions"].as_array().is_some_and(|a| {
                    a.iter()
                        .any(|x| x["type"] == "Ready" && x["status"] == "True")
                }),
                deleting: m.get("deletionTimestamp").is_some_and(|v| !v.is_null()),
                mirror,
            });
        }
        target_pods.sort_by(|a, b| {
            (&a.object.namespace, &a.object.object.name)
                .cmp(&(&b.object.namespace, &b.object.object.name))
        });
        let ns = &c.workload.deployment.namespace;
        let d = self
            .get(&format!(
                "/apis/apps/v1/namespaces/{ns}/deployments/{}",
                c.workload.deployment.object.name
            ))
            .await?;
        let r = self
            .get(&format!(
                "/apis/apps/v1/namespaces/{ns}/replicasets/{}",
                c.workload.replica_set.name
            ))
            .await?;
        if !r["metadata"]["ownerReferences"]
            .as_array()
            .is_some_and(|a| {
                a.iter().filter(|o| o["controller"] == true).count() == 1
                    && a.iter().any(|o| {
                        o["controller"] == true
                            && o["kind"] == "Deployment"
                            && o["apiVersion"] == "apps/v1"
                            && o["uid"] == c.workload.deployment.object.uid
                            && o["name"] == c.workload.deployment.object.name
                    })
            })
        {
            return Err(refuse());
        }
        let p = self
            .get(&format!(
                "/apis/policy/v1/namespaces/{ns}/poddisruptionbudgets/{}",
                c.workload.pdb.name
            ))
            .await?;
        let i = Inventory {
            profile: crate::kube_drain::PROFILE.into(),
            contract_digest: c.digest()?,
            from,
            until: self.clock.now_ms(),
            cluster_uid: text(&realm["metadata"]["uid"])?,
            nodes,
            target_pods,
            deployment_uid: text(&d["metadata"]["uid"])?,
            deployment_generation: d["metadata"]["generation"].as_u64().ok_or_else(refuse)?,
            observed_generation: d["status"]["observedGeneration"]
                .as_u64()
                .ok_or_else(refuse)?,
            available: d["status"]["availableReplicas"].as_u64().unwrap_or(0),
            replica_set_uid: text(&r["metadata"]["uid"])?,
            pdb_uid: text(&p["metadata"]["uid"])?,
            pdb_generation: p["metadata"]["generation"].as_u64().ok_or_else(refuse)?,
            pdb_min_available: p["spec"]["minAvailable"].as_u64().ok_or_else(refuse)?,
            pdb_disruptions_allowed: p["status"]["disruptionsAllowed"].as_u64().unwrap_or(0),
        };
        i.validate(c)?;
        Ok(i)
    }
    /// Caller must have retained this exact request in the original native
    /// Pending CAS. This function alone supplies no admission/dispatch authority.
    pub(crate) async fn mutate(
        &self,
        path: &str,
        body: &Value,
        patch: bool,
    ) -> Result<(u16, Value)> {
        let (s, v) = self
            .request(
                if patch { Method::PATCH } else { Method::POST },
                path,
                &[],
                Some(body),
                patch,
            )
            .await?;
        Ok((s.as_u16(), v))
    }
}
pub fn cordon_request(c: &Contract, n: &NodeView, operation: &str) -> Result<Value> {
    c.validate()?;
    n.object.validate()?;
    if n.resource_version.is_empty() || n.resource_version.len() > 256 {
        return Err(refuse());
    }
    if n.object != c.node
        || n.unschedulable
        || n.operation.is_some()
        || !crate::grant_reference::valid_reference(operation)
    {
        return Err(refuse());
    }
    let mut ops = vec![
        json!({"op":"test","path":"/metadata/uid","value":n.object.uid}),
        json!({"op":"test","path":"/metadata/resourceVersion","value":n.resource_version}),
        json!({"op":"add","path":"/spec/unschedulable","value":true}),
    ];
    ops.push(if n.annotations_present {json!({"op":"add","path":"/metadata/annotations/kedgeflow.dev~1drain-operation","value":operation})}else{json!({"op":"add","path":"/metadata/annotations","value":{"kedgeflow.dev/drain-operation":operation}})});
    Ok(json!(ops))
}
pub fn eviction_request(c: &Contract, p: &PodView) -> Result<Value> {
    c.validate()?;
    p.object.validate()?;
    p.owner.validate()?;
    if p.resource_version.is_empty() || p.resource_version.len() > 256 {
        return Err(refuse());
    }
    if p.owner_api_version != "apps/v1"
        || p.object.namespace != c.workload.deployment.namespace
        || p.owner_kind != "ReplicaSet"
        || p.owner != c.workload.replica_set
        || p.mirror
        || p.deleting
    {
        return Err(refuse());
    }
    Ok(
        json!({"apiVersion":"policy/v1","kind":"Eviction","metadata":{"name":p.object.object.name,"namespace":p.object.namespace},"deleteOptions":{"gracePeriodSeconds":c.grace_period_seconds,"preconditions":{"uid":p.object.object.uid,"resourceVersion":p.resource_version}}}),
    )
}
