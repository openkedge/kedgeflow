//! Original controller journal. Pending requests are never repeated after an
//! ambiguous response or process loss. No physical inverse is defined here.
use crate::{
    contracts::{Grant, canonical, digest},
    control_bindings::ControlState,
    error::{Error, Result},
    family_saga::AuthorityView,
    kube_drain::{Contract, PROFILE},
    kube_drain_api::{Inventory, PodView, cordon_request, eviction_request},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
fn refuse() -> Error {
    Error::Refused("original Kubernetes drain journal refused".into())
}
pub const MAX_STATE: usize = 512 << 10;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub control: ControlState,
    pub family: AuthorityView,
    pub checked_at: i64,
    pub native_dispatch_digest: String,
    pub reservation_head: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    pub profile: String,
    pub contract_digest: String,
    pub signed_grant: String,
    pub grant_digest: String,
    pub attempt_id: String,
    pub permit_id: String,
    pub accepted_at: i64,
    pub deferred_until: i64,
    pub initial: Inventory,
    pub authority: Authority,
}
impl Accepted {
    pub fn operation(&self) -> Result<String> {
        digest(
            "kube-drain-operation",
            &json!({"contract_digest":self.contract_digest,"grant_digest":self.grant_digest,"attempt_id":self.attempt_id}),
        )
    }
    pub fn validate(&self, c: &Contract, g: &Grant) -> Result<()> {
        self.initial.availability(c)?;
        let n = self.initial.target(c)?;
        if self.profile != PROFILE
            || self.contract_digest != c.digest()?
            || self.accepted_at < g.valid_from
            || self.accepted_at >= g.expires_at
            || self.initial.until > self.accepted_at
            || self.accepted_at - self.initial.from > 10000
            || self.deferred_until <= self.accepted_at
            || self.deferred_until - self.accepted_at > c.maximum_deferred_ms as i64
            || n.unschedulable
            || n.operation.is_some()
            || self.attempt_id.is_empty()
            || self.attempt_id.len() > 256
            || !crate::grant_reference::valid_reference(&self.permit_id)
            || !crate::grant_reference::valid_reference(&self.grant_digest)
            || self
                .initial
                .target_pods
                .iter()
                .filter(|p| !self.initial.ignored(c, p))
                .count()
                == 0
            || self
                .initial
                .target_pods
                .iter()
                .any(|p| !self.initial.ignored(c, p) && p.deleting)
        {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    Cordon,
    Evict { original_uid: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub sequence: u64,
    pub mutation: Mutation,
    pub inventory: Inventory,
    pub authority: Authority,
    pub authorized_at: i64,
    pub path: String,
    pub request: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Zero means transport/response ambiguity; it is never a retry permission.
    pub http_status: u16,
    pub body_digest: Option<String>,
    pub recorded_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub pending: Pending,
    pub response: Option<Response>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closed {
    pub closed_at: i64,
    pub family_head: String,
    pub phase_head: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub accepted: Accepted,
    pub steps: Vec<Step>,
    pub closed: Option<Closed>,
}
impl State {
    pub fn digest(&self) -> Result<String> {
        digest("kube-drain-state", &json!(self))
    }
    pub fn validate(&self, c: &Contract, g: &Grant) -> Result<()> {
        self.accepted.validate(c, g)?;
        if self.steps.len() > c.maximum_requests as usize
            || canonical(&json!(self))?.len() > MAX_STATE - 4096
        {
            return Err(refuse());
        }
        let mut prior = self.accepted.accepted_at;
        for (n, s) in self.steps.iter().enumerate() {
            let p = &s.pending;
            p.inventory.availability(c)?;
            if p.inventory.target_pods.iter().any(|pod| {
                !p.inventory.ignored(c, pod)
                    && !self
                        .accepted
                        .initial
                        .target_pods
                        .iter()
                        .any(|original| original.object == pod.object)
            }) {
                return Err(refuse());
            }
            if p.sequence != n as u64 + 1
                || p.authorized_at < prior
                || p.authorized_at >= self.accepted.deferred_until
                || p.inventory.until > p.authorized_at
                || p.authorized_at - p.inventory.from > 10000
                || p.authority.checked_at > p.authorized_at
                || p.authority.checked_at < self.accepted.accepted_at
            {
                return Err(refuse());
            }
            if n > 0
                && self.steps[n - 1]
                    .response
                    .as_ref()
                    .is_none_or(|r| !(200..300).contains(&r.http_status) && r.http_status != 429)
            {
                return Err(refuse());
            }
            let (path, request) = match &p.mutation {
                Mutation::Cordon => {
                    if n != 0 {
                        return Err(refuse());
                    }
                    (
                        format!("/api/v1/nodes/{}", c.node.name),
                        cordon_request(c, p.inventory.target(c)?, &self.accepted.operation()?)?,
                    )
                }
                Mutation::Evict { original_uid } => {
                    if n == 0
                        || !matches!(self.steps[0].pending.mutation, Mutation::Cordon)
                        || self.steps[0]
                            .response
                            .as_ref()
                            .is_none_or(|r| !(200..300).contains(&r.http_status))
                        || p.inventory.target(c)?.operation.as_deref()
                            != Some(self.accepted.operation()?.as_str())
                        || !p.inventory.target(c)?.unschedulable
                    {
                        return Err(refuse());
                    }
                    let original = self
                        .accepted
                        .initial
                        .target_pods
                        .iter()
                        .find(|v| {
                            !self.accepted.initial.ignored(c, v)
                                && v.object.object.uid == *original_uid
                        })
                        .ok_or_else(refuse)?;
                    if self.steps[..n].iter().any(|s|matches!(&s.pending.mutation,Mutation::Evict{original_uid:u} if u==original_uid) && s.response.as_ref().is_none_or(|r|r.http_status!=429)) {return Err(refuse());}
                    let current = p
                        .inventory
                        .target_pods
                        .iter()
                        .find(|v| v.object == original.object)
                        .ok_or_else(refuse)?;
                    (
                        format!(
                            "/api/v1/namespaces/{}/pods/{}/eviction",
                            current.object.namespace, current.object.object.name
                        ),
                        eviction_request(c, current)?,
                    )
                }
            };
            if p.path != path || canonical(&p.request)? != canonical(&request)? {
                return Err(refuse());
            }
            if let Some(r) = &s.response {
                if r.recorded_at < p.authorized_at
                    || r.recorded_at < prior
                    || r.http_status > 599
                    || (r.http_status != 0 && r.http_status < 100)
                    || (r.http_status == 0) != r.body_digest.is_none()
                    || r.body_digest
                        .as_ref()
                        .is_some_and(|s| !crate::grant_reference::valid_reference(s))
                {
                    return Err(refuse());
                }
                prior = r.recorded_at;
            } else if n + 1 != self.steps.len() {
                return Err(refuse());
            } else {
                prior = p.authorized_at;
            }
        }
        if let Some(closed) = &self.closed
            && (!self.steps.is_empty()
                || closed.closed_at < self.accepted.accepted_at
                || !crate::grant_reference::valid_reference(&closed.family_head)
                || !crate::grant_reference::valid_reference(&closed.phase_head))
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub fn original_pods(&self, c: &Contract) -> Vec<&PodView> {
        self.accepted
            .initial
            .target_pods
            .iter()
            .filter(|p| !self.accepted.initial.ignored(c, p))
            .collect()
    }
    pub fn physical_status(&self, c: &Contract, observation: &Inventory) -> Result<&'static str> {
        observation.validate(c)?;
        let minimum = self
            .steps
            .last()
            .map(|s| {
                s.response
                    .as_ref()
                    .map(|r| r.recorded_at)
                    .unwrap_or(s.pending.authorized_at)
            })
            .unwrap_or(self.accepted.accepted_at);
        if observation.from < minimum {
            return Err(refuse());
        }
        if observation.until < self.accepted.accepted_at {
            return Err(refuse());
        }
        if self.closed.is_some() {
            return Ok("no_physical_effect");
        }
        let operation = self.accepted.operation()?;
        if !self.steps.is_empty()
            && observation.target(c)?.unschedulable
            && observation.target(c)?.operation.as_deref() == Some(operation.as_str())
            && observation
                .target_pods
                .iter()
                .all(|p| observation.ignored(c, p))
            && observation.availability(c).is_ok()
        {
            return Ok("observed_completed");
        }
        let Some(last) = self.steps.last() else {
            return Ok("accepted");
        };
        Ok(match &last.response {
            None => "unknown",
            Some(r) if r.http_status == 0 => "unknown",
            Some(r) if r.http_status == 429 => "blocked",
            Some(r) if !(200..300).contains(&r.http_status) => "failed",
            _ => "partial",
        })
    }
}
