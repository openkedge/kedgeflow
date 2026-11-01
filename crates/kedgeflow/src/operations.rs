//! Opt-in, monitor-only mTLS readiness. Probes create no execution authority.
use crate::{
    auth::{WorkloadIdentity, valid_spiffe_id},
    endpoint::EndpointPolicy,
    error::{Error, Result},
};
use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

pub const PROFILE: &str = "KF-SERVICE-READINESS-0.1-draft";
pub(crate) fn deserialize_scope<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<crate::governance::EnforcementScope>, D::Error> {
    Ok(Some(crate::governance::EnforcementScope::deserialize(d)?))
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    Ready,
    Refused,
    Unavailable,
    Unverified,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Dependency {
    AuthorityReads,
    ManagedControl,
    IdentityMaterial,
    Probe,
    DatabaseExecution,
    DatabaseQuery,
    Broker,
    Target,
    TargetQuery,
    Collector,
    DeliveryMaterial,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub dependency: Dependency,
    pub condition: Condition,
}
impl Check {
    pub fn result(dependency: Dependency, result: Result<()>) -> Self {
        Self {
            dependency,
            condition: match result {
                Ok(()) => Condition::Ready,
                Err(Error::Refused(_) | Error::Invalid(_)) => Condition::Refused,
                Err(_) => Condition::Unavailable,
            },
        }
    }
    pub fn unverified(dependency: Dependency) -> Self {
        Self {
            dependency,
            condition: Condition::Unverified,
        }
    }
}
#[async_trait]
pub trait Probe: Send + Sync {
    /// Only read-only prerequisites. No proof consumption, writes, mint or dispatch.
    async fn check(&self) -> Vec<Check>;
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub profile: String,
    pub role: Role,
    pub scope: String,
    pub checked_at: i64,
    pub elapsed_ms: u64,
    pub ready: bool,
    pub execution_authority: bool,
    pub checks: Vec<Check>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Control,
    Broker,
    Collector,
    Governance,
    Gateway,
    SqlTarget,
    Recovery,
    Supervision,
}

#[derive(clap::Args, Default)]
#[group(id = "operations_monitor")]
pub struct Arguments {
    /// Opt-in monitor-only GET endpoint on this service's existing mTLS origin.
    #[arg(long, requires = "operations_workload")]
    pub operations_url: Option<String>,
    /// Exact separately enrolled SPIFFE monitor; grants no application permission.
    #[arg(long, requires = "operations_url")]
    pub operations_workload: Option<String>,
}
impl Arguments {
    pub fn endpoint(
        self,
        urls: &[&str],
        protected: bool,
        application_workloads: &[&str],
    ) -> Result<Option<Endpoint>> {
        match (self.operations_url, self.operations_workload) {
            (None, None) => Ok(None),
            (Some(url), Some(workload))
                if protected && !application_workloads.contains(&workload.as_str()) =>
            {
                Ok(Some(Endpoint::new(&url, &workload, urls)?))
            }
            _ => Err(Error::Invalid(
                "monitor endpoint requires protected custody and a distinct paired URL/workload"
                    .into(),
            )),
        }
    }
}
pub struct Endpoint {
    policy: EndpointPolicy,
    workload: String,
}
impl Endpoint {
    pub(crate) fn standalone(url: &str, workload: &str) -> Result<Self> {
        if !valid_spiffe_id(workload) {
            return Err(Error::Invalid("invalid monitor enrollment".into()));
        }
        Ok(Self {
            policy: EndpointPolicy::new(url)?,
            workload: workload.to_owned(),
        })
    }
    /// Trusted operator configuration; origin must match every application URL,
    /// and this path must not shadow an authority or execution route.
    pub fn new(url: &str, workload: &str, application_urls: &[&str]) -> Result<Self> {
        let policy = EndpointPolicy::new(url)?;
        if !valid_spiffe_id(workload) || application_urls.is_empty() {
            return Err(Error::Invalid("invalid monitor enrollment".into()));
        }
        for application in application_urls {
            let endpoint = EndpointPolicy::new(application)?;
            if endpoint.authority() != policy.authority() || endpoint.path() == policy.path() {
                return Err(Error::Invalid(
                    "monitor origin/path conflicts with application".into(),
                ));
            }
        }
        Ok(Self {
            policy,
            workload: workload.to_owned(),
        })
    }
    pub fn attach(self, app: Router, role: Role, probe: Arc<dyn Probe>) -> Router {
        let path = self.policy.path().to_owned();
        let state = Arc::new(Monitor {
            endpoint: self,
            role,
            probe,
            slots: tokio::sync::Semaphore::new(1),
        });
        app.route(&path, any(handle).with_state(state))
    }
}
struct Monitor {
    endpoint: Endpoint,
    role: Role,
    probe: Arc<dyn Probe>,
    slots: tokio::sync::Semaphore,
}
fn refused(status: StatusCode) -> Response {
    (status, [("cache-control", "no-store")], "request refused").into_response()
}
async fn handle(
    State(state): State<Arc<Monitor>>,
    Extension(workload): Extension<WorkloadIdentity>,
    lifecycle: Option<Extension<crate::server::Lifecycle>>,
    request: Request,
) -> Response {
    if let Some(status) = state
        .endpoint
        .policy
        .rejection_status(request.headers(), request.uri())
    {
        return refused(status);
    }
    if workload.as_str() != state.endpoint.workload {
        return refused(StatusCode::FORBIDDEN);
    }
    if request.method() != Method::GET {
        return refused(StatusCode::METHOD_NOT_ALLOWED);
    }
    if !matches!(
        tokio::time::timeout(Duration::from_millis(100), to_bytes(request.into_body(), 0)).await,
        Ok(Ok(_))
    ) {
        return refused(StatusCode::BAD_REQUEST);
    }
    let Ok(_permit) = state.slots.try_acquire() else {
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    };
    use crate::clock::Clock;
    let checked_at = crate::clock::SystemClock.now_ms();
    let start = tokio::time::Instant::now();
    let mut checks = match tokio::time::timeout(Duration::from_secs(5), state.probe.check()).await {
        Ok(checks) if !checks.is_empty() && checks.len() <= 8 => checks,
        _ => vec![Check {
            dependency: Dependency::Probe,
            condition: Condition::Unavailable,
        }],
    };
    if lifecycle.is_some_and(|lifecycle| !lifecycle.0.serving()) {
        checks = vec![Check {
            dependency: Dependency::Probe,
            condition: Condition::Refused,
        }];
    }
    let ready = checks.iter().all(|c| c.condition == Condition::Ready);
    let report = Report {
        profile: PROFILE.into(),
        role: state.role,
        scope: "local_prerequisites".into(),
        checked_at,
        elapsed_ms: start.elapsed().as_millis() as u64,
        ready,
        execution_authority: false,
        checks,
    };
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [("cache-control", "no-store")],
        Json(report),
    )
        .into_response()
}
