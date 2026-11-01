//! Fresh, bounded monitor observations. No token exchange, proof use or cache.
use crate::{
    clock::Clock,
    endpoint::EndpointPolicy,
    error::{Error, Result},
    operations::{Condition, Dependency, PROFILE, Report, Role},
    service_files::ServiceFiles,
};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
pub(crate) fn optional<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Ok(Some(T::deserialize(d)?))
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    pub url: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}
impl RemoteConfig {
    pub async fn load(&self, files: &ServiceFiles, application_url: &str) -> Result<Remote> {
        let monitor = EndpointPolicy::new(&self.url)?;
        let application = EndpointPolicy::new(application_url)?;
        if !files.is_protected()
            || monitor.authority() != application.authority()
            || monitor.path() == application.path()
        {
            return Err(Error::Invalid(
                "upstream monitoring requires protected same-origin distinct endpoint".into(),
            ));
        }
        Ok(Remote {
            client: files
                .http_client(
                    &self.ca,
                    &self.certificate,
                    &self.private_key,
                    Duration::from_secs(5),
                )
                .await?,
            url: self.url.clone(),
        })
    }
}
pub struct Remote {
    client: reqwest::Client,
    url: String,
}
impl Remote {
    pub async fn check(&self, role: Role, query_only: bool, clock: &dyn Clock) -> Result<()> {
        let response = self
            .client
            .get(&self.url)
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .send()
            .await?;
        let status = response.status();
        if response.url().as_str() != self.url
            || response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                != Some("no-store")
            || ![
                reqwest::StatusCode::OK,
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
            ]
            .contains(&status)
        {
            return Err(Error::Unavailable("upstream monitor unavailable".into()));
        }
        let raw = crate::grant_reference::bounded_response(response, 16384).await?;
        let report: Report = serde_json::from_value(crate::contracts::strict_value(&raw)?)?;
        let now = clock.now_ms();
        let mut seen = std::collections::BTreeSet::new();
        if report.profile != PROFILE
            || report.role != role
            || report.scope != "local_prerequisites"
            || report.execution_authority
            || report.checked_at < 0
            || report.checked_at > now.saturating_add(1000)
            || now.saturating_sub(report.checked_at) > 10000
            || report.elapsed_ms > 5000
            || report.checks.is_empty()
            || report.checks.len() > 8
            || report
                .checks
                .iter()
                .any(|c| !seen.insert(format!("{:?}", c.dependency)))
            || report.ready
                != report
                    .checks
                    .iter()
                    .all(|c| c.condition == Condition::Ready)
            || report.ready != (status == reqwest::StatusCode::OK)
        {
            return Err(Error::Refused(
                "invalid or stale upstream readiness observation".into(),
            ));
        }
        // A timeout may replace the full check set, but can never prove ready.
        let expected: &[Dependency] = match role {
            Role::Broker => &[
                Dependency::AuthorityReads,
                Dependency::ManagedControl,
                Dependency::IdentityMaterial,
            ],
            Role::SqlTarget => &[Dependency::DatabaseExecution, Dependency::DatabaseQuery],
            Role::Collector => &[Dependency::AuthorityReads],
            _ => {
                return Err(Error::Invalid(
                    "unsupported upstream monitoring role".into(),
                ));
            }
        };
        if expected.len() != report.checks.len()
            || expected
                .iter()
                .any(|d| !report.checks.iter().any(|c| c.dependency == *d))
        {
            return Err(Error::Refused(
                "incomplete upstream readiness checks".into(),
            ));
        }
        let ready = if query_only {
            role == Role::SqlTarget
                && report.checks.iter().any(|c| {
                    c.dependency == Dependency::DatabaseQuery && c.condition == Condition::Ready
                })
        } else {
            report.ready
        };
        if !ready {
            return Err(Error::Refused("upstream prerequisites refused".into()));
        }
        Ok(())
    }
}
