//! Optional monitor listener for the running query-only worker, never a target API.
use crate::{
    error::{Error, Result},
    operations::{Check, Dependency, Endpoint, Probe, Role},
    operations_client::{Remote, RemoteConfig},
    service_files::ServiceFiles,
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub external_url: String,
    pub monitor_workload: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
    #[serde(default, deserialize_with = "crate::operations_client::optional")]
    pub collector: Option<RemoteConfig>,
}
pub struct Listener {
    listen: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    app: axum::Router,
}
struct WorkerProbe {
    worker: Arc<dyn Probe>,
    collector: Option<Remote>,
}
#[async_trait::async_trait]
impl Probe for WorkerProbe {
    async fn check(&self) -> Vec<Check> {
        let collector = async {
            match &self.collector {
                Some(c) => Some(Check::result(
                    Dependency::Collector,
                    c.check(Role::Collector, false, &crate::clock::SystemClock)
                        .await,
                )),
                None => None,
            }
        };
        let (mut checks, collector) = tokio::join!(self.worker.check(), collector);
        checks.extend(collector);
        checks
    }
}
impl Config {
    pub async fn load(
        &self,
        files: &ServiceFiles,
        source_id: &str,
        worker: Arc<dyn Probe>,
        collector_url: Option<&str>,
    ) -> Result<Listener> {
        if !files.is_protected() || self.monitor_workload == source_id {
            return Err(Error::Invalid(
                "worker monitoring requires protected independent monitor enrollment".into(),
            ));
        }
        let (role, collector) = match (&self.collector, collector_url) {
            (Some(c), Some(url)) => (Role::Supervision, Some(c.load(files, url).await?)),
            (None, None) => (Role::Recovery, None),
            _ => {
                return Err(Error::Invalid(
                    "supervision monitoring requires exactly one collector observation".into(),
                ));
            }
        };
        let tls = files
            .server_tls(&self.certificate, &self.private_key, &self.workload_ca)
            .await?;
        let endpoint = Endpoint::standalone(&self.external_url, &self.monitor_workload)?;
        let app = endpoint.attach(
            axum::Router::new(),
            role,
            Arc::new(WorkerProbe { worker, collector }),
        );
        Ok(Listener {
            listen: self.listen,
            tls,
            app,
        })
    }
}
pub struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort()
    }
}
impl Listener {
    pub async fn start(self) -> Result<Running> {
        let listener = tokio::net::TcpListener::bind(self.listen).await?;
        Ok(Running(tokio::spawn(async move {
            if crate::server::serve_router(listener, self.tls, self.app)
                .await
                .is_err()
            {
                // Losing this listener must be observed as unavailable, never
                // a cached healthy state. Query-only recovery may continue.
                eprintln!("worker monitor listener unavailable");
            }
        })))
    }
}
