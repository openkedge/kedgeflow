//! Monitor-only worker listener: protected preflight is non-listening.
#![cfg(unix)]
mod support;
use kedgeflow::{
    operations::{Check, Dependency, Probe, Report, Role},
    operations_worker::Config,
    service_files::ServiceFiles,
};
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
struct Worker;
#[async_trait::async_trait]
impl Probe for Worker {
    async fn check(&self) -> Vec<Check> {
        vec![
            Check::result(Dependency::AuthorityReads, Ok(())),
            Check::result(Dependency::TargetQuery, Ok(())),
        ]
    }
}
#[tokio::test]
async fn protected_worker_listener_is_optional_scoped_and_removed_on_worker_exit() {
    let pki = support::pki_for_workloads(&["spiffe://test/monitor", "spiffe://test/agent"]);
    let temp = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    for (name, data) in [
        ("cert", &pki[0].server),
        ("key", &pki[0].server_key),
        ("ca", &pki[0].ca),
    ] {
        let path = temp.path().join(name);
        fs::write(&path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    let url = format!("https://{address}/ops");
    let config = Config {
        listen: address,
        external_url: url.clone(),
        monitor_workload: "spiffe://test/monitor".into(),
        certificate: temp.path().join("cert"),
        private_key: temp.path().join("key"),
        workload_ca: temp.path().join("ca"),
        collector: None,
    };
    let files = ServiceFiles::protected(temp.path()).unwrap();
    let worker: Arc<dyn Probe> = Arc::new(Worker);
    assert!(
        config
            .load(
                &ServiceFiles::default(),
                "spiffe://test/recovery",
                worker.clone(),
                None
            )
            .await
            .is_err()
    );
    assert!(
        config
            .load(&files, "spiffe://test/monitor", worker.clone(), None)
            .await
            .is_err()
    );
    assert!(
        config
            .load(
                &files,
                "spiffe://test/recovery",
                worker.clone(),
                Some("https://collector.test/outcomes")
            )
            .await
            .is_err()
    );
    let loaded = config
        .load(&files, "spiffe://test/recovery", worker, None)
        .await
        .unwrap();
    drop(reserved);
    let reservation = std::net::TcpListener::bind(address).unwrap();
    drop(reservation); // preflight did not bind
    let running = loaded.start().await.unwrap();
    let client = |p: &support::Pki| {
        kedgeflow::tls::pinned_http_client_pem(
            p.ca.as_bytes(),
            p.client.as_bytes(),
            p.client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap()
    };
    let monitor = client(&pki[0]);
    let agent = client(&pki[1]);
    let response = monitor.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let report: Report = response.json().await.unwrap();
    assert!(report.ready && !report.execution_authority);
    assert_eq!(report.role, Role::Recovery);
    assert_eq!(agent.get(&url).send().await.unwrap().status(), 403);
    drop(running);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if monitor.get(&url).send().await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn supervision_listener_requires_a_fresh_collector_observation() {
    use kedgeflow::{
        clock::{Clock, SystemClock},
        operations::{Condition, PROFILE},
        operations_client::RemoteConfig,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    let pki = support::pki_with_workload("spiffe://test/monitor");
    let healthy = Arc::new(AtomicBool::new(true));
    let state = healthy.clone();
    let collector = support::serve_tls(
        &pki,
        axum::Router::new().route(
            "/ops",
            axum::routing::get(move || {
                let healthy = state.clone();
                async move {
                    let ready = healthy.load(Ordering::SeqCst);
                    let report = Report {
                        profile: PROFILE.into(),
                        role: Role::Collector,
                        scope: "local_prerequisites".into(),
                        checked_at: SystemClock.now_ms(),
                        elapsed_ms: 0,
                        ready,
                        execution_authority: false,
                        checks: vec![Check {
                            dependency: Dependency::AuthorityReads,
                            condition: if ready {
                                Condition::Ready
                            } else {
                                Condition::Unavailable
                            },
                        }],
                    };
                    (
                        if ready {
                            axum::http::StatusCode::OK
                        } else {
                            axum::http::StatusCode::SERVICE_UNAVAILABLE
                        },
                        [("cache-control", "no-store")],
                        axum::Json(report),
                    )
                }
            }),
        ),
    )
    .await;
    let temp = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    for (name, data) in [
        ("cert", &pki.server),
        ("key", &pki.server_key),
        ("ca", &pki.ca),
        ("client-cert", &pki.client),
        ("client-key", &pki.client_key),
    ] {
        let path = temp.path().join(name);
        fs::write(&path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    let url = format!("https://{address}/ops");
    let config = Config {
        listen: address,
        external_url: url.clone(),
        monitor_workload: "spiffe://test/monitor".into(),
        certificate: temp.path().join("cert"),
        private_key: temp.path().join("key"),
        workload_ca: temp.path().join("ca"),
        collector: Some(RemoteConfig {
            url: format!("{}/ops", collector.url),
            ca: temp.path().join("ca"),
            certificate: temp.path().join("client-cert"),
            private_key: temp.path().join("client-key"),
        }),
    };
    let files = ServiceFiles::protected(temp.path()).unwrap();
    assert!(
        config
            .load(&files, "spiffe://test/recovery", Arc::new(Worker), None)
            .await
            .is_err()
    );
    let loaded = config
        .load(
            &files,
            "spiffe://test/recovery",
            Arc::new(Worker),
            Some(&format!("{}/outcomes", collector.url)),
        )
        .await
        .unwrap();
    drop(reserved);
    let _running = loaded.start().await.unwrap();
    let client = kedgeflow::tls::pinned_http_client_pem(
        pki.ca.as_bytes(),
        pki.client.as_bytes(),
        pki.client_key.as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let report: Report = response.json().await.unwrap();
    assert_eq!(report.role, Role::Supervision);
    healthy.store(false, Ordering::SeqCst);
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 503);
    let report: Report = response.json().await.unwrap();
    assert!(!report.ready);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.dependency == Dependency::Collector && c.condition != Condition::Ready)
    );
    healthy.store(true, Ordering::SeqCst);
    assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
}

#[test]
fn worker_and_upstream_configuration_refuse_null_and_unknown_fields() {
    use serde_json::{Value, json};
    let recovery: Value =
        serde_json::from_str(include_str!("../../../config/recovery.example.json")).unwrap();
    for bad in [Value::Null, json!("ops"), json!({"unknown":true})] {
        let mut config = recovery.clone();
        config["operations"] = bad;
        assert!(
            kedgeflow::recovery_config::RecoveryConfig::decode(
                &serde_json::to_vec(&config).unwrap()
            )
            .is_err()
        );
    }
    let gateway: Value =
        serde_json::from_str(include_str!("../../../config/gateway.example.json")).unwrap();
    for bad in [Value::Null, json!("ops"), json!({"unknown":true})] {
        let mut config = gateway.clone();
        config["operations_dependencies"] = bad;
        assert!(kedgeflow::config::Config::decode(&serde_json::to_vec(&config).unwrap()).is_err());
    }
}
