//! Real mTLS monitor boundary; no public or agent health bypass.
mod support;
use axum::{Router, routing::post};
use kedgeflow::operations::{Check, Condition, Dependency, Endpoint, Probe, Report, Role};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
struct State {
    calls: AtomicUsize,
    mode: AtomicUsize,
}
#[async_trait::async_trait]
impl Probe for State {
    async fn check(&self) -> Vec<Check> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode.load(Ordering::SeqCst) {
            0 => vec![Check::result(Dependency::AuthorityReads, Ok(()))],
            1 => vec![Check::unverified(Dependency::ManagedControl)],
            2 => vec![Check::result(
                Dependency::AuthorityReads,
                Err(kedgeflow::error::Error::Unavailable(
                    "credential-secret-must-not-appear".into(),
                )),
            )],
            _ => {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                vec![]
            }
        }
    }
}
fn client(p: &support::Pki) -> reqwest::Client {
    kedgeflow::tls::pinned_http_client_pem(
        p.ca.as_bytes(),
        p.client.as_bytes(),
        p.client_key.as_bytes(),
        std::time::Duration::from_secs(10),
    )
    .unwrap()
}
#[tokio::test]
async fn actual_mtls_monitor_is_scoped_bounded_and_does_not_shadow_application() {
    let pki = support::pki_for_workloads(&["spiffe://test/monitor", "spiffe://test/agent"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let url = format!("{origin}/ops/ready");
    let app_url = format!("{origin}/execute");
    let state = Arc::new(State {
        calls: AtomicUsize::new(0),
        mode: AtomicUsize::new(0),
    });
    let app = Router::new().route("/execute", post(|| async { "application" }));
    let router = Endpoint::new(&url, "spiffe://test/monitor", &[&app_url])
        .unwrap()
        .attach(app, Role::Collector, state.clone());
    let tls = kedgeflow::tls::server_config_pem(
        pki[0].server.as_bytes(),
        pki[0].server_key.as_bytes(),
        pki[0].ca.as_bytes(),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, tls, router)
            .await
            .unwrap()
    });
    struct Running(tokio::task::JoinHandle<()>);
    impl Drop for Running {
        fn drop(&mut self) {
            self.0.abort()
        }
    }
    let _running = Running(task);
    let monitor = client(&pki[0]);
    let agent = client(&pki[1]);
    let response = monitor.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let report: Report = response.json().await.unwrap();
    assert!(report.ready);
    assert!(!report.execution_authority);
    assert_eq!(report.role, Role::Collector);
    assert_eq!(report.checks[0].condition, Condition::Ready);
    assert!(report.checked_at > 0 && report.elapsed_ms < 5000);
    let calls = state.calls.load(Ordering::SeqCst);
    for request in [
        agent.get(&url),
        monitor.post(&url),
        monitor.get(format!("{url}?x=1")),
        monitor.get(&url).header("origin", "https://browser.test"),
        monitor.get(&url).header("host", "alias.test"),
        monitor.get(&url).body("x"),
    ] {
        assert!(!request.send().await.unwrap().status().is_success());
    }
    let no_certificate = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(pki[0].ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert!(no_certificate.get(&url).send().await.is_err());
    assert_eq!(
        state.calls.load(Ordering::SeqCst),
        calls,
        "unauthorized request invoked probe"
    );
    assert_eq!(
        agent
            .post(&app_url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "application"
    );
    for mode in [1, 2] {
        state.mode.store(mode, Ordering::SeqCst);
        let response = monitor.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 503);
        let body = response.text().await.unwrap();
        assert!(!body.contains("credential-secret"));
        assert!(!serde_json::from_str::<Report>(&body).unwrap().ready);
    }
    state.mode.store(3, Ordering::SeqCst);
    // Start one request, then prove the single-probe slot refuses another.
    let pending_client = monitor.clone();
    let pending_url = url.clone();
    let first = tokio::spawn(async move { pending_client.get(pending_url).send().await.unwrap() });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state.calls.load(Ordering::SeqCst) == calls + 2 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("slow probe did not start");
    assert_eq!(monitor.get(&url).send().await.unwrap().status(), 503);
    let response = first.await.unwrap();
    assert_eq!(response.status(), 503);
    let report: Report = response.json().await.unwrap();
    assert_eq!(report.checks[0].dependency, Dependency::Probe);
    assert!(report.elapsed_ms >= 4900 && report.elapsed_ms < 6500);
}
#[test]
fn monitor_configuration_is_explicit_and_cannot_shadow_or_alias_authority() {
    for (url, workload, applications) in [
        (
            "https://service.test/execute",
            "spiffe://test/monitor",
            vec!["https://service.test/execute"],
        ),
        (
            "https://alias.test/ops",
            "spiffe://test/monitor",
            vec!["https://service.test/execute"],
        ),
        (
            "https://service.test/ops?x=1",
            "spiffe://test/monitor",
            vec!["https://service.test/execute"],
        ),
        (
            "https://service.test/ops",
            "invalid",
            vec!["https://service.test/execute"],
        ),
        ("https://service.test/ops", "spiffe://test/monitor", vec![]),
    ] {
        assert!(Endpoint::new(url, workload, &applications).is_err());
    }
    let args = kedgeflow::operations::Arguments {
        operations_url: Some("https://service.test/ops".into()),
        operations_workload: Some("spiffe://test/monitor".into()),
    };
    assert!(
        args.endpoint(&["https://service.test/execute"], false, &[])
            .is_err()
    );
    let args = kedgeflow::operations::Arguments {
        operations_url: Some("https://service.test/ops".into()),
        operations_workload: Some("spiffe://test/agent".into()),
    };
    assert!(
        args.endpoint(
            &["https://service.test/execute"],
            true,
            &["spiffe://test/agent"]
        )
        .is_err()
    );
}

#[test]
fn plain_leaf_scope_decoder_is_closed_and_refuses_present_null() {
    use kedgeflow::control_config::ControlConfig;
    use serde_json::{Value, json};
    let template: Value =
        serde_json::from_str(include_str!("../../../config/governance.example.json")).unwrap();
    let mut config = template["control"].clone();
    ControlConfig::decode(&serde_json::to_vec(&config).unwrap()).unwrap();
    config["operations_scope"] = template["scope"].clone();
    ControlConfig::decode(&serde_json::to_vec(&config).unwrap()).unwrap();
    for value in [Value::Null, json!("scope"), json!({}), {
        let mut extra = template["scope"].clone();
        extra["unexpected"] = json!(true);
        extra
    }] {
        config["operations_scope"] = value;
        assert!(ControlConfig::decode(&serde_json::to_vec(&config).unwrap()).is_err());
    }
}
