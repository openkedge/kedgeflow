//! Real mTLS upstream reports: freshness, role, completeness and query separation.
#![cfg(unix)]
mod support;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use kedgeflow::{
    clock::{Clock, SystemClock},
    operations::{Check, Condition, Dependency, PROFILE, Report, Role},
    operations_client::RemoteConfig,
    service_files::ServiceFiles,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
async fn reply(State(mode): State<Arc<AtomicUsize>>) -> Response {
    let mode = mode.load(Ordering::SeqCst);
    let mut report = Report {
        profile: PROFILE.into(),
        role: Role::SqlTarget,
        scope: "local_prerequisites".into(),
        checked_at: SystemClock.now_ms(),
        elapsed_ms: 0,
        ready: true,
        execution_authority: false,
        checks: vec![
            Check::result(Dependency::DatabaseExecution, Ok(())),
            Check::result(Dependency::DatabaseQuery, Ok(())),
        ],
    };
    match mode {
        1 => {
            report.ready = false;
            report.checks[0].condition = Condition::Refused
        }
        2 => report.role = Role::Broker,
        3 => report.profile = "unknown".into(),
        4 => report.checked_at -= 10001,
        5 => report.checked_at += 5000,
        6 => report.execution_authority = true,
        7 => report.checks[0].condition = Condition::Refused,
        8 => report.checks[0].dependency = Dependency::DatabaseQuery,
        9 => report.checks.pop().map(|_| ()).unwrap(),
        12 => {
            return (
                StatusCode::FOUND,
                [("location", "https://outside.invalid/ops")],
            )
                .into_response();
        }
        13 => report.scope = "x".repeat(20000),
        _ => (),
    }
    let status = if report.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    if mode == 10 {
        let mut body = serde_json::to_value(report).unwrap();
        body["unexpected"] = true.into();
        return (status, [("cache-control", "no-store")], Json(body)).into_response();
    }
    if mode == 11 {
        return (status, Json(report)).into_response();
    }
    (status, [("cache-control", "no-store")], Json(report)).into_response()
}
#[tokio::test]
async fn upstream_requires_fresh_complete_role_bound_reports_and_no_cached_fallback() {
    let pki = support::pki_with_workload("spiffe://test/monitor");
    let mode = Arc::new(AtomicUsize::new(0));
    let server = support::serve_tls(
        &pki,
        Router::new()
            .route("/ops", get(reply))
            .with_state(mode.clone()),
    )
    .await;
    let temp = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    for (name, data) in [
        ("ca", &pki.ca),
        ("cert", &pki.client),
        ("key", &pki.client_key),
    ] {
        let path = temp.path().join(name);
        fs::write(&path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = RemoteConfig {
        url: format!("{}/ops", server.url),
        ca: temp.path().join("ca"),
        certificate: temp.path().join("cert"),
        private_key: temp.path().join("key"),
    };
    let files = ServiceFiles::protected(temp.path()).unwrap();
    let remote = config
        .load(&files, &format!("{}/execute", server.url))
        .await
        .unwrap();
    remote
        .check(Role::SqlTarget, false, &SystemClock)
        .await
        .unwrap();
    assert!(
        remote
            .check(Role::Broker, false, &SystemClock)
            .await
            .is_err()
    );
    mode.store(1, Ordering::SeqCst);
    assert!(
        remote
            .check(Role::SqlTarget, false, &SystemClock)
            .await
            .is_err()
    );
    remote
        .check(Role::SqlTarget, true, &SystemClock)
        .await
        .unwrap();
    for invalid in 2..=13 {
        mode.store(invalid, Ordering::SeqCst);
        assert!(
            remote
                .check(Role::SqlTarget, true, &SystemClock)
                .await
                .is_err(),
            "accepted invalid mode {invalid}"
        );
    }
    mode.store(0, Ordering::SeqCst);
    remote
        .check(Role::SqlTarget, false, &SystemClock)
        .await
        .unwrap();
    assert!(
        config
            .load(&ServiceFiles::default(), &format!("{}/execute", server.url))
            .await
            .is_err()
    );
    assert!(
        config
            .load(&files, "https://alias.test/execute")
            .await
            .is_err()
    );
    assert!(config.load(&files, &config.url).await.is_err());
    fs::set_permissions(&config.private_key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        config
            .load(&files, &format!("{}/execute", server.url))
            .await
            .is_err()
    );
}
