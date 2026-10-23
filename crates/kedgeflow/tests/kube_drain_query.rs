//! Controller-query wire boundaries only; this is not physical outcome evidence.
mod support;
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use kedgeflow::{kube_drain_query::ControllerQuery, ledger::OutcomeQuerier};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[tokio::test]
async fn physical_query_uses_exact_original_wire_and_refuses_false_acceptance() {
    let state = Arc::new(Mutex::new((
        StatusCode::OK,
        json!(kedgeflow::ledger::AuthoritativeObservation {
            attempt_id: "original".into(),
            root_id: "original-root".into(),
            grant_digest: "a".repeat(64),
            target_reference: format!("kube-controller-accepted:{}", "b".repeat(64)),
            status: "committed".into()
        }),
    )));
    let selected = state.clone();
    let pki = support::pki();
    let server = support::serve_tls(
        &pki,
        Router::new().route(
            "/query",
            post(move |headers: HeaderMap, Json(request): Json<Value>| {
                let selected = selected.clone();
                async move {
                    assert_eq!(
                        headers["authorization"],
                        "Bearer generated-query-token-0000000000000000"
                    );
                    assert_eq!(request, json!({"attempt_id":"original"}));
                    let (status, value) = selected.lock().unwrap().clone();
                    (status, Json(value))
                }
            }),
        ),
    )
    .await;
    let client = kedgeflow::tls::pinned_http_client_pem(
        pki.ca.as_bytes(),
        pki.client.as_bytes(),
        pki.client_key.as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let query = ControllerQuery::new(
        client,
        &format!("{}/query", server.url),
        "generated-query-token-0000000000000000".into(),
    )
    .unwrap();
    let original = state.lock().unwrap().1.clone();
    assert_eq!(query.query("original").await.unwrap().status, "committed");
    for (field, bad) in [
        ("AttemptID", json!("replacement")),
        ("Status", json!("not_found")),
        ("Status", json!("fenced_no_effect")),
        ("TargetReference", json!("physical-completed")),
        (
            "TargetReference",
            json!("kube-controller-accepted:not-a-digest"),
        ),
        ("extra", json!(true)),
    ] {
        let mut value = original.clone();
        value[field] = bad;
        *state.lock().unwrap() = (StatusCode::OK, value);
        assert!(
            query.query("original").await.is_err(),
            "accepted altered {field}"
        );
    }
    for status in [
        StatusCode::NOT_FOUND,
        StatusCode::FORBIDDEN,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        *state.lock().unwrap() = (status, original.clone());
        assert!(query.query("original").await.is_err());
    }
    assert!(query.query("").await.is_err());
    assert!(query.query(&"a".repeat(257)).await.is_err());
}
