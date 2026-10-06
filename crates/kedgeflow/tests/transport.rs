#[path = "support/domain.rs"]
mod domain;
mod support;
use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use kedgeflow::{
    adapter::{HttpAdapter, ResourceAdapter},
    broker::{CredentialBroker, Rfc8693Broker, TargetCredential, WorkloadAssertion},
    clock::Clock,
    error::Result,
    grant_reference::{GrantResolver, HttpsGrantResolver},
    tls::pinned_client_pem,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
struct FixedClock;
impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        domain::NOW
    }
}
struct Assertion(Duration);
#[async_trait]
impl WorkloadAssertion for Assertion {
    async fn assertion(&self, w: &str) -> Result<String> {
        assert_eq!(w, "spiffe://test/agent");
        tokio::time::sleep(self.0).await;
        Ok("actor-assertion".into())
    }
}
fn client(p: &support::Pki) -> kedgeflow::tls::PinnedClient {
    pinned_client_pem(
        p.ca.as_bytes(),
        p.client.as_bytes(),
        p.client_key.as_bytes(),
        Duration::from_secs(3),
    )
    .unwrap()
}

#[tokio::test]
async fn broker_maps_subject_actor_grant_and_never_clamps_broader_tokens() {
    let p = support::pki();
    let captured = Arc::new(Mutex::new(None));
    let mode = Arc::new(AtomicUsize::new(0));
    let saved = captured.clone();
    let selected = mode.clone();
    let server=support::serve_tls(&p,Router::new().fallback(move|headers:HeaderMap,body:Bytes|{let saved=saved.clone();let selected=selected.clone();async move {
        assert!(!headers.contains_key("authorization"));assert!(!headers.contains_key("dpop"));assert!(!headers.contains_key("cookie"));
        *saved.lock().unwrap()=Some(String::from_utf8(body.to_vec()).unwrap());
        axum::Json(json!({"access_token":"target-only","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
            "expires_in":if selected.load(Ordering::SeqCst)==0{2}else{61},"scope":"target:mutate"}))
    }})).await;
    let broker = Rfc8693Broker::new(
        &server.url,
        "https://target.test".into(),
        "target:mutate".into(),
        client(&p),
        Arc::new(Assertion(Duration::ZERO)),
        Arc::new(FixedClock),
        Duration::from_secs(1),
    )
    .unwrap();
    let (call, _) = domain::call();
    let token = broker
        .exchange(&call, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(token.token, "target-only");
    assert_eq!(token.expires_at_ms, domain::NOW + 2000);
    let fields: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(captured.lock().unwrap().as_ref().unwrap().as_bytes())
            .into_owned()
            .collect();
    assert_eq!(fields["subject_token"], call.identity.access_token);
    assert_eq!(fields["actor_token"], "actor-assertion");
    assert_eq!(fields["kedgeflow_grant_digest"], call.grant_digest);
    assert_eq!(fields["kedgeflow_attempt_id"], call.attempt_id);
    assert_eq!(fields["scope"], "target:mutate");
    mode.store(1, Ordering::SeqCst);
    assert!(
        broker
            .exchange(&call, Instant::now() + Duration::from_secs(2))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn assertion_delay_exhausts_whole_exchange_budget_before_network() {
    let p = support::pki();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let server = support::serve_tls(
        &p,
        Router::new().fallback(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    )
    .await;
    let broker = Rfc8693Broker::new(
        &server.url,
        "target".into(),
        "mutate".into(),
        client(&p),
        Arc::new(Assertion(Duration::from_secs(1))),
        Arc::new(FixedClock),
        Duration::from_millis(20),
    )
    .unwrap();
    let (call, _) = domain::call();
    assert!(
        broker
            .exchange(&call, Instant::now() + Duration::from_secs(2))
            .await
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn resolver_has_requester_scope_no_caller_credentials_and_bounded_complete_envelope() {
    let p = support::pki();
    let (call, _) = domain::call();
    let raw = call.signed_grant.clone();
    let seen = Arc::new(Mutex::new(None));
    let saved = seen.clone();
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = mode.clone();
    let server = support::serve_tls(
        &p,
        Router::new().fallback(move |headers: HeaderMap, body: Bytes| {
            let raw = raw.clone();
            let saved = saved.clone();
            let selected = selected.clone();
            async move {
                for name in ["authorization", "dpop", "cookie", "mcp-kedgeflow-grant"] {
                    assert!(!headers.contains_key(name));
                }
                assert_eq!(headers["accept-encoding"], "identity");
                *saved.lock().unwrap() = Some(serde_json::from_slice::<Value>(&body).unwrap());
                match selected.load(Ordering::SeqCst) {
                    0 => (StatusCode::OK, raw).into_response(),
                    1 => (StatusCode::OK, vec![b' '; 65537]).into_response(),
                    2 => (StatusCode::OK, [("content-encoding", "gzip")], raw).into_response(),
                    _ => StatusCode::TEMPORARY_REDIRECT.into_response(),
                }
            }
        }),
    )
    .await;
    let resolver = HttpsGrantResolver::new(&server.url, client(&p)).unwrap();
    assert_eq!(
        resolver
            .resolve(&call.identity, &call.grant_digest)
            .await
            .unwrap(),
        call.signed_grant
    );
    let scope = seen.lock().unwrap().clone().unwrap();
    assert_eq!(scope["grant_digest"], call.grant_digest);
    assert_eq!(scope["subject"], json!(call.identity.subject));
    assert_eq!(scope["workload_id"], call.identity.workload_id);
    assert_eq!(scope.as_object().unwrap().len(), 5);
    for m in 1..=3 {
        mode.store(m, Ordering::SeqCst);
        assert!(
            resolver
                .resolve(&call.identity, &call.grant_digest)
                .await
                .is_err()
        );
    }
    assert!(
        resolver
            .resolve(&call.identity, "https://caller-selected.test/grant")
            .await
            .is_err()
    );
}
#[tokio::test]
async fn adapter_strips_metadata_and_requires_exact_terminal_receipt() {
    let p = support::pki();
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = mode.clone();
    let captured = Arc::new(Mutex::new(None));
    let saved = captured.clone();
    let (call, _) = domain::call();
    let resource = call.grant.resources[0].clone();
    let server=support::serve_tls(&p,Router::new().fallback(move|headers:HeaderMap,body:Bytes|{let selected=selected.clone();let saved=saved.clone();let resource=resource.clone();async move {
        assert_eq!(headers["authorization"],"Bearer target-only");for name in ["dpop","cookie","mcp-kedgeflow-grant","mcp-kedgeflow-grant-ref"]{assert!(!headers.contains_key(name));}
        let request:Value=serde_json::from_slice(&body).unwrap();*saved.lock().unwrap()=Some(request.clone());let args=&request["params"]["arguments"];
        let mut result=json!({"resultType":"complete","isError":false,"structuredContent":{"kedgeflow_terminal_receipt":{
            "attempt_id":args["kf_attempt_id"],"grant_digest":args["kf_grant_digest"],"resource":resource,"fence":args["fence"],"status":"committed","post_version":2}}});
        let mode=selected.load(Ordering::SeqCst);match mode{1=>{result["structuredContent"]=json!({});},2=>result["isError"]=json!(true),
            3=>result["resultType"]=json!("accepted"),4=>result["structuredContent"]["kedgeflow_terminal_receipt"]["attempt_id"]=json!("another"),_=>{}}
        if mode==5 {axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32010,"message":"STATE_GUARD_VIOLATION"}}))}
        else{axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))}
    }})).await;
    let adapter = HttpAdapter::new(
        &server.url,
        client(&p),
        "target".into(),
        "read-only".into(),
        Arc::new(FixedClock),
    )
    .unwrap();
    let credential = TargetCredential {
        token: "target-only".into(),
        expires_at_ms: domain::NOW + 2000,
        audience: "target".into(),
    };
    assert_eq!(
        adapter.dispatch(&call, &credential).await.unwrap().status,
        "committed"
    );
    let request = captured.lock().unwrap().clone().unwrap();
    assert_eq!(
        request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );
    assert_eq!(
        request["params"]["arguments"]["kf_resource_incarnation"],
        call.grant.resources[0].incarnation
    );
    for m in 1..=4 {
        mode.store(m, Ordering::SeqCst);
        assert!(adapter.dispatch(&call, &credential).await.is_err());
    }
    mode.store(5, Ordering::SeqCst);
    assert_eq!(
        adapter.dispatch(&call, &credential).await.unwrap().status,
        "state_guard_violation"
    );
}
#[tokio::test]
async fn oversized_valid_token_prefix_is_not_silently_accepted() {
    let p = support::pki();
    let mut bytes=serde_json::to_vec(&json!({"access_token":"target-only","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","expires_in":2,"scope":"mutate"})).unwrap();
    bytes.resize(65536, b' ');
    bytes.extend_from_slice(b"malicious trailing data");
    let server = support::serve_tls(
        &p,
        Router::new().fallback(move || {
            let bytes = bytes.clone();
            async move { (StatusCode::OK, bytes) }
        }),
    )
    .await;
    let broker = Rfc8693Broker::new(
        &server.url,
        "target".into(),
        "mutate".into(),
        client(&p),
        Arc::new(Assertion(Duration::ZERO)),
        Arc::new(FixedClock),
        Duration::from_secs(1),
    )
    .unwrap();
    let (call, _) = domain::call();
    assert!(
        broker
            .exchange(&call, Instant::now() + Duration::from_secs(2))
            .await
            .is_err()
    );
}
