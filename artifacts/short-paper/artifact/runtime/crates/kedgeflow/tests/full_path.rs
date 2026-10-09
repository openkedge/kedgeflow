//! Real etcd plus actual mTLS broker and fenced mock target. Subject identity
//! and workload assertion issuance are explicit synthetic test boundaries.
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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kedgeflow::{
    adapter::HttpAdapter,
    auth::{Authenticator, Identity, WorkloadIdentity},
    broker::{Rfc8693Broker, WorkloadAssertion},
    clock::Clock,
    contracts::sign_grant,
    error::Result,
    gateway::Gateway,
    ledger::{AuthorityLedger, EtcdLedger},
    tls::pinned_client_pem,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
struct FixedClock;
impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        domain::NOW
    }
}
struct Auth(Identity);
#[async_trait]
impl Authenticator for Auth {
    async fn authenticate(&self, _: &HeaderMap, w: &WorkloadIdentity) -> Result<Identity> {
        assert_eq!(w.as_str(), self.0.workload_id);
        Ok(self.0.clone())
    }
}
struct Assertion;
#[async_trait]
impl WorkloadAssertion for Assertion {
    async fn assertion(&self, _: &str) -> Result<String> {
        Ok("synthetic-actor".into())
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
async fn actual_fenced_target_rejects_stale_state_and_lost_response_keeps_consumption() {
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(e) => e,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
            eprintln!("SKIP full path: real ETCD_ENDPOINT absent");
            return;
        }
    };
    let ledger = Arc::new(
        EtcdLedger::new(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint,
            format!("/kf-full-path/{}", rand::random::<u64>()),
        )
        .unwrap(),
    );
    let (call, verifier) = domain::call();
    ledger.publish_policy(&call.grant).await.unwrap();
    let p = support::pki();
    let resource = call.grant.resources[0].clone();
    let state = Arc::new(Mutex::new((1_u64, 0_u64, 0_u64)));
    let saved = state.clone();
    let drop_reply = Arc::new(AtomicBool::new(false));
    let lose = drop_reply.clone();
    let target=support::serve_tls(&p,Router::new().fallback(move|headers:HeaderMap,raw:Bytes|{let saved=saved.clone();let resource=resource.clone();let lose=lose.clone();async move{
        assert_eq!(headers["authorization"],"Bearer target-only");assert!(!headers.contains_key("mcp-kedgeflow-grant"));assert!(!headers.contains_key("dpop"));
        let request:Value=serde_json::from_slice(&raw).unwrap();let args=&request["params"]["arguments"];let mut state=saved.lock().unwrap();
        assert_eq!(args["node"],resource.id);assert_eq!(args["kf_resource_incarnation"],resource.incarnation);
        let fence=args["fence"].as_u64().unwrap();let expected=args["expected_version"].as_u64().unwrap();
        if expected!=state.0 || fence<=state.1 {return axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32010,"message":"STATE_GUARD_VIOLATION"}})).into_response();}
        // The same mutex owns predicate check, fencing and mutation. This
        // resource-specific primitive is absent from an ordinary MCP success.
        state.0+=1;state.1=fence;state.2+=1;
        let result=json!({"jsonrpc":"2.0","id":request["id"],"result":{"resultType":"complete","isError":false,"content":[],"structuredContent":{
            "drained":true,"kedgeflow_terminal_receipt":{"attempt_id":args["kf_attempt_id"],"grant_digest":args["kf_grant_digest"],"resource":resource,"fence":fence,"status":"committed","post_version":state.0}}}});
        if lose.load(Ordering::SeqCst){StatusCode::SERVICE_UNAVAILABLE.into_response()}else{axum::Json(result).into_response()}
    }})).await;
    let trust = verifier.clone();
    let authority = ledger.clone();
    let broker_server=support::serve_tls(&p,Router::new().fallback(move|body:Bytes|{let trust=trust.clone();let authority=authority.clone();async move{
        let fields:BTreeMap<String,String>=url::form_urlencoded::parse(&body).into_owned().collect();
        let raw=URL_SAFE_NO_PAD.decode(&fields["kedgeflow_grant"]).unwrap();let grant=trust.verify(&raw,domain::NOW).unwrap();
        assert_eq!(grant.digest,fields["kedgeflow_grant_digest"]);assert_eq!(fields["subject_token"],"caller-token-never-forward");
        assert_eq!(authority.status(&grant.grant,&fields["kedgeflow_attempt_id"]).await.unwrap().status,"claimed");
        axum::Json(json!({"access_token":"target-only","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","scope":"mutate","expires_in":2}))
    }})).await;
    let clock = Arc::new(FixedClock);
    let broker = Rfc8693Broker::new(
        &broker_server.url,
        "target".into(),
        "mutate".into(),
        client(&p),
        Arc::new(Assertion),
        clock.clone(),
        Duration::from_secs(2),
    )
    .unwrap();
    let adapter = HttpAdapter::new(
        &target.url,
        client(&p),
        "target".into(),
        String::new(),
        clock.clone(),
    )
    .unwrap();
    let gateway = Gateway {
        verifier: verifier.clone(),
        ledger: ledger.clone(),
        auth: Arc::new(Auth(call.identity.clone())),
        broker: Arc::new(broker),
        adapter: Arc::new(adapter),
        resolver: None,
        tools: BTreeMap::from([(call.descriptor.name.clone(), call.descriptor.clone())]),
        timeout: Duration::from_secs(5),
        clock,
    };
    gateway.validate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        "spiffe://test/agent".try_into().unwrap(),
    )];
    let cert = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    let workload = WorkloadIdentity::from_verified_cert_der(cert.der()).unwrap();
    for index in 0..3 {
        let mut grant = call.grant.clone();
        grant.root_id = format!("full-root-{index}");
        grant.gid = format!("full-grant-{index}");
        grant.nonce = format!("full-nonce-{index}");
        grant.fence += index;
        let mut request = call.request.clone();
        if index == 2 {
            request.params.arguments["expected_version"] = json!(2);
            grant.predicate_descriptor["clauses"][0]["expected_version"] = json!("2");
            grant.parameters_digest =
                kedgeflow::contracts::digest("parameters", &request.params.arguments).unwrap();
            drop_reply.store(true, Ordering::SeqCst);
        }
        let raw = sign_grant(
            &grant,
            "test-key",
            &ed25519_dalek::SigningKey::from_bytes(&[6; 32]),
        )
        .unwrap();
        let digest = verifier.verify(&raw, domain::NOW).unwrap().digest;
        ledger.issue(&grant, &digest).await.unwrap();
        let headers = HeaderMap::from_iter([(
            "mcp-kedgeflow-grant".parse().unwrap(),
            URL_SAFE_NO_PAD.encode(raw).parse().unwrap(),
        )]);
        let result = gateway
            .handle(&headers, &workload, &serde_json::to_vec(&request).unwrap())
            .await;
        match index {
            0 => assert!(result.get("result").is_some()),
            1 => assert_eq!(result["error"]["message"], "STATE_GUARD_VIOLATION"),
            _ => {
                assert_eq!(result["error"]["message"], "OUTCOME_UNKNOWN");
                let attempt = result["error"]["data"]["attempt_id"].as_str().unwrap();
                assert_eq!(
                    ledger.status(&grant, attempt).await.unwrap().status,
                    "unknown"
                );
            }
        }
        assert_eq!(
            gateway
                .handle(&headers, &workload, &serde_json::to_vec(&request).unwrap())
                .await["error"]["message"],
            "NONCE_CONSUMED"
        );
    }
    assert_eq!(*state.lock().unwrap(), (3, call.grant.fence + 2, 2));
}
