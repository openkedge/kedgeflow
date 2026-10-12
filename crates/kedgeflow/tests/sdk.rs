//! Unmodified official SDK against Rust routing with a real etcd authority.
//! Identity and broker are explicit synthetic boundaries in this transport test.
#[path = "support/domain.rs"]
mod domain;
use async_trait::async_trait;
use axum::Extension;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderMap;
use kedgeflow::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::{Authenticator, Identity, WorkloadIdentity},
    broker::{CredentialBroker, TargetCredential},
    clock::Clock,
    contracts::sign_grant,
    endpoint::EndpointPolicy,
    error::Result,
    gateway::{Gateway, Request, VerifiedCall},
    ledger::{AuthorityLedger, EtcdLedger},
    server,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
struct ClockFixture;
impl Clock for ClockFixture {
    fn now_ms(&self) -> i64 {
        domain::NOW
    }
}

#[tokio::test]
async fn node_agent_refuses_untrusted_records_remediation_and_overlapping_store_owners() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let node = std::env::var("KF_SDK_NODE").unwrap_or_else(|_| "node".into());
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(node)
            .arg(root.join("tests/sdk/agent-vectors.mjs"))
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "PASS");
}
struct Auth(Identity);
#[async_trait]
impl Authenticator for Auth {
    async fn authenticate(&self, _: &HeaderMap, _: &WorkloadIdentity) -> Result<Identity> {
        Ok(self.0.clone())
    }
}
struct Broker;
#[async_trait]
impl CredentialBroker for Broker {
    async fn exchange(&self, _: &VerifiedCall, _: Instant) -> Result<TargetCredential> {
        Ok(TargetCredential {
            token: "synthetic-target-only".into(),
            expires_at_ms: domain::NOW + 2000,
            audience: "target".into(),
        })
    }
}
struct Adapter(AtomicUsize);
#[async_trait]
impl ResourceAdapter for Adapter {
    async fn dispatch(&self, c: &VerifiedCall, _: &TargetCredential) -> Result<AdapterResult> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            status: "committed".into(),
            result: json!({"resultType":"complete","isError":false,"content":[],"structuredContent":{"drained":true,
        "kedgeflow_terminal_receipt":{"attempt_id":c.attempt_id,"grant_digest":c.grant_digest,"resource":c.grant.resources[0],"fence":c.grant.fence,"status":"committed","post_version":2}}}),
        })
    }
    async fn read(&self, _: &Request, _: &Identity) -> Result<Value> {
        Ok(json!({"resultType":"complete","content":[]}))
    }
}
#[tokio::test]
async fn official_client_discovers_remediates_executes_and_refuses_replay() {
    let required = std::env::var("KF_REQUIRE_SDK").as_deref() == Ok("1");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = root.join("tests/sdk/interop.mjs");
    let modules = root.join("tests/sdk/node_modules/@modelcontextprotocol/client/package.json");
    if !modules.is_file() {
        assert!(
            !required,
            "KF_REQUIRE_SDK=1 requires npm ci --prefix tests/sdk"
        );
        eprintln!("SKIP official SDK: npm ci --prefix tests/sdk");
        return;
    }
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(e) => e,
        Err(_) => {
            assert!(!required, "SDK requires real ETCD_ENDPOINT");
            eprintln!("SKIP SDK: real ETCD_ENDPOINT absent");
            return;
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let external = format!("https://{address}/mcp");
    let (mut call, mut verifier) = domain::call();
    call.grant.audience = external.clone();
    call.grant.resources[0].id = "node-a".into();
    call.descriptor.resource = Some(call.grant.resources[0].clone());
    call.descriptor.adapter_contract["guard_scope"] = json!(["node-a"]);
    call.grant.adapter_contract = call.descriptor.adapter_contract.clone();
    call.grant.predicate_descriptor["clauses"][0]["resource"] = json!(call.grant.resources[0]);
    call.request.params.arguments["node"] = json!("node-a");
    call.grant.parameters_digest =
        kedgeflow::contracts::digest("parameters", &call.request.params.arguments).unwrap();
    call.signed_grant = sign_grant(
        &call.grant,
        "test-key",
        &ed25519_dalek::SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    verifier.audience = external.clone();
    call.grant_digest = verifier
        .verify(&call.signed_grant, domain::NOW)
        .unwrap()
        .digest;
    let ledger = Arc::new(
        EtcdLedger::new(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint,
            format!("/kf-sdk/{}", rand::random::<u64>()),
        )
        .unwrap(),
    );
    ledger.publish_policy(&call.grant).await.unwrap();
    ledger.issue(&call.grant, &call.grant_digest).await.unwrap();
    let adapter = Arc::new(Adapter(AtomicUsize::new(0)));
    let gateway = Arc::new(Gateway {
        verifier,
        ledger,
        auth: Arc::new(Auth(call.identity.clone())),
        broker: Arc::new(Broker),
        adapter: adapter.clone(),
        resolver: None,
        tools: BTreeMap::from([(call.descriptor.name.clone(), call.descriptor.clone())]),
        timeout: Duration::from_secs(5),
        clock: Arc::new(ClockFixture),
    });
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        "spiffe://test/agent".try_into().unwrap(),
    )];
    let cert = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    let workload = WorkloadIdentity::from_verified_cert_der(cert.der()).unwrap();
    let router =
        server::router(gateway, EndpointPolicy::new(&external).unwrap()).layer(Extension(workload));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path().join("sdk-fixture.json");
    std::fs::write(&fixture,serde_json::to_vec(&json!({"endpoint":format!("http://{address}/mcp"),"grant":URL_SAFE_NO_PAD.encode(&call.signed_grant),"grant_digest":call.grant_digest})).unwrap()).unwrap();
    let node = std::env::var("KF_SDK_NODE").unwrap_or_else(|_| "node".into());
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(node)
            .arg(&script)
            .arg(&fixture)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    server.abort();
    assert!(
        output.status.success(),
        "SDK failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "PASS");
    assert_eq!(adapter.0.load(Ordering::SeqCst), 1);
    if let Ok(path) = std::env::var("KF_SDK_RESULT_PATH") {
        let path = std::path::PathBuf::from(path);
        let path = if path.is_absolute() {
            path
        } else {
            root.join(path)
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, &output.stdout).unwrap();
    }
}
