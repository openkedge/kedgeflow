#[path = "support/domain.rs"]
mod domain;
mod support;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderValue};
use kedgeflow::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::{Authenticator, Identity, WorkloadIdentity},
    broker::{CredentialBroker, TargetCredential},
    clock::Clock,
    contracts::{Grant, GrantVerifier},
    error::{Error, Result},
    gateway::{Gateway, Request, VerifiedCall},
    grant_reference::GrantResolver,
    ledger::{Attempt, AuthorityLedger, EtcdLedger, OutcomeQuerier},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
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
struct Broker {
    count: AtomicUsize,
    clock: Arc<TestClock>,
    fail: bool,
}
#[async_trait]
impl CredentialBroker for Broker {
    async fn exchange(&self, c: &VerifiedCall, _: Instant) -> Result<TargetCredential> {
        self.count.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(Error::Unavailable("test broker failure".into()));
        }
        Ok(TargetCredential {
            token: "target-only".into(),
            expires_at_ms: self.clock.now_ms() + 2000,
            audience: c.grant.audience.clone(),
        })
    }
}
struct Adapter {
    count: AtomicUsize,
    unknown: bool,
}
#[async_trait]
impl ResourceAdapter for Adapter {
    async fn dispatch(&self, c: &VerifiedCall, t: &TargetCredential) -> Result<AdapterResult> {
        assert_ne!(t.token, c.identity.access_token);
        self.count.fetch_add(1, Ordering::SeqCst);
        if self.unknown {
            return Err(Error::Unknown("lost result after possible effect".into()));
        }
        Ok(AdapterResult {
            result: json!({"resultType":"complete","isError":false,"structuredContent":{"drained":true}}),
            status: "committed".into(),
        })
    }
    async fn read(&self, _: &Request, _: &Identity) -> Result<Value> {
        Ok(json!({"resultType":"complete","content":[]}))
    }
}
struct Resolver(Vec<u8>);
#[async_trait]
impl GrantResolver for Resolver {
    async fn resolve(&self, i: &Identity, _: &str) -> Result<Vec<u8>> {
        assert_eq!(i.access_token, "caller-token-never-forward");
        Ok(self.0.clone())
    }
}
struct LateLedger {
    inner: Arc<EtcdLedger>,
    clock: Arc<TestClock>,
    lose_claim_reply: bool,
}
#[async_trait]
impl AuthorityLedger for LateLedger {
    async fn publish_policy(&self, g: &Grant) -> Result<()> {
        self.inner.publish_policy(g).await
    }
    async fn issue(&self, g: &Grant, d: &str) -> Result<()> {
        self.inner.issue(g, d).await
    }
    async fn claim(&self, g: &Grant, d: &str, id: &str) -> Result<Attempt> {
        let a = self.inner.claim(g, d, id).await?;
        if self.lose_claim_reply {
            Err(Error::Unavailable("lost committed claim reply".into()))
        } else {
            Ok(a)
        }
    }
    async fn claim_recorded(
        &self,
        g: &Grant,
        d: &str,
        id: &str,
        context: &kedgeflow::recovery::ExecutionRecord,
    ) -> Result<Attempt> {
        let a = self.inner.claim_recorded(g, d, id, context).await?;
        if self.lose_claim_reply {
            Err(Error::Unavailable("lost committed claim reply".into()))
        } else {
            Ok(a)
        }
    }
    async fn finish_recorded(
        &self,
        g: &Grant,
        a: &Attempt,
        status: &str,
        evidence: &Value,
    ) -> Result<()> {
        self.inner.finish_recorded(g, a, status, evidence).await
    }
    async fn execution_status(
        &self,
        g: &Grant,
        d: &str,
    ) -> Result<kedgeflow::ledger::ExecutionStatus> {
        self.inner.execution_status(g, d).await
    }
    async fn replace(&self, o: &Grant, n: &Grant, d: &str) -> Result<()> {
        self.inner.replace(o, n, d).await
    }
    async fn authorize_dispatch(&self, g: &Grant, d: &str, id: &str) -> Result<()> {
        self.inner.authorize_dispatch(g, d, id).await?;
        self.clock.0.store(g.expires_at, Ordering::SeqCst);
        Ok(())
    }
    async fn finish(&self, g: &Grant, a: &Attempt, s: &str) -> Result<()> {
        self.inner.finish(g, a, s).await
    }
    async fn status(&self, g: &Grant, id: &str) -> Result<Attempt> {
        self.inner.status(g, id).await
    }
    async fn reconcile(&self, g: &Grant, id: &str, q: &dyn OutcomeQuerier) -> Result<Attempt> {
        self.inner.reconcile(g, id, q).await
    }
}
struct Fixture {
    gateway: Gateway,
    ledger: Arc<EtcdLedger>,
    call: VerifiedCall,
    broker: Arc<Broker>,
    adapter: Arc<Adapter>,
    workload: WorkloadIdentity,
    clock: Arc<TestClock>,
}
async fn fixture(unknown: bool, fail: bool) -> Option<Fixture> {
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(e) => e,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
            eprintln!("SKIP gateway real-etcd fixture: ETCD_ENDPOINT absent");
            return None;
        }
    };
    let (call, verifier) = domain::call();
    let ledger = Arc::new(
        EtcdLedger::new(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint,
            format!(
                "/kf-gateway-tests/{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ),
        )
        .unwrap(),
    );
    ledger.publish_policy(&call.grant).await.unwrap();
    ledger.issue(&call.grant, &call.grant_digest).await.unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(domain::NOW)));
    let broker = Arc::new(Broker {
        count: AtomicUsize::new(0),
        clock: clock.clone(),
        fail,
    });
    let adapter = Arc::new(Adapter {
        count: AtomicUsize::new(0),
        unknown,
    });
    let cert = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut cert = cert;
    cert.subject_alt_names = vec![rcgen::SanType::URI(
        "spiffe://test/agent".try_into().unwrap(),
    )];
    let cert = cert
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    let workload = WorkloadIdentity::from_verified_cert_der(cert.der()).unwrap();
    let mut read = call.descriptor.clone();
    read.name = "read".into();
    read.read_only = true;
    read.status_scope.clear();
    read.required_scope = "read".into();
    let gateway = Gateway {
        verifier,
        ledger: ledger.clone(),
        auth: Arc::new(Auth(call.identity.clone())),
        broker: broker.clone(),
        adapter: adapter.clone(),
        resolver: Some(Arc::new(Resolver(call.signed_grant.clone()))),
        tools: BTreeMap::from([
            (call.descriptor.name.clone(), call.descriptor.clone()),
            ("read".into(), read),
        ]),
        timeout: Duration::from_secs(5),
        clock: clock.clone(),
    };
    gateway.validate().unwrap();
    Some(Fixture {
        gateway,
        ledger,
        call,
        broker,
        adapter,
        workload,
        clock,
    })
}
fn headers(f: &Fixture) -> HeaderMap {
    HeaderMap::from_iter([(
        "mcp-kedgeflow-grant".parse().unwrap(),
        HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(&f.call.signed_grant)).unwrap(),
    )])
}
async fn invoke(f: &Fixture, h: &HeaderMap, request: &Request) -> Value {
    f.gateway
        .handle(h, &f.workload, &serde_json::to_vec(request).unwrap())
        .await
}
fn message(v: &Value) -> &str {
    v["error"]["message"].as_str().unwrap()
}

#[tokio::test]
async fn remediation_negotiation_read_and_scope_never_claim() {
    let Some(mut f) = fixture(false, false).await else {
        return;
    };
    let result = invoke(&f, &HeaderMap::new(), &f.call.request).await;
    assert_eq!(message(&result), "NEEDS_EVIDENCE");
    assert!(result["error"]["data"]["proposal_digest"].is_null());
    assert_eq!(
        result["error"]["data"]["grant_carriage"],
        "Mcp-KedgeFlow-Grant"
    );
    let mut request = f.call.request.clone();
    request.params.meta.insert(
        "io.modelcontextprotocol/clientCapabilities".into(),
        json!({}),
    );
    assert_eq!(
        message(&invoke(&f, &headers(&f), &request).await),
        "KF_EXTENSION_NOT_NEGOTIATED"
    );
    request = f.call.request.clone();
    request.params.name = "read".into();
    request.params.arguments = json!({});
    assert!(
        invoke(&f, &HeaderMap::new(), &request)
            .await
            .get("result")
            .is_some()
    );
    assert_eq!(
        message(&invoke(&f, &headers(&f), &request).await),
        "UNEXPECTED_GRANT"
    );
    f.gateway.auth = Arc::new(Auth(Identity {
        scopes: Default::default(),
        ..f.call.identity.clone()
    }));
    assert_eq!(
        message(&invoke(&f, &headers(&f), &f.call.request).await),
        "INSUFFICIENT_SCOPE"
    );
    assert_eq!(f.broker.count.load(Ordering::SeqCst), 0);
    assert_eq!(f.adapter.count.load(Ordering::SeqCst), 0);
    f.ledger
        .claim(&f.call.grant, &f.call.grant_digest, "still-unclaimed")
        .await
        .unwrap();
}
#[tokio::test]
async fn binding_failures_and_ambiguous_carriage_precede_claim() {
    let Some(f) = fixture(false, false).await else {
        return;
    };
    let mut request = f.call.request.clone();
    request.params.arguments["expected_version"] = json!(2);
    assert_eq!(
        message(&invoke(&f, &headers(&f), &request).await),
        "GRANT_MISMATCH"
    );
    let mut h = headers(&f);
    h.insert(
        "mcp-kedgeflow-grant-ref",
        HeaderValue::from_str(&f.call.grant_digest).unwrap(),
    );
    assert_eq!(
        message(&invoke(&f, &h, &f.call.request).await),
        "GRANT_MISMATCH"
    );
    h = HeaderMap::new();
    h.insert(
        "mcp-kedgeflow-grant-ref",
        HeaderValue::from_str(&"a".repeat(64)).unwrap(),
    );
    assert_eq!(
        message(&invoke(&f, &h, &f.call.request).await),
        "GRANT_MISMATCH"
    );
    f.ledger
        .claim(&f.call.grant, &f.call.grant_digest, "binding-did-not-claim")
        .await
        .unwrap();
    assert_eq!(f.broker.count.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn inline_and_reference_share_consumption_and_one_effect() {
    let Some(f) = fixture(false, false).await else {
        return;
    };
    let h = HeaderMap::from_iter([(
        "mcp-kedgeflow-grant-ref".parse().unwrap(),
        HeaderValue::from_str(&f.call.grant_digest).unwrap(),
    )]);
    assert!(
        invoke(&f, &h, &f.call.request)
            .await
            .get("result")
            .is_some()
    );
    assert_eq!(
        message(&invoke(&f, &headers(&f), &f.call.request).await),
        "NONCE_CONSUMED"
    );
    assert_eq!(f.broker.count.load(Ordering::SeqCst), 1);
    assert_eq!(f.adapter.count.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn broker_failure_and_lost_result_keep_claimed_authority() {
    for (unknown, fail, status) in [(false, true, "not_dispatched"), (true, false, "unknown")] {
        let Some(f) = fixture(unknown, fail).await else {
            return;
        };
        let result = invoke(&f, &headers(&f), &f.call.request).await;
        assert_eq!(
            message(&result),
            if fail {
                "CREDENTIAL_UNAVAILABLE"
            } else {
                "OUTCOME_UNKNOWN"
            }
        );
        let id = result["error"]["data"]["attempt_id"].as_str().unwrap();
        assert_eq!(
            f.ledger.status(&f.call.grant, id).await.unwrap().status,
            status
        );
        let queried = invoke(&f, &HeaderMap::new(), &status_request(&f)).await;
        assert_eq!(queried["result"]["state"], status);
        assert_eq!(queried["result"]["attempt_id"], id);
        assert_eq!(
            message(&invoke(&f, &headers(&f), &f.call.request).await),
            "NONCE_CONSUMED"
        );
        assert_eq!(f.adapter.count.load(Ordering::SeqCst), usize::from(unknown));
    }
}

#[tokio::test]
async fn corrupted_retained_attempt_and_dispatch_correlation_refuse_status() {
    let Some(f) = fixture(false, false).await else {
        return;
    };
    let a = f
        .ledger
        .claim(&f.call.grant, &f.call.grant_digest, "original")
        .await
        .unwrap();
    let queried = f
        .ledger
        .execution_status(&f.call.grant, &f.call.grant_digest)
        .await
        .unwrap();
    assert_eq!(queried.state, "claimed");
    f.ledger
        .authorize_dispatch(&f.call.grant, &f.call.grant_digest, &a.id)
        .await
        .unwrap();
    assert_eq!(
        f.ledger
            .execution_status(&f.call.grant, &f.call.grant_digest)
            .await
            .unwrap()
            .state,
        "dispatch_authorized"
    );
    let part = |s: &str| URL_SAFE_NO_PAD.encode(s);
    let root = format!(
        "{}/domains/{}/roots/{}",
        f.ledger.namespace(),
        part(&f.call.grant.conflict_domain),
        part(&f.call.grant.root_id)
    );
    let attempt_key = format!("{root}/attempts/{}", part(&a.id));
    let outbox_key = format!("{root}/outbox/{}", part(&a.id));
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let put = |key: String, value: String| {
        let endpoint = endpoint.clone();
        async move {
            use base64::engine::general_purpose::STANDARD;
            reqwest::Client::new()
                .post(format!("{endpoint}/v3/kv/put"))
                .json(&json!({"key":STANDARD.encode(key),"value":STANDARD.encode(value)}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        }
    };
    let mut changed = a.clone();
    changed.grant_digest = "f".repeat(64);
    put(
        attempt_key.clone(),
        serde_json::to_string(&changed).unwrap(),
    )
    .await;
    assert_eq!(
        message(&invoke(&f, &HeaderMap::new(), &status_request(&f)).await),
        "STATUS_UNAVAILABLE"
    );
    put(attempt_key, serde_json::to_string(&a).unwrap()).await;
    put(outbox_key, "committed".into()).await;
    assert!(
        f.ledger
            .execution_status(&f.call.grant, &f.call.grant_digest)
            .await
            .is_err()
    );
    assert!(
        f.ledger
            .execution_status(&f.call.grant, &"f".repeat(64))
            .await
            .is_err()
    );
    assert_eq!(f.broker.count.load(Ordering::SeqCst), 0);
    assert_eq!(f.adapter.count.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn final_ledger_latency_cannot_dispatch_after_expiry() {
    let Some(mut f) = fixture(false, false).await else {
        return;
    };
    f.gateway.ledger = Arc::new(LateLedger {
        inner: f.ledger.clone(),
        clock: f.clock.clone(),
        lose_claim_reply: false,
    });
    let result = invoke(&f, &headers(&f), &f.call.request).await;
    assert_eq!(message(&result), "DISPATCH_VALIDITY_EXPIRED");
    let id = result["error"]["data"]["attempt_id"].as_str().unwrap();
    assert_eq!(
        f.ledger.status(&f.call.grant, id).await.unwrap().status,
        "not_dispatched"
    );
    assert_eq!(f.adapter.count.load(Ordering::SeqCst), 0);
    assert!(matches!(
        f.ledger
            .claim(&f.call.grant, &f.call.grant_digest, "never-refunded")
            .await,
        Err(Error::NonceConsumed)
    ));
}

fn status_request(f: &Fixture) -> Request {
    let mut r = f.call.request.clone();
    r.method = kedgeflow::execution_status::METHOD.into();
    r.params.arguments = json!({"profile":kedgeflow::execution_status::PROFILE,"grant":String::from_utf8(f.call.signed_grant.clone()).unwrap()});
    r.params
        .meta
        .get_mut("io.modelcontextprotocol/clientCapabilities")
        .unwrap()["extensions"][kedgeflow::execution_status::EXTENSION] =
        json!({"profile":kedgeflow::execution_status::PROFILE});
    r
}

#[tokio::test]
async fn retries_and_expired_status_resolve_original_attempt_without_execution() {
    let Some(mut f) = fixture(false, false).await else {
        return;
    };
    let status = status_request(&f);
    let unclaimed = invoke(&f, &HeaderMap::new(), &status).await;
    assert_eq!(unclaimed["result"]["state"], "unclaimed");
    assert!(unclaimed["result"]["attempt_id"].is_null());
    invoke(&f, &headers(&f), &f.call.request)
        .await
        .get("result")
        .unwrap();
    let first = invoke(&f, &headers(&f), &f.call.request).await;
    assert_eq!(message(&first), "NONCE_CONSUMED");
    let original = first["error"]["data"]["attempt_id"].as_str().unwrap();
    assert_eq!(first["error"]["data"]["state"], "committed");
    assert_eq!(
        f.ledger
            .status(&f.call.grant, original)
            .await
            .unwrap()
            .status,
        "committed"
    );
    for rpc_id in 20..24 {
        let mut r = f.call.request.clone();
        r.id = json!(rpc_id);
        let replay = invoke(&f, &headers(&f), &r).await;
        assert_eq!(replay["error"]["data"]["attempt_id"], original);
    }
    f.clock.0.store(f.call.grant.expires_at, Ordering::SeqCst);
    // A new current token/delegation may disclose the retained attempt, while
    // execution remains expired and exact-delegation-bound.
    f.gateway.auth = Arc::new(Auth(Identity {
        delegation_digest: "f".repeat(64),
        scopes: std::collections::BTreeSet::from(["kf.status".into()]),
        ..f.call.identity.clone()
    }));
    for _ in 0..4 {
        let reply = invoke(&f, &HeaderMap::new(), &status).await;
        assert_eq!(reply["result"]["attempt_id"], original);
        assert_eq!(reply["result"]["state"], "committed");
    }
    assert_eq!(f.broker.count.load(Ordering::SeqCst), 1);
    assert_eq!(f.adapter.count.load(Ordering::SeqCst), 1);
    assert!(matches!(
        f.ledger
            .claim(&f.call.grant, &f.call.grant_digest, "never-reopened")
            .await,
        Err(Error::NonceConsumed)
    ));
}

#[tokio::test]
async fn status_requires_current_scope_identity_and_closed_lookup() {
    let Some(mut f) = fixture(false, false).await else {
        return;
    };
    let status = status_request(&f);
    let mut wrong = status.clone();
    wrong.params.arguments["dispatch"] = json!(true);
    assert_eq!(
        message(&invoke(&f, &HeaderMap::new(), &wrong).await),
        "INVALID_STATUS_PARAMS"
    );
    wrong = status.clone();
    wrong.params.arguments["attempt_id"] = json!("invented");
    assert_eq!(
        message(&invoke(&f, &HeaderMap::new(), &wrong).await),
        "STATUS_FORBIDDEN"
    );
    assert_eq!(
        message(&invoke(&f, &headers(&f), &status).await),
        "UNEXPECTED_GRANT_HEADER"
    );
    wrong = status.clone();
    wrong.params.meta.insert(
        "io.modelcontextprotocol/clientCapabilities".into(),
        json!({}),
    );
    assert_eq!(
        message(&invoke(&f, &HeaderMap::new(), &wrong).await),
        "KF_STATUS_NOT_NEGOTIATED"
    );
    f.gateway.auth = Arc::new(Auth(Identity {
        scopes: std::collections::BTreeSet::from(["mutate".into()]),
        ..f.call.identity.clone()
    }));
    assert_eq!(
        message(&invoke(&f, &HeaderMap::new(), &status).await),
        "INSUFFICIENT_STATUS_SCOPE"
    );
    for changed in 0..3 {
        let mut identity = f.call.identity.clone();
        match changed {
            0 => identity.subject.sub = "another".into(),
            1 => identity.dpop_jkt = "another".into(),
            _ => identity.delegation_digest = "renewed-token-allowed".into(),
        }
        f.gateway.auth = Arc::new(Auth(identity));
        let r = invoke(&f, &HeaderMap::new(), &status).await;
        if changed < 2 {
            assert_eq!(message(&r), "STATUS_FORBIDDEN");
        } else {
            assert_eq!(r["result"]["state"], "unclaimed");
        }
    }
    assert_eq!(f.broker.count.load(Ordering::SeqCst), 0);
    assert_eq!(f.adapter.count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn lost_claim_reply_resolves_consumed_original_and_never_exchanges() {
    let Some(mut f) = fixture(false, false).await else {
        return;
    };
    f.gateway.ledger = Arc::new(LateLedger {
        inner: f.ledger.clone(),
        clock: f.clock.clone(),
        lose_claim_reply: true,
    });
    let first = invoke(&f, &headers(&f), &f.call.request).await;
    assert_eq!(message(&first), "ROOT_UNAVAILABLE_OR_CONSUMED");
    assert_eq!(first["error"]["data"]["state"], "claimed");
    let original = first["error"]["data"]["attempt_id"].as_str().unwrap();
    assert_eq!(
        f.ledger
            .status(&f.call.grant, original)
            .await
            .unwrap()
            .status,
        "claimed"
    );
    let replay = invoke(&f, &headers(&f), &f.call.request).await;
    assert_eq!(replay["error"]["data"]["attempt_id"], original);
    assert_eq!(f.broker.count.load(Ordering::SeqCst), 0);
    assert_eq!(f.adapter.count.load(Ordering::SeqCst), 0);
}
#[test]
fn parameter_and_caller_binding_refuses_substitution() {
    let (c, _): (VerifiedCall, GrantVerifier) = domain::call();
    let mut identity = c.identity.clone();
    identity.workload_id = "spiffe://other/agent".into();
    assert!(
        kedgeflow::gateway::bind_call(
            &c.grant,
            &identity,
            &c.descriptor,
            &c.request.params.arguments
        )
        .is_err()
    );
}

#[tokio::test]
async fn oversized_signed_grant_requires_reference_and_preserves_one_claim() {
    let Some(mut f) = fixture(false, false).await else {
        return;
    };
    f.call.grant.root_id.push_str("-large");
    f.call.grant.gid.push_str("-large");
    f.call.grant.nonce.push_str("-large");
    f.call.grant.adapter_contract["commit_point"] =
        json!("mock atomic fenced transition; ".repeat(450));
    f.call.signed_grant = kedgeflow::contracts::sign_grant(
        &f.call.grant,
        "test-key",
        &ed25519_dalek::SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    f.call.grant_digest = f
        .gateway
        .verifier
        .verify(&f.call.signed_grant, domain::NOW)
        .unwrap()
        .digest;
    assert!(
        URL_SAFE_NO_PAD.encode(&f.call.signed_grant).len()
            > kedgeflow::grant_reference::MAX_INLINE_HEADER
    );
    f.gateway
        .tools
        .get_mut("node_drain")
        .unwrap()
        .adapter_contract = f.call.grant.adapter_contract.clone();
    f.gateway.resolver = Some(Arc::new(Resolver(f.call.signed_grant.clone())));
    f.ledger
        .issue(&f.call.grant, &f.call.grant_digest)
        .await
        .unwrap();
    assert_eq!(
        message(&invoke(&f, &headers(&f), &f.call.request).await),
        "GRANT_HEADER_TOO_LARGE"
    );
    let h = HeaderMap::from_iter([(
        "mcp-kedgeflow-grant-ref".parse().unwrap(),
        HeaderValue::from_str(&f.call.grant_digest).unwrap(),
    )]);
    assert!(
        invoke(&f, &h, &f.call.request)
            .await
            .get("result")
            .is_some()
    );
    assert_eq!(
        message(&invoke(&f, &h, &f.call.request).await),
        "NONCE_CONSUMED"
    );
    assert_eq!(f.broker.count.load(Ordering::SeqCst), 1);
    assert_eq!(f.adapter.count.load(Ordering::SeqCst), 1);
}

#[test]
fn sql_grant_binds_reservation_and_refuses_legacy_or_injected_arguments() {
    let (mut call, _) = domain::call();
    call.grant.action.id = kedgeflow::postgres_action::ACTION.into();
    call.grant.action.version = "1.0".into();
    call.descriptor.action = Some(call.grant.action.clone());
    let args = json!({"resource_id":call.grant.resources[0].id,"expected_version":1,"reservation":"booking:a"});
    call.grant.parameters_digest = kedgeflow::contracts::digest("parameters", &args).unwrap();
    call.descriptor.validate().unwrap();
    let bind = |args: &Value| {
        kedgeflow::gateway::bind_call(&call.grant, &call.identity, &call.descriptor, args)
    };
    assert!(bind(&args).is_ok());
    for change in [
        json!({"reservation":"booking:b"}),
        json!({"resource_id":"other"}),
        json!({"expected_version":2}),
        json!({"fence":1}),
        json!({"node":call.grant.resources[0].id}),
    ] {
        let mut substituted = args.clone();
        substituted
            .as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        assert!(bind(&substituted).is_err());
    }
    // Even freshly bound application digests cannot select an unsupported SQL
    // argument shape or predicate version at the independent broker boundary.
    call.grant.parameters_digest = kedgeflow::contracts::digest(
        "parameters",
        &json!({"node":call.grant.resources[0].id,"expected_version":1}),
    )
    .unwrap();
    assert!(
        kedgeflow::gateway::bind_call(
            &call.grant,
            &call.identity,
            &call.descriptor,
            &json!({"node":call.grant.resources[0].id,"expected_version":1})
        )
        .is_err()
    );
}
