//! Generated software identities, native TLS/DPoP and real-etcd root resolution.
use super::*;
use kedgeflow::{
    a2a_root::{
        EXTENSION, HttpsRootResolver, PATH, PROFILE, Reader, Registration, ResolveRequest,
        RootResolver,
    },
    a2a_root_service::RootResolutionService,
    coordination::{Coordination, ReservationEnrollment, ReservationScope, ReservationState},
};
use std::collections::BTreeSet;
fn scope(actions: &[&str], resources: &[&str]) -> ReservationScope {
    ReservationScope {
        actions: actions.iter().map(|s| (*s).into()).collect(),
        resources: resources.iter().map(|s| (*s).into()).collect(),
    }
}
fn registration(h: &Harness, url: &str) -> Registration {
    Registration {
        profile: PROFILE.into(),
        root_id: "coordination-root".into(),
        root_generation: 1,
        enrollment: ReservationEnrollment {
            tenant: h.f.trust.tenant.clone(),
            conflict_domain: "complete-synthetic-boundary".into(),
            scope: scope(&["reserve", "inspect"], &["one", "two"]),
            forward: 10,
            compensation: 5,
        },
        delegation_id: "reader-delegation".into(),
        authority_endpoint: url.into(),
        required_scope: "kf.root.resolve".into(),
        readers: vec![Reader {
            subject: h.f.identity.subject.clone(),
            workload_id: "spiffe://test/agent".into(),
            scope: scope(&["reserve"], &["one", "two"]),
        }],
    }
}
fn request(r: &Registration) -> ResolveRequest {
    ResolveRequest {
        profile: PROFILE.into(),
        request_id: "request-one".into(),
        part: r.reference_part(),
        scope: scope(&["reserve"], &["one"]),
        parent_operation: None,
        task_id: Some("task-one".into()),
        context_id: Some("context-one".into()),
    }
}
fn access(h: &Harness, subject: &str, scopes: &str) -> String {
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
    jwt(
        json!({"alg":"EdDSA","typ":"at+jwt"}),
        json!({"iss":h.f.identity.subject.iss,"sub":subject,"aud":AUD,"exp":NOW/1000+60,"iat":NOW/1000,"scope":scopes,"cnf":{"jkt":jkt}}),
        7,
    )
}
struct Peer {
    h: Harness,
    r: Registration,
    c: Coordination,
    resolver: RootResolver,
    client: reqwest::Client,
    token: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Peer {
    async fn new() -> Option<Self> {
        let h = Harness::new().await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let r = registration(
            &h,
            &format!("https://{}{PATH}", listener.local_addr().unwrap()),
        );
        let c = Coordination::new(h.ledger.clone(), &r.root_id).unwrap();
        c.enroll(r.enrollment.clone()).await.unwrap();
        let resolver = RootResolver::new(h.ledger.clone(), r.clone()).unwrap();
        resolver.enroll().await.unwrap();
        let auth = DualAuthenticator::new(
            &h.f.identity.subject.iss,
            AUD,
            &r.authority_endpoint,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let service =
            Arc::new(RootResolutionService::new(resolver.clone(), auth, h.clock.clone()).unwrap());
        let tls = kedgeflow::tls::server_config_pem(
            h.agent_pki.server.as_bytes(),
            h.agent_pki.server_key.as_bytes(),
            h.agent_pki.ca.as_bytes(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, tls, service.router())
                .await
                .unwrap();
        });
        let client = kedgeflow::tls::pinned_http_client_pem(
            h.agent_pki.ca.as_bytes(),
            h.agent_pki.client.as_bytes(),
            h.agent_pki.client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap();
        let token = access(&h, &h.f.identity.subject.sub, "kf.root.resolve");
        Some(Self {
            h,
            r,
            c,
            resolver,
            client,
            token,
            task,
        })
    }
    fn headers(&self) -> http::HeaderMap {
        self.headers_for(&self.token)
    }
    fn headers_for(&self, token: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        let proof = jwt(
            json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":self.h.jwk}),
            json!({"jti":format!("a2a-{}",self.h.jti.fetch_add(1,Ordering::SeqCst)),"htm":"POST","htu":self.r.authority_endpoint,"iat":NOW/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}),
            8,
        );
        h.insert("authorization", format!("DPoP {token}").parse().unwrap());
        h.insert("dpop", proof.parse().unwrap());
        h.insert("a2a-version", "1.0".parse().unwrap());
        h.insert("a2a-extensions", EXTENSION.parse().unwrap());
        h
    }
    async fn post(&self, body: &Value) -> (reqwest::StatusCode, Value) {
        self.post_headers(body, self.headers()).await
    }
    async fn post_headers(
        &self,
        body: &Value,
        headers: http::HeaderMap,
    ) -> (reqwest::StatusCode, Value) {
        let response = self
            .client
            .post(&self.r.authority_endpoint)
            .headers(headers)
            .json(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        (response.status(), response.json().await.unwrap())
    }
    fn pinned(&self) -> HttpsRootResolver {
        HttpsRootResolver::new(
            self.r.clone(),
            kedgeflow::tls::pinned_client_pem(
                self.h.agent_pki.ca.as_bytes(),
                self.h.agent_pki.client.as_bytes(),
                self.h.agent_pki.client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap(),
        )
        .unwrap()
    }
}
fn op(n: u8) -> String {
    format!("{n:064x}")
}
#[tokio::test]
async fn a2a_native_hierarchical_views_narrow_without_allocating_or_reopening_unknown() {
    let Some(p) = Peer::new().await else { return };
    p.c.allocate(&op(1), None, scope(&["reserve"], &["one", "two"]), 6, 3)
        .await
        .unwrap();
    p.c.allocate(&op(2), Some(&op(1)), scope(&["reserve"], &["one"]), 2, 1)
        .await
        .unwrap();
    p.c.consume(&op(2), "original-attempt").await.unwrap();
    let before = p.c.status().await.unwrap();
    let mut q = request(&p.r);
    q.parent_operation = Some(op(1));
    let composite = p.pinned().resolve(&q, &p.headers()).await.unwrap();
    assert_eq!(composite.parent_state, Some(ReservationState::Composite));
    q.parent_operation = Some(op(2));
    let first = p.pinned().resolve(&q, &p.headers()).await.unwrap();
    assert_eq!(first.parent_state, Some(ReservationState::Unknown));
    assert!(!first.execution_authority && !first.child_grants_supported && first.root_active);
    q.request_id = "another-request".into();
    q.task_id = Some("new-task".into());
    q.context_id = Some("new-context".into());
    let second = p.pinned().resolve(&q, &p.headers()).await.unwrap();
    assert_eq!(first.snapshot_digest, second.snapshot_digest);
    assert_eq!(second.task_id, q.task_id);
    assert_eq!(before, p.c.status().await.unwrap());
    assert!(p.c.consume(&op(1), "composite-execution").await.is_err());
    assert!(p.c.consume(&op(2), "replacement-attempt").await.is_err());
    p.c.stop().await.unwrap();
    let stopped = p.pinned().resolve(&q, &p.headers()).await.unwrap();
    assert!(!stopped.root_active && !stopped.execution_authority);
    assert_ne!(first.snapshot_digest, stopped.snapshot_digest);
    assert_eq!(stopped.parent_state, Some(ReservationState::Unknown));
    assert!(
        p.c.allocate(&op(3), Some(&op(1)), q.scope.clone(), 1, 0)
            .await
            .is_err()
    );
    let output = serde_json::to_value(stopped).unwrap();
    for name in [
        "allocations",
        "signed_grant",
        "free",
        "forward",
        "compensation",
    ] {
        assert!(output.get(name).is_none());
    }
}
#[tokio::test]
async fn a2a_identity_scope_parent_and_reference_substitution_refuse() {
    let Some(p) = Peer::new().await else { return };
    p.c.allocate(&op(1), None, scope(&["reserve"], &["two"]), 1, 0)
        .await
        .unwrap();
    let original = serde_json::to_value(request(&p.r)).unwrap();
    for path in ["root_id", "delegation_id", "authority_endpoint"] {
        let mut v = original.clone();
        v["part"]["data"][path] = json!(if path == "authority_endpoint" {
            "https://elsewhere.invalid/a2a/root:resolve"
        } else {
            "substitute"
        });
        assert_eq!(p.post(&v).await.0, 403, "{path}");
    }
    for q in [
        scope(&["inspect"], &["one"]),
        scope(&["reserve"], &["unregistered"]),
    ] {
        let mut v = original.clone();
        v["scope"] = json!(q);
        assert_eq!(p.post(&v).await.0, 403);
    }
    let mut v = original.clone();
    v["parent_operation"] = json!(op(1));
    assert_eq!(p.post(&v).await.0, 403);
    v["parent_operation"] = json!(op(99));
    assert_eq!(p.post(&v).await.0, 403);
    for token in [
        access(&p.h, "different-subject", "kf.root.resolve"),
        access(&p.h, &p.h.f.identity.subject.sub, "kf.admit"),
    ] {
        assert_eq!(
            p.post_headers(&original, p.headers_for(&token)).await.0,
            403
        );
    }
    // Same CA and OAuth identity, different verified workload is not a registered reader.
    let response =
        p.h.gateway
            .post(&p.r.authority_endpoint)
            .headers(p.headers())
            .json(&original)
            .send()
            .await
            .unwrap();
    assert_eq!(response.status(), 403);
    let mut h = p.headers();
    h.remove("authorization");
    assert_eq!(p.post_headers(&original, h).await.0, 401);
    let headers = p.headers();
    assert_eq!(p.post_headers(&original, headers.clone()).await.0, 200);
    assert_eq!(p.post_headers(&original, headers).await.0, 401);
    let untrusted = reqwest::Client::builder().no_proxy().build().unwrap();
    assert!(
        untrusted
            .post(&p.r.authority_endpoint)
            .json(&original)
            .send()
            .await
            .is_err()
    );
}
#[tokio::test]
async fn a2a_activation_closed_parts_and_legacy_carriage_refuse_before_resolution() {
    let Some(p) = Peer::new().await else { return };
    let original = serde_json::to_value(request(&p.r)).unwrap();
    for (name, value) in [
        ("a2a-version", None),
        ("a2a-version", Some("0.3")),
        ("a2a-extensions", None),
        (
            "a2a-extensions",
            Some("urn:kedgeflow:a2a:root-resolution:9.9"),
        ),
        ("a2a-extensions", Some("")),
    ] {
        let mut h = p.headers();
        h.remove(name);
        if let Some(v) = value {
            h.insert(name, v.parse().unwrap());
        }
        assert_eq!(p.post_headers(&original, h).await.0, 400);
    }
    for name in ["a2a-version", "a2a-extensions"] {
        let mut h = p.headers();
        let v = h[name].clone();
        h.append(name, v);
        assert_eq!(p.post_headers(&original, h).await.0, 400);
    }
    for extensions in [
        format!("{EXTENSION},{EXTENSION}"),
        format!("{EXTENSION},"),
        format!("{EXTENSION},not a URI"),
        format!("{EXTENSION},urn:kedgeflow:a2a:root-resolution:9.9"),
    ] {
        let mut h = p.headers();
        h.insert("a2a-extensions", extensions.parse().unwrap());
        assert_eq!(p.post_headers(&original, h).await.0, 400);
    }
    let mut h = p.headers();
    h.insert(
        "a2a-extensions",
        format!("urn:example:unused, {EXTENSION}").parse().unwrap(),
    );
    assert_eq!(p.post_headers(&original, h).await.0, 200);
    let mut bad = Vec::new();
    let mut v = original.clone();
    v["part"]["kind"] = json!("data");
    bad.push(v);
    let mut v = original.clone();
    v["part"]["text"] = json!("mixed discriminator");
    bad.push(v);
    let mut v = original.clone();
    v["part"]["data"]["saga_budget"] = json!({"units":1});
    bad.push(v);
    let mut v = original.clone();
    v["part"]["data"]["root_generation"] = json!(2);
    bad.push(v);
    let mut v = original.clone();
    v["part"]["data"]["assurance_profile"] = json!("frozen-but-unimplemented");
    bad.push(v);
    let mut v = original.clone();
    v["scope"]["resources"] = json!(["one", "one"]);
    bad.push(v);
    let mut v = original.clone();
    v.as_object_mut().unwrap().remove("parent_operation");
    bad.push(v);
    for v in bad {
        assert_eq!(p.post(&v).await.0, 400, "{v}");
    }
    let raw = serde_json::to_string(&original).unwrap();
    let duplicate = raw.replacen(
        "\"request_id\":",
        "\"request_id\":\"injected\",\"request_id\":",
        1,
    );
    let response = p
        .client
        .post(&p.r.authority_endpoint)
        .headers(p.headers())
        .header("content-type", "application/json")
        .body(duplicate)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    for (name, value, code) in [
        ("origin", "https://browser.invalid", 403),
        ("host", "wrong.invalid", 421),
        ("content-type", "application/a2a+json", 415),
    ] {
        let mut h = p.headers();
        h.insert(name, value.parse().unwrap());
        let response = p
            .client
            .post(&p.r.authority_endpoint)
            .headers(h)
            .body(raw.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), code);
    }
    assert_eq!(
        p.client
            .get(&p.r.authority_endpoint)
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    assert_eq!(
        p.client
            .post(format!("{}?alias=1", p.r.authority_endpoint))
            .headers(p.headers())
            .json(&original)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
}
#[tokio::test]
async fn a2a_withdrawal_is_permanent_across_recreation_configuration_changes_and_races() {
    let Some(p) = Peer::new().await else { return };
    assert!(p.resolver.enroll().await.is_err());
    let q = serde_json::to_value(request(&p.r)).unwrap();
    let before = p.c.status().await.unwrap();
    let mut changed = p.r.clone();
    changed.readers[0].scope.resources = BTreeSet::from(["one".into()]);
    let changed = RootResolver::new(p.h.ledger.clone(), changed).unwrap();
    let mut identity = p.h.f.identity.clone();
    identity.scopes.insert(p.r.required_scope.clone());
    assert!(changed.resolve(&identity, &request(&p.r)).await.is_err());
    let (result, withdrawn) = tokio::join!(p.post(&q), p.resolver.withdraw());
    withdrawn.unwrap();
    assert!([200, 403].contains(&result.0.as_u16()));
    if result.0 == 200 {
        assert_eq!(result.1["execution_authority"], false);
    }
    assert_eq!(p.post(&q).await.0, 403);
    let recreated = RootResolver::new(p.h.ledger.clone(), p.r.clone()).unwrap();
    recreated.withdraw().await.unwrap();
    assert!(recreated.enroll().await.is_err());
    let mut changed = p.r.clone();
    changed.readers[0].scope.resources = BTreeSet::from(["one".into()]);
    let replacement = RootResolver::new(p.h.ledger.clone(), changed).unwrap();
    assert!(replacement.enroll().await.is_err());
    assert!(replacement.withdraw().await.is_err());
    assert_eq!(before, p.c.status().await.unwrap());
}
fn coord_key(p: &Peer) -> String {
    format!(
        "{}/coordination/{}",
        p.h.prefix,
        kedgeflow::contracts::digest("coordination-root", &json!(p.r.root_id)).unwrap()
    )
}
async fn mutate_key(_p: &Peer, key: &str, value: Option<&[u8]>) {
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    use base64::engine::general_purpose::STANDARD;
    let (route, body) = match value {
        Some(v) => (
            "put",
            json!({"key":STANDARD.encode(key),"value":STANDARD.encode(v)}),
        ),
        None => ("deleterange", json!({"key":STANDARD.encode(key)})),
    };
    let response = reqwest::Client::new()
        .post(format!("{endpoint}/v3/kv/{route}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
}
#[tokio::test]
async fn a2a_missing_corrupt_root_domain_and_duplicate_retained_scope_never_synthesize_views() {
    let Some(p) = Peer::new().await else { return };
    let q = serde_json::to_value(request(&p.r)).unwrap();
    let root = coord_key(&p);
    let original = p.h.ledger.read_key(&root).await.unwrap().unwrap();
    mutate_key(&p, &root, None).await;
    assert_eq!(p.post(&q).await.0, 403);
    mutate_key(&p, &root, Some(b"{broken")).await;
    assert_eq!(p.post(&q).await.0, 503);
    let mut state: Value = serde_json::from_slice(&original).unwrap();
    state["enrollment"]["scope"]["resources"] = json!(["one", "one", "two"]);
    mutate_key(&p, &root, Some(&serde_json::to_vec(&state).unwrap())).await;
    assert_eq!(p.post(&q).await.0, 503);
    mutate_key(&p, &root, Some(&original)).await;
    let domain = format!(
        "{}/coordination-domains/{}",
        p.h.prefix,
        kedgeflow::contracts::digest(
            "coordination-domain",
            &json!({"tenant":p.r.enrollment.tenant,"domain":p.r.enrollment.conflict_domain})
        )
        .unwrap()
    );
    let saved = p.h.ledger.read_key(&domain).await.unwrap().unwrap();
    mutate_key(&p, &domain, Some(b"substituted")).await;
    assert_eq!(p.post(&q).await.0, 403);
    mutate_key(&p, &domain, Some(&saved)).await;
    assert_eq!(p.post(&q).await.0, 200);
    let acl = format!(
        "{}/a2a-root-resolvers/{}",
        p.h.prefix,
        kedgeflow::contracts::digest(
            "a2a-root-resolution-key",
            &json!({"root_id":p.r.root_id,"delegation_id":p.r.delegation_id})
        )
        .unwrap()
    );
    let saved_acl = p.h.ledger.read_key(&acl).await.unwrap().unwrap();
    mutate_key(&p, &acl, None).await;
    assert_eq!(p.post(&q).await.0, 403);
    mutate_key(&p, &acl, Some(b"substituted ACL")).await;
    assert_eq!(p.post(&q).await.0, 403);
    mutate_key(&p, &acl, Some(&saved_acl)).await;
    assert_eq!(p.post(&q).await.0, 200);
    // Complete conservation is checked even for a sibling outside the reader's scope.
    let mut state: Value = serde_json::from_slice(&original).unwrap();
    state["allocations"][op(90)] = json!({"operation_digest":op(90),"parent":null,"scope":scope(&["inspect"],&["two"]),"forward":11,"compensation":0,"state":"allocated","attempt_id":null});
    mutate_key(&p, &root, Some(&serde_json::to_vec(&state).unwrap())).await;
    assert_ne!(p.post(&q).await.0, 200);
    state["allocations"][op(90)]["forward"] = json!(1);
    state["allocations"][op(90)]["scope"]["resources"] = json!(["two", "two"]);
    mutate_key(&p, &root, Some(&serde_json::to_vec(&state).unwrap())).await;
    assert_eq!(p.post(&q).await.0, 503);
}
#[tokio::test]
async fn a2a_registration_rejects_scope_identity_generation_endpoint_and_duplicate_sets() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let good = registration(&h, "https://localhost:9443/a2a/root:resolve");
    assert_eq!(good.agent_extension().unwrap()["uri"], EXTENSION);
    let mut bad = Vec::new();
    let mut r = good.clone();
    r.root_generation = 2;
    bad.push(json!(r));
    let mut r = good.clone();
    r.readers.push(r.readers[0].clone());
    bad.push(json!(r));
    let mut r = good.clone();
    r.readers[0].scope.resources.insert("outside".into());
    bad.push(json!(r));
    let mut r = good.clone();
    r.readers[0].workload_id = "unverified-workload".into();
    bad.push(json!(r));
    let mut r = good.clone();
    r.authority_endpoint = "http://localhost:9443/a2a/root:resolve".into();
    bad.push(json!(r));
    let mut r = good.clone();
    r.authority_endpoint = "https://localhost:9443/elsewhere".into();
    bad.push(json!(r));
    let mut v = json!(good);
    v["readers"][0]["scope"]["resources"] = json!(["one", "one"]);
    bad.push(v);
    for v in bad {
        assert!(Registration::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    let auth = DualAuthenticator::new(
        "https://wrong-issuer.invalid",
        AUD,
        &good.authority_endpoint,
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    let resolver = RootResolver::new(h.ledger.clone(), good.clone()).unwrap();
    assert!(RootResolutionService::new(resolver, auth, h.clock.clone()).is_err());
    let c = Coordination::new(h.ledger.clone(), &good.root_id).unwrap();
    let mut other = good.enrollment.clone();
    other.compensation += 1;
    c.enroll(other).await.unwrap();
    assert!(
        RootResolver::new(h.ledger.clone(), good)
            .unwrap()
            .enroll()
            .await
            .is_err()
    );
}
#[tokio::test]
async fn a2a_pinned_client_never_follows_reference_locations_or_accepts_redirected_authority() {
    use axum::{Router, body::Body, response::Response, routing::any};
    use std::sync::atomic::AtomicUsize;
    let Some(p) = Peer::new().await else { return };
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let trap = support::serve_tls(
        &p.h.agent_pki,
        Router::new().fallback(any(move || {
            let c = count.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                "trap"
            }
        })),
    )
    .await;
    let mut q = request(&p.r);
    q.part.data.authority_endpoint = format!("{}{PATH}", trap.url);
    assert!(p.pinned().resolve(&q, &p.headers()).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let location = format!("{}{PATH}", trap.url);
    let redirect = support::serve_tls(
        &p.h.agent_pki,
        Router::new().route(
            PATH,
            any(move || {
                let l = location.clone();
                async move {
                    Response::builder()
                        .status(307)
                        .header("location", l)
                        .body(Body::empty())
                        .unwrap()
                }
            }),
        ),
    )
    .await;
    let mut r = p.r.clone();
    r.authority_endpoint = format!("{}{PATH}", redirect.url);
    let pinned = HttpsRootResolver::new(
        r.clone(),
        kedgeflow::tls::pinned_client_pem(
            p.h.agent_pki.ca.as_bytes(),
            p.h.agent_pki.client.as_bytes(),
            p.h.agent_pki.client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(pinned.resolve(&request(&r), &p.headers()).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn a2a_client_refuses_forged_scope_correlation_tenant_and_execution_flags() {
    use axum::{Json, Router, routing::post};
    let Some(p) = Peer::new().await else { return };
    let q = request(&p.r);
    let (_, good) = p.post(&json!(q)).await;
    let mut bad = Vec::new();
    for (name, value) in [
        ("execution_authority", json!(true)),
        ("child_grants_supported", json!(true)),
        ("tenant", json!("other-tenant")),
        ("conflict_domain", json!("other-domain")),
        ("request_id", json!("other-request")),
        ("task_id", json!("other-task")),
        ("snapshot_digest", json!("not-a-digest")),
        ("parent_state", json!("allocated")),
    ] {
        let mut v = good.clone();
        v[name] = value;
        bad.push(v);
    }
    let mut v = good.clone();
    v["scope"]["resources"] = json!(["one", "two"]);
    bad.push(v);
    let mut v = good.clone();
    v["scope"]["resources"] = json!(["one", "one"]);
    bad.push(v);
    let mut v = good.clone();
    v["unregistered"] = json!(true);
    bad.push(v);
    for value in bad {
        let server = support::serve_tls(
            &p.h.agent_pki,
            Router::new().route(
                PATH,
                post(move || {
                    let v = value.clone();
                    async move { Json(v) }
                }),
            ),
        )
        .await;
        let mut r = p.r.clone();
        r.authority_endpoint = format!("{}{PATH}", server.url);
        let resolver = HttpsRootResolver::new(
            r.clone(),
            kedgeflow::tls::pinned_client_pem(
                p.h.agent_pki.ca.as_bytes(),
                p.h.agent_pki.client.as_bytes(),
                p.h.agent_pki.client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(resolver.resolve(&request(&r), &p.headers()).await.is_err());
    }
}
#[tokio::test]
async fn a2a_unavailable_storage_and_restore_quarantine_refuse_without_capacity_changes() {
    let Some(p) = Peer::new().await else { return };
    let before = p.c.status().await.unwrap();
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = dead.local_addr().unwrap();
    drop(dead);
    let ledger = EtcdLedger::new(
        reqwest::Client::new(),
        format!("http://{address}"),
        &p.h.prefix,
    )
    .unwrap();
    let resolver = RootResolver::new(ledger, p.r.clone()).unwrap();
    let mut identity = p.h.f.identity.clone();
    identity.scopes.insert("kf.root.resolve".into());
    assert!(matches!(
        resolver.resolve(&identity, &request(&p.r)).await,
        Err(kedgeflow::error::Error::Unavailable(_))
    ));
    let marker = format!("{}/restore-gate", p.h.prefix);
    mutate_key(&p, &marker, Some(b"enrolled-test-marker")).await;
    assert_eq!(p.post(&json!(request(&p.r))).await.0, 403);
    assert!(p.resolver.withdraw().await.is_err());
    mutate_key(&p, &marker, None).await;
    assert_eq!(before, p.c.status().await.unwrap());
}
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_shipping_control_checks_enrolls_serves_withdraws_and_restarts() {
    use axum::{Extension, Json, Router, response::IntoResponse, routing::post};
    use base64::engine::general_purpose::STANDARD;
    use kedgeflow::auth::WorkloadIdentity;
    use std::os::unix::fs::PermissionsExt;
    let Some(p) = Peer::new().await else { return };
    let h = &p.h;
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let proxy = support::serve_tls(
        &h.agent_pki,
        Router::new().route(
            "/v3/kv/txn",
            post(
                move |Extension(w): Extension<WorkloadIdentity>,
                      headers: http::HeaderMap,
                      Json(v): Json<Value>| {
                    let endpoint = endpoint.clone();
                    async move {
                        assert_eq!(w.as_str(), "spiffe://test/agent");
                        assert_eq!(headers["authorization"], "operator-etcd-token");
                        let response = reqwest::Client::new()
                            .post(format!("{endpoint}/v3/kv/txn"))
                            .json(&v)
                            .send()
                            .await
                            .unwrap();
                        let code = response.status();
                        let bytes = response.bytes().await.unwrap();
                        (code, [("content-type", "application/json")], bytes).into_response()
                    }
                },
            ),
        ),
    )
    .await;
    let dir = tempfile::Builder::new()
        .prefix("kf-a2a-cli-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, raw: &[u8]| {
        let path = dir.path().join(name);
        std::fs::write(&path, raw).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let ca = write("ca.pem", h.agent_pki.ca.as_bytes());
    let cert = write("server.pem", h.agent_pki.server.as_bytes());
    let key = write("server-key.pem", h.agent_pki.server_key.as_bytes());
    let client = write("client.pem", h.agent_pki.client.as_bytes());
    let client_key = write("client-key.pem", h.agent_pki.client_key.as_bytes());
    let token_file = write("etcd-token", b"operator-etcd-token");
    let admission = write("admission", STANDARD.encode([6; 32]).as_bytes());
    let issuer = write("issuer", STANDARD.encode([5; 32]).as_bytes());
    let encoded = |map: &BTreeMap<String, ed25519_dalek::VerifyingKey>| {
        map.iter()
            .map(|(id, k)| (id.clone(), STANDARD.encode(k.as_bytes())))
            .collect::<BTreeMap<_, _>>()
    };
    let evidence:BTreeMap<_,_>=h.f.trust.evidence.iter().map(|(id,e)|(id,json!({"obligation":e.obligation,"provider_id":e.provider_id,"provider_version":e.provider_version,"keys":encoded(&e.keys),"question":e.question,"result_schema_ref":e.result_schema_ref,"result_schema":e.result_schema,"max_age_ms":e.max_age_ms,"predicates":e.predicates}))).collect();
    let listen = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listen.local_addr().unwrap();
    drop(listen);
    let origin = format!("https://{address}");
    let mut r = p.r.clone();
    r.authority_endpoint = format!("{origin}{PATH}");
    r.delegation_id = "shipping-reader".into();
    let mut config: Value =
        serde_json::from_str(include_str!("../../../../config/control.example.json")).unwrap();
    let material = json!({"a2a":r,"listen":address.to_string(),"admission_url":format!("{origin}/admission"),"issuance_url":format!("{origin}/issuance"),"status_url":format!("{origin}/status"),"delegation_audience":AUD,"oidc_issuer":h.f.identity.subject.iss,"oidc_public_key_base64":STANDARD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),"require_control":true,"gateway_audience":h.registration.scope.audience,"certificate":cert,"private_key":key,"workload_ca":ca,"etcd_endpoint":proxy.url,"etcd_prefix":h.prefix,"etcd_ca":ca,"etcd_certificate":client,"etcd_private_key":client_key,"etcd_token_file":token_file,"admission_signing_key_file":admission,"issuer_signing_key_file":issuer,"tenant":h.f.trust.tenant,"workload_id":h.f.trust.proposal_workload_id,"subjects":[h.f.identity.subject],"descriptor_digest":h.f.trust.descriptor_digest,"ownership_epoch":h.f.trust.ownership_epoch,"policy":{"id":h.f.trust.policy.id,"epoch":h.f.trust.policy.epoch,"cedar":h.definition.cedar,"max_certificate_lifetime_ms":h.definition.max_certificate_lifetime_ms},"proposal_keys":encoded(&keys(1)),"registry_keys":encoded(&keys(2)),"manifest_keys":encoded(&keys(3)),"evidence":evidence});
    config
        .as_object_mut()
        .unwrap()
        .extend(material.as_object().unwrap().clone());
    let path = write("control.json", &serde_json::to_vec(&config).unwrap());
    let run = |flag: &str| {
        let path = path.clone();
        let flag = flag.to_owned();
        async move {
            tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-control"))
                .arg("--config")
                .arg(path)
                .arg(flag)
                .output()
                .await
                .unwrap()
        }
    };
    let before = p.c.status().await.unwrap();
    for flag in ["--check", "--print-a2a-extension"] {
        let out = run(flag).await;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        if flag == "--print-a2a-extension" {
            assert_eq!(
                serde_json::from_slice::<Value>(&out.stdout).unwrap()["uri"],
                EXTENSION
            );
        }
    }
    let mut identity = h.f.identity.clone();
    identity.scopes.insert("kf.root.resolve".into());
    let resolver = RootResolver::new(h.ledger.clone(), r.clone()).unwrap();
    assert!(resolver.resolve(&identity, &request(&r)).await.is_err());
    let out = run("--enroll-a2a-root").await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!run("--enroll-a2a-root").await.status.success());
    let headers = || {
        let now = kedgeflow::clock::Clock::now_ms(&kedgeflow::clock::SystemClock) / 1000;
        let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
        let token = jwt(
            json!({"alg":"EdDSA","typ":"at+jwt"}),
            json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":AUD,"exp":now+60,"iat":now,"scope":"kf.root.resolve","cnf":{"jkt":jkt}}),
            7,
        );
        let proof = jwt(
            json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":h.jwk}),
            json!({"jti":format!("shipping-{}",h.jti.fetch_add(1,Ordering::SeqCst)),"htm":"POST","htu":r.authority_endpoint,"iat":now,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}),
            8,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("DPoP {token}").parse().unwrap());
        headers.insert("dpop", proof.parse().unwrap());
        headers.insert("a2a-version", "1.0".parse().unwrap());
        headers.insert("a2a-extensions", EXTENSION.parse().unwrap());
        headers
    };
    let spawn = || {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-control"))
            .arg("--config")
            .arg(&path)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    };
    let post = || {
        p.client
            .post(&r.authority_endpoint)
            .headers(headers())
            .json(&request(&r))
    };
    let mut child = spawn();
    let mut first = None;
    for _ in 0..100 {
        if let Ok(response) = post().send().await {
            first = Some(response);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let response = first.expect("shipping control listener did not start");
    assert_eq!(response.status(), 200);
    let view: Value = response.json().await.unwrap();
    assert_eq!(view["execution_authority"], false);
    // Existing authority route still handles its own profile after router composition.
    let response = p
        .client
        .post(format!("{origin}/admission"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let out = run("--withdraw-a2a-root").await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(run("--withdraw-a2a-root").await.status.success());
    assert_eq!(post().send().await.unwrap().status(), 403);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let mut restarted = spawn();
    let mut status = None;
    for _ in 0..100 {
        if let Ok(response) = post().send().await {
            status = Some(response.status());
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(status.unwrap(), 403);
    restarted.kill().await.unwrap();
    restarted.wait().await.unwrap();
    config["a2a"]["readers"][0]["scope"]["resources"] = json!(["one"]);
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run("--enroll-a2a-root").await.status.success());
    config["a2a"]["enrollment"]["tenant"] = json!("other-tenant");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run("--check").await.status.success());
    config["a2a"] = json!(r);
    config["a2a"]["readers"][0]["scope"]["resources"] = json!(["one", "one"]);
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run("--check").await.status.success());
    config.as_object_mut().unwrap().remove("a2a");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(run("--check").await.status.success());
    let mut legacy = spawn();
    let mut status = None;
    for _ in 0..100 {
        if let Ok(response) = post().send().await {
            status = Some(response.status());
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(status.unwrap(), 404);
    legacy.kill().await.unwrap();
    legacy.wait().await.unwrap();
    assert_eq!(before, p.c.status().await.unwrap());
}
#[tokio::test]
async fn a2a_native_v2_reservation_views_preserve_history_costs_and_claimed_attempt() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let mut budget = super::reserved_leaf::registration(&h, 2);
    budget.profile = kedgeflow::reservation_history::LEAF_PROFILE.into();
    h.ledger = h.ledger.clone().with_reservation(budget.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let record = h.issue().await.unwrap().record;
    let grant = GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    }
    .verify_retained(record.signed_grant.as_bytes())
    .unwrap()
    .grant;
    h.ledger
        .claim(&grant, &record.grant_digest, "native-original-attempt")
        .await
        .unwrap();
    let mut r = registration(&h, "https://localhost:9443/a2a/root:resolve");
    r.root_id = budget.root_id.clone();
    r.enrollment = budget.enrollment.clone();
    r.readers[0].scope = budget.enrollment.scope.clone();
    let resolver = RootResolver::new(h.ledger.clone(), r.clone()).unwrap();
    resolver.enroll().await.unwrap();
    let c = Coordination::new(h.ledger.clone(), &r.root_id).unwrap();
    let before = c.status().await.unwrap();
    let head = format!(
        "{}/reservation-history/{}/head",
        h.prefix,
        budget.digest().unwrap()
    );
    let history = h.ledger.read_key(&head).await.unwrap().unwrap();
    let mut identity = h.f.identity.clone();
    identity.scopes.insert(r.required_scope.clone());
    let mut q = request(&r);
    q.scope = r.enrollment.scope.clone();
    q.parent_operation = Some(record.issuance_key.clone());
    let view = resolver.resolve(&identity, &q).await.unwrap();
    assert_eq!(view.parent_state, Some(ReservationState::Unknown));
    assert!(!view.execution_authority);
    assert_eq!(before, c.status().await.unwrap());
    assert_eq!(Some(history), h.ledger.read_key(&head).await.unwrap());
    assert_eq!(
        before.allocations[&record.issuance_key]
            .attempt_id
            .as_deref(),
        Some("native-original-attempt")
    );
    assert!(
        c.consume(&record.issuance_key, "replacement")
            .await
            .is_err()
    );
    h.ledger.stop_reservation().await.unwrap();
    assert!(!resolver.resolve(&identity, &q).await.unwrap().root_active);
    let issued = h.issue().await;
    assert!(issued.is_err());
}
#[tokio::test]
async fn a2a_shared_dpop_replay_across_native_replicas_changes_no_capacity() {
    use kedgeflow::shared_auth::{SharedAuthConfig, SubjectWorkload};
    let Some(p) = Peer::new().await else { return };
    let config = SharedAuthConfig {
        capacity: 32,
        registrations: vec![SubjectWorkload {
            subject: p.h.f.identity.subject.clone(),
            workload_id: "spiffe://test/agent".into(),
            allowed_scopes: BTreeSet::from([p.r.required_scope.clone()]),
        }],
    };
    let auth = || {
        DualAuthenticator::new(
            &p.h.f.identity.subject.iss,
            AUD,
            &p.r.authority_endpoint,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
        .with_shared_replay(p.h.ledger.clone(), config.clone())
        .unwrap()
    };
    let a = auth();
    let b = auth();
    let der = rustls_pemfile::certs(&mut std::io::BufReader::new(
        p.h.agent_pki.client.as_bytes(),
    ))
    .next()
    .unwrap()
    .unwrap();
    let workload = kedgeflow::auth::WorkloadIdentity::from_verified_cert_der(der.as_ref()).unwrap();
    let proof = p.headers();
    let before = p.c.status().await.unwrap();
    let (one, two) = tokio::join!(
        a.authenticate_shared_at(&proof, &workload, NOW / 1000),
        b.authenticate_shared_at(&proof, &workload, NOW / 1000)
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    let identity = one.or(two).unwrap();
    let view = p.resolver.resolve(&identity, &request(&p.r)).await.unwrap();
    assert!(!view.execution_authority);
    let recreated = auth();
    assert!(
        recreated
            .authenticate_shared_at(&proof, &workload, NOW / 1000)
            .await
            .is_err()
    );
    assert_eq!(before, p.c.status().await.unwrap());
}
