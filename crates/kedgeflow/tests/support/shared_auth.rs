//! Reuses the existing signed identity vectors; real etcd, no local fallback.
use super::*;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    ledger::EtcdLedger,
    shared_auth::{PROFILE, SharedAuthConfig, SubjectWorkload},
};
fn config(capacity: usize) -> SharedAuthConfig {
    SharedAuthConfig {
        capacity,
        registrations: vec![SubjectWorkload {
            subject: kedgeflow::contracts::Subject {
                iss: ISSUER.into(),
                sub: "user".into(),
            },
            workload_id: "spiffe://test/agent".into(),
            allowed_scopes: BTreeSet::from(["mutate".into(), "read".into()]),
        }],
    }
}
fn ledger() -> Option<EtcdLedger> {
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
            eprintln!("SKIP shared authentication: ETCD_ENDPOINT absent");
            return None;
        }
    };
    Some(
        EtcdLedger::new(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            &endpoint,
            format!(
                "/kf-auth/{}/{:x}",
                std::process::id(),
                rand::random::<u64>()
            ),
        )
        .unwrap(),
    )
}
fn shared(l: &EtcdLedger, c: SharedAuthConfig) -> DualAuthenticator {
    verifier().with_shared_replay(l.clone(), c).unwrap()
}
fn key(l: &EtcdLedger) -> String {
    let realm = digest(
        "authentication-realm",
        &json!({
            "profile":PROFILE,"issuer":ISSUER,"audience":ENDPOINT,"external_url":ENDPOINT
        }),
    )
    .unwrap();
    format!("{}/authentication/replay/{realm}", l.namespace())
}
async fn read(l: &EtcdLedger) -> Option<Value> {
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let r: Value = reqwest::Client::new()
        .post(format!("{endpoint}/v3/kv/range"))
        .json(&json!({"key":STANDARD.encode(key(l))}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    r["kvs"].as_array().and_then(|k| k.first()).map(|v| {
        serde_json::from_slice(&STANDARD.decode(v["value"].as_str().unwrap()).unwrap()).unwrap()
    })
}
async fn overwrite(l: &EtcdLedger, k: &str, raw: &str) {
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let r = reqwest::Client::new()
        .post(format!("{endpoint}/v3/kv/put"))
        .json(&json!({"key":STANDARD.encode(k),"value":STANDARD.encode(raw)}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let _ = l;
}
#[tokio::test]
async fn independent_replicas_and_restart_consume_one_proof() {
    let Some(l) = ledger() else {
        return;
    };
    let a = shared(&l, config(4));
    let b = shared(&l, config(4));
    let w = workload(&["spiffe://test/agent"]);
    let (h, _, _, _) = vectors("valid", "shared-once", NOW);
    assert!(a.authenticate_at(&h, &w, NOW).is_err());
    let (x, y) = tokio::join!(
        a.authenticate_shared_at(&h, &w, NOW),
        b.authenticate_shared_at(&h, &w, NOW)
    );
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    assert!(
        shared(&l, config(4))
            .authenticate_shared_at(&h, &w, NOW)
            .await
            .is_err()
    );
    assert_eq!(
        read(&l).await.unwrap()["entries"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    let (fresh, _, _, _) = vectors("valid", "fresh-after-restart", NOW);
    shared(&l, config(4))
        .authenticate_shared_at(&fresh, &w, NOW)
        .await
        .unwrap();
}
#[tokio::test]
async fn registration_substitution_refuses_before_consumption() {
    let Some(l) = ledger() else {
        return;
    };
    let w = workload(&["spiffe://test/agent"]);
    let (h, _, _, _) = vectors("valid", "registered-only", NOW);
    let a = shared(&l, config(4));
    assert!(
        a.authenticate_shared_at(&h, &workload(&["spiffe://test/other"]), NOW)
            .await
            .is_err()
    );
    let mut c = config(4);
    c.registrations[0].subject.sub = "other".into();
    assert!(
        shared(&l, c)
            .authenticate_shared_at(&h, &w, NOW)
            .await
            .is_err()
    );
    let mut c = config(4);
    c.registrations[0].allowed_scopes.remove("mutate");
    assert!(
        shared(&l, c)
            .authenticate_shared_at(&h, &w, NOW)
            .await
            .is_err()
    );
    let (invalid, _, _, _) = vectors("wrong_dpop_signature", "registered-only", NOW);
    assert!(a.authenticate_shared_at(&invalid, &w, NOW).await.is_err());
    assert!(read(&l).await.is_none());
    a.authenticate_shared_at(&h, &w, NOW).await.unwrap();
}
#[tokio::test]
async fn shared_capacity_retains_future_proof_through_full_window() {
    let Some(l) = ledger() else {
        return;
    };
    let w = workload(&["spiffe://test/agent"]);
    let a = shared(&l, config(1));
    let (h, _, _, _) = vectors("valid", "future-proof", NOW + 5);
    a.authenticate_shared_at(&h, &w, NOW).await.unwrap();
    assert_eq!(
        read(&l).await.unwrap()["entries"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap(),
        NOW + 71
    );
    let (other, _, _, _) = vectors("valid", "next", NOW + 65);
    assert!(
        a.authenticate_shared_at(&other, &w, NOW + 65)
            .await
            .is_err()
    );
    assert!(a.authenticate_shared_at(&h, &w, NOW + 65).await.is_err());
    assert_eq!(read(&l).await.unwrap()["last_seen"], NOW);
    let (other, _, _, _) = vectors("valid", "next", NOW + 71);
    a.authenticate_shared_at(&other, &w, NOW + 71)
        .await
        .unwrap();
    assert!(a.authenticate_shared_at(&h, &w, NOW + 71).await.is_err());
    assert_eq!(
        read(&l).await.unwrap()["entries"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn clock_regression_and_registration_drift_preserve_state() {
    let Some(l) = ledger() else {
        return;
    };
    let w = workload(&["spiffe://test/agent"]);
    let (h, _, _, _) = vectors("valid", "first", NOW);
    shared(&l, config(4))
        .authenticate_shared_at(&h, &w, NOW + 1)
        .await
        .unwrap();
    let before = read(&l).await.unwrap();
    let (fresh, _, _, _) = vectors("valid", "second", NOW);
    assert!(
        shared(&l, config(4))
            .authenticate_shared_at(&fresh, &w, NOW)
            .await
            .is_err()
    );
    assert!(
        shared(&l, config(5))
            .authenticate_shared_at(&fresh, &w, NOW + 1)
            .await
            .is_err()
    );
    let mut c = config(4);
    c.registrations[0].allowed_scopes.insert("admin".into());
    assert!(
        shared(&l, c)
            .authenticate_shared_at(&fresh, &w, NOW + 1)
            .await
            .is_err()
    );
    assert_eq!(read(&l).await.unwrap(), before);
}
#[tokio::test]
async fn corrupt_state_and_restore_quarantine_cannot_fall_back() {
    let Some(l) = ledger() else {
        return;
    };
    let w = workload(&["spiffe://test/agent"]);
    let (h, _, _, _) = vectors("valid", "first", NOW);
    let a = shared(&l, config(4));
    a.authenticate_shared_at(&h, &w, NOW).await.unwrap();
    let original = read(&l).await.unwrap();
    let (fresh, _, _, _) = vectors("valid", "second", NOW);
    let mut corrupt = original.clone();
    corrupt["extra"] = json!(true);
    overwrite(&l, &key(&l), &corrupt.to_string()).await;
    assert!(a.authenticate_shared_at(&fresh, &w, NOW).await.is_err());
    assert_eq!(read(&l).await.unwrap(), corrupt);
    let mut corrupt = original.clone();
    corrupt["entries"][hex::encode([42u8; 32])] = json!(NOW + 72);
    overwrite(&l, &key(&l), &corrupt.to_string()).await;
    assert!(a.authenticate_shared_at(&fresh, &w, NOW).await.is_err());
    overwrite(&l, &key(&l), &original.to_string()).await;
    overwrite(&l, &format!("{}/restore-gate", l.namespace()), "{}").await;
    assert!(a.authenticate_shared_at(&fresh, &w, NOW).await.is_err());
    assert_eq!(read(&l).await.unwrap(), original);
}
#[tokio::test]
async fn shared_store_outage_has_no_process_local_acceptance() {
    let Some(l) = ledger() else {
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let dead = EtcdLedger::new(
        reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap(),
        &dead,
        l.namespace(),
    )
    .unwrap();
    let a = shared(&dead, config(4));
    let (h, _, _, _) = vectors("valid", "outage", NOW);
    let w = workload(&["spiffe://test/agent"]);
    for _ in 0..2 {
        assert!(a.authenticate_shared_at(&h, &w, NOW).await.is_err());
    }
    assert!(read(&l).await.is_none());
    shared(&l, config(4))
        .authenticate_shared_at(&h, &w, NOW)
        .await
        .unwrap();
}
#[tokio::test]
async fn lost_successful_consumption_reply_is_consumed_after_restart() {
    use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
    async fn proxy(
        State(endpoint): State<String>,
        Json(v): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        let reply: Value = reqwest::Client::new()
            .post(format!("{endpoint}/v3/kv/txn"))
            .json(&v)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let write = v["success"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.get("request_put").is_some());
        (
            if write {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            },
            Json(reply),
        )
    }
    let Some(l) = ledger() else {
        return;
    };
    let router = Router::new()
        .route("/v3/kv/txn", post(proxy))
        .with_state(std::env::var("ETCD_ENDPOINT").unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let proxied = EtcdLedger::new(reqwest::Client::new(), &endpoint, l.namespace()).unwrap();
    let (h, _, _, _) = vectors("valid", "lost-reply", NOW);
    let w = workload(&["spiffe://test/agent"]);
    assert!(
        shared(&proxied, config(4))
            .authenticate_shared_at(&h, &w, NOW)
            .await
            .is_err()
    );
    assert_eq!(
        read(&l).await.unwrap()["entries"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert!(
        shared(&l, config(4))
            .authenticate_shared_at(&h, &w, NOW)
            .await
            .is_err()
    );
    task.abort();
    let _ = task.await;
}
#[test]
fn shared_registration_and_state_are_closed_and_bounded() {
    let mut c = config(0);
    assert!(c.validate(ISSUER).is_err());
    c.capacity = 4097;
    assert!(c.validate(ISSUER).is_err());
    c = config(1);
    c.registrations.push(c.registrations[0].clone());
    assert!(c.validate(ISSUER).is_err());
    c = config(1);
    c.registrations[0].subject.iss = "other".into();
    assert!(c.validate(ISSUER).is_err());
    c = config(1);
    c.registrations[0].workload_id = "spiffe://test/../other".into();
    assert!(c.validate(ISSUER).is_err());
    let mut v = serde_json::to_value(config(4)).unwrap();
    v["registrations"][0]["allowed_scopes"] = json!(["read", "read"]);
    assert!(serde_json::from_value::<SharedAuthConfig>(v).is_err());
    let v = json!({"profile":PROFILE,"registration_digest":hex::encode([0u8;32]),"last_seen":NOW,"entries":{}});
    kedgeflow::shared_auth::validate_state(&v).unwrap();
    let mut v = v;
    v["entries"]["raw-jti"] = json!(NOW);
    assert!(kedgeflow::shared_auth::validate_state(&v).is_err());
}
