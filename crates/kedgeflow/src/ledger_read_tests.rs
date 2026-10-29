//! Real-etcd snapshot races; the proxy never fabricates a successful read.
use super::*;
use axum::{Json, Router, extract::State, routing::post};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Fixture {
    client: Client,
    backend: String,
    target: String,
    watched: std::sync::Mutex<String>,
    epoch: String,
    races: AtomicUsize,
    reads: AtomicUsize,
    mutations: AtomicUsize,
    malformed: AtomicBool,
    hold: AtomicBool,
}
impl Fixture {
    async fn send(&self, request: Value) -> Value {
        self.client
            .post(format!("{}/v3/kv/txn", self.backend))
            .json(&request)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn epoch_bytes(&self) -> Vec<u8> {
        let response = self
            .send(json!({"compare":[],"success":[get(&self.epoch)],"failure":[]}))
            .await;
        range_kv(&response["responses"][0]).unwrap().unwrap().value
    }
    async fn sequence(&self) -> u64 {
        serde_json::from_slice::<Value>(&self.epoch_bytes().await).unwrap()["sequence"]
            .as_u64()
            .unwrap()
    }
}
async fn relay(State(f): State<Arc<Fixture>>, Json(request): Json<Value>) -> Json<Value> {
    let success = request["success"].as_array().unwrap();
    let watched = STANDARD.encode(f.watched.lock().unwrap().as_bytes());
    let target_read = success
        .iter()
        .any(|op| op["request_range"]["key"] == watched);
    if success.iter().any(|op| op.get("request_put").is_some()) {
        f.mutations.fetch_add(1, Ordering::SeqCst);
    }
    if target_read {
        f.reads.fetch_add(1, Ordering::SeqCst);
        if f.hold.swap(false, Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
        if f.races
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            let old = f.epoch_bytes().await;
            let mut next: Value = serde_json::from_slice(&old).unwrap();
            let sequence = next["sequence"].as_u64().unwrap() + 1;
            next["sequence"] = json!(sequence);
            next["nonce"] = json!(hex::encode(rand::random::<[u8; 32]>()));
            let changed = f.send(json!({"compare":[value_eq(&f.epoch, std::str::from_utf8(&old).unwrap())],
                "success":[put(&f.epoch, &record(&next).unwrap()),put(&f.target, &format!("after-{sequence}"))],"failure":[]})).await;
            assert_eq!(
                changed["succeeded"], true,
                "real concurrent writer must win its CAS"
            );
        }
    }
    let mut response = f.send(request).await;
    if target_read && f.malformed.swap(false, Ordering::SeqCst) {
        response["responses"] = json!([]);
    }
    Json(response)
}
fn relocate(value: &mut Value, old: &str, namespace: &str) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if key == "namespace" && value.as_str() == Some(old) {
                    *value = json!(namespace);
                } else {
                    relocate(value, old, namespace);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                relocate(value, old, namespace);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn guarded_reads_recapture_real_epoch_without_retrying_mutations_or_bad_replies() {
    let Ok(backend) = std::env::var("ETCD_ENDPOINT") else {
        assert_ne!(
            std::env::var("KF_REQUIRE_ETCD").as_deref(),
            Ok("1"),
            "required real etcd missing"
        );
        eprintln!("SKIP real-etcd guarded read regression: ETCD_ENDPOINT missing");
        return;
    };
    let namespace = format!("/kf-read-epoch-{}", rand::random::<u64>());
    let mut trust: Value = serde_json::from_str(include_str!("../../../results/verification/rfc-m8-kubernetes-process-boundaries-2026-10-23/native-artifacts/family-saga-two-sql/audit-trust.json")).unwrap();
    let old = trust["registration"]["namespace"]
        .as_str()
        .unwrap()
        .to_owned();
    relocate(&mut trust, &old, &namespace);
    let registration: crate::family::Registration =
        serde_json::from_value(trust["registration"].clone()).unwrap();
    registration.validate().unwrap();
    let f = Arc::new(Fixture {
        client: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        backend,
        target: format!("{namespace}/read-test"),
        watched: std::sync::Mutex::new(format!("{namespace}/read-test")),
        epoch: format!("{namespace}/family/saga/epoch"),
        races: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        mutations: AtomicUsize::new(0),
        malformed: AtomicBool::new(false),
        hold: AtomicBool::new(false),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/v3/kv/txn", post(relay))
        .with_state(f.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let base = EtcdLedger::new(f.client.clone(), endpoint, &namespace).unwrap();
    let family = crate::family::Family::new(base, registration).unwrap();
    family.enroll().await.unwrap();
    let ledger = family.manager_ledger();
    let initial = f.sequence().await;
    f.races.store(1, Ordering::SeqCst);
    assert_eq!(
        ledger.read_key(&f.target).await.unwrap().unwrap(),
        format!("after-{}", initial + 1).as_bytes()
    );
    assert_eq!(f.reads.load(Ordering::SeqCst), 2);
    assert_eq!(f.sequence().await, initial + 1);

    f.reads.store(0, Ordering::SeqCst);
    f.races.store(1, Ordering::SeqCst);
    assert_eq!(
        ledger
            .read_keys(&[f.target.clone(), format!("{namespace}/missing")])
            .await
            .unwrap(),
        vec![Some(format!("after-{}", initial + 2).into_bytes()), None]
    );
    assert_eq!(f.reads.load(Ordering::SeqCst), 2);
    f.reads.store(0, Ordering::SeqCst);
    f.races.store(3, Ordering::SeqCst);
    let error = ledger.read_key(&f.target).await.unwrap_err();
    assert!(
        matches!(error, Error::Unavailable(ref reason) if reason == "native guarded read epoch raced")
    );
    assert_eq!(f.reads.load(Ordering::SeqCst), 3);
    assert_eq!(f.sequence().await, initial + 5);

    f.reads.store(0, Ordering::SeqCst);
    f.malformed.store(true, Ordering::SeqCst);
    let error = ledger.read_key(&f.target).await.unwrap_err();
    assert!(
        matches!(error, Error::Unavailable(ref reason) if reason == "invalid guarded read response shape")
    );
    assert_eq!(f.reads.load(Ordering::SeqCst), 1);
    let mutations = f.mutations.load(Ordering::SeqCst);
    assert!(matches!(
        ledger
            .guarded_ranges(vec![put(&f.target, "forbidden")])
            .await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(f.mutations.load(Ordering::SeqCst), mutations);
    let never = format!("{namespace}/never-written");
    assert!(
        !ledger
            .txn(
                vec![version_zero(&f.target)],
                vec![put(&never, "must-not-appear")],
                vec![]
            )
            .await
            .unwrap()
            .succeeded
    );
    assert_eq!(f.mutations.load(Ordering::SeqCst), mutations + 1);
    assert!(ledger.read_key(&never).await.unwrap().is_none());
    assert_eq!(f.sequence().await, initial + 5);
    f.reads.store(0, Ordering::SeqCst);
    f.hold.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let error = ledger.read_key(&f.target).await.unwrap_err();
    assert!(
        matches!(error, Error::Unavailable(ref reason) if reason == "native guarded read deadline elapsed")
    );
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(6));
    assert_eq!(f.reads.load(Ordering::SeqCst), 1);
    // Snapshot recovery may recapture its read, but missing original authority
    // must remain missing. No synthetic positive recovery records are installed.
    let envelope: Value =
        serde_json::from_str(include_str!("../../../fixtures/grant.json")).unwrap();
    let grant: Grant = serde_json::from_value(envelope["payload"].clone()).unwrap();
    let candidate = crate::recovery::Candidate {
        grant,
        attempt_id: "read-only-missing".into(),
    };
    *f.watched.lock().unwrap() = ledger.root(&candidate.grant);
    f.reads.store(0, Ordering::SeqCst);
    f.races.store(1, Ordering::SeqCst);
    let error = ledger.recovery_snapshot(&candidate).await.err().unwrap();
    assert!(
        matches!(error, Error::Unavailable(ref reason) if reason == "inconsistent recovery snapshot: missing record 3")
    );
    assert_eq!(f.reads.load(Ordering::SeqCst), 2);
    *f.watched.lock().unwrap() = format!("{namespace}/recovery/index/");
    f.reads.store(0, Ordering::SeqCst);
    f.races.store(1, Ordering::SeqCst);
    let (page, cursor) = ledger.recovery_page(None, 8).await.unwrap();
    assert!(page.is_empty() && cursor.is_none());
    assert_eq!(f.reads.load(Ordering::SeqCst), 2);
    assert_eq!(f.sequence().await, initial + 7);
    server.abort();
    let _ = server.await;
}
