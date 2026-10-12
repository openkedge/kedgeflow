//! Native authority + separate single-member witness etcd. Snapshot rollback is
//! a privileged stopped prefix copy, not a disk/power-loss rehearsal.
#[allow(dead_code, unused_imports)]
#[path = "support/admission_fixture.rs"]
mod fixture;
mod support;
use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use fixture::{Fixture, NOW, Time, signed};
use kedgeflow::{
    auth::WorkloadIdentity,
    contracts::{Grant, sign_grant},
    error::Error,
    ledger::{AuthorityLedger, EtcdLedger},
    restore::{RestoreGate, RestoreHead, WitnessRecord, WitnessState},
};
use reqwest::Client;
use serde_json::{Value, json};
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::TempDir;
const GD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn wire(s: &str) -> String {
    STANDARD.encode(s)
}
fn put(k: &str, v: &str) -> Value {
    json!({"request_put":{"key":wire(k),"value":wire(v)}})
}
async fn txn(endpoint: &str, body: Value) -> Value {
    Client::new()
        .post(format!("{endpoint}/v3/kv/txn"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
struct WitnessProcess {
    child: Child,
    _dir: TempDir,
    endpoint: String,
}
impl Drop for WitnessProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl WitnessProcess {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let client = port();
        let mut peer = port();
        while peer == client {
            peer = port();
        }
        let endpoint = format!("http://127.0.0.1:{client}");
        let peer = format!("http://127.0.0.1:{peer}");
        let binary = std::env::var("ETCD_BINARY").unwrap_or_else(|_| "etcd".into());
        let log = std::fs::File::create(dir.path().join("witness.log")).unwrap();
        let child = Command::new(binary)
            .args([
                "--name=witness",
                &format!("--data-dir={}", dir.path().join("data").display()),
                &format!("--listen-client-urls={endpoint}"),
                &format!("--advertise-client-urls={endpoint}"),
                &format!("--listen-peer-urls={peer}"),
                &format!("--initial-advertise-peer-urls={peer}"),
                &format!("--initial-cluster=witness={peer}"),
                "--initial-cluster-state=new",
                "--log-level=error",
            ])
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut p = Self {
            child,
            _dir: dir,
            endpoint,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                p.child.try_wait().unwrap().is_none(),
                "witness exited during startup"
            );
            if Client::new()
                .get(format!("{}/health", p.endpoint))
                .timeout(Duration::from_millis(200))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return p;
            }
            assert!(Instant::now() < deadline, "witness readiness timeout");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
struct Proxy {
    endpoint: String,
    role: &'static str,
    fault: AtomicU8,
}
fn writes(body: &Value) -> bool {
    ["success", "failure"].iter().any(|branch| {
        body[*branch].as_array().is_some_and(|ops| {
            ops.iter().any(|op| {
                op.get("request_txn")
                    .map_or_else(|| op.get("request_range").is_none(), writes)
            })
        })
    })
}
async fn proxy(
    State(p): State<Arc<Proxy>>,
    Extension(w): Extension<WorkloadIdentity>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(w.as_str(), "spiffe://test/restore-operator");
    assert_eq!(h["authorization"], p.role);
    let mutation = writes(&body);
    if mutation
        && p.fault
            .compare_exchange(3, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        let key = body["compare"][0]["key"].clone();
        txn(&p.endpoint, json!({"success":[{"request_put":{"key":key,"value":wire("corrupted-by-test-restore")}}]})).await;
    }
    let finalization = body["success"].as_array().unwrap().iter().any(|op| {
        op.get("request_put")
            .and_then(|v| v["value"].as_str())
            .and_then(|s| STANDARD.decode(s).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .is_some_and(|v| v["state"] == "ready")
    });
    let response = match Client::new()
        .post(format!("{}/v3/kv/txn", p.endpoint))
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r.error_for_status().unwrap().json::<Value>().await.unwrap(),
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"test witness unavailable"})),
            );
        }
    };
    let lose = mutation
        && (p
            .fault
            .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
            || (finalization
                && p.fault
                    .compare_exchange(2, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()));
    if lose {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"test-owned lost transaction response"})),
        );
    }
    (StatusCode::OK, Json(response))
}
struct Harness {
    local: String,
    prefix: String,
    witness: WitnessProcess,
    gate: RestoreGate,
    ledger: EtcdLedger,
    direct: EtcdLedger,
    local_proxy: Arc<Proxy>,
    witness_proxy: Arc<Proxy>,
    _servers: Vec<support::HttpsServer>,
    dir: TempDir,
    grant: Grant,
}
impl Harness {
    async fn new() -> Option<Self> {
        let local = match std::env::var("ETCD_ENDPOINT") {
            Ok(s) => s,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP restore test: ETCD_ENDPOINT required");
                return None;
            }
        };
        let witness = WitnessProcess::start().await;
        let dir = tempfile::tempdir().unwrap();
        let prefix = format!(
            "/kf-restore-tests/{}",
            hex::encode(rand::random::<[u8; 16]>())
        );
        let pki = support::pki_with_workload("spiffe://test/restore-operator");
        let local_proxy = Arc::new(Proxy {
            endpoint: local.clone(),
            role: "local-role",
            fault: AtomicU8::new(0),
        });
        let witness_proxy = Arc::new(Proxy {
            endpoint: witness.endpoint.clone(),
            role: "witness-role",
            fault: AtomicU8::new(0),
        });
        let l = support::serve_tls(
            &pki,
            Router::new()
                .route("/v3/kv/txn", post(proxy))
                .with_state(local_proxy.clone()),
        )
        .await;
        let w = support::serve_tls(
            &pki,
            Router::new()
                .route("/v3/kv/txn", post(proxy))
                .with_state(witness_proxy.clone()),
        )
        .await;
        for (name, value) in [
            ("ca.pem", pki.ca.as_str()),
            ("client.pem", pki.client.as_str()),
            ("key.pem", pki.client_key.as_str()),
            ("local.token", "local-role"),
            ("witness.token", "witness-role"),
        ] {
            std::fs::write(dir.path().join(name), value).unwrap();
        }
        let path = |s: &str| dir.path().join(s);
        let config = json!({"etcd_endpoint":l.url,"etcd_prefix":prefix,"etcd_ca":path("ca.pem"),"etcd_certificate":path("client.pem"),"etcd_private_key":path("key.pem"),"etcd_token_file":path("local.token"),
            "restore_gate":{"endpoint":w.url,"prefix":"/independent-witness","ca":path("ca.pem"),"certificate":path("client.pem"),"private_key":path("key.pem"),"token_file":path("witness.token")}});
        std::fs::write(path("restore.json"), serde_json::to_vec(&config).unwrap()).unwrap();
        let c = kedgeflow::restore::RestoreOperatorConfig::decode(
            &serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        let direct = c.ledger().await.unwrap();
        let gate = c.restore_gate.gate().await.unwrap();
        let ledger = direct
            .clone()
            .with_restore_gate(gate.clone())
            .unwrap()
            .with_clock(Arc::new(Time(NOW)));
        let mut payload = fixture::payload("grant");
        payload["valid_from"] = json!(NOW);
        payload["issued_at"] = json!(NOW);
        payload["expires_at"] = json!(NOW + 30000);
        let grant = serde_json::from_value(payload).unwrap();
        let h = Self {
            local,
            prefix,
            witness,
            gate,
            ledger,
            direct,
            local_proxy,
            witness_proxy,
            _servers: vec![l, w],
            dir,
            grant,
        };
        let output = h.cli("--enroll-empty").await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(h)
    }
    async fn cli(&self, flag: &str) -> std::process::Output {
        tokio::time::timeout(
            Duration::from_secs(8),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-restore"))
                .args([
                    flag,
                    "--config",
                    self.dir.path().join("restore.json").to_str().unwrap(),
                ])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn snapshot(&self) -> Vec<Value> {
        let t=txn(&self.local,json!({"success":[{"request_range":{"key":wire(&format!("{}/",self.prefix)),"range_end":wire(&format!("{}0",self.prefix))}}]})).await;
        t["responses"][0]["response_range"]["kvs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    async fn restore(&self, snapshot: Vec<Value>) {
        let mut ops = vec![
            json!({"request_delete_range":{"key":wire(&format!("{}/",self.prefix)),"range_end":wire(&format!("{}0",self.prefix))}}),
        ];
        // etcd rejects delete+put overlapping ranges in the same transaction.
        txn(&self.local, json!({"success":ops})).await;
        ops = snapshot
            .into_iter()
            .map(|kv| json!({"request_put":{"key":kv["key"],"value":kv["value"]}}))
            .collect();
        if !ops.is_empty() {
            txn(&self.local, json!({"success":ops})).await;
        }
    }
    async fn witness_record(&self) -> WitnessRecord {
        let t = txn(
            &self.witness.endpoint,
            json!({"success":[{"request_range":{"key":wire("/independent-witness/head")}}]}),
        )
        .await;
        let bytes = STANDARD
            .decode(
                t["responses"][0]["response_range"]["kvs"][0]["value"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn set_witness(&self, record: &WitnessRecord) {
        txn(&self.witness.endpoint,json!({"success":[put("/independent-witness/head",&String::from_utf8(kedgeflow::contracts::canonical(&serde_json::to_value(record).unwrap()).unwrap()).unwrap())]})).await;
    }
    async fn candidate(&self) -> kedgeflow::issuance::AdmittedIssuance {
        let f = Fixture::new();
        let p = f.packet();
        let (v, cert, mut g) = f.authority(&p);
        let cert = signed("certificate", cert, 3);
        g.certificate_digest = fixture::record_hash(&cert);
        let inputs = f
            .trust
            .verify_inputs(&f.identity, p.borrowed(), &Time(NOW))
            .unwrap();
        let admitted = v
            .validate_inputs(
                &inputs,
                &cert,
                &sign_grant(
                    &g,
                    "key-5",
                    &ed25519_dalek::SigningKey::from_bytes(&[5; 32]),
                )
                .unwrap(),
                &Time(NOW),
            )
            .unwrap();
        self.ledger.publish_policy(&g).await.unwrap();
        admitted
    }
    async fn assert_quarantined(&self) {
        let before = self.snapshot().await;
        assert!(self.gate.check(&self.ledger).await.is_err());
        assert!(matches!(
            self.ledger.publish_policy(&self.grant).await,
            Err(Error::Refused(_) | Error::Unavailable(_))
        ));
        assert!(
            self.ledger
                .claim(&self.grant, GD, "reopened")
                .await
                .is_err()
        );
        let status = self.cli("--status").await;
        assert!(!status.status.success());
        assert_eq!(
            self.snapshot().await,
            before,
            "quarantine must not change local state"
        );
    }
}
#[tokio::test]
async fn stale_snapshot_cannot_reopen_root_or_reset_fence() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.grant).await.unwrap();
    h.ledger.issue(&h.grant, GD).await.unwrap();
    let candidate = h.candidate().await;
    let stale = h.snapshot().await;
    let fence = h
        .ledger
        .reserve_fence(&candidate, &Time(NOW))
        .await
        .unwrap();
    assert_eq!(fence.fence(), 1);
    h.ledger.claim(&h.grant, GD, "original").await.unwrap();
    let latest = h.snapshot().await;
    let retained = h.witness_record().await;
    h.restore(stale).await;
    h.assert_quarantined().await;
    assert!(
        h.ledger
            .reserve_fence(&candidate, &Time(NOW))
            .await
            .is_err()
    );
    assert_eq!(h.witness_record().await, retained);
    assert!(!h.cli("--enroll-empty").await.status.success());
    h.restore(latest).await;
    assert!(h.cli("--status").await.status.success());
    assert!(matches!(
        h.ledger.claim(&h.grant, GD, "another").await,
        Err(Error::NonceConsumed)
    ));
    assert_eq!(
        h.ledger
            .reserve_fence(&candidate, &Time(NOW))
            .await
            .unwrap()
            .fence(),
        1
    );
    println!(
        "restore matrix: stale snapshot quarantined; exact latest snapshot preserves original consumption and fence"
    );
}
#[tokio::test]
async fn missing_local_marker_including_pre_enrollment_snapshot_is_quarantined() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.restore(Vec::new()).await;
    h.assert_quarantined().await;
    assert!(!h.cli("--enroll-empty").await.status.success());
}
#[tokio::test]
async fn omitted_gate_and_wrong_or_missing_witness_refuse() {
    let Some(h) = Harness::new().await else {
        return;
    };
    assert!(matches!(
        h.direct.publish_policy(&h.grant).await,
        Err(Error::Refused(_))
    ));
    let mut r = h.witness_record().await;
    r.head.enrollment = "b".repeat(64);
    h.set_witness(&r).await;
    h.assert_quarantined().await;
    txn(
        &h.witness.endpoint,
        json!({"success":[{"request_delete_range":{"key":wire("/independent-witness/head")}}]}),
    )
    .await;
    h.assert_quarantined().await;
}
#[tokio::test]
async fn reservation_reply_loss_leaves_pending_without_local_mutation() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let before = h.snapshot().await;
    h.witness_proxy.fault.store(1, Ordering::SeqCst);
    assert!(h.ledger.publish_policy(&h.grant).await.is_err());
    assert_eq!(h.witness_record().await.state, WitnessState::Pending);
    assert_eq!(h.snapshot().await, before);
    h.assert_quarantined().await;
}
#[tokio::test]
async fn local_commit_reply_loss_keeps_advanced_state_quarantined() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let old = h.gate.check(&h.ledger).await.unwrap();
    h.local_proxy.fault.store(1, Ordering::SeqCst);
    assert!(h.ledger.publish_policy(&h.grant).await.is_err());
    let w = h.witness_record().await;
    assert_eq!(w.state, WitnessState::Pending);
    assert_eq!(w.head.sequence, old.sequence + 1);
    let snapshot = h.snapshot().await;
    let marker = snapshot
        .iter()
        .find(|kv| {
            STANDARD.decode(kv["key"].as_str().unwrap()).unwrap()
                == format!("{}/restore-gate", h.prefix).as_bytes()
        })
        .unwrap();
    let head: RestoreHead =
        serde_json::from_slice(&STANDARD.decode(marker["value"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(head, w.head);
    h.assert_quarantined().await;
}
#[tokio::test]
async fn witness_outage_blocks_writes_and_checks() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    h.witness.child.kill().unwrap();
    h.witness.child.wait().unwrap();
    // Abort the TLS proxy too: no accepted malformed response or crash of its
    // test-owned forwarder substitutes for transport unavailability.
    h._servers.pop();
    h.assert_quarantined().await;
}
#[tokio::test]
async fn concurrent_mutations_do_not_diverge_heads_and_restart_is_read_only() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let (a, b) = tokio::join!(
        h.ledger.publish_policy(&h.grant),
        h.ledger.publish_policy(&h.grant)
    );
    assert!(a.is_ok() || b.is_ok());
    let head = h.gate.check(&h.ledger).await.unwrap();
    assert!(head.sequence >= 1);
    let output = h.cli("--status").await;
    assert!(output.status.success());
    let returned: RestoreHead = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(returned, head);
    assert_eq!(
        h.gate.check(&h.ledger).await.unwrap(),
        head,
        "status must not advance witness"
    );
}
#[tokio::test]
async fn nonempty_namespace_cannot_be_enrolled_as_fresh() {
    let Some(h) = Harness::new().await else {
        return;
    };
    // A new independently retained witness namespace cannot enroll existing
    // authority, even when the original gate's registration is bypassed by an
    // operator-provided direct handle. It becomes pending and stays held.
    let witness = EtcdLedger::new(Client::new(), &h.witness.endpoint, "/new-witness").unwrap();
    let gate = RestoreGate::new(witness).unwrap();
    let before = h.snapshot().await;
    assert!(gate.enroll_empty(&h.direct).await.is_err());
    assert_eq!(h.snapshot().await, before);
    assert!(gate.enroll_empty(&h.direct).await.is_err());
    assert!(RestoreGate::new(h.ledger.clone()).is_err());
    assert!(
        h.direct
            .clone()
            .with_restore_gate(RestoreGate::new(h.direct.clone()).unwrap())
            .is_err()
    );
}

#[tokio::test]
async fn finalized_witness_reply_loss_preserves_consumption_on_retry() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.grant).await.unwrap();
    h.ledger.issue(&h.grant, GD).await.unwrap();
    h.witness_proxy.fault.store(2, Ordering::SeqCst);
    assert!(h.ledger.claim(&h.grant, GD, "original").await.is_err());
    assert_eq!(h.witness_record().await.state, WitnessState::Ready);
    h.gate.check(&h.ledger).await.unwrap();
    assert!(matches!(
        h.ledger.claim(&h.grant, GD, "retry").await,
        Err(Error::NonceConsumed)
    ));
    assert_eq!(
        h.ledger.status(&h.grant, "original").await.unwrap().status,
        "claimed"
    );
}
#[tokio::test]
async fn restore_during_reserved_write_fails_outer_cas_and_leaves_pending() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.local_proxy.fault.store(3, Ordering::SeqCst);
    assert!(h.ledger.publish_policy(&h.grant).await.is_err());
    assert_eq!(h.witness_record().await.state, WitnessState::Pending);
    let keys = h.snapshot().await;
    assert_eq!(
        keys.len(),
        1,
        "outer CAS must not apply policy/ownership writes"
    );
    h.assert_quarantined().await;
}
