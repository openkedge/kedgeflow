//! Real-etcd recovery CAS and pinned signed receipts; explicit software target.
#[path = "support/domain.rs"]
mod domain;
mod support;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use kedgeflow::{
    clock::Clock,
    contracts::{GrantVerifier, digest},
    error::{Error, Result},
    ledger::{AuthoritativeObservation, AuthorityLedger, EtcdLedger, OutcomeQuerier},
    recovery::{Candidate, ExecutionRecord, RecoveryWorker, verify_outcomes},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
struct Time;
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        domain::NOW + 120000
    }
}
struct Query {
    candidate: Candidate,
    digest: String,
    calls: AtomicUsize,
    mode: AtomicUsize,
}
#[async_trait]
impl OutcomeQuerier for Query {
    async fn query(&self, id: &str) -> Result<AuthoritativeObservation> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 4 {
            return Err(Error::Unavailable("software target unavailable".into()));
        }
        Ok(AuthoritativeObservation {
            attempt_id: if mode == 3 {
                "wrong-attempt".into()
            } else {
                id.into()
            },
            root_id: self.candidate.grant.root_id.clone(),
            grant_digest: self.digest.clone(),
            status: match mode {
                0 => "pending",
                1 => "committed",
                2 => "not_found",
                5 => "not_dispatched",
                _ => "committed",
            }
            .into(),
            target_reference: "software:operation:241".into(),
        })
    }
}
struct Fixture {
    ledger: EtcdLedger,
    c: Candidate,
    context: ExecutionRecord,
    digest: String,
    query: Arc<Query>,
}
impl Fixture {
    async fn new() -> Option<Self> {
        Self::new_with_deadline(None).await
    }
    async fn new_with_deadline(deadline: Option<i64>) -> Option<Self> {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(v) => v,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP recovery: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let (mut call, _) = domain::call();
        let time = chrono::Utc::now().timestamp_millis();
        call.grant.issued_at = time - 120000;
        call.grant.valid_from = time - 120000;
        call.grant.expires_at = deadline.unwrap_or(time - 60000);
        call.signed_grant = kedgeflow::contracts::sign_grant(
            &call.grant,
            "test-key",
            &SigningKey::from_bytes(&[6; 32]),
        )
        .unwrap();
        call.grant_digest = GrantVerifier {
            keys: BTreeMap::from([(
                "test-key".into(),
                SigningKey::from_bytes(&[6; 32]).verifying_key(),
            )]),
            audience: call.grant.audience.clone(),
        }
        .verify_retained(&call.signed_grant)
        .unwrap()
        .digest;
        let prefix = format!(
            "/kf-recovery/{}/{}",
            std::process::id(),
            rand::random::<u64>()
        );
        let ledger = EtcdLedger::new(reqwest::Client::new(), endpoint, prefix)
            .unwrap()
            .with_clock(Arc::new(Time));
        ledger.publish_policy(&call.grant).await.unwrap();
        ledger.issue(&call.grant, &call.grant_digest).await.unwrap();
        let c = Candidate {
            grant: call.grant,
            attempt_id: "recover-original".into(),
        };
        let context = ExecutionRecord {
            signed_grant: String::from_utf8(call.signed_grant).unwrap(),
            tool: call.descriptor.name,
            parameters: call.request.params.arguments,
        };
        let query = Arc::new(Query {
            candidate: c.clone(),
            digest: call.grant_digest.clone(),
            calls: AtomicUsize::new(0),
            mode: AtomicUsize::new(0),
        });
        Some(Self {
            ledger,
            c,
            context,
            digest: call.grant_digest,
            query,
        })
    }
    fn worker(&self) -> RecoveryWorker {
        RecoveryWorker::new(
            self.ledger.clone(),
            self.verifier(),
            self.query.clone(),
            "outcome-14".into(),
            SigningKey::from_bytes(&[14; 32]),
            "spiffe://test/outcome".into(),
            Arc::new(Time),
        )
        .unwrap()
    }
    fn verifier(&self) -> GrantVerifier {
        GrantVerifier {
            keys: BTreeMap::from([(
                "test-key".into(),
                SigningKey::from_bytes(&[6; 32]).verifying_key(),
            )]),
            audience: self.c.grant.audience.clone(),
        }
    }
    async fn claim(&self) -> kedgeflow::ledger::Attempt {
        self.ledger
            .claim_recorded(
                &self.c.grant,
                &self.digest,
                &self.c.attempt_id,
                &self.context,
            )
            .await
            .unwrap()
    }
    async fn dispatch(&self) {
        self.ledger
            .authorize_dispatch(&self.c.grant, &self.digest, &self.c.attempt_id)
            .await
            .unwrap();
    }
    fn attempt_key(&self) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let part = |s: &str| URL_SAFE_NO_PAD.encode(s);
        format!(
            "{}/domains/{}/roots/{}/attempts/{}",
            self.ledger.namespace(),
            part(&self.c.grant.conflict_domain),
            part(&self.c.grant.root_id),
            part(&self.c.attempt_id)
        )
    }
    async fn consumed(&self) {
        assert!(matches!(
            self.ledger
                .claim(&self.c.grant, &self.digest, "another")
                .await,
            Err(Error::NonceConsumed)
        ));
        let mut next = self.c.grant.clone();
        next.root_generation += 1;
        next.fence += 1;
        next.gid.push_str("-next");
        assert!(
            self.ledger
                .replace(&self.c.grant, &next, &self.digest)
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn restarted_workers_seal_only_pre_dispatch_and_never_release_allowance() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.claim().await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let worker = f.worker();
        let c = f.c.clone();
        tasks.spawn(async move { worker.recover(&c).await });
    }
    let mut successes = 0;
    while let Some(r) = tasks.join_next().await {
        if r.unwrap().is_ok() {
            successes += 1;
        }
    }
    assert!(successes > 0);
    let head = f.worker().recover(&f.c).await.unwrap();
    assert_eq!(head.state, "not_dispatched");
    assert_eq!(
        f.worker().recover(&f.c).await.unwrap().receipt_digest,
        head.receipt_digest
    );
    assert_eq!(f.query.calls.load(Ordering::SeqCst), 0);
    assert!(
        f.ledger
            .authorize_dispatch(&f.c.grant, &f.digest, &f.c.attempt_id)
            .await
            .is_err()
    );
    let bundle = f.ledger.export_outcomes(&f.c).await.unwrap();
    assert_eq!(bundle.receipts.len(), 1);
    assert_eq!(bundle.journal.len(), 2);
    assert!(bundle.journal.iter().any(|v| v["phase"] == "claimed"));
    let verified = verify_outcomes(
        &bundle,
        &f.verifier(),
        &BTreeMap::from([(
            "outcome-14".into(),
            SigningKey::from_bytes(&[14; 32]).verifying_key(),
        )]),
        "spiffe://test/outcome",
    )
    .unwrap();
    assert_eq!(verified.reported_status, "not_dispatched");
    assert!(!verified.missing_links.is_empty());
    f.consumed().await;
}
#[tokio::test]
async fn dispatch_and_recovery_race_cannot_emit_false_undispatched_receipts() {
    for _ in 0..12 {
        let Some(f) = Fixture::new().await else {
            return;
        };
        f.claim().await;
        let worker = f.worker();
        let (dispatch, recovered) = tokio::join!(
            f.ledger
                .authorize_dispatch(&f.c.grant, &f.digest, &f.c.attempt_id),
            worker.recover(&f.c)
        );
        let head = match recovered {
            Ok(v) => v,
            Err(_) => f.worker().recover(&f.c).await.unwrap(),
        };
        if dispatch.is_ok() {
            assert_eq!(head.state, "unknown");
        } else {
            assert_eq!(head.state, "not_dispatched");
        }
        f.consumed().await;
    }
}
#[tokio::test]
async fn explicit_reconciliation_retains_commit_evidence_for_the_receipt_chain() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.claim().await;
    f.dispatch().await;
    let pending = f.worker().recover(&f.c).await.unwrap();
    assert_eq!(pending.state, "unknown");
    f.query.mode.store(1, Ordering::SeqCst);
    let committed = f
        .ledger
        .reconcile(&f.c.grant, &f.c.attempt_id, f.query.as_ref())
        .await
        .unwrap();
    assert_eq!(committed.status, "committed");
    let queries = f.query.calls.load(Ordering::SeqCst);
    let head = f.worker().recover(&f.c).await.unwrap();
    assert_eq!(head.state, "committed");
    assert_eq!(f.query.calls.load(Ordering::SeqCst), queries);
    let bundle = f.ledger.export_outcomes(&f.c).await.unwrap();
    assert_eq!(bundle.receipts.len(), 2);
    assert_eq!(
        bundle.evidence[&head.evidence_digest]["observation"]["Status"],
        "committed"
    );
    assert_eq!(
        bundle.evidence[&pending.evidence_digest]["observation"]["Status"],
        "pending"
    );
    let verified = verify_outcomes(
        &bundle,
        &f.verifier(),
        &BTreeMap::from([(
            "outcome-14".into(),
            SigningKey::from_bytes(&[14; 32]).verifying_key(),
        )]),
        "spiffe://test/outcome",
    )
    .unwrap();
    assert_eq!(verified.reported_status, "committed");
    f.consumed().await;
}
#[tokio::test]
async fn possible_sends_keep_unknown_then_resolve_commit_with_retained_receipt_chain() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let original = f.claim().await;
    f.dispatch().await;
    let worker = f.worker();
    let mut heads = Vec::new();
    for mode in [0, 2, 5, 3, 4] {
        f.query.mode.store(mode, Ordering::SeqCst);
        let head = worker.recover(&f.c).await.unwrap();
        assert_eq!(head.state, "unknown");
        heads.push(head);
        f.consumed().await;
    }
    f.query.mode.store(1, Ordering::SeqCst);
    let head = f.worker().recover(&f.c).await.unwrap();
    assert_eq!(head.state, "committed");
    let calls = f.query.calls.load(Ordering::SeqCst);
    assert_eq!(
        f.worker().recover(&f.c).await.unwrap().receipt_digest,
        head.receipt_digest
    );
    assert_eq!(f.query.calls.load(Ordering::SeqCst), calls);
    assert!(
        f.ledger
            .finish(&f.c.grant, &original, "unknown")
            .await
            .is_err()
    );
    let bundle = f.ledger.export_outcomes(&f.c).await.unwrap();
    assert_eq!(bundle.receipts.len(), 6);
    let keys = BTreeMap::from([(
        "outcome-14".into(),
        SigningKey::from_bytes(&[14; 32]).verifying_key(),
    )]);
    let report = verify_outcomes(&bundle, &f.verifier(), &keys, "spiffe://test/outcome").unwrap();
    assert_eq!(report.receipts_verified, 6);
    assert_eq!(report.reported_status, "committed");
    assert!(
        bundle
            .evidence
            .values()
            .any(|v| v["kind"] == "uncorrelated_query")
    );
    let mut bad = bundle.clone();
    bad.receipts.remove(0);
    assert!(verify_outcomes(&bad, &f.verifier(), &keys, "spiffe://test/outcome").is_err());
    let mut bad = bundle.clone();
    bad.receipts.swap(0, 1);
    assert!(verify_outcomes(&bad, &f.verifier(), &keys, "spiffe://test/outcome").is_err());
    let mut bad = bundle.clone();
    bad.evidence.clear();
    assert!(verify_outcomes(&bad, &f.verifier(), &keys, "spiffe://test/outcome").is_err());
    let mut bad = bundle.clone();
    bad.execution.parameters["expected_version"] = json!(99);
    assert!(verify_outcomes(&bad, &f.verifier(), &keys, "spiffe://test/outcome").is_err());
    assert!(verify_outcomes(&bundle, &f.verifier(), &keys, "other").is_err());
    let wrong = BTreeMap::from([(
        "outcome-14".into(),
        SigningKey::from_bytes(&[6; 32]).verifying_key(),
    )]);
    assert!(verify_outcomes(&bundle, &f.verifier(), &wrong, "spiffe://test/outcome").is_err());
    // Actual offline binary uses independent trusted keys, not keys in the bundle.
    use base64::{Engine, engine::general_purpose::STANDARD};
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("bundle.json");
    let trust = dir.path().join("trust.json");
    std::fs::write(&input, serde_json::to_vec(&bundle).unwrap()).unwrap();
    std::fs::write(&trust,serde_json::to_vec(&json!({"gateway_audience":f.c.grant.audience,"source_id":"spiffe://test/outcome","grant_keys":{"test-key":STANDARD.encode(SigningKey::from_bytes(&[6;32]).verifying_key().as_bytes())},"outcome_keys":{"outcome-14":STANDARD.encode(SigningKey::from_bytes(&[14;32]).verifying_key().as_bytes())}})).unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-outcomes"))
        .args([
            "--bundle",
            input.to_str().unwrap(),
            "--trust",
            trust.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!("offline trace: {}", String::from_utf8_lossy(&output.stdout));
}
#[tokio::test]
async fn terminal_gateway_evidence_is_retained_before_receipt_and_invalid_context_refuses() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut bad = f.context.clone();
    bad.parameters["expected_version"] = json!(9);
    assert!(
        f.ledger
            .claim_recorded(&f.c.grant, &f.digest, &f.c.attempt_id, &bad)
            .await
            .is_err()
    );
    let attempt = f.claim().await;
    f.dispatch().await;
    let evidence = json!({"kind":"adapter_reply","result":{"committed_target_evidence":"original bytes as canonical JSON","attempt_id":f.c.attempt_id}});
    f.ledger
        .finish_recorded(&f.c.grant, &attempt, "committed", &evidence)
        .await
        .unwrap();
    let head = f.worker().recover(&f.c).await.unwrap();
    assert_eq!(head.state, "committed");
    assert_eq!(f.query.calls.load(Ordering::SeqCst), 0);
    let bundle = f.ledger.export_outcomes(&f.c).await.unwrap();
    assert_eq!(
        bundle.evidence[&digest("outcome-evidence", &evidence).unwrap()],
        evidence
    );
    assert_eq!(
        bundle
            .journal
            .iter()
            .map(|v| v["phase"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["claimed", "dispatch_authorized", "committed"]
    );
    let page = f.worker().sweep(None, 1).await.unwrap();
    assert_eq!(page.examined, 1);
    assert_eq!(page.unavailable, 0);
    assert!(f.worker().sweep(Some("invalid-cursor"), 1).await.is_err());
}

#[tokio::test]
async fn killed_query_worker_restarts_over_native_mtls_without_redispatch() {
    use axum::{Extension, Json, Router, extract::State, http::HeaderMap, routing::post};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use kedgeflow::auth::WorkloadIdentity;
    use std::time::Duration;
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.claim().await;
    f.dispatch().await;
    #[derive(Clone)]
    struct Proxy(String);
    async fn proxy(
        State(p): State<Proxy>,
        Extension(w): Extension<WorkloadIdentity>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(w.as_str(), "spiffe://test/outcome");
        assert_eq!(headers["authorization"], "software-etcd-role");
        let reply = reqwest::Client::new()
            .post(format!("{}/v3/kv/txn", p.0))
            .json(&body)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        Json(reply)
    }
    struct Target {
        entered: tokio::sync::Notify,
        blocked: AtomicUsize,
        calls: AtomicUsize,
        c: Candidate,
        gd: String,
    }
    async fn query(
        State(t): State<Arc<Target>>,
        Extension(w): Extension<WorkloadIdentity>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(w.as_str(), "spiffe://test/outcome");
        assert_eq!(headers["authorization"], "Bearer software-query-only");
        assert_eq!(
            body,
            json!({"profile":kedgeflow::recovery::PROFILE,"operation":"query","attempt_id":t.c.attempt_id})
        );
        t.calls.fetch_add(1, Ordering::SeqCst);
        t.entered.notify_one();
        if t.blocked.load(Ordering::SeqCst) == 1 {
            std::future::pending::<()>().await;
        }
        Json(
            json!({"AttemptID":t.c.attempt_id,"RootID":t.c.grant.root_id,"GrantDigest":t.gd,"Status":"committed","TargetReference":"software:committed-before-lost-reply"}),
        )
    }
    let pki = support::pki_with_workload("spiffe://test/outcome");
    let proxy_server = support::serve_tls(
        &pki,
        Router::new()
            .route("/v3/kv/txn", post(proxy))
            .with_state(Proxy(std::env::var("ETCD_ENDPOINT").unwrap())),
    )
    .await;
    let target = Arc::new(Target {
        entered: tokio::sync::Notify::new(),
        blocked: AtomicUsize::new(1),
        calls: AtomicUsize::new(0),
        c: f.c.clone(),
        gd: f.digest.clone(),
    });
    let target_server = support::serve_tls(
        &pki,
        Router::new()
            .route("/query", post(query))
            .with_state(target.clone()),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    for (name, body) in [
        ("ca.pem", pki.ca.as_str()),
        ("client.pem", pki.client.as_str()),
        ("client-key.pem", pki.client_key.as_str()),
        ("etcd-token", "software-etcd-role"),
        ("query-token", "software-query-only"),
    ] {
        std::fs::write(path.join(name), body).unwrap();
    }
    std::fs::write(path.join("receipt-key"), STANDARD.encode([14; 32])).unwrap();
    let config = json!({"etcd_endpoint":proxy_server.url,"etcd_prefix":f.ledger.namespace(),"etcd_ca":path.join("ca.pem"),"etcd_certificate":path.join("client.pem"),"etcd_private_key":path.join("client-key.pem"),"etcd_token_file":path.join("etcd-token"),"gateway_audience":f.c.grant.audience,"grant_keys":{"test-key":STANDARD.encode(SigningKey::from_bytes(&[6;32]).verifying_key().as_bytes())},"query_url":format!("{}/query",target_server.url),"query_ca":path.join("ca.pem"),"query_certificate":path.join("client.pem"),"query_private_key":path.join("client-key.pem"),"query_token_file":path.join("query-token"),"receipt_key_id":"outcome-14","receipt_signing_key_file":path.join("receipt-key"),"source_id":"spiffe://test/outcome","page_size":8,"poll_interval_ms":100});
    let file = path.join("config.json");
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let executable = env!("CARGO_BIN_EXE_kf-recover");
    let output = tokio::process::Command::new(executable)
        .args(["--config", file.to_str().unwrap(), "--check"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    assert_eq!(target.calls.load(Ordering::SeqCst), 0);
    let mut child = tokio::process::Command::new(executable)
        .args(["--config", file.to_str().unwrap(), "--once"])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), target.entered.notified())
        .await
        .unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    assert!(
        f.ledger
            .read_key(&format!("{}/receipt-head", f.attempt_key()))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.ledger
            .execution_status(&f.c.grant, &f.digest)
            .await
            .unwrap()
            .state,
        "dispatch_authorized"
    );
    target.blocked.store(0, Ordering::SeqCst);
    for _ in 0..2 {
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new(executable)
                .args(["--config", file.to_str().unwrap(), "--once"])
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
        println!(
            "native recovery CLI: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    assert_eq!(target.calls.load(Ordering::SeqCst), 2); // Killed query + successful query; terminal restart is read-only.
    let bundle = f.ledger.export_outcomes(&f.c).await.unwrap();
    assert_eq!(bundle.receipts.len(), 1);
    assert_eq!(
        f.ledger
            .execution_status(&f.c.grant, &f.digest)
            .await
            .unwrap()
            .state,
        "committed"
    );
    f.consumed().await;
}

#[tokio::test]
async fn corrupted_execution_context_fails_before_query_or_receipt() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.claim().await;
    f.dispatch().await;
    let mut context = f.context.clone();
    context.signed_grant = context.signed_grant.replace("test-key", "wrong-key");
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    reqwest::Client::new().post(format!("{endpoint}/v3/kv/put")).json(&json!({"key":STANDARD.encode(format!("{}/execution",f.attempt_key())),"value":STANDARD.encode(serde_json::to_vec(&context).unwrap())})).send().await.unwrap().error_for_status().unwrap();
    let sweep = f.worker().sweep(None, 4).await.unwrap();
    assert_eq!(sweep.unavailable, 1);
    assert_eq!(sweep.reported, 0);
    assert_eq!(f.query.calls.load(Ordering::SeqCst), 0);
    assert!(
        f.ledger
            .read_key(&format!("{}/receipt-head", f.attempt_key()))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.ledger
            .execution_status(&f.c.grant, &f.digest)
            .await
            .unwrap()
            .state,
        "dispatch_authorized"
    );
    f.consumed().await;
}

#[tokio::test]
async fn active_dispatch_budget_defers_takeover_and_query() {
    let Some(f) = Fixture::new_with_deadline(Some(domain::NOW + 180000)).await else {
        return;
    };
    f.claim().await;
    let page = f.worker().sweep(None, 4).await.unwrap();
    assert_eq!(page.deferred, 1);
    assert_eq!(page.unavailable, 0);
    assert_eq!(page.reported, 0);
    assert_eq!(f.query.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.ledger
            .execution_status(&f.c.grant, &f.digest)
            .await
            .unwrap()
            .state,
        "claimed"
    );
    assert!(
        f.ledger
            .read_key(&format!("{}/receipt-head", f.attempt_key()))
            .await
            .unwrap()
            .is_none()
    );
}
