//! Shipping inverse process loss and stopped logical authority rollback.
use super::super::super::{
    live_agent::Running,
    sql_failure::{prefix_snapshot, restore_prefix},
};
use super::*;
use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use kedgeflow::{
    adapter::ResourceAdapter,
    auth::WorkloadIdentity,
    broker::TargetCredential,
    clock::{Clock, SystemClock},
    gateway::VerifiedCall,
    ledger::OutcomeQuerier,
    postgres_compensation::CompensationStore,
    recovery_config::HttpOutcomeQuerier,
    restore::RestoreGate,
};
use std::{
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
};
use tokio::sync::Notify;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Point {
    Locked,
    Committed,
    Restore,
    SqlUnknown,
    SqlRetained,
}
impl Point {
    fn sql_restore(self) -> bool {
        matches!(self, Self::SqlUnknown | Self::SqlRetained)
    }
}
struct Relay {
    upstream: String,
    authority: String,
    gateway: reqwest::Client,
    reader: reqwest::Client,
    point: Point,
    entered: Notify,
    release: Notify,
    sends: AtomicUsize,
    queries: AtomicUsize,
}
async fn relay(
    State(p): State<Arc<Relay>>,
    Extension(w): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(v): Json<Value>,
) -> Response {
    let dispatch = v["operation"] == "dispatch";
    let (path, client) = if dispatch {
        assert_eq!(w.as_str(), "spiffe://test/gateway");
        p.sends.fetch_add(1, Ordering::SeqCst);
        ("dispatch", &p.gateway)
    } else {
        assert_eq!(w.as_str(), "spiffe://test/recovery");
        assert_eq!(
            headers["authorization"],
            format!("Bearer {INVERSE_QUERY_TOKEN}")
        );
        p.queries.fetch_add(1, Ordering::SeqCst);
        ("query", &p.reader)
    };
    let mut request = client
        .post(format!("{}/{path}", p.upstream))
        .header("host", &p.authority)
        .json(&v);
    if let Some(h) = headers.get("authorization") {
        request = request.header("authorization", h);
    }
    let response = match request.send().await {
        Ok(r) => r,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let status = response.status();
    let raw = response.bytes().await.unwrap();
    if dispatch && p.point != Point::Locked {
        assert!(status.is_success(), "{}", String::from_utf8_lossy(&raw));
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).unwrap()["status"],
            "committed"
        );
        p.entered.notify_one();
        p.release.notified().await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (status, [("content-type", "application/json")], raw).into_response()
}
struct Process {
    child: tokio::process::Child,
    config: PathBuf,
}
impl Process {
    async fn start(config: &Path, query: &str, reader: &reqwest::Client) -> Self {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(config.with_extension("stderr.log"))
            .unwrap();
        let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-compensation-target"))
            .arg("--config")
            .arg(config)
            .arg("--postgres-peer-uid")
            .arg(rustix::process::geteuid().as_raw().to_string())
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut p = Self {
            child,
            config: config.into(),
        };
        for _ in 0..200 {
            assert!(
                p.child.try_wait().unwrap().is_none(),
                "{}",
                std::fs::read_to_string(config.with_extension("stderr.log")).unwrap()
            );
            if reader.post(query).bearer_auth(INVERSE_QUERY_TOKEN).json(&json!({"profile":kedgeflow::recovery::PROFILE,"operation":"query","attempt_id":"readiness"})).send().await.is_ok_and(|r|r.status() == StatusCode::NOT_FOUND) { return p; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("inverse target readiness timeout");
    }
    async fn kill(&mut self) {
        self.child.start_kill().unwrap();
        assert_eq!(self.child.wait().await.unwrap().signal(), Some(9));
    }
}
async fn run(point: Point) {
    for (name, required) in [
        ("ETCD_ENDPOINT", "KF_REQUIRE_ETCD"),
        ("KF_POSTGRES_TEST_SOCKET", "KF_REQUIRE_POSTGRES"),
    ] {
        if std::env::var(name).is_err() {
            assert_ne!(std::env::var(required).as_deref(), Ok("1"));
            eprintln!("SKIP inverse failure: {name} absent");
            return;
        }
    }
    let witness = if point == Point::Restore || point.sql_restore() {
        Some(support::witness::WitnessProcess::start().await)
    } else {
        None
    };
    let gate = witness.as_ref().map(|w| {
        RestoreGate::new(
            EtcdLedger::new(
                reqwest::Client::new(),
                &w.endpoint,
                format!("/inverse-witness-{}", rand::random::<u64>()),
            )
            .unwrap(),
        )
        .unwrap()
    });
    let Some(mut h) = Box::pin(sql_inverse_setup_guarded(
        SystemClock.now_ms(),
        None,
        false,
        false,
        gate.clone(),
        Some(15000),
    ))
    .await
    else {
        return;
    };
    let until = h.inverse.clock.now_ms();
    if SystemClock.now_ms() < until {
        tokio::time::sleep(Duration::from_millis(
            (until - SystemClock.now_ms()).max(0) as u64 + 30,
        ))
        .await;
    }
    h.inverse
        .clock
        .0
        .store(SystemClock.now_ms(), Ordering::SeqCst);
    let ticking = h.inverse.clock.clone();
    let _ticker = Running(tokio::spawn(async move {
        loop {
            ticking.0.store(SystemClock.now_ms(), Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }));
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, raw: &[u8]| {
        let path = directory.path().join(name);
        std::fs::write(&path, raw).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let pki = support::pki_for_workloads(&[
        "spiffe://test/gateway",
        "spiffe://test/recovery",
        "spiffe://test/barrier",
    ]);
    let client = |n: usize| {
        kedgeflow::tls::pinned_client_pem(
            pki[n].ca.as_bytes(),
            pki[n].client.as_bytes(),
            pki[n].client_key.as_bytes(),
            Duration::from_secs(10),
        )
        .unwrap()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let public_url = format!("https://{address}");
    let private = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let private_address = private.local_addr().unwrap();
    drop(private);
    let upstream = format!("https://{private_address}");
    let dispatch = format!("{public_url}/dispatch");
    let query = format!("{public_url}/query");
    h.pin.target_audience = dispatch.clone();
    let relay_state = Arc::new(Relay {
        upstream: upstream.clone(),
        authority: address.to_string(),
        gateway: client(0).client().clone(),
        reader: client(1).client().clone(),
        point,
        entered: Notify::new(),
        release: Notify::new(),
        sends: AtomicUsize::new(0),
        queries: AtomicUsize::new(0),
    });
    let router = Router::new()
        .route("/dispatch", post(relay))
        .route("/query", post(relay))
        .with_state(relay_state.clone());
    let tls = kedgeflow::tls::server_config_pem(
        pki[0].server.as_bytes(),
        pki[0].server_key.as_bytes(),
        pki[0].ca.as_bytes(),
    )
    .unwrap();
    let _relay = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, tls, router)
            .await
            .unwrap();
    }));
    let cfg = json!({"profile":kedgeflow::compensation_target::PROFILE,"listen":private_address,"dispatch_url":dispatch,"query_url":query,"barrier_url":format!("{public_url}/barrier"),
        "certificate":write("server.pem",pki[0].server.as_bytes()),"private_key":write("server-key.pem",pki[0].server_key.as_bytes()),"workload_ca":write("ca.pem",pki[0].ca.as_bytes()),
        "database":{"connection":{"socket_directory":std::fs::canonicalize(std::env::var("KF_POSTGRES_TEST_SOCKET").unwrap()).unwrap(),"port":5432,"database":"postgres","executor_user":"kf_inverse_executor","query_user":"kf_inverse_reader"},"barrier_user":"kf_inverse_barrier"},
        "trust":{"inverse_execution":{"profile":kedgeflow::compensation_execution::PROFILE,"contract":h.contract,"forward":native::trust_value(&h.forward,&h.registration),"outcome_keys":public(19),"source_id":"spiffe://test/inverse-outcome"},"topology":h.topology,"registration":h.pin,"forward_gateway_workload":"spiffe://test/gateway"},
        "grant_keys":public(5),"gateway_audience":h.inverse.registration.scope.audience,"token_issuer":"https://broker.test/exchange","target_keys":public(29),"query_token_file":write("query-token",INVERSE_QUERY_TOKEN.as_bytes()),"barrier_token_file":write("barrier-token",INVERSE_BARRIER_TOKEN.as_bytes()),"barrier_workload":"spiffe://test/barrier","barrier_key_id":"key-17","barrier_signing_key_file":write("barrier-key",STANDARD.encode([17;32]).as_bytes()),"barrier_lifetime_ms":20000});
    let config = write("target.json", &serde_json::to_vec(&cfg).unwrap());
    // Readiness also traverses the relay and its independent query identity.
    let mut process = Process::start(&config, &query, client(1).client()).await;
    let origin = std::env::var("ETCD_ENDPOINT").unwrap();
    let old = prefix_snapshot(&origin, &h.inverse.prefix).await;
    let backup = if point.sql_restore() {
        Some(storage::Backup::capture(directory.path(), &db_connection()).await)
    } else {
        None
    };
    let (rec, c, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    let adapter = kedgeflow::compensation_adapter::CompensationAdapter::new(
        &dispatch,
        client(0),
        h.target_trust(),
        h.grants(),
        kedgeflow::target_token::TargetTokenVerifier::new(
            "https://broker.test/exchange".into(),
            keys(29),
        )
        .unwrap(),
        h.inverse.ledger.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let call=VerifiedCall { request:serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":h.inverse.tool().name,"arguments":h.inverse.f.proposal["parameters"]}})).unwrap(),grant:c.grant.clone(),grant_digest:rec.grant_digest.clone(),signed_grant:rec.signed_grant.as_bytes().to_vec(),attempt_id:c.attempt_id.clone(),identity:h.inverse.f.identity.clone(),descriptor:h.inverse.tool() };
    let token_expiry = serde_json::from_slice::<Value>(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()["exp"]
        .as_i64()
        .unwrap()
        * 1000;
    let credential = TargetCredential {
        token,
        expires_at_ms: token_expiry,
        audience: dispatch,
    };
    // A separate owner session holds the actual protected row, never a fake target hook.
    let db = db_connection();
    let mut owner = super::super::super::sql_leaf::owner(&db).await;
    let lock = if point == Point::Locked {
        let tx = owner.transaction().await.unwrap();
        tx.query_one("SELECT resource_id FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2 FOR UPDATE",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap();
        Some(tx)
    } else {
        None
    };
    let sending = tokio::spawn(async move { adapter.dispatch(&call, &credential).await });
    if point == Point::Locked {
        for step in 0..2000 {
            let count:i64=h.admin.query_one("SELECT count(*) FROM pg_stat_activity WHERE usename='kf_inverse_executor' AND wait_event_type='Lock'",&[]).await.unwrap().get(0);
            if count == 1 {
                break;
            }
            if sending.is_finished() {
                panic!(
                    "dispatch stopped before lock: {:?}; sends={}",
                    sending.await.unwrap().err(),
                    relay_state.sends.load(Ordering::SeqCst)
                );
            }
            assert!(
                step < 1999,
                "inverse did not reach SQL lock; sends={}",
                relay_state.sends.load(Ordering::SeqCst)
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    } else {
        tokio::time::timeout(Duration::from_secs(10), relay_state.entered.notified())
            .await
            .unwrap();
    }
    process.kill().await;
    if let Some(tx) = lock {
        tx.rollback().await.unwrap();
        for step in 0..200 {
            let count: i64 = h
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity WHERE usename='kf_inverse_executor'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if count == 0 {
                break;
            }
            assert!(step < 199, "dead inverse SQL session did not exit");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    process = Process::start(&process.config, &query, client(1).client()).await;
    if point != Point::Locked {
        relay_state.release.notify_one();
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(12), sending)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let stored = h.store.lookup(&h.pin.tenant, &c.attempt_id).await.unwrap();
    assert_eq!(stored.is_some(), point != Point::Locked);
    if let Some(o) = &stored {
        assert_eq!(o.status, kedgeflow::postgres_action::Status::Committed);
        assert_eq!(o.request.root_id, c.grant.root_id);
        assert_eq!(o.request.grant_digest, rec.grant_digest);
    }
    let row=h.admin.query_one("SELECT version,last_fence,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap();
    assert_eq!(
        row.get::<_, i64>(0),
        if point == Point::Locked { 242 } else { 243 }
    );
    assert_eq!(
        row.get::<_, String>(2),
        if point == Point::Locked {
            "booking:pilot"
        } else {
            "free"
        }
    );
    let fence = row.get::<_, i64>(1);
    assert_eq!(
        fence,
        if point == Point::Locked {
            1
        } else {
            c.grant.fence as i64
        }
    );
    let held = h.inverse.ledger.compensation_spend().await.unwrap();
    assert_eq!(
        held.state,
        kedgeflow::coordination::ReservationState::Unknown
    );
    h.forward.ledger.stop_reservation().await.unwrap();
    let wait = (c.grant.expires_at - SystemClock.now_ms()).max(0);
    tokio::time::sleep(Duration::from_millis(wait as u64 + 30)).await;
    let reader = HttpOutcomeQuerier::new(
        client(1).client().clone(),
        &query,
        INVERSE_QUERY_TOKEN.into(),
    )
    .unwrap();
    let worker = kedgeflow::recovery::RecoveryWorker::new(
        h.inverse.ledger.clone(),
        h.grants(),
        Arc::new(reader),
        "key-19".into(),
        SigningKey::from_bytes(&[19; 32]),
        "spiffe://test/inverse-outcome".into(),
        Arc::new(SystemClock),
    )
    .unwrap();
    if let Some(backup) = backup {
        let retained = if point == Point::SqlRetained {
            Some(worker.recover(&c).await.unwrap())
        } else {
            None
        };
        process.kill().await;
        h.inverse._task.abort();
        h.forward._task.abort();
        Box::pin(storage::rehearse(
            &h,
            &rec,
            &c,
            stored.as_ref().unwrap(),
            retained.as_ref(),
            &backup,
            gate.as_ref().unwrap(),
        ))
        .await;
        assert_eq!(relay_state.sends.load(Ordering::SeqCst), 1);
        assert_eq!(
            h.store.lookup(&h.pin.tenant, &c.attempt_id).await.unwrap(),
            stored
        );
        return;
    }
    let receipt = worker.recover(&c).await.unwrap();
    assert_eq!(
        receipt.state,
        if point == Point::Locked {
            "unknown"
        } else {
            "committed"
        }
    );
    assert_eq!(json!(worker.recover(&c).await.unwrap()), json!(receipt));
    let spent = h.inverse.ledger.compensation_spend().await.unwrap();
    assert_eq!(spent.compensation_units, held.compensation_units);
    assert_eq!(
        spent.state,
        if point == Point::Locked {
            kedgeflow::coordination::ReservationState::Unknown
        } else {
            kedgeflow::coordination::ReservationState::Committed
        }
    );
    assert!(
        h.inverse
            .ledger
            .claim(&c.grant, &rec.grant_digest, "replacement")
            .await
            .is_err()
    );
    let bundle = Box::pin(super::lineage::export(&h)).await.unwrap();
    let verified =
        kedgeflow::compensation_lineage::verify(&bundle, &super::lineage::trust(&h)).unwrap();
    assert_eq!(
        verified.status,
        if point == Point::Locked {
            "unresolved"
        } else {
            "compensated"
        }
    );
    if let Some(gate) = gate {
        let latest = prefix_snapshot(&origin, &h.inverse.prefix).await;
        // Stop all authority writers before privileged logical prefix replacement.
        h.inverse._task.abort();
        h.forward._task.abort();
        restore_prefix(&origin, &h.inverse.prefix, &old).await;
        assert!(gate.check(&h.inverse.ledger).await.is_err());
        assert!(gate.enroll_empty(&h.inverse.ledger).await.is_err());
        assert!(worker.recover(&c).await.is_err());
        assert!(
            h.inverse
                .ledger
                .claim(&c.grant, &rec.grant_digest, "replacement")
                .await
                .is_err()
        );
        // Keep every execution pin while deliberately omitting only the gate.
        let execution: kedgeflow::compensation_execution::ExecutionConfig =
            serde_json::from_value(json!({
                "profile":kedgeflow::compensation_execution::PROFILE,
                "contract":h.contract,"forward":native::trust_value(&h.forward,&h.registration),
                "outcome_keys":public(19),"source_id":"spiffe://test/inverse-outcome"
            }))
            .unwrap();
        let bypass = execution
            .attach(
                EtcdLedger::new(reqwest::Client::new(), &origin, &h.inverse.prefix)
                    .unwrap()
                    .with_clock(h.inverse.clock.clone())
                    .requiring_control(Some(h.inverse.registration.trust_digest.clone()))
                    .with_action_domain(kedgeflow::action_domain::Selection {
                        topology: h.topology.clone(),
                        lane: kedgeflow::action_domain::Lane::Inverse,
                    })
                    .unwrap(),
            )
            .unwrap();
        let bypass_error = bypass
            .claim(&c.grant, &rec.grant_digest, "bypass")
            .await
            .unwrap_err();
        assert!(
            bypass_error
                .to_string()
                .contains("restore quarantine: witness required"),
            "{bypass_error}"
        );
        assert!(Box::pin(super::lineage::export(&h)).await.is_err());
        assert_eq!(
            h.store.lookup(&h.pin.tenant, &c.attempt_id).await.unwrap(),
            stored
        );
        let independent = HttpOutcomeQuerier::new(
            client(1).client().clone(),
            &query,
            INVERSE_QUERY_TOKEN.into(),
        )
        .unwrap()
        .query(&c.attempt_id)
        .await
        .unwrap();
        assert_eq!(independent.status, "committed");
        assert_eq!(independent.grant_digest, rec.grant_digest);
        restore_prefix(&origin, &h.inverse.prefix, &latest).await;
        gate.check(&h.inverse.ledger).await.unwrap();
        let values = |snapshot: &Value| {
            snapshot["kvs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|kv| (kv["key"].as_str().unwrap().to_owned(), kv["value"].clone()))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(
            values(&prefix_snapshot(&origin, &h.inverse.prefix).await),
            values(&latest)
        );
        assert_eq!(json!(worker.recover(&c).await.unwrap()), json!(receipt));
        assert_eq!(h.inverse.ledger.compensation_spend().await.unwrap(), spent);
        let restored = Box::pin(super::lineage::export(&h)).await.unwrap();
        // Observer checkpoints are freshly signed at export time. Compare the
        // retained original evidence, excluding only those capture attestations.
        let retained = |b: &kedgeflow::compensation_lineage::Bundle| {
            let mut v = json!(b.evidence);
            for forward in v["forward"].as_object_mut().unwrap().values_mut() {
                forward.as_object_mut().unwrap().remove("checkpoint");
            }
            digest("inverse-failure-retained-evidence", &v).unwrap()
        };
        assert_eq!(retained(&restored), retained(&bundle));
        assert_eq!(
            kedgeflow::compensation_lineage::verify(&restored, &super::lineage::trust(&h))
                .unwrap()
                .status,
            "compensated"
        );
        assert!(
            h.inverse
                .ledger
                .claim(&c.grant, &rec.grant_digest, "replacement")
                .await
                .is_err()
        );
    }
    assert_eq!(relay_state.sends.load(Ordering::SeqCst), 1);
    assert!(relay_state.queries.load(Ordering::SeqCst) > 0);
    assert_eq!(
        h.store.lookup(&h.pin.tenant, &c.attempt_id).await.unwrap(),
        stored
    );
    process.kill().await;
}
#[tokio::test]
async fn compensation_sql_failure_target_kill_at_real_row_lock_holds_original_unknown() {
    Box::pin(run(Point::Locked)).await;
}
#[tokio::test]
async fn compensation_sql_failure_target_kill_after_commit_recovers_original_only() {
    Box::pin(run(Point::Committed)).await;
}
#[tokio::test]
async fn compensation_sql_failure_witness_quarantines_stale_inverse_authority() {
    Box::pin(run(Point::Restore)).await;
}

fn db_connection() -> kedgeflow::postgres_store::UnixDatabase {
    kedgeflow::postgres_store::UnixDatabase {
        socket_directory: std::env::var("KF_POSTGRES_TEST_SOCKET").unwrap().into(),
        port: 5432,
        database: "postgres".into(),
        executor_user: "kf_executor".into(),
        query_user: "kf_reader".into(),
    }
}
#[path = "compensation_storage_restore.rs"]
mod storage;
#[tokio::test]
async fn compensation_sql_storage_restore_missing_commit_keeps_original_unknown() {
    Box::pin(run(Point::SqlUnknown)).await;
}
#[tokio::test]
async fn compensation_sql_storage_restore_retains_original_signed_commit() {
    Box::pin(run(Point::SqlRetained)).await;
}
