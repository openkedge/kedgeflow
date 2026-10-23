//! Real API and shipping CLI boundary qualification; no test clock override.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_api_refuses_stale_resource_version_and_recreated_uid() {
    let directory = PathBuf::from(std::env::var("KF_KUBE_FIXTURE").unwrap());
    let c = kd::Contract::decode(&std::fs::read(directory.join("contract.json")).unwrap()).unwrap();
    let ca = std::fs::read(directory.join("ca.pem")).unwrap();
    let mutator = std::fs::read_to_string(directory.join("mutator.token")).unwrap();
    let observer = std::fs::read_to_string(directory.join("observer.token")).unwrap();
    let api = Api::new(&c.api_origin, &ca, observer.clone(), Arc::new(SystemClock)).unwrap();
    let inventory = api.inventory(&c).await.unwrap();
    let original = inventory
        .target_pods
        .iter()
        .find(|p| !inventory.ignored(&c, p))
        .unwrap();
    let request = kedgeflow::kube_drain_api::eviction_request(&c, original).unwrap();
    let path = format!(
        "{}/api/v1/namespaces/{}/pods/{}",
        c.api_origin.trim_end_matches('/'),
        original.object.namespace,
        original.object.object.name
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    admin_scenario("touch-target-pod");
    let stale = client
        .post(format!("{path}/eviction"))
        .bearer_auth(&mutator)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), reqwest::StatusCode::CONFLICT);
    let changed: Value = client
        .get(&path)
        .bearer_auth(&observer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(changed["metadata"]["uid"], original.object.object.uid);
    assert_ne!(
        changed["metadata"]["resourceVersion"],
        original.resource_version
    );
    assert!(changed["metadata"]["deletionTimestamp"].is_null());
    admin_scenario("recreate-target-pod");
    let replacement: Value = client
        .get(&path)
        .bearer_auth(&observer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(replacement["metadata"]["uid"], original.object.object.uid);
    // Refresh only RV in this target-primitive probe, so UID is independently
    // stale. This is not a second controller send or a recovery algorithm.
    let mut wrong_uid = request.clone();
    wrong_uid["deleteOptions"]["preconditions"]["resourceVersion"] =
        replacement["metadata"]["resourceVersion"].clone();
    let stale = client
        .post(format!("{path}/eviction"))
        .bearer_auth(&mutator)
        .json(&wrong_uid)
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), reqwest::StatusCode::CONFLICT);
    let remaining: Value = client
        .get(&path)
        .bearer_auth(observer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(remaining["metadata"]["uid"], replacement["metadata"]["uid"]);
    assert!(remaining["metadata"]["deletionTimestamp"].is_null());
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(PathBuf::from(out).join("kube-drain-api-preconditions.json"), canonical(&json!({
            "status":"passed","contract_digest":c.digest().unwrap(),"original":original,
            "original_request":request,"replacement_uid":replacement["metadata"]["uid"],
            "stale_resource_version_status":409,"stale_uid_status":409,"replacement_deleting":false,
            "scope":"actual policy/v1 eviction API using limited mutator; separate owned administrator fault injection; target primitive qualification only, not native dispatch or proof of original no-effect"
        })).unwrap()).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_process_closed_absence_defeats_delayed_acceptance_and_restores_sql() {
    let mut r = Box::pin(setup_physical()).await;
    let process = ProcessFixture::with_pause(&r, Pause::BeforeAcceptCas).await;
    let mut child = process.start().await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let target = format!("{}/accept", process.endpoint);
    let (record, candidate, token) =
        Box::pin(authorize_physical_for(&mut r.physical, &target)).await;
    assert!(
        r.controller
            .close_absent(&record.signed_grant, &candidate.attempt_id)
            .await
            .is_err()
    );
    let request = process.gateway.post(&target).bearer_auth(token).json(
        &kedgeflow::kube_drain_http::Accept {
            profile: kd::PROFILE.into(),
            operation: "accept".into(),
            signed_grant: URL_SAFE_NO_PAD.encode(record.signed_grant.as_bytes()),
            attempt_id: candidate.attempt_id.clone(),
            parameters: r.physical.f.proposal["parameters"].clone(),
        },
    );
    let delayed = tokio::spawn(async move { request.send().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(4), process.gate.pending.notified())
        .await
        .unwrap();
    assert!(r.controller.state().await.unwrap().is_none());
    Box::pin(owner_now(&r.saga, IntentAction::Quiesce, 3)).await;
    let grant_path = process.directory.path().join("original-grant.json");
    std::fs::write(&grant_path, record.signed_grant.as_bytes()).unwrap();
    let closed = process
        .command("close-absent")
        .arg("--signed-grant")
        .arg(grant_path)
        .arg("--attempt")
        .arg(&candidate.attempt_id)
        .output()
        .await
        .unwrap();
    assert!(
        closed.status.success(),
        "{}",
        String::from_utf8_lossy(&closed.stderr)
    );
    let closed: Signed<kedgeflow::kube_drain_proof::NoDispatch> =
        serde_json::from_slice(&closed.stdout).unwrap();
    assert_eq!(closed.body.attempt_id, candidate.attempt_id);
    process.gate.release.notify_one();
    assert_eq!(
        delayed.await.unwrap().status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(process.gate.requests.load(Ordering::SeqCst), 1);
    assert_eq!(process.gate.successful.load(Ordering::SeqCst), 0);
    assert!(r.controller.state().await.unwrap().is_none());
    let worker = kedgeflow::recovery::RecoveryWorker::new(
        r.physical.ledger.clone(),
        GrantVerifier {
            keys: keys(5),
            audience: r.physical.registration.scope.audience.clone(),
        },
        Arc::new(ProcessOutcome {
            client: process.query.clone(),
            endpoint: format!("{}/query", process.endpoint),
        }),
        "key-14".into(),
        SigningKey::from_bytes(&[14; 32]),
        "spiffe://test/outcome".into(),
        Arc::new(SystemClock),
    )
    .unwrap();
    // Recovery takeover still honors the original native grant budget even
    // after the positive physical gate has closed. Waiting does not establish
    // no-effect; only the already retained closure proof can establish that.
    let remaining = candidate.grant.expires_at - now();
    if remaining > 0 {
        assert!(remaining <= 5000);
        tokio::time::sleep(Duration::from_millis(remaining as u64 + 1)).await;
    }
    let receipt = worker.recover(&candidate).await.unwrap();
    assert_eq!(receipt.state, "unknown");
    let summary = r.saga.collect().await.unwrap().verify(&r.r).unwrap();
    assert_eq!(summary["child-1"].forward, saga::ForwardState::NoEffect);
    assert_eq!(
        summary["child-1"].physical_status.as_deref(),
        Some("no_physical_dispatch")
    );
    restore_sql_now(&mut r).await;
    let aggregate = r
        .saga
        .export(&super::super::super::observer("family-observer", 33))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.r.clone(),
        },
    )
    .unwrap();
    assert_eq!(report.status, "compensated");
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    let row = r.sql.admin.query_one("SELECT version,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2", &[&r.sql.pin.tenant, &r.sql.pin.resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 243);
    assert_eq!(row.get::<_, String>(1), "free");
    retain(&r, "kube-drain-process-absent", &aggregate);
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        std::fs::write(PathBuf::from(out).join("kube-drain-process-absent/process.json"), canonical(&json!({
            "delayed_original_acceptance_cas_attempts":1,"acceptance_cas_successes":0,
            "closed_absence_digest":closed.digest().unwrap(),"original_attempt":candidate.attempt_id,
            "fresh_sql_inverse":"version 243/free","physical_status":"no_physical_dispatch",
            "scope":"shipping controller and close-absent CLI; actual etcd CAS; real SQL restore; real owned API observation; original acceptance paused before CAS"
        })).unwrap()).unwrap();
    }
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_process_root_stop_defeats_paused_pending_cas() {
    let mut r = Box::pin(setup_physical()).await;
    let process = ProcessFixture::with_pause(&r, Pause::BeforeCas).await;
    let mut child = process.start().await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let (record, candidate, accepted) = accept_original(&mut r, &process).await;
    tokio::time::timeout(Duration::from_secs(4), process.gate.pending.notified())
        .await
        .unwrap();
    stop_root_now(&r, 302).await;
    process.gate.release.notify_one();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(process.gate.requests.load(Ordering::SeqCst), 1);
    assert_eq!(process.gate.successful.load(Ordering::SeqCst), 0);
    assert!(
        r.controller
            .state()
            .await
            .unwrap()
            .unwrap()
            .body
            .steps
            .is_empty()
    );
    seal_acceptance(&r, &record, &candidate, &accepted).await;
    let closed = process.command("close-unstarted").output().await.unwrap();
    assert!(
        closed.status.success(),
        "{}",
        String::from_utf8_lossy(&closed.stderr)
    );
    let closed: Signed<State> = serde_json::from_slice(&closed.stdout).unwrap();
    assert!(closed.body.closed.is_some() && closed.body.steps.is_empty());
    assert!(
        !r.api
            .inventory(&r.contract)
            .await
            .unwrap()
            .target(&r.contract)
            .unwrap()
            .unschedulable
    );
    let aggregate = r
        .saga
        .export(&super::super::super::observer("family-observer", 33))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.r.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        report.nodes["child-1"].forward,
        saga::ForwardState::NoEffect
    );
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    retain(&r, "kube-drain-process-stop", &aggregate);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_protected_deferred_expiry_cannot_authorize_first_mutation() {
    let directory = PathBuf::from(std::env::var("KF_KUBE_FIXTURE").unwrap());
    let mut contract =
        kd::Contract::decode(&std::fs::read(directory.join("contract.json")).unwrap()).unwrap();
    // Narrow only this protected enrollment. Production's bound is unchanged.
    contract.maximum_deferred_ms = 1;
    let ca = std::fs::read(directory.join("ca.pem")).unwrap();
    let mut r = Box::pin(setup_physical_api(Some((contract, ca)))).await;
    let process = ProcessFixture::with_pause(&r, Pause::PassThrough).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let (record, candidate, token) = Box::pin(authorize_physical(&mut r.physical)).await;
    let accepted = r
        .controller
        .accept(
            record.signed_grant.clone(),
            candidate.attempt_id.clone(),
            r.physical.f.proposal["parameters"].clone(),
            &token,
        )
        .await
        .unwrap();
    assert_eq!(
        accepted.body.accepted.deferred_until - accepted.body.accepted.accepted_at,
        1
    );
    seal_acceptance(&r, &record, &candidate, &accepted).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let refused = process.command("advance").output().await.unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("refused"));
    assert_eq!(
        r.controller
            .state()
            .await
            .unwrap()
            .unwrap()
            .digest()
            .unwrap(),
        accepted.digest().unwrap()
    );
    assert!(
        !r.api
            .inventory(&r.contract)
            .await
            .unwrap()
            .target(&r.contract)
            .unwrap()
            .unschedulable
    );
    let aggregate = r
        .saga
        .export(&super::super::super::observer("family-observer", 33))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.r.clone(),
        },
    )
    .unwrap();
    assert_eq!(report.nodes["child-1"].forward, saga::ForwardState::Unknown);
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    retain(&r, "kube-drain-deferred-expiry", &aggregate);
}
