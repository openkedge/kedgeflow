//! Real native CAS barriers around the protected controller's Pending and Send.
use super::super::super::process::agent as common;
use super::*;

async fn race(send: bool, deadline: bool) {
    let sink = SinkServer::new(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let (mut r, identity, source, mut source_child) = Box::pin(setup_source_for(
        Some(sink.policy(4000, 16)),
        format!("https://{listen}/accept"),
    ))
    .await;
    let process = Process::new(&r, &source, &identity, listen);
    let supervisor = SupervisorProcess::new(&r, &source, &identity, &sink);
    let loaded = kedgeflow::managed_drain_controller_config::Config::load(
        &process.directory.path().canonicalize().unwrap(),
        &process.config,
    )
    .await
    .unwrap();
    let before = sql_rows(&r).await;
    drop(listener);
    let mut child = process.start().await;
    let (record, candidate, token) = Box::pin(supervisor::authorize(&mut r, &source)).await;
    source.pending_pause.send.store(send, Ordering::SeqCst);
    source.pending_pause.forward.store(true, Ordering::SeqCst);
    source.pending_pause.armed.store(true, Ordering::SeqCst);
    let accepted = loaded
        .controller
        .accept(
            record.signed_grant.clone(),
            candidate.attempt_id.clone(),
            r.physical.f.proposal["parameters"].clone(),
            &token,
        )
        .await
        .unwrap();
    loaded
        .controller
        .acceptance_result(accepted.clone())
        .await
        .unwrap();
    Box::pin(seal_acceptance(&r, &record, &candidate, &accepted)).await;
    let store = Store::new(r.physical.ledger.clone()).unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while source.pending_pause.intercepted.load(Ordering::SeqCst) == 0 {
        assert!(child.try_wait().unwrap().is_none(), "{}", process.log());
        assert!(
            tokio::time::Instant::now() < until,
            "native mutation barrier not reached: {}",
            process.log()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let paused = r.controller.state().await.unwrap().unwrap();
    assert_eq!(paused.body.steps.len(), usize::from(send));
    if deadline {
        // The independent shipping timer must commit stop/outbox while its
        // mutation worker is held. Do not advance a clock or alter any grant.
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let status = store.status().await.unwrap().unwrap();
            if status.stop_required && status.incident.is_some() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "deadline did not stop held worker: {}",
                process.log()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    } else {
        Box::pin(common::stop_root(&r, 701)).await;
    }
    source.pending_pause.release.notify_one();
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    let reply = loop {
        if let Some(reply) = source.pending_pause.result.lock().unwrap().clone() {
            break reply;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "held native transaction never returned"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        reply.get("header").is_some(),
        "actual native response required"
    );
    assert!(
        !reply["succeeded"].as_bool().unwrap_or(false),
        "original held CAS must actually lose"
    );
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let final_state = r.controller.state().await.unwrap().unwrap();
    assert_eq!(
        json!(final_state),
        json!(paused),
        "refused CAS cannot advance mechanical state"
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
    // Wait only for the original operating deadline and consumed query expiry.
    // Neither timeout releases physical authority or refunds either allowance.
    let status = store.status().await.unwrap().unwrap();
    let until = status
        .pending
        .as_ref()
        .map_or(status.deadline, |q| q.expires_at.max(status.deadline));
    let remaining = until.saturating_sub(now());
    if remaining > 0 {
        assert!(remaining <= 5000);
        tokio::time::sleep(Duration::from_millis(remaining as u64 + 1)).await;
    }
    supervisor.json("tick").await;
    let observed = supervisor.json("observe").await;
    assert_eq!(observed["observed"], true);
    assert_eq!(
        observed["operating"]["observation"]["resolution"],
        "unresolved"
    );
    let delivered = supervisor.json("deliver").await;
    assert_eq!(delivered["attempted"], true);
    let status = store.status().await.unwrap().unwrap();
    assert!(status.stop_required && status.unresolved());
    assert!(
        status
            .incident
            .as_ref()
            .unwrap()
            .acknowledgement_digest
            .is_some()
    );
    if send {
        assert!(
            !process
                .command("close-unstarted")
                .output()
                .await
                .unwrap()
                .status
                .success()
        );
    }
    let (bundle, trust) = supervisor::export(&supervisor, &r).await;
    let report = bundle.verify(&trust).unwrap();
    assert_eq!(report["held_forward"], 2);
    assert_eq!(report["held_compensation"], 1);
    assert_eq!(report["execution_authority"], false);
    assert_eq!(report["operating"]["send_checks"], 0);
    assert_eq!(before, sql_rows(&r).await);
    let name = format!(
        "managed-race-{}-{}",
        if send { "send" } else { "pending" },
        if deadline { "deadline" } else { "stop" }
    );
    supervisor::save(
        &name,
        &bundle,
        &trust,
        json!({
            "shipping_controller":true,"shipping_source":true,"shipping_supervisor":true,
            "paused_cas":if send {"send"} else {"pending"}, "stop":if deadline {"operating_deadline"} else {"root_stop"},
            "actual_native_refusal":reply,"intercepted":source.pending_pause.intercepted.load(Ordering::SeqCst),
            "mechanical_steps":final_state.body.steps.len(),"physical_requests":0,
            "incident_ack_does_not_resolve":true,"sql_rows_unchanged":true,
            "scope":"generated same-host identities; actual native CAS/SQL/Kubernetes, not deployed custody acceptance"
        }),
    );
    source_child.kill().await.unwrap();
    source_child.wait().await.unwrap();
    if send && deadline {
        native_bounds(&r).await;
    }
}

async fn native_bounds(r: &Ready) {
    // Adversarial storage inputs, not signed positive evidence. The clean
    // aggregate has already been saved and independently verified above.
    let store = Store::new(r.physical.ledger.clone()).unwrap();
    let before = json!(store.status().await.unwrap());
    let base = store.context.base();
    let prefix = format!("{base}/records/");
    let end = format!("{base}/records0");
    let poison = format!("{prefix}zz-negative-storage-");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("{}/v3/kv/txn", std::env::var("ETCD_ENDPOINT").unwrap());
    let txn = |ops: Vec<Value>| {
        client
            .post(&url)
            .json(&json!({"compare":[],"success":ops,"failure":[]}))
    };
    let rows: Value = txn(vec![
        json!({"request_range":{"key":STANDARD.encode(&prefix),"range_end":STANDARD.encode(&end)}}),
    ])
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let retained = rows["responses"][0]["response_range"]["kvs"]
        .as_array()
        .unwrap()
        .len();
    let mut results = Vec::new();
    for (total, bytes, expected) in [
        (513, 1, "managed material count limit exceeded"),
        (512, 8192, "response exceeds bound"),
    ] {
        let value = canonical(&json!({"negative_storage_fixture":"x".repeat(bytes)})).unwrap();
        let writes: Vec<_> = (0..total - retained)
            .map(|n| {
                json!({"request_put":{
            "key":STANDARD.encode(format!("{poison}{n:04}")),"value":STANDARD.encode(&value)}})
            })
            .collect();
        for chunk in writes.chunks(64) {
            let response: Value = txn(chunk.to_vec())
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(response["succeeded"], true);
        }
        let observed: Value = txn(vec![json!({"request_range":{"key":STANDARD.encode(&prefix),"range_end":STANDARD.encode(&end)}})])
            .send().await.unwrap().json().await.unwrap();
        let rows = observed["responses"][0]["response_range"]["kvs"]
            .as_array()
            .unwrap();
        assert_eq!(rows.len(), total);
        let error = store.status().await.unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
        results.push(json!({"native_material_count":total,"injected_value_bytes":value.len(),
            "actual_native_response_bytes":serde_json::to_vec(&observed).unwrap().len(),"refusal":error}));
        let cleared: Value = txn(vec![json!({"request_delete_range":{"key":STANDARD.encode(&poison),"range_end":STANDARD.encode(format!("{prefix}zz-negative-storage."))}})])
            .send().await.unwrap().json().await.unwrap();
        assert_eq!(cleared["succeeded"], true);
        assert_eq!(
            json!(store.status().await.unwrap()),
            before,
            "negative range must not advance the original operating head"
        );
    }
    if let Some(output) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        std::fs::write(PathBuf::from(output).join("managed-native-boundaries.json"), canonical(&json!({
            "cases":results,"original_operating_head_unchanged":true,
            "scope":"actual native negative count and effective 4MiB wire cap; exact 32MiB journal accounting remains a separate quota-only unit test"
        })).unwrap()).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_race_pending_root_stop() {
    Box::pin(race(false, false)).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_race_pending_operating_deadline() {
    Box::pin(race(false, true)).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_race_send_root_stop() {
    Box::pin(race(true, false)).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_race_send_operating_deadline() {
    Box::pin(race(true, true)).await;
}
