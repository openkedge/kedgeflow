//! Real-etcd query-only saga observations; no inverse target or execution claim.
use super::reserved_history as native;
use super::*;
use kedgeflow::{
    hierarchical_leaf::Principal,
    saga::{Compensation as C, Forward as F, Inverse, Node, PROFILE, Plan, SagaObserver, Status},
};
use std::sync::atomic::AtomicUsize;
fn plan(h: &mut Harness, r: &kedgeflow::reserved_leaf::Registration, count: usize) -> Plan {
    let mut nodes = vec![];
    for n in 0..count {
        h.f.proposal["qid"] = json!(format!("saga-forward-{n}"));
        let operation =
            h.f.trust
                .operation_key(&h.f.identity, &h.f.packet().proposal)
                .unwrap();
        let mut scope = r.scope.clone();
        scope.action.id = "capacity.release".into();
        scope.action.digest = "9".repeat(64);
        nodes.push(Node {
            node_id: format!("node-{n}"),
            operation_key: operation,
            principal: Principal {
                subject: h.f.identity.subject.clone(),
                workload_id: h.f.identity.workload_id.clone(),
            },
            depends_on: if n > 0 {
                vec![format!("node-{}", n - 1)]
            } else {
                vec![]
            },
            inverse: Some(Inverse {
                scope,
                semantics_digest: "a".repeat(64),
                applicability_digest: "b".repeat(64),
                late_effect_barrier_digest: "c".repeat(64),
                compensation_units: 1,
            }),
        });
    }
    h.f.proposal["qid"] = json!("saga-forward-0");
    Plan {
        profile: PROFILE.into(),
        saga_id: "fixture-saga".into(),
        registration_digest: r.digest().unwrap(),
        nodes,
    }
}
fn observer(h: &Harness, r: &kedgeflow::reserved_leaf::Registration, p: &Plan) -> SagaObserver {
    SagaObserver::new(h.ledger.clone(), p.clone(), native::trust(h, r)).unwrap()
}

// Use the exact public ledger key encoding rather than an independently guessed path.
fn saga_base(h: &Harness, p: &Plan) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}/saga-observations/{}",
        h.prefix,
        URL_SAFE_NO_PAD.encode(p.saga_id.as_bytes())
    )
}
async fn write(h: &Harness, key: &str, value: Option<&[u8]>) {
    use base64::engine::general_purpose::STANDARD;
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let (path, body) = match value {
        Some(v) => (
            "put",
            json!({"key":STANDARD.encode(key),"value":STANDARD.encode(v)}),
        ),
        None => ("deleterange", json!({"key":STANDARD.encode(key)})),
    };
    reqwest::Client::new()
        .post(format!("{endpoint}/v3/kv/{path}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let _ = h;
}
#[tokio::test]
async fn saga_create_only_identity_restart_and_absence_never_grant_authority() {
    let Some((mut h, r)) = native::ready_profile(2, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 2);
    let o = observer(&h, &r, &p);
    let budget = native::budget(&h, &r).await;
    let enrolled = o.enroll().await.unwrap();
    assert_eq!(enrolled.revision, 1);
    assert!(!enrolled.execution_authority);
    assert!(!enrolled.dependency_order_enforced);
    assert_eq!(o.reconcile().await.unwrap(), enrolled);
    let recreated = observer(&h, &r, &p);
    assert_eq!(recreated.enroll().await.unwrap(), enrolled);
    assert_eq!(recreated.status().await.unwrap(), enrolled);
    assert_eq!(native::budget(&h, &r).await, budget);
    let mut changed = p.clone();
    changed.nodes[0].inverse.as_mut().unwrap().semantics_digest = "d".repeat(64);
    assert!(observer(&h, &r, &changed).enroll().await.is_err());
    let mut changed = p.clone();
    changed.saga_id = "new-task-id".into();
    assert!(observer(&h, &r, &changed).enroll().await.is_err());
    let mut changed_trust = native::trust(&h, &r);
    changed_trust.lineage.outcome_keys = keys(17);
    let wrong = SagaObserver::new(h.ledger.clone(), p.clone(), changed_trust).unwrap();
    assert!(wrong.status().await.is_err());
    assert!(wrong.request_compensation().await.is_err());
    assert_eq!(o.history().await.unwrap().len(), 1);
}
#[tokio::test]
async fn saga_unknown_partial_commit_and_compensation_request_keep_original_costs_blocked() {
    let Some((mut h, r)) = native::ready_profile(2, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 2);
    let o = observer(&h, &r, &p);
    o.enroll().await.unwrap();
    let rec = h.issue().await.unwrap().record;
    let s = o.reconcile().await.unwrap();
    assert_eq!(s.nodes["node-0"].forward, F::Issued);
    let c = native::claim(&h, &rec, "original-saga-attempt").await;
    h.ledger
        .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    assert_eq!(
        o.reconcile().await.unwrap().nodes["node-0"].forward,
        F::Unknown
    );
    let s = o.request_compensation().await.unwrap();
    assert_eq!(s.nodes["node-0"].compensation, C::BlockedForwardUnknown);
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    native::worker(&h, &c, &rec.grant_digest, "not_found", calls.clone())
        .recover(&c)
        .await
        .unwrap();
    assert_eq!(
        o.reconcile().await.unwrap().nodes["node-0"].forward,
        F::Unknown
    );
    h.ledger.stop_reservation().await.unwrap();
    native::worker(&h, &c, &rec.grant_digest, "committed", calls)
        .recover(&c)
        .await
        .unwrap();
    let held = native::budget(&h, &r).await;
    let s = observer(&h, &r, &p).reconcile().await.unwrap();
    assert_eq!(s.status, Status::NeedsOperator);
    assert!(!s.budget_active);
    let n = &s.nodes["node-0"];
    assert_eq!(n.forward, F::Committed);
    assert_eq!(n.compensation, C::RequiresFreshAdmissionAndBarrier);
    assert_eq!(n.attempt_id.as_deref(), Some("original-saga-attempt"));
    assert_eq!(n.grant_digest.as_deref(), Some(rec.grant_digest.as_str()));
    assert_eq!(s.nodes["node-1"].forward, F::Planned);
    assert!(!s.execution_authority);
    assert_eq!(o.request_compensation().await.unwrap(), s);
    assert_eq!(o.reconcile().await.unwrap(), s);
    assert_eq!(native::budget(&h, &r).await, held);
    assert_eq!(o.history().await.unwrap().last().unwrap().after, s);
}
#[tokio::test]
async fn saga_pre_send_no_effect_never_enables_inverse_or_refunds() {
    let Some((mut h, r)) = native::ready_profile(1, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 1);
    let o = observer(&h, &r, &p);
    o.enroll().await.unwrap();
    let rec = h.issue().await.unwrap().record;
    let c = native::claim(&h, &rec, "before-send").await;
    o.reconcile().await.unwrap();
    o.request_compensation().await.unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    native::worker(&h, &c, &rec.grant_digest, "committed", calls.clone())
        .recover(&c)
        .await
        .unwrap();
    let held = native::budget(&h, &r).await;
    let s = o.reconcile().await.unwrap();
    assert_eq!(s.nodes["node-0"].forward, F::ProvenNoEffect);
    assert_eq!(s.nodes["node-0"].compensation, C::BlockedNotCommitted);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(native::budget(&h, &r).await, held);
    assert_eq!(
        (
            held.allocations[&rec.issuance_key].forward,
            held.allocations[&rec.issuance_key].compensation
        ),
        (1, 1)
    );
}
#[tokio::test]
async fn saga_dependency_intent_detects_violation_but_does_not_claim_native_enforcement() {
    let Some((mut h, r)) = native::ready_profile(2, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 2);
    let o = observer(&h, &r, &p);
    o.enroll().await.unwrap();
    h.f.proposal["qid"] = json!("saga-forward-1");
    h.issue().await.unwrap();
    let s = o.reconcile().await.unwrap();
    assert!(s.nodes["node-1"].dependency_violation);
    assert_eq!(s.status, Status::NeedsOperator);
    h.f.proposal["qid"] = json!("saga-forward-0");
    let rec = h.issue().await.unwrap().record;
    let c = native::claim(&h, &rec, "predecessor").await;
    h.ledger
        .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    native::worker(
        &h,
        &c,
        &rec.grant_digest,
        "committed",
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(&c)
    .await
    .unwrap();
    let s = o.reconcile().await.unwrap();
    assert!(s.nodes["node-1"].unmet_dependencies.is_empty());
    assert!(s.nodes["node-1"].dependency_violation);
    assert!(!s.dependency_order_enforced);
}
#[tokio::test]
async fn saga_closed_graph_inverse_identity_and_hypothetical_capacity_validation() {
    let example = Plan::decode(include_bytes!(
        "../../../../config/saga-observation-plan.example.json"
    ))
    .unwrap();
    let registration: kedgeflow::reserved_leaf::Registration = serde_json::from_slice(
        include_bytes!("../../../../config/hierarchical-history.example.json"),
    )
    .unwrap();
    assert_eq!(example.registration_digest, registration.digest().unwrap());

    let Some((mut h, r)) = native::ready_profile(2, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 2);
    let t = native::trust(&h, &r);
    Plan::decode(&serde_json::to_vec(&p).unwrap())
        .unwrap()
        .validate(&t)
        .unwrap();
    for variant in [
        "cycle",
        "duplicate",
        "dangling",
        "principal",
        "operation",
        "root",
        "inverse-cost",
        "inverse-resource",
        "same-action",
        "overdraw",
    ] {
        let mut bad = p.clone();
        match variant {
            "cycle" => bad.nodes[0].depends_on = vec!["node-1".into()],
            "duplicate" => bad.nodes[1].node_id = "node-0".into(),
            "dangling" => bad.nodes[0].depends_on = vec!["missing".into()],
            "principal" => bad.nodes[0].principal.workload_id = "spiffe://test/unapproved".into(),
            "operation" => bad.nodes[1].operation_key = bad.nodes[0].operation_key.clone(),
            "root" => bad.registration_digest = "0".repeat(64),
            "inverse-cost" => bad.nodes[0].inverse.as_mut().unwrap().compensation_units = 2,
            "inverse-resource" => {
                bad.nodes[0]
                    .inverse
                    .as_mut()
                    .unwrap()
                    .scope
                    .resource
                    .incarnation = "changed".into()
            }
            "same-action" => {
                bad.nodes[0].inverse.as_mut().unwrap().scope.action = r.scope.action.clone()
            }
            "overdraw" => {
                let mut n = bad.nodes[0].clone();
                n.node_id = "third".into();
                n.operation_key = "d".repeat(64);
                bad.nodes.push(n);
            }
            _ => unreachable!(),
        }
        assert!(bad.validate(&t).is_err(), "{variant}");
    }
    let mut v = json!(p);
    v["nodes"][1]["depends_on"] = json!(["node-0", "node-0"]);
    assert!(Plan::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut v = json!(p);
    v["execution_authority"] = json!(true);
    assert!(Plan::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    let raw = serde_json::to_string(&p)
        .unwrap()
        .replacen('{', "{\"profile\":\"duplicate\",", 1);
    assert!(Plan::decode(raw.as_bytes()).is_err());
    let mut wrong = native::trust_value(&h, &r);
    wrong["lineage"]["outcome_keys"] = json!(r.hierarchy.as_ref().unwrap().delegation_keys);
    assert!(
        kedgeflow::reserved_lineage::TrustConfig::decode(&serde_json::to_vec(&wrong).unwrap())
            .unwrap()
            .registration()
            .is_err()
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saga_concurrent_observers_append_one_original_observation() {
    let Some((mut h, r)) = native::ready_profile(1, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 1);
    let o = observer(&h, &r, &p);
    o.enroll().await.unwrap();
    let rec = h.issue().await.unwrap().record;
    let c = native::claim(&h, &rec, "one-original").await;
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    native::worker(
        &h,
        &c,
        &rec.grant_digest,
        "unknown",
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(&c)
    .await
    .unwrap();
    let mut jobs = vec![];
    for _ in 0..8 {
        let o = observer(&h, &r, &p);
        jobs.push(tokio::spawn(async move { o.reconcile().await }));
    }
    let mut passed = 0;
    for j in jobs {
        if j.await.unwrap().is_ok() {
            passed += 1;
        }
    }
    assert!(passed > 0);
    assert_eq!(o.status().await.unwrap().revision, 2);
    assert_eq!(o.history().await.unwrap().len(), 2);
}
#[tokio::test]
async fn saga_refuses_adoption_unplanned_children_and_missing_original_authorization() {
    let Some((mut h, r)) = native::ready_profile(2, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 1);
    let o = observer(&h, &r, &p);
    o.enroll().await.unwrap();
    let rec = h.issue().await.unwrap().record;
    o.reconcile().await.unwrap();
    let key = format!("{}/admission-chain/{}", h.prefix, rec.issuance_key);
    let raw = h.ledger.read_key(&key).await.unwrap().unwrap();
    write(&h, &key, None).await;
    assert!(o.reconcile().await.is_err());
    write(&h, &key, Some(&raw)).await;
    h.f.proposal["qid"] = json!("unplanned-operation");
    h.issue().await.unwrap();
    assert!(o.reconcile().await.is_err());
    let Some((mut h, r)) = native::ready_profile(1, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 1);
    h.issue().await.unwrap();
    assert!(observer(&h, &r, &p).enroll().await.is_err());
}
#[tokio::test]
async fn saga_missing_corrupt_head_latest_proofs_and_older_journal_never_reset() {
    let Some((mut h, r)) = native::ready_profile(1, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 1);
    let o = observer(&h, &r, &p);
    o.enroll().await.unwrap();
    let rec = h.issue().await.unwrap().record;
    let issued = o.reconcile().await.unwrap();
    native::claim(&h, &rec, "held").await;
    o.reconcile().await.unwrap();
    let base = saga_base(&h, &p);
    for suffix in ["head", "events/000003"] {
        let key = format!("{base}/{suffix}");
        let raw = h.ledger.read_key(&key).await.unwrap().unwrap();
        write(&h, &key, Some(b"{}")).await;
        assert!(o.status().await.is_err());
        assert!(o.enroll().await.is_err());
        write(&h, &key, Some(&raw)).await;
    }
    let older = format!("{base}/events/000002");
    let raw = h.ledger.read_key(&older).await.unwrap().unwrap();
    write(&h, &older, None).await;
    assert!(o.history().await.is_err());
    write(&h, &older, Some(&raw)).await;
    let proof = format!(
        "{base}/proofs/{}",
        issued.nodes["node-0"].proof_digest.as_ref().unwrap()
    );
    write(&h, &proof, None).await;
    assert!(o.history().await.is_err());
    let proof = format!(
        "{base}/proofs/{}",
        o.status().await.unwrap().nodes["node-0"]
            .proof_digest
            .as_ref()
            .unwrap()
    );
    write(&h, &proof, None).await;
    assert!(o.status().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saga_stale_observation_cas_refuses_new_receipt_without_budget_change() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use base64::engine::general_purpose::STANDARD;
    use std::sync::atomic::AtomicBool;
    for phase in ["receipt", "stop"] {
        let Some((mut h, r)) = native::ready_profile(1, true).await else {
            return;
        };
        let p = plan(&mut h, &r, 1);
        let o = observer(&h, &r, &p);
        o.enroll().await.unwrap();
        let rec = h.issue().await.unwrap().record;
        let c = native::claim(&h, &rec, "race-receipt").await;
        h.ledger
            .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
            .await
            .unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let first = Arc::new(AtomicBool::new(true));
        let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
        let router = Router::new().route(
            "/v3/kv/txn",
            post({
                let entered = entered.clone();
                let release = release.clone();
                move |Json(v): Json<Value>| {
                    let entered = entered.clone();
                    let release = release.clone();
                    let first = first.clone();
                    let endpoint = endpoint.clone();
                    async move {
                        let selected = v["success"].as_array().is_some_and(|ops| {
                            ops.iter().any(|op| {
                                op["request_put"]["value"]
                                    .as_str()
                                    .and_then(|s| STANDARD.decode(s).ok())
                                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                                    .is_some_and(|v| {
                                        v["profile"] == PROFILE
                                            && v["revision"] == 2
                                            && v["nodes"].is_object()
                                    })
                            })
                        });
                        if selected && first.swap(false, Ordering::SeqCst) {
                            entered.notify_one();
                            release.notified().await;
                        }
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
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let _proxy = live_agent::Running(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }));
        let ledger = EtcdLedger::new(reqwest::Client::new(), endpoint, &h.prefix)
            .unwrap()
            .with_clock(h.clock.clone())
            .requiring_control(None)
            .with_reservation(r.clone())
            .unwrap();
        let delayed = SagaObserver::new(ledger, p.clone(), native::trust(&h, &r)).unwrap();
        let job = tokio::spawn(async move { delayed.reconcile().await });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        let budget = native::budget(&h, &r).await;
        h.clock.0.store(NOW + 6000, Ordering::SeqCst);
        if phase == "receipt" {
            native::worker(
                &h,
                &c,
                &rec.grant_digest,
                "unknown",
                Arc::new(AtomicUsize::new(0)),
            )
            .recover(&c)
            .await
            .unwrap();
            assert_eq!(native::budget(&h, &r).await, budget);
        } else {
            h.ledger.stop_reservation().await.unwrap();
        }
        release.notify_one();
        assert!(job.await.unwrap().is_err());
        assert_eq!(o.status().await.unwrap().revision, 1);
        let s = o.reconcile().await.unwrap();
        assert_eq!(s.nodes["node-0"].forward, F::Unknown);
        assert_eq!(
            s.nodes["node-0"].receipt_digest.is_some(),
            phase == "receipt"
        );
        assert_eq!(s.budget_active, phase == "receipt");
    }
}

#[tokio::test]
async fn saga_journal_exhaustion_keeps_original_unknown_allowances_and_read_only_status() {
    let Some((mut h, r)) = native::ready_profile(8, true).await else {
        return;
    };
    let mut p = plan(&mut h, &r, 8);
    for n in &mut p.nodes {
        n.depends_on.clear();
    }
    let o = observer(&h, &r, &p);
    o.enroll().await.unwrap();
    let mut operations = vec![];
    for n in 0..8 {
        h.f.proposal["qid"] = json!(format!("saga-forward-{n}"));
        let rec = h.issue().await.unwrap().record;
        let c = native::claim(&h, &rec, &format!("original-{n}")).await;
        h.ledger
            .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
            .await
            .unwrap();
        operations.push((rec, c));
    }
    o.reconcile().await.unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    let held = native::budget(&h, &r).await;
    for n in 0..126 {
        let (rec, c) = &operations[n % 8];
        native::worker(
            &h,
            c,
            &rec.grant_digest,
            if (n / 8) % 2 == 0 {
                "unknown"
            } else {
                "pending"
            },
            Arc::new(AtomicUsize::new(0)),
        )
        .recover(c)
        .await
        .unwrap();
        let s = o
            .reconcile()
            .await
            .unwrap_or_else(|e| panic!("observation {n}: {e}"));
        assert_eq!(s.revision, n as u64 + 3);
    }
    let s = o.status().await.unwrap();
    assert_eq!(s.revision, kedgeflow::saga::MAX_EVENTS);
    assert!(s.nodes.values().all(|n| n.forward == F::Unknown));
    assert!(o.request_compensation().await.is_err());
    assert_eq!(o.reconcile().await.unwrap(), s);
    assert_eq!(native::budget(&h, &r).await, held);
    assert_eq!(o.history().await.unwrap().len(), 128);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saga_shipping_cli_tls_check_enroll_reconcile_restart_and_blocked_request() {
    use axum::{Extension, Json, Router, response::IntoResponse, routing::post};
    use kedgeflow::auth::WorkloadIdentity;
    use std::os::unix::fs::PermissionsExt;
    let Some((mut h, r)) = native::ready_profile(1, true).await else {
        return;
    };
    let p = plan(&mut h, &r, 1);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let router = Router::new().route(
        "/v3/kv/txn",
        post(
            move |Extension(w): Extension<WorkloadIdentity>,
                  headers: http::HeaderMap,
                  Json(v): Json<Value>| {
                let endpoint = endpoint.clone();
                let count = count.clone();
                async move {
                    assert_eq!(w.as_str(), "spiffe://test/agent");
                    assert_eq!(headers["authorization"], "saga-observer-token");
                    count.fetch_add(1, Ordering::SeqCst);
                    // The shipping observer may write only its own observer namespace/identity markers.
                    for op in v["success"].as_array().unwrap() {
                        if let Some(k) = op["request_put"]["key"].as_str() {
                            let raw = base64::engine::general_purpose::STANDARD.decode(k).unwrap();
                            let key = String::from_utf8(raw).unwrap();
                            assert!(
                                key.contains("/saga-observations/")
                                    || key.contains("/saga-observation-roots/")
                                    || key.contains("/saga-observation-operations/")
                            );
                        }
                    }
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
    );
    let proxy = support::serve_tls(&h.agent_pki, router).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let ca = write("ca.pem", h.agent_pki.ca.as_bytes());
    let cert = write("cert.pem", h.agent_pki.client.as_bytes());
    let key = write("key.pem", h.agent_pki.client_key.as_bytes());
    let token = write("token", b"saga-observer-token");
    let mut config = json!({"plan":p,"trust":native::trust_value(&h,&r),"etcd_endpoint":proxy.url,"etcd_ca":ca,"etcd_certificate":cert,"etcd_private_key":key,"etcd_token_file":token});
    let path = write("saga.json", &serde_json::to_vec(&config).unwrap());
    let run = |flag: &str| {
        let path = path.clone();
        let flag = flag.to_owned();
        async move {
            tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-saga"))
                .arg("--config")
                .arg(path)
                .arg(flag)
                .output()
                .await
                .unwrap()
        }
    };
    let out = run("--check").await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let out = run("--enroll").await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = h.issue().await.unwrap().record;
    native::claim(&h, &rec, "shipping-original").await;
    let held = native::budget(&h, &r).await;
    let out = run("--once").await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["nodes"]["node-0"]["attempt_id"], "shipping-original");
    let out = run("--request-compensation").await;
    assert!(out.status.success());
    let s: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        s["nodes"]["node-0"]["compensation"],
        "blocked_forward_unknown"
    );
    assert_eq!(s["execution_authority"], false);
    let out = run("--status").await;
    assert!(out.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap(), s);
    assert!(run("--history").await.status.success());
    assert_eq!(native::budget(&h, &r).await, held);
    config["plan"]["saga_id"] = json!("changed-after-restart");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run("--enroll").await.status.success());
}
