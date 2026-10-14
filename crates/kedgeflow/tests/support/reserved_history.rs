//! v0.2 budgets, native receipt refinement and independently pinned offline replay.
use super::*;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    control_history::HistoryObserver,
    coordination::{Coordination, ReservationState as S},
    ledger::{AuthoritativeObservation, OutcomeQuerier},
    recovery::{Candidate, ExecutionRecord, RecoveryWorker},
    reservation_history::{LEAF_PROFILE, MAX_EVENTS, PROFILE},
    reserved_leaf::{Registration, ReservationBinding},
    reserved_lineage::{Bundle, Trust, TrustConfig, verify},
};
use std::sync::atomic::AtomicUsize;
fn encoded(map: &BTreeMap<String, ed25519_dalek::VerifyingKey>) -> BTreeMap<String, String> {
    map.iter()
        .map(|(id, k)| (id.clone(), STANDARD.encode(k.as_bytes())))
        .collect()
}
fn trust_value(h: &Harness, r: &Registration) -> Value {
    let t = &h.f.trust;
    let evidence:BTreeMap<_,_>=t.evidence.iter().map(|(id,e)|(id,json!({"obligation":e.obligation,"provider_id":e.provider_id,"provider_version":e.provider_version,"keys":encoded(&e.keys),"question":e.question,"result_schema_ref":e.result_schema_ref,"result_schema":e.result_schema,"max_age_ms":e.max_age_ms,"predicates":e.predicates}))).collect();
    json!({"registration":r,"namespace":h.prefix,"observer_id":"budget-observer","observer_keys":encoded(&keys(15)),"lineage":{"tenant":t.tenant,"workload_id":t.proposal_workload_id,"subjects":[h.f.identity.subject],"delegation_audience":h.f.proposal["delegation"]["token_audience"],"gateway_audience":r.scope.audience,"action_scope":t.required_scope,"proposal_keys":encoded(&t.proposal_keys),"registry_keys":encoded(&t.registry_keys),"manifest_keys":encoded(&t.manifest_keys),"admission_keys":encoded(&keys(6)),"grant_keys":encoded(&keys(5)),"outcome_keys":encoded(&keys(14)),"source_id":"spiffe://test/outcome","descriptor_digest":t.descriptor_digest,"ownership_epoch":t.ownership_epoch,"max_proposal_age_ms":t.max_proposal_age_ms,"policy":{"id":h.definition.policy_id,"epoch":t.policy.epoch,"cedar":h.definition.cedar,"max_certificate_lifetime_ms":h.definition.max_certificate_lifetime_ms},"evidence":evidence}})
}
fn trust(h: &Harness, r: &Registration) -> Trust {
    TrustConfig::decode(&serde_json::to_vec(&trust_value(h, r)).unwrap())
        .unwrap()
        .registration()
        .unwrap()
}
fn observer() -> HistoryObserver {
    HistoryObserver::new(
        "budget-observer".into(),
        "key-15".into(),
        SigningKey::from_bytes(&[15; 32]),
    )
    .unwrap()
}
async fn ready(units: u64) -> Option<(Harness, Registration)> {
    let mut h = Harness::new().await?;
    let mut r = super::reserved_leaf::registration(&h, units);
    r.profile = LEAF_PROFILE.into();
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let i = h.bootstrap().await;
    assert!(h.post(&h.ack(&i), true).await.0.is_success());
    Some((h, r))
}
fn grant(h: &Harness, record: &kedgeflow::ledger::IssuanceRecord) -> Grant {
    GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    }
    .verify_retained(record.signed_grant.as_bytes())
    .unwrap()
    .grant
}
async fn claim(h: &Harness, record: &kedgeflow::ledger::IssuanceRecord, id: &str) -> Candidate {
    let c = Candidate {
        grant: grant(h, record),
        attempt_id: id.into(),
    };
    h.ledger
        .claim_recorded(
            &c.grant,
            &record.grant_digest,
            id,
            &ExecutionRecord {
                signed_grant: record.signed_grant.clone(),
                tool: "node_drain".into(),
                parameters: h.f.proposal["parameters"].clone(),
            },
        )
        .await
        .unwrap();
    c
}
struct Query {
    c: Candidate,
    gd: String,
    status: String,
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl OutcomeQuerier for Query {
    async fn query(&self, _: &str) -> kedgeflow::error::Result<AuthoritativeObservation> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthoritativeObservation {
            attempt_id: self.c.attempt_id.clone(),
            root_id: self.c.grant.root_id.clone(),
            grant_digest: self.gd.clone(),
            target_reference: "software-target/original".into(),
            status: self.status.clone(),
        })
    }
}
fn worker(
    h: &Harness,
    c: &Candidate,
    gd: &str,
    status: &str,
    calls: Arc<AtomicUsize>,
) -> RecoveryWorker {
    RecoveryWorker::new(
        h.ledger.clone(),
        GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        },
        Arc::new(Query {
            c: c.clone(),
            gd: gd.into(),
            status: status.into(),
            calls,
        }),
        "key-14".into(),
        SigningKey::from_bytes(&[14; 32]),
        "spiffe://test/outcome".into(),
        h.clock.clone(),
    )
    .unwrap()
}
async fn budget(h: &Harness, r: &Registration) -> kedgeflow::coordination::ReservationSnapshot {
    Coordination::new(h.ledger.clone(), &r.root_id)
        .unwrap()
        .status()
        .await
        .unwrap()
}
async fn export(h: &Harness, r: &Registration, c: &Candidate, key: &str) -> Bundle {
    h.ledger
        .export_reserved_lineage(c, key, &observer(), &trust(h, r))
        .await
        .unwrap()
}
fn resign(b: &mut Bundle) {
    let mut prev = None;
    for (i, e) in b.events.iter_mut().enumerate() {
        e.sequence = i as u64 + 1;
        e.previous_digest = prev;
        prev = Some(e.digest().unwrap());
    }
    b.checkpoint.payload.event_count = b.events.len() as u64;
    b.checkpoint.payload.head_digest = prev.unwrap();
    b.checkpoint.payload.lineage_digest =
        kedgeflow::contracts::digest("reserved-inner-lineage", &json!(b.lineage)).unwrap();
    let mut raw = format!("KedgeFlow:{PROFILE}\0").into_bytes();
    raw.extend(canonical(&json!({"profile":b.checkpoint.profile,"key_id":b.checkpoint.key_id,"payload":b.checkpoint.payload})).unwrap());
    b.checkpoint.signature =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[15; 32]).sign(&raw).to_bytes());
}

#[tokio::test]
async fn reserved_history_pre_dispatch_receipt_refines_once_without_refund_after_stop() {
    let Some((mut h, r)) = ready(1).await else {
        return;
    };
    let rec = h.issue().await.unwrap().record;
    let reused = h.issue().await.unwrap();
    assert!(reused.reused);
    assert_eq!(reused.record, rec);
    let c = claim(&h, &rec, "before-send").await;
    h.ledger.stop_reservation().await.unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    let w = worker(&h, &c, &rec.grant_digest, "committed", calls.clone());
    let first = w.recover(&c).await.unwrap();
    let again = w.recover(&c).await.unwrap();
    assert_eq!(first.receipt_digest, again.receipt_digest);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let s = budget(&h, &r).await;
    assert!(!s.active);
    let a = &s.allocations[&rec.issuance_key];
    assert_eq!(a.state, S::ProvenNoEffect);
    assert_eq!((a.forward, a.compensation), (1, 1));
    assert!(
        h.ledger
            .claim(&c.grant, &rec.grant_digest, "replacement")
            .await
            .is_err()
    );
    assert!(
        h.ledger
            .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
            .await
            .is_err()
    );
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    let result = verify(&b, &trust(&h, &r)).unwrap();
    assert_eq!(result.budget_state, S::ProvenNoEffect);
    assert_eq!(
        b.events.iter().filter(|e| e.data.phase == "refine").count(),
        1
    );
    assert!(!result.execution_authority);
    assert!(
        h.ledger
            .export_lineage(&c, &rec.issuance_key)
            .await
            .is_err()
    );
    h.f.proposal["qid"] = json!("another-operation");
    assert!(h.issue().await.is_err());
}

#[tokio::test]
async fn reserved_history_uncertain_queries_hold_unknown_until_original_commit_is_reported() {
    let Some((mut h, r)) = ready(1).await else {
        return;
    };
    let rec = h.issue().await.unwrap().record;
    let c = claim(&h, &rec, "dispatched-original").await;
    h.ledger
        .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    h.ledger.stop_reservation().await.unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    for status in ["not_found", "pending", "fenced_no_effect", "unknown"] {
        let w = worker(
            &h,
            &c,
            &rec.grant_digest,
            status,
            Arc::new(AtomicUsize::new(0)),
        );
        w.recover(&c).await.unwrap();
        assert_eq!(
            budget(&h, &r).await.allocations[&rec.issuance_key].state,
            S::Unknown
        );
        assert_eq!(
            verify(&export(&h, &r, &c, &rec.issuance_key).await, &trust(&h, &r))
                .unwrap()
                .budget_state,
            S::Unknown
        );
    }
    let w = worker(
        &h,
        &c,
        &rec.grant_digest,
        "committed",
        Arc::new(AtomicUsize::new(0)),
    );
    w.recover(&c).await.unwrap();
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    let v = verify(&b, &trust(&h, &r)).unwrap();
    assert_eq!(v.budget_state, S::Committed);
    assert_eq!((v.held_forward, v.held_compensation), (1, 1));
    assert_eq!(v.lineage.attempt_id, c.attempt_id);
    h.f.proposal["qid"] = json!("new-after-commit");
    assert!(h.issue().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_history_competing_receipt_workers_append_one_original_refinement() {
    let Some((h, r)) = ready(1).await else { return };
    let rec = h.issue().await.unwrap().record;
    let c = claim(&h, &rec, "receipt-race").await;
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    let mut jobs = Vec::new();
    for _ in 0..8 {
        let w = worker(
            &h,
            &c,
            &rec.grant_digest,
            "unknown",
            Arc::new(AtomicUsize::new(0)),
        );
        let c = c.clone();
        jobs.push(tokio::spawn(async move { w.recover(&c).await }));
    }
    let mut success = 0;
    for j in jobs {
        if j.await.unwrap().is_ok() {
            success += 1;
        }
    }
    assert!(success >= 1);
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    assert_eq!(
        b.events.iter().filter(|e| e.data.phase == "refine").count(),
        1
    );
    assert_eq!(
        verify(&b, &trust(&h, &r)).unwrap().budget_state,
        S::ProvenNoEffect
    );
}

#[tokio::test]
async fn reserved_history_closed_and_resigned_semantic_substitutions_refuse() {
    let Some((h, r)) = ready(2).await else { return };
    let rec = h.issue().await.unwrap().record;
    let c = claim(&h, &rec, "audit-original").await;
    h.ledger
        .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    worker(
        &h,
        &c,
        &rec.grant_digest,
        "committed",
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(&c)
    .await
    .unwrap();
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    let t = trust(&h, &r);
    Bundle::decode(&serde_json::to_vec(&b).unwrap()).unwrap();
    for variant in [
        "allocation",
        "fence",
        "dispatch",
        "refinement",
        "reorder",
        "cost",
        "attempt",
        "refund",
        "root",
        "namespace",
        "capture",
    ] {
        let mut bad = b.clone();
        match variant {
            "allocation" => {
                bad.events.remove(1);
            }
            "fence" => bad.events[1].data.fence = Some(999),
            "dispatch" => {
                bad.events.retain(|e| e.data.phase != "dispatch");
            }
            "refinement" => {
                bad.events.retain(|e| e.data.phase != "refine");
            }
            "reorder" => bad.events.swap(2, 3),
            "cost" => {
                bad.events[1]
                    .after
                    .allocations
                    .get_mut(&rec.issuance_key)
                    .unwrap()
                    .forward = 2
            }
            "attempt" => bad.events[3].data.attempt_id = Some("substitute".into()),
            "refund" => bad.events.last_mut().unwrap().after.allocations.clear(),
            "root" => bad.events[0].registration_digest = "a".repeat(64),
            "namespace" => bad.checkpoint.payload.namespace = "/wrong".into(),
            "capture" => bad.checkpoint.payload.captured_at = 0,
            _ => unreachable!(),
        }
        resign(&mut bad);
        assert!(verify(&bad, &t).is_err(), "{variant}");
    }
    let mut duplicate_scope = json!(b);
    let id = duplicate_scope["events"][0]["after"]["enrollment"]["scope"]["actions"][0].clone();
    duplicate_scope["events"][0]["after"]["enrollment"]["scope"]["actions"]
        .as_array_mut()
        .unwrap()
        .push(id);
    assert!(Bundle::decode(&serde_json::to_vec(&duplicate_scope).unwrap()).is_err());
    let mut bad = json!(b);
    bad["unknown"] = json!(true);
    assert!(Bundle::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let duplicate =
        serde_json::to_string(&b)
            .unwrap()
            .replacen("{", "{\"profile\":\"duplicate\",", 1);
    assert!(Bundle::decode(duplicate.as_bytes()).is_err());
    for variant in ["issuer", "observer", "outcome", "root", "cost", "profile"] {
        let mut tv = trust_value(&h, &r);
        match variant {
            "issuer" => tv["registration"]["issuer_keys"] = json!(encoded(&keys(6))),
            "observer" => tv["observer_keys"] = json!(encoded(&keys(5))),
            "outcome" => tv["lineage"]["outcome_keys"] = json!(encoded(&keys(5))),
            "root" => tv["registration"]["root_id"] = json!("wrong"),
            "cost" => tv["registration"]["compensation_units"] = json!(0),
            "profile" => tv["registration"]["profile"] = json!("KF-RESERVED-LEAF-0.1-draft"),
            _ => unreachable!(),
        }
        let changed = TrustConfig::decode(&serde_json::to_vec(&tv).unwrap())
            .unwrap()
            .registration();
        assert!(
            changed.is_err() || verify(&b, &changed.unwrap()).is_err(),
            "{variant}"
        );
    }
}

pub(super) async fn sdk_finalize(h: &Harness, first: &Value) {
    let mut r = super::reserved_leaf::registration(h, 1);
    r.profile = LEAF_PROFILE.into();
    let gd = first["grant_digest"].as_str().unwrap();
    let raw = h
        .ledger
        .read_key(&format!("{}/reserved-grants/{gd}", h.prefix))
        .await
        .unwrap()
        .unwrap();
    let binding: ReservationBinding = serde_json::from_slice(&raw).unwrap();
    let raw = h
        .ledger
        .read_key(&format!(
            "{}/issuance/{}",
            h.prefix, binding.payload.operation_key
        ))
        .await
        .unwrap()
        .unwrap();
    let issued: kedgeflow::ledger::IssuanceRecord = serde_json::from_slice(&raw).unwrap();
    let c = Candidate {
        grant: grant(h, &issued),
        attempt_id: first["attempt_id"].as_str().unwrap().into(),
    };
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    worker(h, &c, gd, "committed", calls.clone())
        .recover(&c)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut tv = trust_value(h, &r);
    tv["lineage"]["delegation_audience"] = json!(AUD);
    let t = TrustConfig::decode(&serde_json::to_vec(&tv).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    let b = h
        .ledger
        .export_reserved_lineage(&c, &binding.payload.operation_key, &observer(), &t)
        .await
        .unwrap();
    let v = verify(&b, &t).unwrap();
    assert_eq!(v.budget_state, S::Committed);
    assert!(!v.budget_active);
    assert_eq!(v.events_verified, 7);
    println!(
        "reserved SDK PASS: original committed attempt refined after stop; seven conserved authority/history events; independent offline audit; no extra target query"
    );
}

#[tokio::test]
async fn reserved_history_shipping_offline_cli_rejects_wrong_observer_and_namespace() {
    let Some((h, r)) = ready(1).await else { return };
    let rec = h.issue().await.unwrap().record;
    let c = claim(&h, &rec, "cli-attempt").await;
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    worker(
        &h,
        &c,
        &rec.grant_digest,
        "unknown",
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(&c)
    .await
    .unwrap();
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    let dir = tempfile::tempdir().unwrap();
    let tv = dir.path().join("trust.json");
    let bf = dir.path().join("bundle.json");
    std::fs::write(&tv, serde_json::to_vec(&trust_value(&h, &r)).unwrap()).unwrap();
    std::fs::write(&bf, serde_json::to_vec(&b).unwrap()).unwrap();
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-reserved-lineage"))
            .arg("--trust")
            .arg(&tv)
            .arg("--bundle")
            .arg(&bf)
            .output()
            .unwrap()
    };
    let out = run();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["budget_state"], "proven_no_effect");
    assert_eq!(v["execution_authority"], false);
    for field in ["observer_id", "namespace"] {
        let mut bad = trust_value(&h, &r);
        bad[field] = json!("wrong");
        std::fs::write(&tv, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(!run().status.success());
    }
}

#[tokio::test]
async fn reserved_history_missing_head_latest_or_prior_events_never_synthesizes_audit() {
    let Some((h, r)) = ready(2).await else { return };
    let rec = h.issue().await.unwrap().record;
    let c = claim(&h, &rec, "held-original").await;
    let base = format!("{}/reservation-history/{}", h.prefix, r.digest().unwrap());
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let client = reqwest::Client::new();
    let put = |key: String, raw: Vec<u8>| {
        let client = client.clone();
        let endpoint = endpoint.clone();
        async move {
            client
                .post(format!("{endpoint}/v3/kv/put"))
                .json(&json!({"key":STANDARD.encode(key.as_bytes()),"value":STANDARD.encode(raw)}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        }
    };
    let head = format!("{base}/head");
    let original = h.ledger.read_key(&head).await.unwrap().unwrap();
    put(head.clone(), b"{}".to_vec()).await;
    assert!(
        h.ledger
            .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
            .await
            .is_err()
    );
    assert!(h.issue().await.is_err());
    put(head, original).await;
    let latest = format!("{base}/events/000004");
    let raw = h.ledger.read_key(&latest).await.unwrap().unwrap();
    client
        .post(format!("{endpoint}/v3/kv/deleterange"))
        .json(&json!({"key":STANDARD.encode(latest.as_bytes())}))
        .send()
        .await
        .unwrap();
    assert!(
        h.ledger
            .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
            .await
            .is_err()
    );
    put(latest, raw).await;
    let legacy = Coordination::new(h.ledger.clone(), &r.root_id).unwrap();
    assert!(legacy.stop().await.is_err());
    assert!(
        legacy
            .allocate(&"a".repeat(64), None, r.enrollment.scope.clone(), 1, 1)
            .await
            .is_err()
    );
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    worker(
        &h,
        &c,
        &rec.grant_digest,
        "unknown",
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(&c)
    .await
    .unwrap();
    let older = format!("{base}/events/000002");
    client
        .post(format!("{endpoint}/v3/kv/deleterange"))
        .json(&json!({"key":STANDARD.encode(older)}))
        .send()
        .await
        .unwrap();
    assert!(
        h.ledger
            .export_reserved_lineage(&c, &rec.issuance_key, &observer(), &trust(&h, &r))
            .await
            .is_err()
    );
    assert_eq!(
        budget(&h, &r).await.allocations[&rec.issuance_key].state,
        S::ProvenNoEffect
    );
}

#[tokio::test]
async fn reserved_history_exhaustion_holds_allocations_and_reserves_final_stop_event() {
    let Some((mut h, r)) = ready(128).await else {
        return;
    };
    for i in 0..127 {
        h.f.proposal["qid"] = json!(format!("bounded-{i}"));
        h.issue().await.unwrap();
    }
    let base = format!("{}/reservation-history/{}", h.prefix, r.digest().unwrap());
    let head_key = format!("{base}/head");
    let head = || h.ledger.read_key(&head_key);
    // Read directly without manufacturing a shorter history or resetting capacity.
    let value: Value = serde_json::from_slice(&head().await.unwrap().unwrap()).unwrap();
    assert_eq!(value["sequence"], MAX_EVENTS - 1);
    h.f.proposal["qid"] = json!("exhausted-new-operation");
    assert!(h.issue().await.is_err());
    assert_eq!(budget(&h, &r).await.allocations.len(), 127);
    h.ledger.stop_reservation().await.unwrap();
    h.ledger.stop_reservation().await.unwrap();
    let value: Value = serde_json::from_slice(&head().await.unwrap().unwrap()).unwrap();
    assert_eq!(value["sequence"], MAX_EVENTS);
    assert!(!budget(&h, &r).await.active);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_history_recovery_cas_races_dispatch_and_stop_without_false_no_effect() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use std::sync::atomic::AtomicBool;
    for phase in ["dispatch", "stop"] {
        let Some((mut h, r)) = ready(1).await else {
            return;
        };
        let rec = h.issue().await.unwrap().record;
        let c = claim(&h, &rec, "raced-original").await;
        let direct = h.ledger.clone();
        h.clock.0.store(NOW + 6000, Ordering::SeqCst);
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let block = Arc::new(AtomicBool::new(true));
        let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
        let router = Router::new().route(
            "/v3/kv/txn",
            post({
                let entered = entered.clone();
                let release = release.clone();
                move |Json(value): Json<Value>| {
                    let entered = entered.clone();
                    let release = release.clone();
                    let block = block.clone();
                    let endpoint = endpoint.clone();
                    async move {
                        let selected = value["success"].as_array().is_some_and(|ops| {
                            ops.iter().any(|op| {
                                op["request_put"]["value"]
                                    .as_str()
                                    .and_then(|s| STANDARD.decode(s).ok())
                                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                                    .is_some_and(|v| v["data"]["phase"] == "refine")
                            })
                        });
                        if selected && block.swap(false, Ordering::SeqCst) {
                            entered.notify_one();
                            release.notified().await;
                        }
                        let response = reqwest::Client::new()
                            .post(format!("{endpoint}/v3/kv/txn"))
                            .json(&value)
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
        h.ledger = EtcdLedger::new(reqwest::Client::new(), endpoint, &h.prefix)
            .unwrap()
            .with_clock(h.clock.clone())
            .requiring_control(Some(h.registration.trust_digest.clone()))
            .with_reservation(r.clone())
            .unwrap();
        let w = worker(
            &h,
            &c,
            &rec.grant_digest,
            "unknown",
            Arc::new(AtomicUsize::new(0)),
        );
        let candidate = c.clone();
        let op = tokio::spawn(async move { w.recover(&candidate).await });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        if phase == "dispatch" {
            direct
                .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
                .await
                .unwrap();
        } else {
            direct.stop_reservation().await.unwrap();
        }
        release.notify_one();
        assert!(op.await.unwrap().is_err());
        assert_eq!(
            budget(&h, &r).await.allocations[&rec.issuance_key].state,
            S::Unknown
        );
        let w = worker(
            &h,
            &c,
            &rec.grant_digest,
            "unknown",
            Arc::new(AtomicUsize::new(0)),
        );
        w.recover(&c).await.unwrap();
        let expected = if phase == "dispatch" {
            S::Unknown
        } else {
            S::ProvenNoEffect
        };
        assert_eq!(
            budget(&h, &r).await.allocations[&rec.issuance_key].state,
            expected
        );
        assert_eq!(
            verify(&export(&h, &r, &c, &rec.issuance_key).await, &trust(&h, &r))
                .unwrap()
                .budget_state,
            expected
        );
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_history_shipping_recovery_cli_refines_original_and_refuses_missing_config() {
    use axum::{Extension, Json, Router, response::IntoResponse, routing::post};
    use kedgeflow::{auth::WorkloadIdentity, clock::Clock};
    use std::os::unix::fs::PermissionsExt;
    let now = kedgeflow::clock::SystemClock.now_ms() - 6000;
    let Some(mut h) = Harness::with_setup(None, now, |_| {}).await else {
        return;
    };
    let mut r = super::reserved_leaf::registration(&h, 1);
    r.profile = LEAF_PROFILE.into();
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    h.f.identity.delegation_digest =
        kedgeflow::contracts::digest("delegation", &h.f.proposal["delegation"]).unwrap();
    let mut packet = h.f.packet();
    let mut manifest =
        serde_json::from_slice::<Value>(&packet.manifest).unwrap()["payload"].clone();
    manifest["assembled_at"] = json!(now - 2);
    packet.manifest = fixture::signed("manifest", manifest, 3);
    let inputs =
        h.f.trust
            .verify_inputs(&h.f.identity, packet.borrowed(), &Time(now))
            .unwrap();
    let controller = AdmissionController::new(
        CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
        "key-6".into(),
        SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    let cert = h
        .ledger
        .admit(
            &controller.prepare(&inputs, &Time(now)).unwrap(),
            &Time(now),
        )
        .await
        .unwrap()
        .record
        .signed_certificate;
    let authority = GrantAuthority::new(
        IssuanceVerifier {
            tenant: h.f.trust.tenant.clone(),
            admission_keys: keys(6),
            grants: GrantVerifier {
                keys: keys(5),
                audience: h.registration.scope.audience.clone(),
            },
        },
        "key-5".into(),
        SigningKey::from_bytes(&[5; 32]),
    )
    .unwrap();
    let rec = authority
        .issue(&h.ledger, &inputs, cert.as_bytes(), &Time(now))
        .await
        .unwrap()
        .record;

    let c = claim(&h, &rec, "shipping-recovery-original").await;
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let router = Router::new().route(
        "/v3/kv/txn",
        post(
            move |Extension(w): Extension<WorkloadIdentity>,
                  headers: http::HeaderMap,
                  Json(v): Json<Value>| {
                let endpoint = endpoint.clone();
                async move {
                    assert_eq!(w.as_str(), "spiffe://test/agent");
                    assert_eq!(headers["authorization"], "recovery-etcd-token");
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
    let queries = Arc::new(AtomicUsize::new(0));
    let q = queries.clone();
    let target = support::serve_tls(
        &h.agent_pki,
        Router::new().route(
            "/query",
            post(move || {
                let q = q.clone();
                async move {
                    q.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"Status":"unknown"}))
                }
            }),
        ),
    )
    .await;
    let dir = tempfile::Builder::new()
        .prefix("kf-reserved-recovery-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let root = dir.path();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let p = root.join(name);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    };
    let ca = write("ca.pem", h.agent_pki.ca.as_bytes());
    let cert = write("client.pem", h.agent_pki.client.as_bytes());
    let key = write("client-key.pem", h.agent_pki.client_key.as_bytes());
    let token = write("etcd-token", b"recovery-etcd-token");
    let query = write("query-token", b"query-only-token");
    let seed = write("outcome-seed", STANDARD.encode([14; 32]).as_bytes());
    let mut config = json!({"reservation":r,"etcd_endpoint":proxy.url,"etcd_prefix":h.prefix,"etcd_ca":ca,"etcd_certificate":cert,"etcd_private_key":key,"etcd_token_file":token,"gateway_audience":r.scope.audience,"grant_keys":r.issuer_keys,"query_url":format!("{}/query",target.url),"query_ca":ca,"query_certificate":cert,"query_private_key":key,"query_token_file":query,"receipt_key_id":"key-14","receipt_signing_key_file":seed,"source_id":"spiffe://test/outcome","page_size":16,"poll_interval_ms":1000});
    let path = write("recovery.json", &serde_json::to_vec(&config).unwrap());
    let run = |flag: &str| {
        let path = path.clone();
        let flag = flag.to_owned();
        async move {
            tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-recover"))
                .arg("--config")
                .arg(path)
                .arg(flag)
                .output()
                .await
                .unwrap()
        }
    };
    let checked = run("--check").await;
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert_eq!(
        budget(&h, &r).await.allocations[&rec.issuance_key].state,
        S::Unknown
    );
    config.as_object_mut().unwrap().remove("reservation");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let rejected = run("--once").await;
    assert!(!rejected.status.success());
    assert_eq!(
        budget(&h, &r).await.allocations[&rec.issuance_key].state,
        S::Unknown
    );
    config["reservation"] = json!(r);
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let resolved = run("--once").await;
    assert!(
        resolved.status.success(),
        "{}",
        String::from_utf8_lossy(&resolved.stderr)
    );
    let sweep: Value = serde_json::from_slice(&resolved.stdout).unwrap();
    assert_eq!(sweep["reported"], 1);
    assert_eq!(
        budget(&h, &r).await.allocations[&rec.issuance_key].state,
        S::ProvenNoEffect
    );
    assert_eq!(queries.load(Ordering::SeqCst), 0);
    assert!(run("--once").await.status.success());
    h.clock
        .0
        .store(kedgeflow::clock::SystemClock.now_ms(), Ordering::SeqCst);
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    assert_eq!(
        b.events.iter().filter(|e| e.data.phase == "refine").count(),
        1
    );
    config["reservation"]["issuer_keys"] = json!(encoded(&keys(6)));
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run("--check").await.status.success());
}

#[tokio::test]
async fn reserved_history_two_original_operations_conserve_active_budget_after_no_effect() {
    let Some((mut h, r)) = ready(2).await else {
        return;
    };
    let first = h.issue().await.unwrap().record;
    h.f.proposal["qid"] = json!("second-budget-operation");
    let second = h.issue().await.unwrap().record;
    assert_eq!(grant(&h, &first).fence, 1);
    assert_eq!(grant(&h, &second).fence, 2);
    let a = claim(&h, &first, "original-a").await;
    let b = claim(&h, &second, "original-b").await;
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    for (c, record) in [(&a, &first), (&b, &second)] {
        worker(
            &h,
            c,
            &record.grant_digest,
            "unknown",
            Arc::new(AtomicUsize::new(0)),
        )
        .recover(c)
        .await
        .unwrap();
    }
    let state = budget(&h, &r).await;
    assert!(state.active);
    assert_eq!(state.allocations.len(), 2);
    assert!(
        state
            .allocations
            .values()
            .all(|a| a.state == S::ProvenNoEffect)
    );
    assert_eq!(
        state.allocations.values().map(|a| a.forward).sum::<u64>(),
        2
    );
    assert_eq!(
        state
            .allocations
            .values()
            .map(|a| a.compensation)
            .sum::<u64>(),
        2
    );
    h.f.proposal["qid"] = json!("no-refund-third-operation");
    assert!(h.issue().await.is_err());
    assert_eq!(budget(&h, &r).await.allocations.len(), 2);
    h.ledger.stop_reservation().await.unwrap();
    for (c, record) in [(&a, &first), (&b, &second)] {
        let bundle = export(&h, &r, c, &record.issuance_key).await;
        let result = verify(&bundle, &trust(&h, &r)).unwrap();
        assert_eq!(result.budget_state, S::ProvenNoEffect);
        assert_eq!(result.events_verified, 10);
        assert_eq!(result.lineage.operation_key, record.issuance_key);
    }
}
