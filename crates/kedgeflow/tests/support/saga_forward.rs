//! Native forward DAG authority against managed etcd; no inverse execution claim.
use super::reserved_history as native;
use super::*;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    coordination::{Coordination, ReservationState as S},
    hierarchical_leaf::Principal,
    reserved_leaf::{Registration, verify_binding},
    reserved_lineage::{Bundle, verify},
    saga_forward::{LINEAGE_PROFILE, Node, PROFILE, Plan},
};
use std::sync::atomic::AtomicUsize;

pub(super) fn registration(h: &mut Harness, count: usize, chain: bool) -> Registration {
    let mut r = super::hierarchical_leaf::registration(h, count as u64);
    let original = h.f.proposal["qid"].clone();
    let mut nodes = Vec::new();
    for n in 0..count {
        if count > 1 {
            h.f.proposal["qid"] = json!(format!("forward-{n}"));
        }
        nodes.push(Node {
            node_id: format!("node-{n}"),
            operation_key: h
                .f
                .trust
                .operation_key(&h.f.identity, &h.f.packet().proposal)
                .unwrap(),
            principal: Principal {
                subject: h.f.identity.subject.clone(),
                workload_id: h.f.identity.workload_id.clone(),
            },
            depends_on: if chain && n > 0 {
                vec![format!("node-{}", n - 1)]
            } else {
                vec![]
            },
        });
    }
    h.f.proposal["qid"] = if count > 1 {
        json!("forward-0")
    } else {
        original
    };
    r.profile = PROFILE.into();
    r.saga = Some(Plan {
        profile: PROFILE.into(),
        saga_id: "approved-forward-saga".into(),
        valid_from: NOW - 1000,
        expires_at: NOW + 60000,
        nodes,
        outcome_keys: keys(14)
            .into_iter()
            .map(|(id, k)| (id, STANDARD.encode(k.as_bytes())))
            .collect(),
        source_id: "spiffe://test/outcome".into(),
    });
    r.validate().unwrap();
    r
}
async fn ready(count: usize, chain: bool) -> Option<(Harness, Registration)> {
    let mut h = Harness::new().await?;
    let r = registration(&mut h, count, chain);
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let i = h.bootstrap().await;
    assert!(h.post(&h.ack(&i), true).await.0.is_success());
    Some((h, r))
}
async fn export(
    h: &Harness,
    r: &Registration,
    c: &kedgeflow::recovery::Candidate,
    op: &str,
) -> Bundle {
    let observer = kedgeflow::control_history::HistoryObserver::new(
        "budget-observer".into(),
        "key-15".into(),
        SigningKey::from_bytes(&[15; 32]),
    )
    .unwrap();
    h.ledger
        .export_reserved_lineage(c, op, &observer, &native::trust(h, r))
        .await
        .unwrap()
}
async fn committed(
    h: &Harness,
    rec: &kedgeflow::ledger::IssuanceRecord,
) -> kedgeflow::recovery::Candidate {
    let c = native::claim(h, rec, "original-forward").await;
    h.ledger
        .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    native::worker(
        h,
        &c,
        &rec.grant_digest,
        "committed",
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(&c)
    .await
    .unwrap();
    c
}
async fn write(_h: &Harness, key: &str, value: Option<&[u8]>) {
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let (route, body) = match value {
        Some(v) => (
            "put",
            json!({"key":STANDARD.encode(key),"value":STANDARD.encode(v)}),
        ),
        None => ("deleterange", json!({"key":STANDARD.encode(key)})),
    };
    assert!(
        reqwest::Client::new()
            .post(format!("{endpoint}/v3/kv/{route}"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
}
fn plan_key(h: &Harness, r: &Registration) -> String {
    format!(
        "{}/saga-forward-plans/{}",
        h.prefix,
        URL_SAFE_NO_PAD.encode(&r.root_id)
    )
}

#[tokio::test]
async fn saga_forward_enrollment_holds_entire_dag_before_any_grant_or_admission() {
    let Some((mut h, r)) = ready(3, false).await else {
        return;
    };
    let before = native::budget(&h, &r).await;
    assert_eq!(before.allocations.len(), 5);
    assert_eq!(
        before
            .allocations
            .values()
            .filter(|a| a.state == S::Allocated && a.attempt_id.is_none())
            .count(),
        3
    );
    for n in &r.saga.as_ref().unwrap().nodes {
        assert!(
            h.ledger
                .read_key(&format!("{}/issuance/{}", h.prefix, n.operation_key))
                .await
                .unwrap()
                .is_none()
        );
    }
    let first = h.issue().await.unwrap();
    assert!(h.issue().await.unwrap().reused);
    assert_eq!(native::budget(&h, &r).await, before);
    // Independent branches can claim without waiting for a sibling outcome.
    for n in 1..3 {
        h.f.proposal["qid"] = json!(format!("forward-{n}"));
        let rec = h.issue().await.unwrap().record;
        native::claim(&h, &rec, &format!("parallel-{n}")).await;
    }
    assert_eq!(
        native::budget(&h, &r)
            .await
            .allocations
            .values()
            .filter(|a| a.state == S::Unknown)
            .count(),
        2
    );
    h.f.proposal["qid"] = json!("unplanned");
    assert!(h.issue().await.is_err());
    assert!(h.ledger.enroll_reservation().await.is_err());
    h.ledger.stop_reservation().await.unwrap();
    assert!(h.issue().await.is_err());
    assert!(first.record.grant_digest.len() == 64);
    let mut stopped = native::budget(&h, &r).await;
    stopped.active = false;
    assert_eq!(native::budget(&h, &r).await, stopped);
}
#[tokio::test]
async fn saga_forward_signed_commit_enables_successor_and_complete_replay_without_refund() {
    let Some((mut h, r)) = ready(2, true).await else {
        return;
    };
    h.f.proposal["qid"] = json!("forward-1");
    assert!(h.issue().await.is_err());
    h.f.proposal["qid"] = json!("forward-0");
    let rec = h.issue().await.unwrap().record;
    let c = native::claim(&h, &rec, "original-forward").await;
    h.ledger
        .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    h.f.proposal["qid"] = json!("forward-1");
    assert!(h.issue().await.is_err());
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    for status in ["pending", "not_found", "unknown", "fenced_no_effect"] {
        native::worker(
            &h,
            &c,
            &rec.grant_digest,
            status,
            Arc::new(AtomicUsize::new(0)),
        )
        .recover(&c)
        .await
        .unwrap();
        assert!(h.issue().await.is_err());
    }
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
    let next = h.issue().await.unwrap().record;
    assert!(h.issue().await.unwrap().reused);
    let nc = native::claim(&h, &next, "successor-original").await;
    h.ledger
        .authorize_dispatch(&nc.grant, &next.grant_digest, &nc.attempt_id)
        .await
        .unwrap();
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    let v = verify(&b, &native::trust(&h, &r)).unwrap();
    assert_eq!(b.profile, LINEAGE_PROFILE);
    assert_eq!(v.budget_state, S::Committed);
    assert_eq!(b.authorizations.as_ref().unwrap().len(), 2);
    let state = native::budget(&h, &r).await;
    assert_eq!(state.allocations[&rec.issuance_key].state, S::Committed);
    assert_eq!(state.allocations[&next.issuance_key].state, S::Unknown);
    assert_eq!(state.allocations.len(), 4);
    for a in state
        .allocations
        .values()
        .filter(|a| a.state != S::Composite)
    {
        assert_eq!((a.forward, a.compensation), (1, 1));
    }
    // Rehash and correctly sign a structurally consistent history in which the
    // successor issue precedes the predecessor's first signed refinement.
    let mut out_of_order = b.clone();
    let index = out_of_order
        .events
        .iter()
        .position(|e| {
            e.data.phase == "issue" && e.data.operation_key.as_deref() == Some(&next.issuance_key)
        })
        .unwrap();
    let mut early = out_of_order.events.remove(index);
    early.after = out_of_order.events[3].after.clone();
    out_of_order.events.insert(4, early);
    super::reserved_history::resign(&mut out_of_order);
    assert!(verify(&out_of_order, &native::trust(&h, &r)).is_err());
    // Even a freshly signed observer cannot invent capacity at genesis.
    let mut changed = b.clone();
    changed.events[0]
        .after
        .allocations
        .remove(&next.issuance_key);
    super::reserved_history::resign(&mut changed);
    assert!(verify(&changed, &native::trust(&h, &r)).is_err());
    // A trusted checkpoint cannot reinterpret the same grants as another saga.
    let mut wrong = r.clone();
    wrong.saga.as_mut().unwrap().saga_id = "replacement".into();
    assert!(verify(&b, &native::trust(&h, &wrong)).is_err());
}
#[tokio::test]
async fn saga_forward_no_effect_never_enables_successor_and_unissued_holds_replay() {
    let Some((mut h, r)) = ready(2, true).await else {
        return;
    };
    let rec = h.issue().await.unwrap().record;
    let c = native::claim(&h, &rec, "never-dispatched").await;
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
    assert_eq!(
        native::budget(&h, &r).await.allocations[&rec.issuance_key].state,
        S::ProvenNoEffect
    );
    h.f.proposal["qid"] = json!("forward-1");
    assert!(h.issue().await.is_err());
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    assert_eq!(b.authorizations.as_ref().unwrap().len(), 1);
    verify(&b, &native::trust(&h, &r)).unwrap();
}
#[tokio::test]
async fn saga_forward_closed_profile_graph_capacity_principal_and_role_pins_refuse() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let example: Registration =
        serde_json::from_str(include_str!("../../../../config/saga-forward.example.json")).unwrap();
    example.validate().unwrap();
    let r = registration(&mut h, 2, true);
    let mutate: Vec<fn(&mut Registration)> = vec![
        |r| r.profile = kedgeflow::reservation_history::HIERARCHICAL_LEAF_PROFILE.into(),
        |r| r.hierarchy = None,
        |r| r.saga = None,
        |r| r.saga.as_mut().unwrap().nodes[0].depends_on = vec!["node-1".into()],
        |r| r.saga.as_mut().unwrap().nodes[1].depends_on = vec!["absent".into()],
        |r| r.saga.as_mut().unwrap().nodes[1].depends_on = vec!["node-0".into(); 2],
        |r| {
            r.saga.as_mut().unwrap().nodes[1].operation_key =
                r.saga.as_ref().unwrap().nodes[0].operation_key.clone()
        },
        |r| r.saga.as_mut().unwrap().nodes[1].principal.workload_id = "substitution".into(),
        |r| r.saga.as_mut().unwrap().expires_at = NOW + 60001,
        |r| r.forward_units = 2,
        |r| r.saga.as_mut().unwrap().outcome_keys = r.issuer_keys.clone(),
        |r| {
            r.saga.as_mut().unwrap().outcome_keys =
                r.hierarchy.as_ref().unwrap().delegation_keys.clone()
        },
    ];
    for f in mutate {
        let mut bad = r.clone();
        f(&mut bad);
        assert!(bad.validate().is_err());
    }
    let mut value = json!(r);
    value["saga"] = Value::Null;
    assert!(serde_json::from_value::<Registration>(value).is_err());
    let mut value = json!(r);
    value["saga"]["inverse"] = json!({});
    assert!(serde_json::from_value::<Registration>(value).is_err());
    let mut wrong = native::trust_value(&h, &r);
    wrong["lineage"]["source_id"] = json!("wrong");
    assert!(
        kedgeflow::reserved_lineage::TrustConfig::decode(&serde_json::to_vec(&wrong).unwrap())
            .unwrap()
            .registration()
            .is_err()
    );
}
#[tokio::test]
async fn saga_forward_mandatory_binding_and_frozen_grant_refuse_reinterpretation() {
    let Some((h, r)) = ready(1, false).await else {
        return;
    };
    let rec = h.issue().await.unwrap().record;
    let g = native::grant(&h, &rec);
    let b = h
        .ledger
        .retained_reservation_binding(&g, &rec.grant_digest)
        .await
        .unwrap();
    let raw = serde_json::to_vec(&b).unwrap();
    let payload = verify_binding(&raw, &r, rec.signed_grant.as_bytes()).unwrap();
    assert_eq!(payload.saga.unwrap().node_id, "node-0");
    assert!(g.saga_budget.is_null() && g.parent_grant_digest.is_none());
    for field in ["saga", "parent_grant_digest"] {
        let mut v = json!(b);
        v["payload"].as_object_mut().unwrap().remove(field);
        assert!(
            verify_binding(
                &serde_json::to_vec(&v).unwrap(),
                &r,
                rec.signed_grant.as_bytes()
            )
            .is_err()
        );
    }
    let mut mutated = g.clone();
    mutated.saga_budget = json!({"forward":1});
    let raw =
        kedgeflow::contracts::sign_grant(&mutated, "key-5", &SigningKey::from_bytes(&[5; 32]))
            .unwrap();
    assert!(
        GrantVerifier {
            keys: keys(5),
            audience: r.scope.audience.clone()
        }
        .verify_retained(&raw)
        .is_err()
    );
}
#[tokio::test]
async fn saga_forward_missing_plan_configuration_and_original_predecessor_proofs_refuse() {
    let Some((mut h, r)) = ready(2, true).await else {
        return;
    };
    let rec = h.issue().await.unwrap().record;
    let c = committed(&h, &rec).await;
    h.f.proposal["qid"] = json!("forward-1");
    let raw = h.ledger.read_key(&plan_key(&h, &r)).await.unwrap().unwrap();
    write(&h, &plan_key(&h, &r), None).await;
    assert!(h.issue().await.is_err());
    write(&h, &plan_key(&h, &r), Some(&raw)).await;
    let configured = h.ledger.clone();
    h.ledger = EtcdLedger::new(
        reqwest::Client::new(),
        std::env::var("ETCD_ENDPOINT").unwrap(),
        &h.prefix,
    )
    .unwrap()
    .with_clock(h.clock.clone())
    .requiring_control(Some(h.registration.trust_digest.clone()));
    assert!(h.issue().await.is_err());
    h.ledger = configured;
    let out = h.ledger.export_outcomes(&c).await.unwrap();
    let receipt: kedgeflow::contracts::Envelope =
        serde_json::from_str(out.receipts.last().unwrap()).unwrap();
    let rd = kedgeflow::contracts::record_digest(&receipt).unwrap();
    for key in [
        format!("{}/issuance/{}", h.prefix, rec.issuance_key),
        format!("{}/admission-chain/{}", h.prefix, rec.issuance_key),
        format!(
            "{}/domains/{}/roots/{}/attempts/{}/receipts/{rd}",
            h.prefix,
            URL_SAFE_NO_PAD.encode(&c.grant.conflict_domain),
            URL_SAFE_NO_PAD.encode(&c.grant.root_id),
            URL_SAFE_NO_PAD.encode(&c.attempt_id)
        ),
    ] {
        let raw = h
            .ledger
            .read_key(&key)
            .await
            .unwrap()
            .expect("original proof");
        write(&h, &key, None).await;
        assert!(h.issue().await.is_err());
        write(&h, &key, Some(&raw)).await;
    }
    assert!(h.issue().await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saga_forward_stop_races_every_native_authority_boundary() {
    race(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saga_forward_missing_predecessor_receipt_races_every_native_authority_boundary() {
    race(true).await;
}
async fn race(proof_race: bool) {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use std::sync::atomic::AtomicBool;
    for phase in [
        "admission",
        "fence-allocation",
        "issuance",
        "attempts",
        "dispatch",
    ] {
        let Some((mut h, r)) = ready(if proof_race { 2 } else { 1 }, proof_race).await else {
            return;
        };
        let missing = if proof_race {
            let first = h.issue().await.unwrap().record;
            let c = committed(&h, &first).await;
            let out = h.ledger.export_outcomes(&c).await.unwrap();
            let receipt: kedgeflow::contracts::Envelope =
                serde_json::from_str(&out.receipts[0]).unwrap();
            let rd = kedgeflow::contracts::record_digest(&receipt).unwrap();
            h.f.proposal["qid"] = json!("forward-1");
            Some(format!(
                "{}/domains/{}/roots/{}/attempts/{}/receipts/{rd}",
                h.prefix,
                URL_SAFE_NO_PAD.encode(&c.grant.conflict_domain),
                URL_SAFE_NO_PAD.encode(&c.grant.root_id),
                URL_SAFE_NO_PAD.encode(&c.attempt_id)
            ))
        } else {
            None
        };
        let direct = h.ledger.clone();
        let issued = if matches!(phase, "attempts" | "dispatch") {
            Some(h.issue().await.unwrap().record)
        } else {
            None
        };
        if phase == "dispatch" {
            let rec = issued.as_ref().unwrap();
            direct
                .claim(&native::grant(&h, rec), &rec.grant_digest, "original-race")
                .await
                .unwrap();
        }
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let block = Arc::new(AtomicBool::new(true));
        let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
        let router = Router::new().route(
            "/v3/kv/txn",
            post({
                let entered = entered.clone();
                let release = release.clone();
                move |Json(v): Json<Value>| {
                    let entered = entered.clone();
                    let release = release.clone();
                    let block = block.clone();
                    let endpoint = endpoint.clone();
                    async move {
                        let selected = v["success"].as_array().is_some_and(|ops| {
                            ops.iter().any(|op| {
                                if phase == "dispatch" {
                                    op["request_put"]["value"]
                                        .as_str()
                                        .and_then(|s| STANDARD.decode(s).ok())
                                        .is_some_and(|b| b == b"dispatch_authorized")
                                } else {
                                    op["request_put"]["key"]
                                        .as_str()
                                        .and_then(|s| STANDARD.decode(s).ok())
                                        .is_some_and(|b| {
                                            String::from_utf8_lossy(&b)
                                                .contains(&format!("/{phase}/"))
                                        })
                                }
                            })
                        });
                        if selected && block.swap(false, Ordering::SeqCst) {
                            entered.notify_one();
                            release.notified().await;
                        }
                        let response = reqwest::Client::new()
                            .post(format!("{endpoint}/v3/kv/txn"))
                            .json(&v)
                            .send()
                            .await
                            .unwrap();
                        let status = response.status();
                        let bytes = response.bytes().await.unwrap();
                        (status, [("content-type", "application/json")], bytes).into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let proxy = live_agent::Running(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }));
        h.ledger = EtcdLedger::new(reqwest::Client::new(), endpoint, &h.prefix)
            .unwrap()
            .with_clock(h.clock.clone())
            .requiring_control(Some(h.registration.trust_digest.clone()))
            .with_reservation(r.clone())
            .unwrap();
        let operation = tokio::spawn(async move {
            match phase {
                "attempts" => {
                    let rec = issued.unwrap();
                    h.ledger
                        .claim(&native::grant(&h, &rec), &rec.grant_digest, "raced-child")
                        .await
                        .map(|_| ())
                }
                "dispatch" => {
                    let rec = issued.unwrap();
                    h.ledger
                        .authorize_dispatch(
                            &native::grant(&h, &rec),
                            &rec.grant_digest,
                            "original-race",
                        )
                        .await
                }
                _ => h.issue().await.map(|_| ()),
            }
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect(phase);
        if let Some(key) = missing {
            assert!(direct.read_key(&key).await.unwrap().is_some());
            let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
            assert!(
                reqwest::Client::new()
                    .post(format!("{endpoint}/v3/kv/deleterange"))
                    .json(&json!({"key":STANDARD.encode(key)}))
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success()
            );
        } else {
            direct.stop_reservation().await.unwrap();
        }
        release.notify_one();
        assert!(operation.await.unwrap().is_err(), "{phase}");
        let state = Coordination::new(direct, &r.root_id)
            .unwrap()
            .status()
            .await
            .unwrap();
        assert_eq!(state.active, proof_race);
        let leaves: Vec<_> = state
            .allocations
            .values()
            .filter(|a| a.state != S::Composite)
            .collect();
        assert_eq!(leaves.len(), if proof_race { 2 } else { 1 });
        if matches!(
            phase,
            "admission" | "fence-allocation" | "issuance" | "attempts"
        ) {
            assert_eq!(leaves.iter().filter(|a| a.state == S::Allocated).count(), 1);
        } else {
            assert_eq!(leaves.iter().filter(|a| a.state == S::Unknown).count(), 1);
        }
        drop(proxy);
    }
}

#[tokio::test]
async fn saga_forward_shipping_offline_clis_verify_explicit_profiles_and_refuse_changed_trust() {
    let Some((h, r)) = ready(1, false).await else {
        return;
    };
    let rec = h.issue().await.unwrap().record;
    let c = committed(&h, &rec).await;
    let b = export(&h, &r, &c, &rec.issuance_key).await;
    let binding = h
        .ledger
        .retained_reservation_binding(&c.grant, &rec.grant_digest)
        .await
        .unwrap();
    let d = tempfile::tempdir().unwrap();
    let registration = d.path().join("registration.json");
    let grant = d.path().join("grant.json");
    let seal = d.path().join("binding.json");
    let trust = d.path().join("trust.json");
    let bundle = d.path().join("bundle.json");
    std::fs::write(&registration, serde_json::to_vec(&r).unwrap()).unwrap();
    std::fs::write(&grant, &rec.signed_grant).unwrap();
    std::fs::write(&seal, serde_json::to_vec(&binding).unwrap()).unwrap();
    std::fs::write(
        &trust,
        serde_json::to_vec(&native::trust_value(&h, &r)).unwrap(),
    )
    .unwrap();
    std::fs::write(&bundle, serde_json::to_vec(&b).unwrap()).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-reservation"))
        .args([
            "--registration",
            registration.to_str().unwrap(),
            "--grant",
            grant.to_str().unwrap(),
            "--binding",
            seal.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["profile"], PROFILE);
    assert_eq!(v["execution_authority"], false);
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-reserved-lineage"))
            .arg("--trust")
            .arg(&trust)
            .arg("--bundle")
            .arg(&bundle)
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
    assert_eq!(v["budget_state"], "committed");
    assert_eq!(v["execution_authority"], false);
    let mut wrong = native::trust_value(&h, &r);
    wrong["registration"]["saga"]["source_id"] = json!("substitute");
    std::fs::write(&trust, serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(!run().status.success());
}
