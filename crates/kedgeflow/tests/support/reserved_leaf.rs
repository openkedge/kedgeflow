//! Native producer/consumer tests against managed control and real etcd.
use super::*;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    coordination::{Coordination, ReservationEnrollment, ReservationScope, ReservationState},
    reserved_leaf::{PROFILE as RESERVED, Registration, verify_binding},
};
use std::collections::BTreeSet;

pub(super) fn registration(h: &Harness, units: u64) -> Registration {
    Registration {
        hierarchy: None,
        profile: RESERVED.into(),
        root_id: "approved-capacity-root".into(),
        root_generation: 1,
        enrollment: ReservationEnrollment {
            tenant: h.registration.tenant.clone(),
            conflict_domain: h.registration.scope.conflict_domain.clone(),
            scope: ReservationScope {
                actions: BTreeSet::from([h.registration.scope.action.id.clone()]),
                resources: BTreeSet::from([h.registration.scope.resource.id.clone()]),
            },
            forward: units,
            compensation: units,
        },
        scope: h.registration.scope.clone(),
        policy: h.registration.policy.clone(),
        ownership_epoch: h.registration.ownership_epoch,
        forward_units: 1,
        compensation_units: 1,
        issuer_keys: keys(5)
            .iter()
            .map(|(id, k)| (id.clone(), STANDARD.encode(k.as_bytes())))
            .collect(),
    }
}
async fn ready(units: u64) -> Option<(Harness, Registration)> {
    let mut h = Harness::new().await?;
    let r = registration(&h, units);
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    Some((h, r))
}
fn grant(record: &kedgeflow::ledger::IssuanceRecord) -> Grant {
    GrantVerifier {
        keys: keys(5),
        audience:
            serde_json::from_str::<Value>(&record.signed_grant).unwrap()["payload"]["audience"]
                .as_str()
                .unwrap()
                .into(),
    }
    .verify_retained(record.signed_grant.as_bytes())
    .unwrap()
    .grant
}
fn coordination(h: &Harness, r: &Registration) -> Coordination {
    Coordination::new(h.ledger.clone(), &r.root_id).unwrap()
}
fn issuer(h: &Harness) -> GrantAuthority {
    GrantAuthority::new(
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
    .unwrap()
}

#[tokio::test]
async fn reserved_leaf_recreated_issuer_reuses_binding_allocation_and_fence() {
    let Some((h, r)) = ready(1).await else { return };
    let first = h.issue().await.unwrap();
    let second = h.issue().await.unwrap();
    assert!(!first.reused);
    assert!(second.reused);
    assert_eq!(first.record, second.record);
    let g = grant(&first.record);
    let b = h
        .ledger
        .retained_reservation_binding(&g, &first.record.grant_digest)
        .await
        .unwrap();
    let p = verify_binding(
        &serde_json::to_vec(&b).unwrap(),
        &r,
        first.record.signed_grant.as_bytes(),
    )
    .unwrap();
    assert_eq!(p.operation_key, first.record.issuance_key);
    let state = coordination(&h, &r).status().await.unwrap();
    assert_eq!(state.allocations.len(), 1);
    assert_eq!(
        state.allocations[&p.operation_key].state,
        ReservationState::Allocated
    );
    assert_eq!(g.fence, 1);
    assert!(h.ledger.enroll_reservation().await.is_err());
    assert!(
        Coordination::new(h.ledger.clone(), "other-root")
            .unwrap()
            .enroll(r.enrollment.clone())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_leaf_last_slot_competing_native_proposals_conserve_both_budgets() {
    let Some((mut h, r)) = ready(1).await else {
        return;
    };
    let controller = AdmissionController::new(
        CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
        "key-6".into(),
        SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    let mut tasks = Vec::new();
    for n in 0..8 {
        h.f.proposal["qid"] = json!(format!("reserved-contender-{n}"));
        let packet = h.f.packet();
        let inputs =
            h.f.trust
                .verify_inputs(&h.f.identity, packet.borrowed(), &Time(NOW))
                .unwrap();
        let certificate = h
            .ledger
            .admit(
                &controller.prepare(&inputs, &Time(NOW)).unwrap(),
                &Time(NOW),
            )
            .await
            .unwrap()
            .record
            .signed_certificate;
        let ledger = h.ledger.clone();
        let authority = issuer(&h);
        tasks.push(tokio::spawn(async move {
            authority
                .issue(&ledger, &inputs, certificate.as_bytes(), &Time(NOW))
                .await
        }));
    }
    let mut successes = Vec::new();
    for task in tasks {
        if let Ok(v) = task.await.unwrap() {
            successes.push(v);
        }
    }
    assert_eq!(successes.len(), 1);
    let state = coordination(&h, &r).status().await.unwrap();
    assert_eq!(state.allocations.len(), 1);
    assert_eq!(
        state.allocations.values().map(|a| a.forward).sum::<u64>(),
        1
    );
    assert_eq!(
        state
            .allocations
            .values()
            .map(|a| a.compensation)
            .sum::<u64>(),
        1
    );
    assert!(
        state
            .allocations
            .contains_key(&successes[0].record.issuance_key)
    );
    assert_eq!(grant(&successes[0].record).fence, 1);
}

#[tokio::test]
async fn reserved_leaf_seals_block_library_parent_consume_and_outcome_refinement() {
    let Some((h, r)) = ready(2).await else { return };
    let record = h.issue().await.unwrap().record;
    let g = grant(&record);
    let c = coordination(&h, &r);
    assert!(
        c.allocate(
            &"a".repeat(64),
            Some(&record.issuance_key),
            r.enrollment.scope.clone(),
            1,
            1
        )
        .await
        .is_err()
    );
    assert!(
        c.consume(&record.issuance_key, "outside-attempt")
            .await
            .is_err()
    );
    let a = h
        .ledger
        .claim(&g, &record.grant_digest, "native-attempt")
        .await
        .unwrap();
    assert!(c.consume(&record.issuance_key, &a.id).await.is_err());
    for outcome in [
        ReservationState::Committed,
        ReservationState::ProvenNoEffect,
    ] {
        assert!(
            c.observe(&record.issuance_key, &a.id, outcome)
                .await
                .is_err()
        );
    }
    let held = c.status().await.unwrap();
    assert_eq!(
        held.allocations[&record.issuance_key].state,
        ReservationState::Unknown
    );
    assert_eq!(
        held.allocations[&record.issuance_key].attempt_id.as_deref(),
        Some("native-attempt")
    );
    assert!(
        h.ledger
            .authorize_dispatch(&g, &record.grant_digest, "other-attempt")
            .await
            .is_err()
    );
    h.ledger
        .authorize_dispatch(&g, &record.grant_digest, &a.id)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_leaf_competing_claims_consume_original_attempt_once() {
    let Some((h, r)) = ready(1).await else { return };
    let record = h.issue().await.unwrap().record;
    let g = grant(&record);
    let mut tasks = Vec::new();
    for n in 0..8 {
        let l = h.ledger.clone();
        let g = g.clone();
        let gd = record.grant_digest.clone();
        tasks.push(tokio::spawn(async move {
            l.claim(&g, &gd, &format!("claim-{n}")).await
        }));
    }
    let mut claimed = Vec::new();
    for t in tasks {
        if let Ok(a) = t.await.unwrap() {
            claimed.push(a);
        }
    }
    assert_eq!(claimed.len(), 1);
    let state = coordination(&h, &r).status().await.unwrap();
    assert_eq!(
        state.allocations[&record.issuance_key]
            .attempt_id
            .as_deref(),
        Some(claimed[0].id.as_str())
    );
    assert!(
        h.ledger
            .claim(&g, &record.grant_digest, &claimed[0].id)
            .await
            .is_err()
    );
    h.ledger.stop_reservation().await.unwrap();
    assert!(
        h.ledger
            .authorize_dispatch(&g, &record.grant_digest, &claimed[0].id)
            .await
            .is_err()
    );
    assert!(h.issue().await.is_err());
    h.clock.0.store(NOW + 60000, Ordering::SeqCst);
    assert_eq!(
        h.ledger.status(&g, &claimed[0].id).await.unwrap().status,
        "claimed"
    );
    let b = h
        .ledger
        .retained_reservation_binding(&g, &record.grant_digest)
        .await
        .unwrap();
    verify_binding(
        &serde_json::to_vec(&b).unwrap(),
        &r,
        record.signed_grant.as_bytes(),
    )
    .unwrap();
    let c = kedgeflow::recovery::Candidate {
        grant: g,
        attempt_id: claimed[0].id.clone(),
    };
    assert!(
        h.ledger
            .export_lineage(&c, &record.issuance_key)
            .await
            .is_err()
    );
    assert!(!coordination(&h, &r).status().await.unwrap().active);
}

#[tokio::test]
async fn reserved_leaf_omitted_configuration_wrong_pins_and_raw_ports_fail_closed() {
    let Some((mut h, r)) = ready(1).await else {
        return;
    };
    let record = h.issue().await.unwrap().record;
    let g = grant(&record);
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
    assert!(
        h.ledger
            .claim(&g, &record.grant_digest, "omitted")
            .await
            .is_err()
    );
    assert!(h.ledger.issue(&g, &record.grant_digest).await.is_err());
    let mut next = g.clone();
    next.root_generation += 1;
    next.fence += 1;
    next.nonce = "replacement".into();
    next.gid = "replacement".into();
    assert!(h.ledger.replace(&g, &next, &"a".repeat(64)).await.is_err());
    let mut changed = r.clone();
    changed.forward_units = 1;
    changed.compensation_units = 0;
    let wrong = configured.clone().with_reservation(changed).unwrap();
    assert!(
        wrong
            .claim(&g, &record.grant_digest, "changed-pins")
            .await
            .is_err()
    );
    let mut scope = g.clone();
    scope.resources[0].incarnation = "recreated".into();
    assert!(
        configured
            .claim(&scope, &record.grant_digest, "changed-scope")
            .await
            .is_err()
    );
    let b = configured
        .retained_reservation_binding(&g, &record.grant_digest)
        .await
        .unwrap();
    assert!(
        configured
            .claim(&g, &"a".repeat(64), "changed-grant")
            .await
            .is_err()
    );
    assert_eq!(
        coordination(&h, &r).status().await.unwrap().allocations[&b.payload.operation_key].state,
        ReservationState::Allocated
    );
}

#[tokio::test]
async fn reserved_leaf_binding_offline_substitutions_and_closed_carriage_refused() {
    let Some((h, r)) = ready(1).await else { return };
    let record = h.issue().await.unwrap().record;
    let g = grant(&record);
    let b = h
        .ledger
        .retained_reservation_binding(&g, &record.grant_digest)
        .await
        .unwrap();
    let value = serde_json::to_value(&b).unwrap();
    for field in [
        "tenant",
        "conflict_domain",
        "root_id",
        "registration_digest",
        "operation_key",
        "grant_digest",
        "certificate_digest",
        "allocation_digest",
    ] {
        let mut changed = value.clone();
        changed["payload"][field] = json!("a".repeat(64));
        assert!(
            verify_binding(
                &serde_json::to_vec(&changed).unwrap(),
                &r,
                record.signed_grant.as_bytes()
            )
            .is_err(),
            "{field}"
        );
    }
    // An approved signature cannot override independently approved context pins.
    for field in [
        "tenant",
        "conflict_domain",
        "root_id",
        "registration_digest",
        "grant_digest",
        "certificate_digest",
        "allocation_digest",
    ] {
        let mut changed = value.clone();
        changed["payload"][field] = json!("a".repeat(64));
        let mut message = format!("KedgeFlow:{RESERVED}\0").into_bytes();
        message.extend(canonical(&json!({"profile":changed["profile"],"kind":changed["kind"],"key_id":changed["key_id"],"payload":changed["payload"]})).unwrap());
        changed["signature"] = json!(
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[5; 32]).sign(&message).to_bytes())
        );
        assert!(
            verify_binding(
                &serde_json::to_vec(&changed).unwrap(),
                &r,
                record.signed_grant.as_bytes()
            )
            .is_err(),
            "signed substitution {field}"
        );
    }
    for field in ["profile", "kind", "key_id", "signature"] {
        let mut changed = value.clone();
        changed[field] = json!("invalid");
        assert!(
            verify_binding(
                &serde_json::to_vec(&changed).unwrap(),
                &r,
                record.signed_grant.as_bytes()
            )
            .is_err()
        );
    }
    let mut extra = value.clone();
    extra["execution_authority"] = json!(true);
    assert!(
        verify_binding(
            &serde_json::to_vec(&extra).unwrap(),
            &r,
            record.signed_grant.as_bytes()
        )
        .is_err()
    );
    let mut pins = r.clone();
    pins.issuer_keys = keys(6)
        .iter()
        .map(|(id, k)| (id.clone(), STANDARD.encode(k.as_bytes())))
        .collect();
    assert!(
        verify_binding(
            &serde_json::to_vec(&b).unwrap(),
            &pins,
            record.signed_grant.as_bytes()
        )
        .is_err()
    );
    let duplicate = String::from_utf8(serde_json::to_vec(&b).unwrap())
        .unwrap()
        .replacen("{", "{\"profile\":\"duplicate\",", 1);
    assert!(verify_binding(duplicate.as_bytes(), &r, record.signed_grant.as_bytes()).is_err());
    assert!(verify_binding(&vec![b' '; 16385], &r, record.signed_grant.as_bytes()).is_err());
    let mut pins = r.clone();
    pins.root_generation = 2;
    assert!(pins.validate().is_err());
    assert!(
        EtcdLedger::new(
            reqwest::Client::new(),
            "http://localhost:2379",
            "/no-managed"
        )
        .unwrap()
        .with_reservation(r)
        .is_err()
    );
}

#[tokio::test]
async fn reserved_leaf_stop_before_claim_holds_capacity_and_prevents_reenrollment() {
    let Some((h, r)) = ready(1).await else { return };
    let record = h.issue().await.unwrap().record;
    let g = grant(&record);
    h.ledger.stop_reservation().await.unwrap();
    assert!(
        h.ledger
            .claim(&g, &record.grant_digest, "stopped")
            .await
            .is_err()
    );
    assert!(h.ledger.enroll_reservation().await.is_err());
    let state = coordination(&h, &r).status().await.unwrap();
    assert!(!state.active);
    assert_eq!(state.allocations.len(), 1);
    assert_eq!(
        state.allocations[&record.issuance_key].state,
        ReservationState::Allocated
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_leaf_stop_races_fence_issuance_claim_and_dispatch_transactions() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use std::sync::atomic::AtomicBool;
    for phase in ["fence-allocation", "issuance", "attempts", "dispatch"] {
        let Some((mut h, r)) = ready(1).await else {
            return;
        };
        let direct = h.ledger.clone();
        let issued = if matches!(phase, "attempts" | "dispatch") {
            Some(h.issue().await.unwrap().record)
        } else {
            None
        };
        let attempt = if phase == "dispatch" {
            let rec = issued.as_ref().unwrap();
            Some(
                direct
                    .claim(&grant(rec), &rec.grant_digest, "race-original")
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
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
                                if phase == "dispatch" {
                                    op["request_put"]["value"]
                                        .as_str()
                                        .and_then(|s| STANDARD.decode(s).ok())
                                        .is_some_and(|v| v == b"dispatch_authorized")
                                } else {
                                    op["request_put"]["key"]
                                        .as_str()
                                        .and_then(|s| STANDARD.decode(s).ok())
                                        .is_some_and(|key| {
                                            String::from_utf8_lossy(&key)
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
                        .claim(&grant(&rec), &rec.grant_digest, "raced")
                        .await
                        .map(|_| ())
                }
                "dispatch" => {
                    let rec = issued.unwrap();
                    h.ledger
                        .authorize_dispatch(&grant(&rec), &rec.grant_digest, &attempt.unwrap().id)
                        .await
                }
                _ => h.issue().await.map(|_| ()),
            }
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect(phase);
        direct.stop_reservation().await.unwrap();
        release.notify_one();
        assert!(operation.await.unwrap().is_err(), "{phase}");
        let state = Coordination::new(direct.clone(), &r.root_id)
            .unwrap()
            .status()
            .await
            .unwrap();
        assert!(!state.active);
        match phase {
            "fence-allocation" => assert!(state.allocations.is_empty()),
            "issuance" | "attempts" => assert_eq!(
                state.allocations.values().next().unwrap().state,
                ReservationState::Allocated
            ),
            _ => assert_eq!(
                state.allocations.values().next().unwrap().state,
                ReservationState::Unknown
            ),
        }
        drop(proxy);
    }
}

#[tokio::test]
async fn reserved_leaf_shipping_offline_verifier_reports_statement_without_authority() {
    let Some((h, r)) = ready(1).await else { return };
    let record = h.issue().await.unwrap().record;
    let b = h
        .ledger
        .retained_reservation_binding(&grant(&record), &record.grant_digest)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let registration = dir.path().join("registration.json");
    let signed = dir.path().join("grant.json");
    let binding = dir.path().join("binding.json");
    std::fs::write(&registration, serde_json::to_vec(&r).unwrap()).unwrap();
    std::fs::write(&signed, &record.signed_grant).unwrap();
    std::fs::write(&binding, serde_json::to_vec(&b).unwrap()).unwrap();
    let command = || {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-reservation"));
        c.arg("--registration")
            .arg(&registration)
            .arg("--grant")
            .arg(&signed)
            .arg("--binding")
            .arg(&binding);
        c
    };
    let out = command().output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["execution_authority"], false);
    assert_eq!(value["live_budget_verified"], false);
    assert_eq!(
        value["historical_issuer_statement"]["operation_key"],
        record.issuance_key
    );
    let mut wrong = r;
    wrong.root_id = "unapproved-root".into();
    std::fs::write(&registration, serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(!command().output().unwrap().status.success());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_leaf_shipping_control_cli_checks_enrolls_and_permanently_stops() {
    use axum::{Extension, Json, Router, response::IntoResponse, routing::post};
    use kedgeflow::auth::WorkloadIdentity;
    use std::os::unix::fs::PermissionsExt;
    for variant in [0, 1, 2] {
        let hierarchical = variant > 0;
        let Some(h) = Harness::new().await else {
            return;
        };
        let mut r = if hierarchical {
            super::hierarchical_leaf::registration(&h, 1)
        } else {
            registration(&h, 1)
        };
        if variant == 2 {
            r.profile = kedgeflow::reservation_history::HIERARCHICAL_LEAF_PROFILE.into();
        }
        let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
        let router = Router::new().route(
            "/v3/kv/txn",
            post(
                move |Extension(workload): Extension<WorkloadIdentity>,
                      headers: http::HeaderMap,
                      Json(v): Json<Value>| {
                    let endpoint = endpoint.clone();
                    async move {
                        assert_eq!(workload.as_str(), "spiffe://test/agent");
                        assert_eq!(headers["authorization"], "operator-etcd-token");
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
        let directory = tempfile::Builder::new()
            .prefix("kf-reserved-cli-")
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        let root = directory.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let p = root.join(name);
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let ca = write("ca.pem", h.agent_pki.ca.as_bytes());
        let cert = write("server.pem", h.agent_pki.server.as_bytes());
        let key = write("server-key.pem", h.agent_pki.server_key.as_bytes());
        let client = write("client.pem", h.agent_pki.client.as_bytes());
        let client_key = write("client-key.pem", h.agent_pki.client_key.as_bytes());
        let token = write("token", b"operator-etcd-token");
        let admission = write("admission-seed", STANDARD.encode([6; 32]).as_bytes());
        let issuer = write("issuer-seed", STANDARD.encode([5; 32]).as_bytes());
        let encoded = |map: &BTreeMap<String, ed25519_dalek::VerifyingKey>| {
            map.iter()
                .map(|(id, k)| (id.clone(), STANDARD.encode(k.as_bytes())))
                .collect::<BTreeMap<_, _>>()
        };
        let evidence:BTreeMap<_,_>=h.f.trust.evidence.iter().map(|(id,e)|(id,json!({"obligation":e.obligation,"provider_id":e.provider_id,"provider_version":e.provider_version,"keys":encoded(&e.keys),"question":e.question,"result_schema_ref":e.result_schema_ref,"result_schema":e.result_schema,"max_age_ms":e.max_age_ms,"predicates":e.predicates}))).collect();
        let mut config: Value =
            serde_json::from_str(include_str!("../../../../config/control.example.json")).unwrap();
        let material = json!({"reservation":r,"require_control":true,"gateway_audience":h.registration.scope.audience,"certificate":cert,"private_key":key,"workload_ca":ca,"etcd_endpoint":proxy.url,"etcd_prefix":h.prefix,"etcd_ca":ca,"etcd_certificate":client,"etcd_private_key":client_key,"etcd_token_file":token,"admission_signing_key_file":admission,"issuer_signing_key_file":issuer,"tenant":h.f.trust.tenant,"workload_id":h.f.trust.proposal_workload_id,"subjects":[h.f.identity.subject],"descriptor_digest":h.f.trust.descriptor_digest,"ownership_epoch":h.f.trust.ownership_epoch,"policy":{"id":h.f.trust.policy.id,"epoch":h.f.trust.policy.epoch,"cedar":h.definition.cedar,"max_certificate_lifetime_ms":h.definition.max_certificate_lifetime_ms},"proposal_keys":encoded(&keys(1)),"registry_keys":encoded(&keys(2)),"manifest_keys":encoded(&keys(3)),"evidence":evidence});
        config
            .as_object_mut()
            .unwrap()
            .extend(material.as_object().unwrap().clone());
        let path = write("control.json", &serde_json::to_vec(&config).unwrap());
        let run = |flag: &str| {
            let path = path.clone();
            let flag = flag.to_owned();
            async move {
                let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-control"))
                    .arg("--config")
                    .arg(path)
                    .arg(flag)
                    .output()
                    .await
                    .unwrap();
                (
                    output.status.success(),
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                )
            }
        };
        let (ok, err) = run("--check").await;
        assert!(ok, "{err}");
        assert!(coordination(&h, &r).status().await.is_err());
        let (ok, err) = run("--enroll-reservation").await;
        assert!(ok, "{err}");
        assert!(coordination(&h, &r).status().await.unwrap().active);
        assert!(!run("--enroll-reservation").await.0);
        let (ok, err) = run("--stop-reservation").await;
        assert!(ok, "{err}");
        assert!(!coordination(&h, &r).status().await.unwrap().active);
        assert!(!run("--enroll-reservation").await.0);
        config["reservation"]["compensation_units"] = json!(0);
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(!run("--stop-reservation").await.0);
    }
}

#[tokio::test]
async fn reserved_leaf_shipping_gateway_configuration_requires_exact_managed_scope() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let r = registration(&h, 1);
    let mut config: Value =
        serde_json::from_str(include_str!("../../../../config/gateway.example.json")).unwrap();
    config["reservation"] = json!(r);
    config["enforcement"] = Value::Null;
    config["external_url"] = json!(r.scope.audience);
    config["grant_key_id"] = json!("key-5");
    config["grant_public_key_base64"] = json!(r.issuer_keys["key-5"]);
    config["oidc_public_key_base64"] =
        json!(STANDARD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()));
    let tool = &mut config["tools"][0];
    tool["action"] = json!(r.scope.action);
    tool["resource"] = json!(r.scope.resource);
    tool["conflict_domain"] = json!(r.scope.conflict_domain);
    tool["adapter_contract"] = json!(r.scope.adapter_contract);
    tool["predicate_id"] = r.scope.predicate_descriptor["id"].clone();
    tool["predicate_version"] = r.scope.predicate_descriptor["version"].clone();
    let validate = |v: Value| {
        serde_json::from_value::<kedgeflow::config::Config>(v)
            .unwrap()
            .validate()
    };
    validate(config.clone()).unwrap();
    for field in ["require_control", "external_url", "grant_public_key_base64"] {
        let mut wrong = config.clone();
        wrong[field] = if field == "require_control" {
            json!(false)
        } else {
            json!("wrong")
        };
        assert!(validate(wrong).is_err(), "{field}");
    }
    for field in ["predicate_id", "predicate_version", "conflict_domain"] {
        let mut wrong = config.clone();
        wrong["tools"][0][field] = json!("wrong");
        assert!(validate(wrong).is_err(), "{field}");
    }
    let mut wrong = config.clone();
    wrong["tools"][0]["resource"]["incarnation"] = json!("recreated");
    assert!(validate(wrong).is_err());
    let mut wrong = config;
    let second = wrong["tools"][0].clone();
    wrong["tools"].as_array_mut().unwrap().push(second);
    assert!(validate(wrong).is_err());
}

#[tokio::test]
async fn reserved_leaf_missing_or_corrupt_retained_index_and_seal_cannot_consume() {
    let Some((h, r)) = ready(1).await else { return };
    let rec = h.issue().await.unwrap().record;
    let g = grant(&rec);
    let root = format!(
        "{}/coordination/{}",
        h.prefix,
        kedgeflow::contracts::digest("coordination-root", &json!(r.root_id)).unwrap()
    );
    let seal = format!(
        "{}/reservation-seals/{}/{}",
        h.prefix,
        URL_SAFE_NO_PAD.encode(root.as_bytes()),
        rec.issuance_key
    );
    let index = format!("{}/reserved-grants/{}", h.prefix, rec.grant_digest);
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let client = reqwest::Client::new();
    for key in [index, seal] {
        let original = h.ledger.read_key(&key).await.unwrap().unwrap();
        for damaged in [None, Some(b"{}".to_vec()), Some(vec![b' '; 16385])] {
            if let Some(value) = damaged {
                client.post(format!("{endpoint}/v3/kv/put")).json(&json!({"key":STANDARD.encode(key.as_bytes()),"value":STANDARD.encode(value)})).send().await.unwrap().error_for_status().unwrap();
            } else {
                client
                    .post(format!("{endpoint}/v3/kv/deleterange"))
                    .json(&json!({"key":STANDARD.encode(key.as_bytes())}))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap();
            }
            assert!(
                h.ledger
                    .claim(&g, &rec.grant_digest, "corrupt-binding")
                    .await
                    .is_err()
            );
            assert_eq!(
                coordination(&h, &r).status().await.unwrap().allocations[&rec.issuance_key].state,
                ReservationState::Allocated
            );
            client.post(format!("{endpoint}/v3/kv/put")).json(&json!({"key":STANDARD.encode(key.as_bytes()),"value":STANDARD.encode(&original)})).send().await.unwrap().error_for_status().unwrap();
        }
    }
    h.ledger
        .claim(&g, &rec.grant_digest, "original-after-repair")
        .await
        .unwrap();
}
