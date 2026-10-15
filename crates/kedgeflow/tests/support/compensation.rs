//! Native inverse prerequisite verification only; synthetic signers prove no target barrier.
use super::reserved_history as native;
use super::*;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    compensation::{
        self as inverse, Applicability, Barrier, Contract, Forward, PROFILE, Parameters, Proof,
        Qualifier, Statement,
    },
    contracts::{digest, record_digest},
    control_history::HistoryObserver,
    hierarchical_leaf::Principal,
    reserved_leaf::Registration,
    reserved_lineage::Bundle,
};
use std::sync::atomic::AtomicUsize;
fn public(n: u8) -> BTreeMap<String, String> {
    keys(n)
        .into_iter()
        .map(|(id, k)| (id, STANDARD.encode(k.as_bytes())))
        .collect()
}
fn registration(h: &Harness) -> Registration {
    let now = kedgeflow::clock::Clock::now_ms(h.clock.as_ref());
    let mut r = super::hierarchical_leaf::registration(h, 1);
    r.profile = kedgeflow::saga_forward::PROFILE.into();
    r.saga = Some(kedgeflow::saga_forward::Plan {
        profile: r.profile.clone(),
        saga_id: "inverse-fixture-saga".into(),
        valid_from: now - 1000,
        expires_at: now + 60000,
        nodes: vec![kedgeflow::saga_forward::Node {
            node_id: "forward".into(),
            operation_key: h
                .f
                .trust
                .operation_key(&h.f.identity, &h.f.packet().proposal)
                .unwrap(),
            principal: Principal {
                subject: h.f.identity.subject.clone(),
                workload_id: h.f.identity.workload_id.clone(),
            },
            depends_on: vec![],
        }],
        outcome_keys: public(14),
        source_id: "spiffe://test/outcome".into(),
    });
    r.validate().unwrap();
    r
}
fn contract(h: &Harness, r: &Registration) -> Contract {
    let mut descriptor = h.f.descriptor.clone();
    descriptor["action"] = json!(inverse::ACTION);
    descriptor["parameter_schema"] = inverse::parameter_schema();
    let pd = digest("parameter-schema", &descriptor["parameter_schema"]).unwrap();
    descriptor["parameter_schema_digest"] = json!(pd);
    descriptor["rendering"]["parameter_schema_digest"] = json!(pd);
    descriptor["adapter_contract"]["commit_point"] =
        json!("one original-terminal check, fenced version CAS and registered restore transaction");
    descriptor["concurrency"]["predicate_descriptor"]["clauses"][0]["expected_version"] =
        json!("242");
    let signed = fixture::signed("ctd", descriptor.clone(), 2);
    let mut scope = r.scope.clone();
    scope.action.id = inverse::ACTION.into();
    scope.action.digest = fixture::record_hash(&signed);
    scope.adapter_contract = descriptor["adapter_contract"].clone();
    scope.predicate_descriptor = descriptor["concurrency"]["predicate_descriptor"].clone();
    let mut proposal = h.f.proposal.clone();
    proposal["qid"] = json!("restore-original");
    let operation =
        h.f.trust
            .operation_key(&h.f.identity, &fixture::signed("proposal", proposal, 1))
            .unwrap();
    let now = kedgeflow::clock::Clock::now_ms(h.clock.as_ref());
    Contract {
        profile: PROFILE.into(),
        contract_id: "approved-conditional-restore".into(),
        registration_digest: r.digest().unwrap(),
        node_id: "forward".into(),
        forward_operation_key: r.saga.as_ref().unwrap().nodes[0].operation_key.clone(),
        inverse_operation_key: operation,
        inverse_principal: r.saga.as_ref().unwrap().nodes[0].principal.clone(),
        inverse_scope: scope,
        inverse_policy: kedgeflow::contracts::Policy {
            id: "inverse-policy".into(),
            epoch: 1,
            digest: "a".repeat(64),
        },
        signed_inverse_ctd: String::from_utf8(signed).unwrap(),
        restore_state_digest: h.f.proposal["baseline_state"][0]["state_digest"]
            .as_str()
            .unwrap()
            .into(),
        semantics: "restore_registered_state_if_original_terminal_and_version_matches".into(),
        forward_version_step: 1,
        compensation_units: 1,
        valid_from: now - 1000,
        expires_at: now + 60000,
        deadline_ms: 30000,
        target_id: "spiffe://test/inverse-target".into(),
        barrier_keys: public(17),
        evaluator_id: "spiffe://test/inverse-evaluator".into(),
        applicability_keys: public(18),
    }
}
fn qualifier(h: &Harness, c: &Contract, r: &Registration) -> Qualifier {
    Qualifier::new(h.ledger.clone(), c.clone(), native::trust(h, r)).unwrap()
}
async fn ready() -> Option<(Harness, Registration, Contract)> {
    let mut h = Harness::new().await?;
    let r = registration(&h);
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let i = h.bootstrap().await;
    assert!(h.post(&h.ack(&i), true).await.0.is_success());
    let c = contract(&h, &r);
    qualifier(&h, &c, &r).enroll().await.unwrap();
    Some((h, r, c))
}
async fn issue(h: &Harness) -> kedgeflow::ledger::IssuanceRecord {
    // Keep the test packet's signed manifest on the harness clock for real-time CLI tests.
    let now = kedgeflow::clock::Clock::now_ms(h.clock.as_ref());
    let mut packet = h.f.packet();
    let mut m: Value = serde_json::from_slice(&packet.manifest).unwrap();
    m["payload"]["assembled_at"] = json!(now - 2);
    packet.manifest = fixture::signed("manifest", m["payload"].clone(), 3);
    let clock = Time(now);
    let inputs =
        h.f.trust
            .verify_inputs(&h.f.identity, packet.borrowed(), &clock)
            .unwrap();
    let controller = AdmissionController::new(
        CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
        "key-6".into(),
        SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    let cert = h
        .ledger
        .admit(&controller.prepare(&inputs, &clock).unwrap(), &clock)
        .await
        .unwrap()
        .record
        .signed_certificate;
    super::hierarchical_leaf::issuer(h)
        .issue(&h.ledger, &inputs, cert.as_bytes(), &clock)
        .await
        .unwrap()
        .record
}
async fn outcome(h: &Harness, r: &Registration, status: &str, dispatch: bool) -> Bundle {
    let rec = issue(h).await;
    let c = native::claim(h, &rec, "inverse-original-forward").await;
    if dispatch {
        h.ledger
            .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
            .await
            .unwrap();
    }
    let now = kedgeflow::clock::Clock::now_ms(h.clock.as_ref());
    h.clock.0.store(now + 6000, Ordering::SeqCst);
    native::worker(
        h,
        &c,
        &rec.grant_digest,
        status,
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(&c)
    .await
    .unwrap();
    h.ledger
        .export_reserved_lineage(
            &c,
            &rec.issuance_key,
            &HistoryObserver::new(
                "budget-observer".into(),
                "key-15".into(),
                SigningKey::from_bytes(&[15; 32]),
            )
            .unwrap(),
            &native::trust(h, r),
        )
        .await
        .unwrap()
}
fn sign(kind: &str, payload: Value, n: u8) -> Statement {
    let mut s = Statement {
        profile: PROFILE.into(),
        kind: kind.into(),
        key_id: format!("key-{n}"),
        payload,
        signature: String::new(),
    };
    s.signature = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[n; 32])
            .sign(&s.message().unwrap())
            .to_bytes(),
    );
    s
}
fn proof(h: &Harness, r: &Registration, c: &Contract, b: Bundle) -> Proof {
    let receipt: kedgeflow::contracts::Envelope =
        serde_json::from_str(b.lineage.outcomes.receipts.last().unwrap()).unwrap();
    let now = kedgeflow::clock::Clock::now_ms(h.clock.as_ref());
    let f = Forward {
        registration_digest: r.digest().unwrap(),
        root_id: r.root_id.clone(),
        saga_id: r.saga.as_ref().unwrap().saga_id.clone(),
        node_id: c.node_id.clone(),
        operation_key: c.forward_operation_key.clone(),
        grant_digest: b.lineage.issuance.grant_digest.clone(),
        attempt_id: b.lineage.outcomes.attempt_id.clone(),
        receipt_digest: record_digest(&receipt).unwrap(),
        resource: r.scope.resource.clone(),
    };
    let parameters = Parameters {
        resource_id: r.scope.resource.id.clone(),
        expected_version: 242,
        forward_grant_digest: f.grant_digest.clone(),
        forward_attempt_id: f.attempt_id.clone(),
        restore_state_digest: c.restore_state_digest.clone(),
    };
    let barrier = sign(
        "barrier",
        json!(Barrier {
            contract_digest: c.digest().unwrap(),
            forward: f.clone(),
            target_id: c.target_id.clone(),
            original_terminal: true,
            no_late_commit: true,
            observed_version: 242,
            valid_from: now,
            expires_at: now + 10000
        }),
        17,
    );
    let app = sign(
        "applicability",
        json!(Applicability {
            contract_digest: c.digest().unwrap(),
            forward: f,
            barrier_digest: barrier.digest().unwrap(),
            evaluator_id: c.evaluator_id.clone(),
            inverse_operation_key: c.inverse_operation_key.clone(),
            inverse_principal: c.inverse_principal.clone(),
            parameters_digest: digest("parameters", &json!(parameters)).unwrap(),
            restore_state_digest: c.restore_state_digest.clone(),
            applicable: true,
            valid_from: now,
            expires_at: now + 5000
        }),
        18,
    );
    Proof {
        profile: PROFILE.into(),
        forward: b,
        barrier,
        applicability: app,
        parameters,
    }
}
fn resign(p: &mut Proof) {
    p.barrier = sign("barrier", p.barrier.payload.clone(), 17);
    p.applicability.payload["barrier_digest"] = json!(p.barrier.digest().unwrap());
    p.applicability.payload["parameters_digest"] =
        json!(digest("parameters", &json!(p.parameters)).unwrap());
    p.applicability = sign("applicability", p.applicability.payload.clone(), 18);
}
fn base(h: &Harness, c: &Contract) -> String {
    format!("{}/inverse-contracts/{}", h.prefix, c.forward_operation_key)
}
async fn write(h: &Harness, key: &str, raw: Option<&[u8]>) {
    let _ = h;
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let (route, v) = match raw {
        Some(raw) => (
            "put",
            json!({"key":STANDARD.encode(key),"value":STANDARD.encode(raw)}),
        ),
        None => ("deleterange", json!({"key":STANDARD.encode(key)})),
    };
    assert!(
        reqwest::Client::new()
            .post(format!("{endpoint}/v3/kv/{route}"))
            .json(&v)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
}
#[tokio::test]
async fn inverse_contract_enrollment_is_original_preissuance_and_pins_complete_trust() {
    let Some((h, r, c)) = ready().await else {
        return;
    };
    assert!(qualifier(&h, &c, &r).enroll().await.is_err());
    let mut wrong = c.clone();
    wrong.contract_id = "replacement".into();
    assert!(qualifier(&h, &wrong, &r).status().await.is_err());
    let mut tv = native::trust_value(&h, &r);
    tv["observer_id"] = json!("replacement-observer");
    let t = kedgeflow::reserved_lineage::TrustConfig::decode(&serde_json::to_vec(&tv).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    assert!(
        Qualifier::new(h.ledger.clone(), c.clone(), t)
            .unwrap()
            .status()
            .await
            .is_err()
    );
    let Some(mut h2) = Harness::new().await else {
        return;
    };
    let r2 = registration(&h2);
    h2.ledger = h2.ledger.clone().with_reservation(r2.clone()).unwrap();
    h2.ledger.enroll_reservation().await.unwrap();
    let installed = h2.bootstrap().await;
    assert!(h2.post(&h2.ack(&installed), true).await.0.is_success());
    let rec = issue(&h2).await;
    let mut c2 = contract(&h2, &r2);
    c2.contract_id = "post-issue-contract".into();
    assert!(qualifier(&h2, &c2, &r2).enroll().await.is_err());
    assert_eq!(rec.issuance_key, c2.forward_operation_key);
    // Ordinary native admission must not claim a prospective inverse operation.
    let Some(h3) = Harness::new().await else {
        return;
    };
    let installed = h3.bootstrap().await;
    assert!(h3.post(&h3.ack(&installed), true).await.0.is_success());
    let op =
        h3.f.trust
            .operation_key(&h3.f.identity, &h3.f.packet().proposal)
            .unwrap();
    write(
        &h3,
        &format!("{}/inverse-operations/{op}", h3.prefix),
        Some(b"reserved inverse identity"),
    )
    .await;
    assert!(h3.issue().await.is_err());
    assert!(
        h3.ledger
            .read_key(&format!("{}/admission/{op}", h3.prefix))
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn inverse_qualified_original_proof_restarts_without_authority_spend_or_refund() {
    let Some((h, r, c)) = ready().await else {
        return;
    };
    let b = outcome(&h, &r, "committed", true).await;
    let p = proof(&h, &r, &c, b);
    let held = native::budget(&h, &r).await;
    h.clock.0.store(NOW + 6500, Ordering::SeqCst);
    let v = qualifier(&h, &c, &r).qualify(p.clone()).await.unwrap();
    assert!(!v.execution_authority && v.fresh_admission_required);
    assert!(
        qualifier(&h, &c, &r)
            .status()
            .await
            .unwrap()
            .within_validity_window
    );
    assert_eq!(native::budget(&h, &r).await, held);
    h.clock.0.fetch_add(1, Ordering::SeqCst);
    let same = qualifier(&h, &c, &r).qualify(p.clone()).await.unwrap();
    assert_eq!(v, same);
    assert_eq!(qualifier(&h, &c, &r).history().await.unwrap().len(), 1);
    assert!(
        h.ledger
            .read_key(&format!(
                "{}/issuance/{}",
                h.prefix, c.inverse_operation_key
            ))
            .await
            .unwrap()
            .is_none()
    );
    h.clock.0.store(NOW + 6400, Ordering::SeqCst);
    let mut regressed = p.clone();
    regressed.applicability.payload["valid_from"] = json!(NOW + 6001);
    resign(&mut regressed);
    assert!(qualifier(&h, &c, &r).qualify(regressed).await.is_err());
    assert_eq!(qualifier(&h, &c, &r).history().await.unwrap().len(), 1);
    h.clock.0.store(NOW + 6501, Ordering::SeqCst);
    h.ledger.stop_reservation().await.unwrap();
    assert!(qualifier(&h, &c, &r).qualify(p).await.is_err());
    let status = qualifier(&h, &c, &r).status().await.unwrap();
    assert!(
        !status.within_validity_window
            && !status.execution_authority
            && status.live_revalidation_required
    );
    assert_eq!(status.qualification.unwrap(), v);
    let mut stopped = held;
    stopped.active = false;
    assert_eq!(native::budget(&h, &r).await, stopped);
}
#[tokio::test]
async fn inverse_unknown_and_pre_send_no_effect_never_qualify_despite_valid_signers() {
    for dispatch in [false, true] {
        let Some((h, r, c)) = ready().await else {
            return;
        };
        let b = outcome(&h, &r, "unknown", dispatch).await;
        let p = proof(&h, &r, &c, b);
        assert!(inverse::verify(&c, &native::trust(&h, &r), &p, NOW + 6000).is_err());
        assert!(qualifier(&h, &c, &r).qualify(p).await.is_err());
        assert!(qualifier(&h, &c, &r).history().await.unwrap().is_empty());
    }
}
#[tokio::test]
async fn inverse_resigned_identity_barrier_applicability_version_and_deadline_substitutions_refuse()
{
    let Some((h, r, c)) = ready().await else {
        return;
    };
    let b = outcome(&h, &r, "committed", true).await;
    let p = proof(&h, &r, &c, b);
    let t = native::trust(&h, &r);
    inverse::verify(&c, &t, &p, NOW + 6000).unwrap();
    let edits: Vec<fn(&mut Proof)> = vec![
        |p| p.barrier.payload["original_terminal"] = json!(false),
        |p| p.barrier.payload["no_late_commit"] = json!(false),
        |p| p.barrier.payload["target_id"] = json!("wrong"),
        |p| p.barrier.payload["forward"]["attempt_id"] = json!("replacement"),
        |p| p.barrier.payload["observed_version"] = json!(243),
        |p| p.barrier.payload["valid_from"] = json!(NOW + 5999),
        |p| p.barrier.payload["expires_at"] = json!(NOW + 36001),
        |p| p.applicability.payload["applicable"] = json!(false),
        |p| p.applicability.payload["evaluator_id"] = json!("wrong"),
        |p| p.applicability.payload["inverse_operation_key"] = json!("9".repeat(64)),
        |p| p.applicability.payload["inverse_principal"]["workload_id"] = json!("replacement"),
        |p| p.applicability.payload["expires_at"] = json!(NOW + 16001),
        |p| p.applicability.payload["valid_from"] = json!(NOW + 5999),
        |p| p.parameters.restore_state_digest = "9".repeat(64),
        |p| p.parameters.forward_attempt_id = "replacement".into(),
        |p| p.parameters.expected_version = 243,
    ];
    for edit in edits {
        let mut bad = p.clone();
        edit(&mut bad);
        resign(&mut bad);
        assert!(inverse::verify(&c, &t, &bad, NOW + 6000).is_err());
    }
    assert!(inverse::verify(&c, &t, &p, NOW + 11000).is_err());
    assert!(inverse::verify(&c, &t, &p, NOW + 5999).is_err());
    let mut wrong = p.clone();
    wrong.applicability = sign("applicability", wrong.applicability.payload, 17);
    assert!(inverse::verify(&c, &t, &wrong, NOW + 6000).is_err());
    let mut wrong = p.clone();
    wrong.applicability.payload["extra"] = json!(true);
    resign(&mut wrong);
    assert!(Proof::decode(&serde_json::to_vec(&wrong).unwrap()).is_err());
    assert!(Proof::decode(br#"{"profile":"a","profile":"b"}"#).is_err());
}
#[tokio::test]
async fn inverse_contract_role_scope_ctd_cost_and_closed_schema_refusals() {
    let Some((h, r, c)) = ready().await else {
        return;
    };
    let t = native::trust(&h, &r);
    let example = Contract::decode(include_bytes!(
        "../../../../config/inverse-contract.example.json"
    ))
    .unwrap();
    let original: Registration =
        serde_json::from_str(include_str!("../../../../config/saga-forward.example.json")).unwrap();
    assert_eq!(example.registration_digest, original.digest().unwrap());
    let descriptor =
        kedgeflow::schema::verify_record(example.signed_inverse_ctd.as_bytes(), "ctd", &keys(2))
            .unwrap();
    assert_eq!(
        record_digest(&descriptor).unwrap(),
        example.inverse_scope.action.digest
    );
    assert_eq!(
        descriptor.payload["parameter_schema"],
        inverse::parameter_schema()
    );
    for n in [1, 2, 3, 4, 5, 6, 14, 15, 16] {
        let mut bad = c.clone();
        bad.barrier_keys = public(n);
        assert!(bad.validate(&t).is_err(), "overlap key {n}");
    }
    let edits: Vec<fn(&mut Contract)> = vec![
        |c| c.applicability_keys = c.barrier_keys.clone(),
        |c| c.inverse_scope.resource.incarnation = "replacement".into(),
        |c| c.inverse_scope.conflict_domain = "other".into(),
        |c| c.compensation_units = 2,
        |c| c.forward_version_step = 2,
        |c| c.inverse_scope.action.digest = "b".repeat(64),
        |c| c.inverse_operation_key = c.forward_operation_key.clone(),
        |c| c.signed_inverse_ctd.push('x'),
    ];
    for f in edits {
        let mut bad = c.clone();
        f(&mut bad);
        assert!(bad.validate(&t).is_err());
    }
    let mut value = json!(c);
    value["barrier_keys"] = Value::Null;
    assert!(Contract::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    // The current executable profile cannot adopt the inverse parameter mapping.
    assert!(kedgeflow::leaf_action::bind(inverse::ACTION,"1.0",&json!({"resource_id":r.scope.resource.id,"expected_version":242,"forward_grant_digest":"a".repeat(64),"forward_attempt_id":"original","restore_state_digest":c.restore_state_digest}),&r.scope.resource,"expected_version").is_err());
}
#[tokio::test]
async fn inverse_missing_native_and_retained_proof_or_journal_never_synthesizes_readiness() {
    let Some((h, r, c)) = ready().await else {
        return;
    };
    let b = outcome(&h, &r, "committed", true).await;
    let p = proof(&h, &r, &c, b);
    let receipt = p.barrier.payload["forward"]["receipt_digest"]
        .as_str()
        .unwrap();
    let g = native::grant(&h, &p.forward.lineage.issuance);
    let attempt = &p.forward.lineage.outcomes.attempt_id;
    let key = format!(
        "{}/domains/{}/roots/{}/attempts/{}/receipts/{receipt}",
        h.prefix,
        URL_SAFE_NO_PAD.encode(&g.conflict_domain),
        URL_SAFE_NO_PAD.encode(&g.root_id),
        URL_SAFE_NO_PAD.encode(attempt)
    );
    for key in [
        key,
        format!("{}/admission-chain/{}", h.prefix, c.forward_operation_key),
    ] {
        let raw = h.ledger.read_key(&key).await.unwrap().unwrap();
        write(&h, &key, None).await;
        assert!(qualifier(&h, &c, &r).qualify(p.clone()).await.is_err());
        write(&h, &key, Some(&raw)).await;
    }
    qualifier(&h, &c, &r).qualify(p).await.unwrap();
    for suffix in ["head", "records/0001", "contract"] {
        let key = format!("{}/{suffix}", base(&h, &c));
        let raw = h.ledger.read_key(&key).await.unwrap().unwrap();
        write(&h, &key, None).await;
        assert!(qualifier(&h, &c, &r).status().await.is_err());
        assert!(qualifier(&h, &c, &r).enroll().await.is_err());
        write(&h, &key, Some(&raw)).await;
    }
    assert_eq!(qualifier(&h, &c, &r).history().await.unwrap().len(), 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inverse_concurrent_qualifiers_retain_one_original_proof_and_never_renew_on_retry() {
    let Some((h, r, c)) = ready().await else {
        return;
    };
    let b = outcome(&h, &r, "committed", true).await;
    let p = proof(&h, &r, &c, b);
    let mut jobs = vec![];
    for _ in 0..8 {
        let q = qualifier(&h, &c, &r);
        let p = p.clone();
        jobs.push(tokio::spawn(async move { q.qualify(p).await }));
    }
    let mut successes = 0;
    for job in jobs {
        successes += usize::from(job.await.unwrap().is_ok());
    }
    assert!(successes >= 1);
    assert_eq!(qualifier(&h, &c, &r).history().await.unwrap().len(), 1);
    h.clock.0.store(NOW + 11000, Ordering::SeqCst);
    assert!(qualifier(&h, &c, &r).qualify(p).await.is_err());
    assert!(
        !qualifier(&h, &c, &r)
            .status()
            .await
            .unwrap()
            .within_validity_window
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inverse_qualification_cas_refuses_stop_and_original_receipt_or_history_deletion() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use std::sync::atomic::AtomicBool;
    for fault in ["stop", "receipt", "history"] {
        let Some((mut h, r, c)) = ready().await else {
            return;
        };
        let b = outcome(&h, &r, "committed", true).await;
        let p = proof(&h, &r, &c, b);
        let direct = h.ledger.clone();
        let held = native::budget(&h, &r).await;
        let native_base = format!("{}/reservation-history/{}", h.prefix, r.digest().unwrap());
        let g = native::grant(&h, &p.forward.lineage.issuance);
        let receipt = format!(
            "{}/domains/{}/roots/{}/attempts/{}/receipts/{}",
            h.prefix,
            URL_SAFE_NO_PAD.encode(&g.conflict_domain),
            URL_SAFE_NO_PAD.encode(&g.root_id),
            URL_SAFE_NO_PAD.encode(&p.forward.lineage.outcomes.attempt_id),
            p.barrier.payload["forward"]["receipt_digest"]
                .as_str()
                .unwrap()
        );
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
                        let chosen = v["success"].as_array().is_some_and(|ops| {
                            ops.iter().any(|o| {
                                o["request_put"]["key"]
                                    .as_str()
                                    .and_then(|s| STANDARD.decode(s).ok())
                                    .is_some_and(|b| {
                                        let s = String::from_utf8_lossy(&b);
                                        s.contains("/inverse-contracts/") && s.contains("/records/")
                                    })
                            })
                        });
                        if chosen && block.swap(false, Ordering::SeqCst) {
                            entered.notify_one();
                            release.notified().await;
                        }
                        let r = reqwest::Client::new()
                            .post(format!("{endpoint}/v3/kv/txn"))
                            .json(&v)
                            .send()
                            .await
                            .unwrap();
                        let code = r.status();
                        let bytes = r.bytes().await.unwrap();
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
        let q = qualifier(&h, &c, &r);
        let task = tokio::spawn(async move { q.qualify(p).await });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        match fault {
            "stop" => direct.stop_reservation().await.unwrap(),
            "receipt" => write(&h, &receipt, None).await,
            _ => write(&h, &format!("{native_base}/events/000001"), None).await,
        }
        release.notify_one();
        assert!(task.await.unwrap().is_err());
        h.ledger = direct;
        assert!(qualifier(&h, &c, &r).history().await.unwrap().is_empty());
        let mut expected = held;
        if fault == "stop" {
            expected.active = false;
        }
        assert_eq!(native::budget(&h, &r).await, expected);
        drop(proxy);
    }
}
#[tokio::test]
async fn inverse_bounded_journal_preserves_original_proofs_and_capacity_at_exhaustion() {
    let Some((h, r, c)) = ready().await else {
        return;
    };
    let b = outcome(&h, &r, "committed", true).await;
    let p = proof(&h, &r, &c, b);
    let held = native::budget(&h, &r).await;
    let mut accepted = 0;
    for n in 0..=inverse::MAX_RECORDS {
        h.clock.0.store(NOW + 6000 + n as i64, Ordering::SeqCst);
        let mut next = p.clone();
        next.applicability.payload["valid_from"] = json!(NOW + 6000 + n as i64);
        resign(&mut next);
        if qualifier(&h, &c, &r).qualify(next).await.is_err() {
            break;
        }
        accepted += 1;
    }
    assert!((1..=inverse::MAX_RECORDS).contains(&accepted));
    let history = qualifier(&h, &c, &r).history().await.unwrap();
    assert_eq!(history.len() as u64, accepted);
    assert_eq!(history[0].sequence, 1);
    assert!(history[0].previous_digest.is_none());
    assert_eq!(native::budget(&h, &r).await, held);
    assert!(
        !qualifier(&h, &c, &r)
            .status()
            .await
            .unwrap()
            .execution_authority
    );
}
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inverse_shipping_cli_mtls_enrolls_qualifies_restarts_and_verifies_offline_without_execution()
 {
    use axum::{Extension, Json, Router, response::IntoResponse, routing::post};
    use kedgeflow::auth::WorkloadIdentity;
    use std::os::unix::fs::PermissionsExt;
    let now = kedgeflow::clock::Clock::now_ms(&kedgeflow::clock::SystemClock);
    let Some(mut h) = Harness::with_setup(None, now, |_| {}).await else {
        return;
    };
    h.f.identity.delegation_digest = digest("delegation", &h.f.proposal["delegation"]).unwrap();
    let r = registration(&h);
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let c = contract(&h, &r);
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
                    assert_eq!(headers["authorization"], "inverse-qualifier-token");
                    count.fetch_add(1, Ordering::SeqCst);
                    for op in v["success"].as_array().unwrap() {
                        if let Some(k) = op["request_put"]["key"].as_str() {
                            let raw = STANDARD.decode(k).unwrap();
                            let s = String::from_utf8_lossy(&raw);
                            assert!(
                                s.contains("/inverse-contracts/")
                                    || s.contains("/inverse-operations/")
                            );
                        }
                    }
                    let r = reqwest::Client::new()
                        .post(format!("{endpoint}/v3/kv/txn"))
                        .json(&v)
                        .send()
                        .await
                        .unwrap();
                    let status = r.status();
                    let bytes = r.bytes().await.unwrap();
                    (status, [("content-type", "application/json")], bytes).into_response()
                }
            },
        ),
    );
    let proxy = support::serve_tls(&h.agent_pki, router).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, raw: &[u8]| {
        let p = dir.path().join(name);
        std::fs::write(&p, raw).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    };
    let ca = write("ca.pem", h.agent_pki.ca.as_bytes());
    let cert = write("cert.pem", h.agent_pki.client.as_bytes());
    let key = write("key.pem", h.agent_pki.client_key.as_bytes());
    let token = write("token", b"inverse-qualifier-token");
    let mut config = json!({"contract":c,"trust":native::trust_value(&h,&r),"etcd_endpoint":proxy.url,"etcd_ca":ca,"etcd_certificate":cert,"etcd_private_key":key,"etcd_token_file":token});
    let path = write("inverse.json", &serde_json::to_vec(&config).unwrap());
    let proof_file = dir.path().join("proof.json");
    let run = |flag: &str| {
        let path = path.clone();
        let proof_file = proof_file.clone();
        let flag = flag.to_owned();
        async move {
            let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-compensation"));
            cmd.arg("--config").arg(path).arg(&flag);
            if flag == "--qualify" {
                cmd.arg("--proof").arg(proof_file);
            }
            cmd.output().await.unwrap()
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
    assert!(!run("--enroll").await.status.success());
    let b = outcome(&h, &r, "committed", true).await;
    // Let wall time catch the intentionally advanced native expiry/recovery clock.
    let wait_until = kedgeflow::clock::Clock::now_ms(h.clock.as_ref());
    let current = kedgeflow::clock::Clock::now_ms(&kedgeflow::clock::SystemClock);
    if current < wait_until {
        tokio::time::sleep(Duration::from_millis((wait_until - current) as u64 + 30)).await;
    }
    h.clock.0.store(
        kedgeflow::clock::Clock::now_ms(&kedgeflow::clock::SystemClock),
        Ordering::SeqCst,
    );
    let p = proof(&h, &r, &c, b);
    write("proof.json", &serde_json::to_vec(&p).unwrap());
    let held = native::budget(&h, &r).await;
    let out = run("--qualify").await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let first: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(first["execution_authority"], false);
    assert_eq!(first["fresh_admission_required"], true);
    let out = run("--qualify").await;
    assert!(out.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap(), first);
    let out = run("--status").await;
    assert!(out.status.success());
    let status: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(status["within_validity_window"], true);
    assert_eq!(status["live_revalidation_required"], true);
    let out = run("--history").await;
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<Vec<Value>>(&out.stdout)
            .unwrap()
            .len(),
        1
    );
    let before = calls.load(Ordering::SeqCst);
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-compensation"))
        .arg("--config")
        .arg(&path)
        .arg("--verify-proof")
        .arg("--proof")
        .arg(&proof_file)
        .arg("--at")
        .arg(first["validated_at"].as_i64().unwrap().to_string())
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(calls.load(Ordering::SeqCst), before);
    assert_eq!(native::budget(&h, &r).await, held);
    h.ledger.stop_reservation().await.unwrap();
    assert!(!run("--qualify").await.status.success());
    let out = run("--status").await;
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["within_validity_window"],
        false
    );
    config["contract"]["contract_id"] = json!("replacement");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run("--status").await.status.success());
}
