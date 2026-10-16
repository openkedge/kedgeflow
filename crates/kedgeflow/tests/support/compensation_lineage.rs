//! Native compound export and separate offline verification over real SQL state.
use super::*;
use kedgeflow::compensation_lineage::{self as audit, Bundle as AuditBundle, TrustConfig};
use kedgeflow::contracts::Envelope;

fn trust_value(h: &SqlInverseReady) -> Value {
    let mut inverse = native::trust_value(&h.inverse, &h.registration)["lineage"].clone();
    inverse["gateway_audience"] = json!(h.inverse.registration.scope.audience);
    inverse["inverse_contract"] = json!(h.contract);
    inverse["outcome_keys"] = json!(public(19));
    inverse["source_id"] = json!("spiffe://test/inverse-outcome");
    json!({"forward":native::trust_value(&h.forward,&h.registration),"inverse":inverse,"topology":h.topology,"contract":h.contract,"broker":{"gateway_workload":h.pin.gateway_workload,"target_audience":h.pin.target_audience,"target_scope":h.pin.target_scope,"max_lifetime_ms":5000,"tool":h.inverse.tool()},"observer_id":"compound-observer","observer_keys":public(20)})
}
pub(super) fn trust(h: &SqlInverseReady) -> audit::Trust {
    TrustConfig::decode(&serde_json::to_vec(&trust_value(h)).unwrap())
        .unwrap()
        .registration()
        .unwrap()
}
pub(super) async fn export(h: &SqlInverseReady) -> kedgeflow::error::Result<AuditBundle> {
    h.inverse
        .ledger
        .export_compensation_lineage(
            &HistoryObserver::new(
                "compound-observer".into(),
                "key-20".into(),
                SigningKey::from_bytes(&[20; 32]),
            )
            .unwrap(),
            &HistoryObserver::new(
                "budget-observer".into(),
                "key-15".into(),
                SigningKey::from_bytes(&[15; 32]),
            )
            .unwrap(),
            &trust(h),
        )
        .await
}
fn resign(b: &mut AuditBundle) {
    b.checkpoint.evidence_digest =
        digest("compensation-lineage-evidence", &json!(b.evidence)).unwrap();
    let mut v = json!(b.checkpoint);
    v.as_object_mut().unwrap().remove("signature");
    let mut raw = format!("KedgeFlow:{}\0", audit::PROFILE).into_bytes();
    raw.extend(kedgeflow::contracts::canonical(&v).unwrap());
    b.checkpoint.signature =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[20; 32]).sign(&raw).to_bytes());
}
struct Query(Arc<kedgeflow::postgres_compensation::PostgresCompensationStore>);
#[async_trait::async_trait]
impl kedgeflow::ledger::OutcomeQuerier for Query {
    async fn query(
        &self,
        id: &str,
    ) -> kedgeflow::error::Result<kedgeflow::ledger::AuthoritativeObservation> {
        use kedgeflow::postgres_compensation::CompensationStore;
        let o =
            self.0.lookup("tenant-42", id).await?.ok_or_else(|| {
                kedgeflow::error::Error::Unknown("no original SQL inverse".into())
            })?;
        Ok(kedgeflow::ledger::AuthoritativeObservation {
            attempt_id: o.request.attempt_id,
            root_id: o.request.root_id,
            grant_digest: o.request.grant_digest,
            target_reference: "postgres/inverse/original".into(),
            status: match o.status {
                kedgeflow::postgres_action::Status::Committed => "committed",
                _ => "fenced_no_effect",
            }
            .into(),
        })
    }
}
fn worker(h: &SqlInverseReady) -> kedgeflow::recovery::RecoveryWorker {
    kedgeflow::recovery::RecoveryWorker::new(
        h.inverse.ledger.clone(),
        h.grants(),
        Arc::new(Query(h.store.clone())),
        "key-19".into(),
        SigningKey::from_bytes(&[19; 32]),
        "spiffe://test/inverse-outcome".into(),
        h.inverse.clock.clone(),
    )
    .unwrap()
}
async fn pending(
    h: &SqlInverseReady,
    rec: &kedgeflow::ledger::IssuanceRecord,
    c: &kedgeflow::recovery::Candidate,
    token: &str,
) -> kedgeflow::postgres_compensation::DispatchRequest {
    let (binding, qualification) = h
        .inverse
        .ledger
        .compensation_dispatch_material(&c.grant, &rec.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    let request = kedgeflow::compensation_target::Dispatch {
        profile: kedgeflow::compensation_target::PROFILE.into(),
        operation: "dispatch".into(),
        signed_grant: URL_SAFE_NO_PAD.encode(rec.signed_grant.as_bytes()),
        attempt_id: c.attempt_id.clone(),
        qualification,
        binding,
    };
    h.target_trust()
        .bind(
            &h.grants(),
            &kedgeflow::target_token::TargetTokenVerifier::new(
                "https://broker.test/exchange".into(),
                keys(29),
            )
            .unwrap(),
            &request,
            token,
            NOW + 6000,
        )
        .unwrap()
}
async fn commit(
    h: &SqlInverseReady,
    rec: &kedgeflow::ledger::IssuanceRecord,
    c: &kedgeflow::recovery::Candidate,
    token: &str,
) {
    use kedgeflow::postgres_compensation::CompensationStore;
    let bound = pending(h, rec, c, token).await;
    assert_eq!(
        h.store.apply(&bound).await.unwrap().status,
        kedgeflow::postgres_action::Status::Committed
    );
}

#[tokio::test]
async fn compensation_sql_compound_complete_original_lineage_verifies_after_stop_and_expiry() {
    let Some(mut h) = Box::pin(sql_inverse_ready()).await else {
        return;
    };
    let initial = Box::pin(export(&h)).await.unwrap();
    assert_eq!(
        audit::verify(&initial, &trust(&h)).unwrap().status,
        "partial"
    );
    let (rec, c, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    // Claimed operations without any signed observation are never invented.
    assert!(Box::pin(export(&h)).await.is_err());
    // Keep the one originally authorized target request in flight; the first
    // query observes no result. Continuing this request is not a new dispatch.
    let bound = pending(&h, &rec, &c, &token).await;
    h.inverse.clock.0.store(NOW + 12000, Ordering::SeqCst);
    let unknown = Box::pin(worker(&h).recover(&c)).await.unwrap();
    assert_eq!(unknown.state, "unknown");
    let b = Box::pin(export(&h)).await.unwrap();
    let v = audit::verify(&b, &trust(&h)).unwrap();
    assert_eq!(v.status, "unresolved");
    assert_eq!(v.inverse_status.as_deref(), Some("unresolved"));
    use kedgeflow::postgres_compensation::CompensationStore;
    assert_eq!(
        h.store.apply(&bound).await.unwrap().status,
        kedgeflow::postgres_action::Status::Committed
    );
    h.forward.ledger.stop_reservation().await.unwrap();
    h.inverse.clock.0.store(NOW + 12000, Ordering::SeqCst);
    assert_eq!(worker(&h).recover(&c).await.unwrap().state, "committed");
    let b = Box::pin(export(&h)).await.unwrap();
    let v = audit::verify(&b, &trust(&h)).unwrap();
    assert_eq!(v.status, "compensated");
    assert!(!v.execution_authority);
    assert!(v.complete_evidence);
    assert_eq!(v.nodes.len(), 1);
    assert_eq!(v.qualifications_verified, 1);
    assert_eq!(
        h.inverse.ledger.compensation_spend().await.unwrap().state,
        kedgeflow::coordination::ReservationState::Committed
    );
    let dir = tempfile::tempdir().unwrap();
    let tp = dir.path().join("trust.json");
    let bp = dir.path().join("bundle.json");
    std::fs::write(&tp, serde_json::to_vec(&trust_value(&h)).unwrap()).unwrap();
    std::fs::write(&bp, serde_json::to_vec(&b).unwrap()).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-compensation-lineage"))
        .args([
            "--trust",
            tp.to_str().unwrap(),
            "--bundle",
            bp.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["status"],
        "compensated"
    );
    let mut wrong = trust_value(&h);
    wrong["forward"]["namespace"] = json!("other-namespace");
    std::fs::write(&tp, serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(
        !std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-compensation-lineage"))
            .args([
                "--trust",
                tp.to_str().unwrap(),
                "--bundle",
                bp.to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    // Deleting a historical receipt must block a fresh native export, even
    // though the already captured, signed evidence remains independently valid.
    let first = &b
        .evidence
        .inverse
        .as_ref()
        .unwrap()
        .lineage
        .as_ref()
        .unwrap()
        .outcomes
        .receipts[0];
    let e: Envelope = serde_json::from_slice(first.as_bytes()).unwrap();
    let key = format!(
        "{}/domains/{}/paired/inverse/roots/{}/attempts/{}/receipts/{}",
        h.inverse.prefix,
        URL_SAFE_NO_PAD.encode(&c.grant.conflict_domain),
        URL_SAFE_NO_PAD.encode(&c.grant.root_id),
        URL_SAFE_NO_PAD.encode(&c.attempt_id),
        record_digest(&e).unwrap()
    );
    let raw = h.inverse.ledger.read_key(&key).await.unwrap().unwrap();
    Box::pin(write(&h.inverse, &key, None)).await;
    assert!(Box::pin(export(&h)).await.is_err());
    assert_eq!(audit::verify(&b, &trust(&h)).unwrap().status, "compensated");
    Box::pin(write(&h.inverse, &key, Some(&raw))).await;
    assert!(Box::pin(export(&h)).await.is_ok());
}

#[tokio::test]
async fn compensation_sql_compound_resigned_semantic_omission_binding_and_role_substitutions_refuse()
 {
    let Some(mut h) = Box::pin(sql_inverse_ready()).await else {
        return;
    };
    let (rec, c, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    commit(&h, &rec, &c, &token).await;
    h.inverse.clock.0.store(NOW + 12000, Ordering::SeqCst);
    worker(&h).recover(&c).await.unwrap();
    let b = Box::pin(export(&h)).await.unwrap();
    let t = trust(&h);
    let mut cases = vec![];
    let mut bad = b.clone();
    bad.evidence.forward.clear();
    cases.push(bad);
    let mut bad = b.clone();
    let f = bad.evidence.forward.values().next().unwrap().clone();
    bad.evidence.forward.insert("extra".into(), f);
    cases.push(bad);
    let mut bad = b.clone();
    bad.evidence.compensating = false;
    cases.push(bad);
    let mut bad = b.clone();
    bad.evidence.qualifications[0].sequence = 2;
    cases.push(bad);
    let mut bad = b.clone();
    bad.evidence.qualifications[0].verification.validated_at += 1;
    cases.push(bad);
    let mut bad = b.clone();
    bad.evidence
        .inverse
        .as_mut()
        .unwrap()
        .binding
        .payload
        .forward
        .attempt_id = "replacement".into();
    cases.push(bad);
    let mut bad = b.clone();
    bad.evidence.inverse.as_mut().unwrap().spend.attempt_id = Some("replacement".into());
    cases.push(bad);
    let mut bad = b.clone();
    bad.evidence
        .inverse
        .as_mut()
        .unwrap()
        .spend
        .compensation_units += 1;
    cases.push(bad);
    let mut bad = b.clone();
    bad.evidence.inverse.as_mut().unwrap().permit = None;
    cases.push(bad);
    let mut bad = b.clone();
    bad.evidence
        .inverse
        .as_mut()
        .unwrap()
        .permit
        .as_mut()
        .unwrap()
        .target_scope = "wider".into();
    cases.push(bad);
    let mut bad = b.clone();
    bad.checkpoint.captured_at = NOW;
    cases.push(bad);
    for mut bad in cases {
        // Re-sign the changed compound statement with the real fixture issuer,
        // and keep the held-spend digest coherent. Semantic checks must still refuse.
        if let Some(i) = &mut bad.evidence.inverse {
            let mut v = json!(i.binding);
            v.as_object_mut().unwrap().remove("signature");
            let mut raw =
                format!("KedgeFlow:{}\0", kedgeflow::compensation_execution::PROFILE).into_bytes();
            raw.extend(canonical(&v).unwrap());
            i.binding.signature =
                URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[5; 32]).sign(&raw).to_bytes());
            i.spend.binding_digest = i.binding.digest().unwrap();
            if let Some(p) = &mut i.permit {
                let mut v = json!(p);
                v.as_object_mut().unwrap().remove("permit_id");
                p.permit_id = digest("broker-permit", &v).unwrap();
            }
        }
        resign(&mut bad);
        assert!(audit::verify(&bad, &t).is_err());
    }
    for n in [5, 6, 14, 15, 17, 18, 19] {
        let mut wrong = trust_value(&h);
        wrong["observer_keys"] = json!(public(n));
        assert!(
            TrustConfig::decode(&serde_json::to_vec(&wrong).unwrap())
                .unwrap()
                .registration()
                .is_err()
        );
    }
    let mut v = json!(b);
    v["unknown"] = json!(true);
    assert!(AuditBundle::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(AuditBundle::decode(&vec![b' '; audit::MAX_BUNDLE + 1]).is_err());
    let mut wrong = trust_value(&h);
    wrong["broker"]["target_scope"] = json!("other");
    assert!(
        audit::verify(
            &b,
            &TrustConfig::decode(&serde_json::to_vec(&wrong).unwrap())
                .unwrap()
                .registration()
                .unwrap()
        )
        .is_err()
    );
}

#[tokio::test]
async fn compensation_sql_compound_allocated_and_proven_no_effect_inverse_keep_held_costs() {
    let Some(h) = Box::pin(sql_inverse_ready()).await else {
        return;
    };
    let held = native::budget(&h.forward, &h.registration).await;
    let rec = execution_issue(&h.inverse).await.unwrap().record;
    let b = Box::pin(export(&h)).await.unwrap();
    assert_eq!(
        audit::verify(&b, &trust(&h))
            .unwrap()
            .inverse_status
            .as_deref(),
        Some("allocated")
    );
    let c = native::claim(&h.inverse, &rec, "compound-not-sent").await;
    h.inverse.clock.0.store(NOW + 12000, Ordering::SeqCst);
    assert_eq!(
        worker(&h).recover(&c).await.unwrap().state,
        "not_dispatched"
    );
    let b = Box::pin(export(&h)).await.unwrap();
    let v = audit::verify(&b, &trust(&h)).unwrap();
    assert_eq!(v.status, "partial");
    assert_eq!(v.inverse_status.as_deref(), Some("no_effect"));
    assert_eq!(native::budget(&h.forward, &h.registration).await, held);
    assert_eq!(
        h.inverse.ledger.compensation_spend().await.unwrap().state,
        kedgeflow::coordination::ReservationState::ProvenNoEffect
    );
    let mut bad = b.clone();
    bad.evidence.inverse.as_mut().unwrap().spend.state =
        kedgeflow::coordination::ReservationState::Committed;
    resign(&mut bad);
    assert!(audit::verify(&bad, &trust(&h)).is_err());
    let mut bad = b.clone();
    bad.evidence.inverse.as_mut().unwrap().lineage = None;
    resign(&mut bad);
    assert!(audit::verify(&bad, &trust(&h)).is_err());
}

#[tokio::test]
async fn compensation_sql_compound_two_node_plan_cannot_omit_original_no_send_lineage() {
    let Some(mut h) = Box::pin(sql_inverse_setup_plan(NOW, None, true)).await else {
        return;
    };
    let held = native::budget(&h.forward, &h.registration).await;
    let (rec, c, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    commit(&h, &rec, &c, &token).await;
    h.inverse.clock.0.store(NOW + 12000, Ordering::SeqCst);
    worker(&h).recover(&c).await.unwrap();
    let b = Box::pin(export(&h)).await.unwrap();
    let t = trust(&h);
    let v = audit::verify(&b, &t).unwrap();
    assert_eq!(v.status, "compensated");
    assert_eq!(v.nodes.len(), 2);
    assert_eq!(b.evidence.forward.len(), 2);
    let extra = &h.registration.saga.as_ref().unwrap().nodes[1].operation_key;
    assert_eq!(v.nodes[extra], "no_effect");
    let mut bad = b.clone();
    bad.evidence.forward.remove(extra);
    resign(&mut bad);
    assert!(audit::verify(&bad, &t).is_err());
    let mut bad = b.clone();
    let selected = bad.evidence.forward[&h.contract.forward_operation_key].clone();
    bad.evidence.forward.insert(extra.clone(), selected);
    resign(&mut bad);
    assert!(audit::verify(&bad, &t).is_err());
    assert_eq!(native::budget(&h.forward, &h.registration).await, held);
}

#[tokio::test]
async fn compensation_sql_compound_final_native_read_cas_rejects_receipt_loss() {
    use axum::{Json, Router, routing::post};
    use kedgeflow::action_domain::{Lane, Selection};
    let Some(mut h) = Box::pin(sql_inverse_ready()).await else {
        return;
    };
    let (rec, c, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    commit(&h, &rec, &c, &token).await;
    h.inverse.clock.0.store(NOW + 12000, Ordering::SeqCst);
    worker(&h).recover(&c).await.unwrap();
    let b = Box::pin(export(&h)).await.unwrap();
    let l = b
        .evidence
        .inverse
        .as_ref()
        .unwrap()
        .lineage
        .as_ref()
        .unwrap();
    let receipt: Envelope = serde_json::from_slice(l.outcomes.receipts[0].as_bytes()).unwrap();
    let key = format!(
        "{}/domains/{}/paired/inverse/roots/{}/attempts/{}/receipts/{}",
        h.inverse.prefix,
        URL_SAFE_NO_PAD.encode(&c.grant.conflict_domain),
        URL_SAFE_NO_PAD.encode(&c.grant.root_id),
        URL_SAFE_NO_PAD.encode(&c.attempt_id),
        record_digest(&receipt).unwrap()
    );
    let raw = h.inverse.ledger.read_key(&key).await.unwrap().unwrap();
    let watched = STANDARD.encode(&key);
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let races = Arc::new(AtomicUsize::new(0));
    let hits = races.clone();
    let route = Router::new().route(
        "/v3/kv/txn",
        post(move |Json(v): Json<Value>| {
            let endpoint = endpoint.clone();
            let watched = watched.clone();
            let hits = hits.clone();
            async move {
                if v["compare"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|c| c["key"] == watched)
                    && hits.fetch_add(1, Ordering::SeqCst) == 0
                {
                    reqwest::Client::new()
                        .post(format!("{endpoint}/v3/kv/deleterange"))
                        .json(&json!({"key":watched}))
                        .send()
                        .await
                        .unwrap()
                        .error_for_status()
                        .unwrap();
                }
                Json(
                    reqwest::Client::new()
                        .post(format!("{endpoint}/v3/kv/txn"))
                        .json(&v)
                        .send()
                        .await
                        .unwrap()
                        .json::<Value>()
                        .await
                        .unwrap(),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, route).await.unwrap();
    });
    let ledger = EtcdLedger::new(
        reqwest::Client::new(),
        format!("http://{address}"),
        &h.inverse.prefix,
    )
    .unwrap()
    .with_clock(h.inverse.clock.clone())
    .with_action_domain(Selection {
        topology: h.topology.clone(),
        lane: Lane::Inverse,
    })
    .unwrap();
    let cfg:kedgeflow::compensation_execution::ExecutionConfig=serde_json::from_value(json!({"profile":kedgeflow::compensation_execution::PROFILE,"contract":h.contract,"forward":native::trust_value(&h.forward,&h.registration),"outcome_keys":public(19),"source_id":"spiffe://test/inverse-outcome"})).unwrap();
    h.inverse.ledger = cfg.attach(ledger).unwrap();
    assert!(Box::pin(export(&h)).await.is_err());
    assert_eq!(races.load(Ordering::SeqCst), 1);
    assert!(h.inverse.ledger.read_key(&key).await.unwrap().is_none());
    assert_eq!(audit::verify(&b, &trust(&h)).unwrap().status, "compensated");
    Box::pin(write(&h.inverse, &key, Some(&raw))).await;
    assert!(Box::pin(export(&h)).await.is_ok());
    server.abort();
}

#[tokio::test]
async fn compensation_sql_compound_allocated_export_refuses_consumed_or_missing_native_authority() {
    let Some(h) = Box::pin(sql_inverse_ready()).await else {
        return;
    };
    let rec = execution_issue(&h.inverse).await.unwrap().record;
    let g = h
        .grants()
        .verify_retained(rec.signed_grant.as_bytes())
        .unwrap()
        .grant;
    let base = format!(
        "{}/domains/{}/paired/inverse/roots/{}",
        h.inverse.prefix,
        URL_SAFE_NO_PAD.encode(&g.conflict_domain),
        URL_SAFE_NO_PAD.encode(&g.root_id)
    );
    let root = h.inverse.ledger.read_key(&base).await.unwrap().unwrap();
    let grant_key = format!("{base}/grants/{}", URL_SAFE_NO_PAD.encode(&g.gid));
    let grant = h
        .inverse
        .ledger
        .read_key(&grant_key)
        .await
        .unwrap()
        .unwrap();
    let nonce = format!("{base}/nonces/{}", URL_SAFE_NO_PAD.encode(&g.nonce));
    assert!(Box::pin(export(&h)).await.is_ok());
    for (key, retained) in [(&base, &root), (&grant_key, &grant)] {
        Box::pin(write(&h.inverse, key, None)).await;
        assert!(Box::pin(export(&h)).await.is_err());
        Box::pin(write(&h.inverse, key, Some(retained))).await;
    }
    Box::pin(write(&h.inverse, &nonce, Some(b"unretained-claim"))).await;
    assert!(Box::pin(export(&h)).await.is_err());
    Box::pin(write(&h.inverse, &nonce, None)).await;
    let mut claimed: Value = serde_json::from_slice(&root).unwrap();
    claimed["status"] = json!("claimed");
    Box::pin(write(
        &h.inverse,
        &base,
        Some(&canonical(&claimed).unwrap()),
    ))
    .await;
    assert!(Box::pin(export(&h)).await.is_err());
    Box::pin(write(&h.inverse, &base, Some(&root))).await;
    assert!(Box::pin(export(&h)).await.is_ok());
    Box::pin(check_unclaimed_forward()).await;
}
async fn check_unclaimed_forward() {
    let Some(h) = Box::pin(sql_inverse_setup_state(NOW, None, true, true)).await else {
        return;
    };
    let b = Box::pin(export(&h)).await.unwrap();
    let extra = &h.registration.saga.as_ref().unwrap().nodes[1].operation_key;
    let v = audit::verify(&b, &trust(&h)).unwrap();
    assert_eq!(v.nodes[extra], "held");
    assert_eq!(b.evidence.forward.len(), 1);
    let selected = &b.evidence.forward[&h.contract.forward_operation_key];
    let auth = &selected.authorizations.as_ref().unwrap()[extra];
    let g = trust(&h)
        .forward
        .lineage
        .grants
        .verify_retained(auth.issuance.signed_grant.as_bytes())
        .unwrap()
        .grant;
    let base = format!(
        "{}/domains/{}/paired/forward/roots/{}",
        h.forward.prefix,
        URL_SAFE_NO_PAD.encode(&g.conflict_domain),
        URL_SAFE_NO_PAD.encode(&g.root_id)
    );
    let root = h.forward.ledger.read_key(&base).await.unwrap().unwrap();
    Box::pin(write(&h.forward, &base, None)).await;
    assert!(Box::pin(export(&h)).await.is_err());
    Box::pin(write(&h.forward, &base, Some(&root))).await;
    let nonce = format!("{base}/nonces/{}", URL_SAFE_NO_PAD.encode(&g.nonce));
    Box::pin(write(&h.forward, &nonce, Some(b"hidden-forward-claim"))).await;
    assert!(Box::pin(export(&h)).await.is_err());
    Box::pin(write(&h.forward, &nonce, None)).await;
    assert!(Box::pin(export(&h)).await.is_ok());
}
