//! Audited static hierarchy: reuse native fault cases, then test graph/all-leaf replay.
use super::*;
use kedgeflow::reservation_history::{HIERARCHICAL_LEAF_PROFILE, HIERARCHICAL_PROFILE};

#[tokio::test]
async fn pre_send_refinement_after_stop_keeps_both_allowances() {
    pre_dispatch_receipt_refines_once_without_refund_after_stop_case(true).await;
}
#[tokio::test]
async fn dispatched_uncertainty_never_refunds_and_original_commit_refines() {
    uncertain_queries_hold_unknown_until_original_commit_is_reported_case(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_workers_race_one_original_refinement() {
    competing_receipt_workers_append_one_original_refinement_case(true).await;
}
#[tokio::test]
async fn shipping_offline_cli_uses_independent_hierarchy_and_observer_pins() {
    shipping_offline_cli_rejects_wrong_observer_and_namespace_case(true).await;
}
#[tokio::test]
async fn missing_corrupt_head_latest_and_older_history_fail_closed() {
    missing_head_latest_or_prior_events_never_synthesizes_audit_case(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_dispatch_receipt_cas_races_dispatch_and_stop() {
    recovery_cas_races_dispatch_and_stop_without_false_no_effect_case(true).await;
}
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shipping_recovery_cli_requires_exact_audited_hierarchy() {
    shipping_recovery_cli_refines_original_and_refuses_missing_config_case(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_slot_cost_issuance_and_history_have_one_atomic_winner() {
    super::super::hierarchical_leaf::last_slot_case(true).await;
}

#[tokio::test]
async fn complete_replay_includes_unclaimed_leaf_and_refuses_resigned_substitutions() {
    let Some((mut h, r)) = ready_profile(2, true).await else {
        return;
    };
    let first = h.issue().await.unwrap().record;
    h.f.proposal["qid"] = json!("unclaimed-second-child");
    let second = h.issue().await.unwrap().record;
    let c = claim(&h, &first, "original-hierarchical-attempt").await;
    h.ledger
        .authorize_dispatch(&c.grant, &first.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    h.ledger.stop_reservation().await.unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    worker(
        &h,
        &c,
        &first.grant_digest,
        "committed",
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(&c)
    .await
    .unwrap();
    let b = export(&h, &r, &c, &first.issuance_key).await;
    let t = trust(&h, &r);
    let v = verify(&b, &t).unwrap();
    assert_eq!(v.profile, HIERARCHICAL_PROFILE);
    assert_eq!(v.events_verified, 7);
    assert_eq!(v.budget_state, S::Committed);
    assert_eq!((v.held_forward, v.held_compensation), (1, 1));
    assert_eq!(b.authorizations.as_ref().unwrap().len(), 2);
    assert!(
        b.authorizations
            .as_ref()
            .unwrap()
            .contains_key(&second.issuance_key)
    );
    assert!(b.events.iter().all(|e| e.data.phase != "allocate"));
    Bundle::decode(&serde_json::to_vec(&b).unwrap()).unwrap();
    for variant in [
        "missing-proof",
        "extra-proof",
        "other-input",
        "other-certificate",
        "other-metadata",
        "proof-grant",
        "static-cost",
        "parent",
        "refund",
        "attempt",
        "dispatch",
        "refine",
        "fence",
        "phase",
        "profile",
        "stop",
        "capture",
    ] {
        let mut bad = b.clone();
        match variant {
            "missing-proof" => {
                bad.authorizations
                    .as_mut()
                    .unwrap()
                    .remove(&second.issuance_key);
            }
            "extra-proof" => {
                let proof = bad.authorizations.as_ref().unwrap()[&second.issuance_key].clone();
                bad.authorizations
                    .as_mut()
                    .unwrap()
                    .insert("a".repeat(64), proof);
            }
            "other-input" => {
                bad.authorizations
                    .as_mut()
                    .unwrap()
                    .get_mut(&second.issuance_key)
                    .unwrap()
                    .packet = b.authorizations.as_ref().unwrap()[&first.issuance_key]
                    .packet
                    .clone()
            }
            "other-certificate" => {
                bad.authorizations
                    .as_mut()
                    .unwrap()
                    .get_mut(&second.issuance_key)
                    .unwrap()
                    .admission = b.authorizations.as_ref().unwrap()[&first.issuance_key]
                    .admission
                    .clone()
            }
            "other-metadata" => {
                bad.authorizations
                    .as_mut()
                    .unwrap()
                    .get_mut(&second.issuance_key)
                    .unwrap()
                    .issuance
                    .binding_digest = "a".repeat(64)
            }
            "proof-grant" => {
                bad.authorizations
                    .as_mut()
                    .unwrap()
                    .get_mut(&second.issuance_key)
                    .unwrap()
                    .issuance = b.authorizations.as_ref().unwrap()[&first.issuance_key]
                    .issuance
                    .clone()
            }
            "static-cost" => {
                let id = r.hierarchy.as_ref().unwrap().grants[0].digest().unwrap();
                for e in &mut bad.events {
                    e.after.allocations.get_mut(&id).unwrap().compensation -= 1;
                }
            }
            "parent" => {
                let id = r.hierarchy.as_ref().unwrap().grants[0].digest().unwrap();
                for e in &mut bad.events {
                    if let Some(a) = e.after.allocations.get_mut(&first.issuance_key) {
                        a.parent = Some(id.clone());
                    }
                }
            }
            "refund" => {
                bad.events
                    .last_mut()
                    .unwrap()
                    .after
                    .allocations
                    .get_mut(&first.issuance_key)
                    .unwrap()
                    .compensation = 0
            }
            "attempt" => {
                bad.events
                    .iter_mut()
                    .find(|e| e.data.phase == "claim")
                    .unwrap()
                    .data
                    .attempt_id = Some("replacement".into())
            }
            "dispatch" => bad.events.retain(|e| e.data.phase != "dispatch"),
            "refine" => bad.events.retain(|e| e.data.phase != "refine"),
            "fence" => {
                bad.events
                    .iter_mut()
                    .find(|e| e.data.phase == "issue")
                    .unwrap()
                    .data
                    .fence = Some(999)
            }
            "phase" => {
                bad.events
                    .iter_mut()
                    .find(|e| e.data.phase == "issue")
                    .unwrap()
                    .data
                    .phase = "allocate".into()
            }
            "profile" => {
                bad.profile = PROFILE.into();
                bad.checkpoint.profile = PROFILE.into();
            }
            "stop" => bad.events.retain(|e| e.data.phase != "stop"),
            "capture" => bad.checkpoint.payload.captured_at = NOW - 1,
            _ => unreachable!(),
        }
        resign(&mut bad);
        assert!(verify(&bad, &t).is_err(), "{variant}");
    }
    // Schema checks raw arrays before BTreeSet decoding, including unused leaves.
    let mut raw = json!(b);
    raw["events"][0]["after"]["enrollment"]["scope"]["actions"] =
        json!([r.scope.action.id, r.scope.action.id]);
    assert!(Bundle::decode(&serde_json::to_vec(&raw).unwrap()).is_err());
    let mut wrong = trust_value(&h, &r);
    wrong["registration"]["profile"] = json!(kedgeflow::hierarchical_leaf::PROFILE);
    assert!(
        TrustConfig::decode(&serde_json::to_vec(&wrong).unwrap())
            .unwrap()
            .registration()
            .is_err()
    );
    let mut wrong = trust_value(&h, &r);
    wrong["observer_keys"] = json!(encoded(&keys(16)));
    assert!(
        TrustConfig::decode(&serde_json::to_vec(&wrong).unwrap())
            .unwrap()
            .registration()
            .is_err()
    );
    // A required original admission cannot be synthesized from the selected leaf.
    let key = format!("{}/admission-chain/{}", h.prefix, second.issuance_key);
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    reqwest::Client::new()
        .post(format!("{endpoint}/v3/kv/deleterange"))
        .json(&json!({"key":STANDARD.encode(key)}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert!(
        h.ledger
            .export_reserved_lineage(&c, &first.issuance_key, &observer(), &t)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn exhaustion_preserves_unknown_capacity_and_final_permanent_stop() {
    let Some((mut h, r)) = ready_profile(128, true).await else {
        return;
    };
    for i in 0..127 {
        h.f.proposal["qid"] = json!(format!("bounded-hierarchy-{i}"));
        let rec = h.issue().await.unwrap().record;
        claim(&h, &rec, &format!("original-{i}")).await;
    }
    let base = format!("{}/reservation-history/{}", h.prefix, r.digest().unwrap());
    let head: Value = serde_json::from_slice(
        &h.ledger
            .read_key(&format!("{base}/head"))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(head["sequence"], MAX_EVENTS - 1);
    let before = budget(&h, &r).await;
    assert_eq!(before.allocations.len(), 129);
    h.f.proposal["qid"] = json!("must-not-spend-last-free-unit");
    assert!(h.issue().await.is_err());
    assert_eq!(budget(&h, &r).await, before);
    h.ledger.stop_reservation().await.unwrap();
    h.ledger.stop_reservation().await.unwrap();
    let after = budget(&h, &r).await;
    assert!(!after.active);
    assert_eq!(before.allocations, after.allocations);
    let head: Value = serde_json::from_slice(
        &h.ledger
            .read_key(&format!("{base}/head"))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(head["sequence"], MAX_EVENTS);
    assert!(h.ledger.enroll_reservation().await.is_err());
}

#[tokio::test]
async fn audited_registration_cannot_adopt_legacy_root_or_overlap_outcome_role() {
    let example: Registration = serde_json::from_str(include_str!(
        "../../../../config/hierarchical-history.example.json"
    ))
    .unwrap();
    example.validate().unwrap();
    assert_eq!(example.profile, HIERARCHICAL_LEAF_PROFILE);
    let Some((h, mut r)) = ready_profile(1, true).await else {
        return;
    };
    assert_eq!(r.profile, HIERARCHICAL_LEAF_PROFILE);
    let rec = h.issue().await.unwrap().record;
    let c = claim(&h, &rec, "held-original").await;
    r.profile = kedgeflow::hierarchical_leaf::PROFILE.into();
    let legacy = h.ledger.clone().with_reservation(r).unwrap();
    assert!(legacy.enroll_reservation().await.is_err());
    assert!(
        legacy
            .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
            .await
            .is_err()
    );
    assert!(
        RecoveryWorker::new(
            h.ledger.clone(),
            GrantVerifier {
                keys: keys(5),
                audience: h.registration.scope.audience.clone()
            },
            Arc::new(Query {
                c,
                gd: rec.grant_digest,
                status: "unknown".into(),
                calls: Arc::new(AtomicUsize::new(0))
            }),
            "key-16".into(),
            SigningKey::from_bytes(&[16; 32]),
            "spiffe://test/outcome".into(),
            h.clock.clone()
        )
        .is_err()
    );
}

#[tokio::test]
async fn assigned_workloads_replay_original_admissions_with_reverse_fence_order() {
    use kedgeflow::hierarchical_leaf::{Assignment, Principal, sign_composite};
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let mut r = registration(&h, 2, true);
    let first_principal = Principal {
        subject: h.f.identity.subject.clone(),
        workload_id: h.f.identity.workload_id.clone(),
    };
    let mut second_principal = first_principal.clone();
    second_principal.subject.sub = "second-approved-subject".into();
    second_principal.workload_id = "spiffe://test/other-approved-agent".into();
    let hierarchy = r.hierarchy.as_mut().unwrap();
    let mut p = hierarchy.grants[0].payload.clone();
    p.principals.push(second_principal.clone());
    let root = sign_composite(p, "key-16", &SigningKey::from_bytes(&[16; 32])).unwrap();
    let parent = root.digest().unwrap();
    hierarchy.grants = vec![root];
    hierarchy.assignments = [first_principal.clone(), second_principal.clone()]
        .into_iter()
        .map(|principal| Assignment {
            principal,
            parent_grant_digest: parent.clone(),
        })
        .collect();
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let (inputs, cert) = super::super::hierarchical_leaf::prepare(&h).await;
    let (_, _, mut g) = h.f.authority(&h.f.packet());
    let envelope =
        kedgeflow::schema::verify_record(cert.as_bytes(), "certificate", &keys(6)).unwrap();
    g.certificate_digest = kedgeflow::contracts::record_digest(&envelope).unwrap();
    g.constraint_digest = envelope.payload["constraint_digest"]
        .as_str()
        .unwrap()
        .into();
    g.expires_at = envelope.payload["expires_at"].as_i64().unwrap();
    let raw =
        kedgeflow::contracts::sign_grant(&g, "key-5", &SigningKey::from_bytes(&[5; 32])).unwrap();
    let admitted = IssuanceVerifier {
        tenant: h.f.trust.tenant.clone(),
        admission_keys: keys(6),
        grants: GrantVerifier {
            keys: keys(5),
            audience: r.scope.audience.clone(),
        },
    }
    .validate_inputs(&inputs, cert.as_bytes(), &raw, &Time(NOW))
    .unwrap();
    h.ledger.reserve_fence(&admitted, &Time(NOW)).await.unwrap();
    assert_eq!(budget(&h, &r).await.allocations.len(), 1);
    h.f.identity.subject = second_principal.subject.clone();
    h.f.identity.workload_id = second_principal.workload_id.clone();
    h.f.trust.proposal_workload_id = second_principal.workload_id.clone();
    h.f.proposal["subject"] = json!(second_principal.subject);
    h.f.proposal["workload_id"] = json!(second_principal.workload_id);
    h.f.proposal["qid"] = json!("second-first-issued");
    let second = h.issue().await.unwrap().record;
    let first = super::super::hierarchical_leaf::issuer(&h)
        .issue(&h.ledger, &inputs, cert.as_bytes(), &Time(NOW))
        .await
        .unwrap()
        .record;
    assert_eq!(grant(&h, &first).fence, 1);
    assert_eq!(grant(&h, &second).fence, 2);
    let a = claim(&h, &first, "first-original").await;
    let b = claim(&h, &second, "second-original").await;
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    for (c, rec) in [(&a, &first), (&b, &second)] {
        worker(
            &h,
            c,
            &rec.grant_digest,
            "unknown",
            Arc::new(AtomicUsize::new(0)),
        )
        .recover(c)
        .await
        .unwrap();
    }
    let mut tv = trust_value(&h, &r);
    tv["lineage"]["subjects"] = json!([first_principal.subject, second_principal.subject]);
    let t = TrustConfig::decode(&serde_json::to_vec(&tv).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    for (c, rec) in [(&a, &first), (&b, &second)] {
        let bundle = h
            .ledger
            .export_reserved_lineage(c, &rec.issuance_key, &observer(), &t)
            .await
            .unwrap();
        let v = verify(&bundle, &t).unwrap();
        assert_eq!(v.budget_state, S::ProvenNoEffect);
        assert_eq!(bundle.events[1].data.fence, Some(2));
        assert_eq!(bundle.events[2].data.fence, Some(1));
        assert_eq!(bundle.authorizations.as_ref().unwrap().len(), 2);
    }
    assert_eq!(
        budget(&h, &r)
            .await
            .allocations
            .values()
            .filter(|a| a.state != S::Composite)
            .map(|a| a.forward)
            .sum::<u64>(),
        2
    );
}
