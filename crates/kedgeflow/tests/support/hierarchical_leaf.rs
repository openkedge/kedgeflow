//! Static hierarchical authority: native managed control and real etcd.
use super::*;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    coordination::{Coordination, ReservationScope, ReservationState as S},
    hierarchical_leaf::{
        Assignment, CompositePayload, Hierarchy, PROFILE as HPROFILE, Principal, scope_digest,
        sign_composite,
    },
    reserved_leaf::{Registration, verify_binding},
};
use std::collections::BTreeSet;
fn public(n: u8) -> BTreeMap<String, String> {
    keys(n)
        .iter()
        .map(|(id, k)| (id.clone(), STANDARD.encode(k.as_bytes())))
        .collect()
}
fn principal(h: &Harness) -> Principal {
    Principal {
        subject: h.f.identity.subject.clone(),
        workload_id: h.f.identity.workload_id.clone(),
    }
}
fn payload(h: &Harness, r: &Registration) -> CompositePayload {
    CompositePayload {
        tenant: r.enrollment.tenant.clone(),
        conflict_domain: r.enrollment.conflict_domain.clone(),
        root_id: r.root_id.clone(),
        root_generation: 1,
        parent_grant_digest: None,
        policy: r.policy.clone(),
        ownership_epoch: r.ownership_epoch,
        leaf_scope_digest: scope_digest(&r.scope).unwrap(),
        scope: r.enrollment.scope.clone(),
        principals: vec![principal(h)],
        forward: r.enrollment.forward,
        compensation: r.enrollment.compensation,
        valid_from: kedgeflow::clock::Clock::now_ms(h.clock.as_ref()) - 1000,
        expires_at: kedgeflow::clock::Clock::now_ms(h.clock.as_ref()) + 60000,
        execution_authority: false,
    }
}
pub(super) fn registration(h: &Harness, units: u64) -> Registration {
    registration_named(h, units, "approved-capacity-root")
}
pub(super) fn registration_named(h: &Harness, units: u64, root_id: &str) -> Registration {
    registration_named_capacity(h, units, units, root_id)
}
pub(super) fn registration_named_capacity(
    h: &Harness,
    units: u64,
    compensation: u64,
    root_id: &str,
) -> Registration {
    let mut r = super::reserved_leaf::registration(h, units);
    r.enrollment.compensation = compensation;
    r.compensation_units = compensation.min(1);
    r.root_id = root_id.into();
    r.profile = HPROFILE.into();
    r.enrollment.scope.actions.insert("planner.reserve".into());
    r.enrollment
        .scope
        .resources
        .insert("wider-planning-resource".into());
    let p = payload(h, &r);
    let root = sign_composite(p.clone(), "key-16", &SigningKey::from_bytes(&[16; 32])).unwrap();
    let mut child = p;
    child.parent_grant_digest = Some(root.digest().unwrap());
    child.scope = ReservationScope {
        actions: BTreeSet::from([r.scope.action.id.clone()]),
        resources: BTreeSet::from([r.scope.resource.id.clone()]),
    };
    let child = sign_composite(child, "key-16", &SigningKey::from_bytes(&[16; 32])).unwrap();
    let assignment = Assignment {
        principal: principal(h),
        parent_grant_digest: child.digest().unwrap(),
    };
    r.hierarchy = Some(Hierarchy {
        delegation_keys: public(16),
        grants: vec![root, child],
        assignments: vec![assignment],
    });
    r.validate().unwrap();
    r
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
fn grant(h: &Harness, record: &kedgeflow::ledger::IssuanceRecord) -> Grant {
    GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    }
    .verify_retained(record.signed_grant.as_bytes())
    .unwrap()
    .grant
}
fn c(h: &Harness, r: &Registration) -> Coordination {
    Coordination::new(h.ledger.clone(), &r.root_id).unwrap()
}
pub(super) fn issuer(h: &Harness) -> GrantAuthority {
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
pub(super) async fn prepare(
    h: &Harness,
) -> (kedgeflow::admission::VerifiedAdmissionInputs, String) {
    let packet = h.f.packet();
    let inputs =
        h.f.trust
            .verify_inputs(&h.f.identity, packet.borrowed(), &Time(NOW))
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
            &controller.prepare(&inputs, &Time(NOW)).unwrap(),
            &Time(NOW),
        )
        .await
        .unwrap()
        .record
        .signed_certificate;
    (inputs, cert)
}
#[tokio::test]
async fn hierarchical_native_child_binding_recreated_issuer_claim_and_dispatch_conserve() {
    let Some((h, r)) = ready(2).await else { return };
    let first = h.issue().await.unwrap();
    let second = h.issue().await.unwrap();
    assert!(!first.reused && second.reused);
    assert_eq!(first.record, second.record);
    let g = grant(&h, &first.record);
    assert!(g.parent_grant_digest.is_none() && g.saga_budget.is_null());
    let binding = h
        .ledger
        .retained_reservation_binding(&g, &first.record.grant_digest)
        .await
        .unwrap();
    assert_eq!(binding.profile, HPROFILE);
    let p = verify_binding(
        &serde_json::to_vec(&binding).unwrap(),
        &r,
        first.record.signed_grant.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        p.parent_grant_digest.as_deref(),
        Some(
            r.hierarchy.as_ref().unwrap().assignments[0]
                .parent_grant_digest
                .as_str()
        )
    );
    let state = c(&h, &r).status().await.unwrap();
    assert_eq!(state.allocations.len(), 3);
    assert_eq!(
        state.allocations[&first.record.issuance_key].parent,
        p.parent_grant_digest
    );
    assert!(
        state
            .allocations
            .values()
            .filter(|a| a.state == S::Composite)
            .all(|a| a.attempt_id.is_none())
    );
    let attempt = h
        .ledger
        .claim(&g, &first.record.grant_digest, "original-child")
        .await
        .unwrap();
    assert!(
        h.ledger
            .claim(&g, &first.record.grant_digest, "new-task-attempt")
            .await
            .is_err()
    );
    h.ledger
        .authorize_dispatch(&g, &first.record.grant_digest, &attempt.id)
        .await
        .unwrap();
    let held = c(&h, &r).status().await.unwrap();
    let a = &held.allocations[&first.record.issuance_key];
    assert_eq!(a.state, S::Unknown);
    assert_eq!(a.attempt_id.as_deref(), Some(attempt.id.as_str()));
    assert_eq!((a.forward, a.compensation), (1, 1));
    h.ledger.stop_reservation().await.unwrap();
    h.ledger.stop_reservation().await.unwrap();
    assert!(h.ledger.enroll_reservation().await.is_err());
    assert!(!c(&h, &r).status().await.unwrap().active);
    let historical = h
        .ledger
        .retained_reservation_binding(&g, &first.record.grant_digest)
        .await
        .unwrap();
    assert_eq!(historical.signature, binding.signature);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchical_last_slot_competitors_issue_one_child_with_atomic_capacity() {
    last_slot_case(false).await;
}
pub(super) async fn last_slot_case(audited: bool) {
    let Some((mut h, r)) = (if audited {
        super::reserved_history::ready_profile(1, true).await
    } else {
        ready(1).await
    }) else {
        return;
    };
    let mut tasks = Vec::new();
    for n in 0..8 {
        h.f.proposal["qid"] = json!(format!("hierarchical-contender-{n}"));
        let (inputs, cert) = prepare(&h).await;
        let ledger = h.ledger.clone();
        let authority = issuer(&h);
        tasks.push(tokio::spawn(async move {
            authority
                .issue(&ledger, &inputs, cert.as_bytes(), &Time(NOW))
                .await
        }));
    }
    let mut winners = Vec::new();
    for t in tasks {
        if let Ok(v) = t.await.unwrap() {
            winners.push(v);
        }
    }
    assert_eq!(winners.len(), 1);
    let state = c(&h, &r).status().await.unwrap();
    assert_eq!(state.allocations.len(), 3);
    let leaf = &state.allocations[&winners[0].record.issuance_key];
    assert_eq!((leaf.forward, leaf.compensation), (1, 1));
    assert_eq!(
        state
            .allocations
            .values()
            .filter(|a| a.state != S::Composite)
            .count(),
        1
    );
    // The original allocation is inseparable from a retained signed issuance.
    for a in state
        .allocations
        .values()
        .filter(|a| a.state != S::Composite)
    {
        assert!(
            h.ledger
                .read_key(&format!("{}/issuance/{}", h.prefix, a.operation_digest))
                .await
                .unwrap()
                .is_some()
        );
    }
    if audited {
        let base = format!("{}/reservation-history/{}", h.prefix, r.digest().unwrap());
        let head: Value = serde_json::from_slice(
            &h.ledger
                .read_key(&format!("{base}/head"))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(head["sequence"], 2);
        let event: kedgeflow::reservation_history::Event = serde_json::from_slice(
            &h.ledger
                .read_key(&format!("{base}/events/000002"))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(event.data.phase, "issue");
        assert_eq!(event.after, state);
        assert_eq!(
            event.data.grant_digest.as_deref(),
            Some(winners[0].record.grant_digest.as_str())
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchical_parallel_branches_narrow_principals_and_conserve_each_parent() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let mut r = registration(&h, 2);
    let first = principal(&h);
    let mut second = first.clone();
    second.subject.sub = "independently-admitted-specialist".into();
    let mut root = payload(&h, &r);
    root.principals.push(second.clone());
    let root = sign_composite(root, "key-16", &SigningKey::from_bytes(&[16; 32])).unwrap();
    let root_id = root.digest().unwrap();
    let mut grants = vec![root];
    let mut assignments = Vec::new();
    for who in [&first, &second] {
        let mut p = payload(&h, &r);
        p.parent_grant_digest = Some(root_id.clone());
        p.principals = vec![who.clone()];
        p.forward = 1;
        p.compensation = 1;
        p.scope = ReservationScope {
            actions: BTreeSet::from([r.scope.action.id.clone()]),
            resources: BTreeSet::from([r.scope.resource.id.clone()]),
        };
        let g = sign_composite(p, "key-16", &SigningKey::from_bytes(&[16; 32])).unwrap();
        assignments.push(Assignment {
            principal: who.clone(),
            parent_grant_digest: g.digest().unwrap(),
        });
        grants.push(g);
    }
    r.hierarchy = Some(Hierarchy {
        delegation_keys: public(16),
        grants,
        assignments,
    });
    r.validate().unwrap();
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let mut tasks = Vec::new();
    for (n, who) in [first, second].iter().enumerate() {
        h.f.identity.subject = who.subject.clone();
        h.f.proposal["subject"] = json!(who.subject);
        h.f.proposal["qid"] = json!(format!("parallel-child-{n}"));
        let (inputs, cert) = prepare(&h).await;
        let ledger = h.ledger.clone();
        let authority = issuer(&h);
        tasks.push(tokio::spawn(async move {
            // Retry only a confirmed refusal under sibling contention; every
            // call first resolves the same retained admitted-operation key.
            for _ in 0..8 {
                match authority
                    .issue(&ledger, &inputs, cert.as_bytes(), &Time(NOW))
                    .await
                {
                    Ok(v) => return v.record,
                    Err(kedgeflow::error::Error::Refused(_)) => continue,
                    Err(e) => panic!("unexpected authority uncertainty: {e}"),
                }
            }
            panic!("parallel child did not issue within the contention bound")
        }));
    }
    let mut records = Vec::new();
    for task in tasks {
        records.push(task.await.unwrap());
    }
    let state = c(&h, &r).status().await.unwrap();
    assert_eq!(state.allocations.len(), 5);
    for rec in &records {
        let g = grant(&h, rec);
        let b = h
            .ledger
            .retained_reservation_binding(&g, &rec.grant_digest)
            .await
            .unwrap();
        let a = &state.allocations[&rec.issuance_key];
        assert_eq!(a.parent, b.payload.parent_grant_digest);
        let parent = &state.allocations[a.parent.as_ref().unwrap()];
        assert_eq!((parent.forward, parent.compensation), (1, 1));
        h.ledger
            .claim(&g, &rec.grant_digest, &format!("attempt-{}", g.subject.sub))
            .await
            .unwrap();
    }
    assert_ne!(
        state.allocations[&records[0].issuance_key].parent,
        state.allocations[&records[1].issuance_key].parent
    );
    h.f.proposal["qid"] = json!("second-task-same-full-parent");
    assert!(h.issue().await.is_err());
}
#[tokio::test]
async fn hierarchical_signed_skeleton_widening_overdraw_expiry_and_profile_mismatch_refuse() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let example: Registration = serde_json::from_str(include_str!(
        "../../../../config/hierarchical-leaf.example.json"
    ))
    .unwrap();
    example.validate().unwrap();
    let good = registration(&h, 2);
    let mut bad = Vec::new();
    for (field, value) in [
        ("tenant", json!("other")),
        ("root_id", json!("other")),
        ("root_generation", json!(2)),
        ("ownership_epoch", json!(999)),
        ("leaf_scope_digest", json!("a".repeat(64))),
        ("forward", json!(3)),
        ("compensation", json!(3)),
        (
            "scope",
            json!({"actions":["outside-parent"],"resources":[h.registration.scope.resource.id]}),
        ),
        (
            "principals",
            json!([{"subject":{"iss":h.f.identity.subject.iss,"sub":"unapproved-user"},"workload_id":h.f.identity.workload_id}]),
        ),
        ("valid_from", json!(NOW - 2000)),
        ("expires_at", json!(NOW + 60001)),
        ("parent_grant_digest", json!("a".repeat(64))),
    ] {
        let mut r = good.clone();
        let hierarchy = r.hierarchy.as_mut().unwrap();
        let mut p = serde_json::to_value(&hierarchy.grants[1].payload).unwrap();
        p[field] = value;
        let p: CompositePayload = serde_json::from_value(p).unwrap();
        hierarchy.grants[1].payload = p;
        let g = &mut hierarchy.grants[1];
        let mut message = format!(
            "KedgeFlow:{}\0",
            kedgeflow::hierarchical_leaf::COMPOSITE_PROFILE
        )
        .into_bytes();
        message.extend(
            canonical(
                &json!({"profile":g.profile,"kind":g.kind,"key_id":g.key_id,"payload":g.payload}),
            )
            .unwrap(),
        );
        g.signature =
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[16; 32]).sign(&message).to_bytes());
        hierarchy.assignments[0].parent_grant_digest = hierarchy.grants[1].digest().unwrap();
        bad.push(r);
    }
    let mut r = good.clone();
    let hierarchy = r.hierarchy.as_mut().unwrap();
    hierarchy.grants.push(hierarchy.grants[0].clone());
    bad.push(r);
    let mut r = good.clone();
    r.hierarchy.as_mut().unwrap().assignments.push(Assignment {
        principal: principal(&h),
        parent_grant_digest: "f".repeat(64),
    });
    bad.push(r);
    let mut r = good.clone();
    r.profile = kedgeflow::reserved_leaf::PROFILE.into();
    bad.push(r);
    let mut r = good.clone();
    r.hierarchy = None;
    bad.push(r);
    let mut r = good.clone();
    r.hierarchy.as_mut().unwrap().grants[1].signature = "A".repeat(86);
    bad.push(r);
    let mut r = good.clone();
    r.hierarchy.as_mut().unwrap().delegation_keys = public(5);
    bad.push(r);
    let mut deep = good.clone();
    let mut lineage = Vec::new();
    let mut parent = None;
    for _ in 0..8 {
        let mut p = payload(&h, &deep);
        p.parent_grant_digest = parent;
        let g = sign_composite(p, "key-16", &SigningKey::from_bytes(&[16; 32])).unwrap();
        parent = Some(g.digest().unwrap());
        lineage.push(g);
    }
    deep.hierarchy.as_mut().unwrap().grants = lineage;
    deep.hierarchy.as_mut().unwrap().assignments[0].parent_grant_digest = parent.unwrap();
    bad.push(deep);
    for r in bad {
        assert!(r.validate().is_err());
    }
    let original = &good.hierarchy.as_ref().unwrap().grants[0];
    let mut reordered = json!(original);
    reordered["payload"]["scope"]["resources"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(
        kedgeflow::hierarchical_leaf::CompositeGrant::decode(
            &serde_json::to_vec(&reordered).unwrap()
        )
        .is_err()
    );
    let mut config = json!(good);
    config["hierarchy"]["grants"][0] = reordered;
    assert!(serde_json::from_value::<Registration>(config).is_err());
    let duplicate =
        serde_json::to_string(original)
            .unwrap()
            .replacen("{", "{\"kind\":\"composite_grant\",", 1);
    assert!(
        serde_json::from_str::<kedgeflow::hierarchical_leaf::CompositeGrant>(&duplicate).is_err()
    );
    assert!(kedgeflow::hierarchical_leaf::CompositeGrant::decode(duplicate.as_bytes()).is_err());
    let mut raw = json!(good);
    raw["hierarchy"]["grants"][0]["payload"]["scope"]["resources"] =
        json!(["duplicate", "duplicate"]);
    assert!(serde_json::from_value::<Registration>(raw).is_err());
    let mut legacy = super::reserved_leaf::registration(&h, 1);
    let raw = json!(legacy);
    assert!(raw.get("hierarchy").is_none());
    legacy.profile = HPROFILE.into();
    assert!(legacy.validate().is_err());
    let mut raw = json!(super::reserved_leaf::registration(&h, 1));
    raw["hierarchy"] = Value::Null;
    assert!(serde_json::from_value::<Registration>(raw).is_err());
}
#[tokio::test]
async fn hierarchical_binding_offline_semantics_and_frozen_grant_reinterpretation_refuse() {
    let Some((h, r)) = ready(1).await else { return };
    let rec = h.issue().await.unwrap().record;
    let g = grant(&h, &rec);
    let b = h
        .ledger
        .retained_reservation_binding(&g, &rec.grant_digest)
        .await
        .unwrap();
    for (field, value) in [
        ("parent_grant_digest", json!("a".repeat(64))),
        ("operation_key", json!("b".repeat(64))),
        ("allocation_digest", json!("c".repeat(64))),
        ("certificate_digest", json!("d".repeat(64))),
    ] {
        let mut v = json!(b);
        v["payload"][field] = value;
        let mut bytes = format!("KedgeFlow:{HPROFILE}\0").into_bytes();
        bytes.extend(canonical(&json!({"profile":v["profile"],"kind":v["kind"],"key_id":v["key_id"],"payload":v["payload"]})).unwrap());
        v["signature"] =
            json!(URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[5; 32]).sign(&bytes).to_bytes()));
        assert!(
            verify_binding(
                &serde_json::to_vec(&v).unwrap(),
                &r,
                rec.signed_grant.as_bytes()
            )
            .is_err()
        );
    }
    let mut changed = g.clone();
    changed.parent_grant_digest = b.payload.parent_grant_digest.clone();
    let signed =
        kedgeflow::contracts::sign_grant(&changed, "key-5", &SigningKey::from_bytes(&[5; 32]))
            .unwrap();
    assert!(
        GrantVerifier {
            keys: keys(5),
            audience: r.scope.audience.clone()
        }
        .verify_retained(&signed)
        .is_err()
    );
    for composite in &r.hierarchy.as_ref().unwrap().grants {
        assert!(
            GrantVerifier {
                keys: keys(16),
                audience: r.scope.audience.clone()
            }
            .verify_retained(&serde_json::to_vec(composite).unwrap())
            .is_err()
        );
    }
    let mut v = json!(b);
    v["payload"]
        .as_object_mut()
        .unwrap()
        .remove("parent_grant_digest");
    assert!(
        verify_binding(
            &serde_json::to_vec(&v).unwrap(),
            &r,
            rec.signed_grant.as_bytes()
        )
        .is_err()
    );
    let mut v = json!(b);
    v["payload"]["parent_grant_digest"] = Value::Null;
    assert!(
        verify_binding(
            &serde_json::to_vec(&v).unwrap(),
            &r,
            rec.signed_grant.as_bytes()
        )
        .is_err()
    );
    let mut legacy = r.clone();
    legacy.hierarchy = None;
    legacy.profile = kedgeflow::reserved_leaf::PROFILE.into();
    legacy.enrollment.scope = ReservationScope {
        actions: BTreeSet::from([r.scope.action.id.clone()]),
        resources: BTreeSet::from([r.scope.resource.id.clone()]),
    };
    assert!(
        verify_binding(
            &serde_json::to_vec(&b).unwrap(),
            &legacy,
            rec.signed_grant.as_bytes()
        )
        .is_err()
    );
}
#[tokio::test]
async fn hierarchical_fence_alone_and_raw_issuance_have_no_capacity_or_execution() {
    let Some((h, r)) = ready(1).await else { return };
    let before = c(&h, &r).status().await.unwrap();
    let (inputs, cert) = prepare(&h).await;
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
    let fence = h.ledger.reserve_fence(&admitted, &Time(NOW)).await.unwrap();
    assert_eq!(before, c(&h, &r).status().await.unwrap());
    assert!(
        h.ledger
            .issue_admitted(&admitted, &Time(NOW))
            .await
            .is_err()
    );
    assert!(
        h.ledger
            .issue_allocated(&admitted, &fence, &Time(NOW))
            .await
            .is_err()
    );
    assert!(h.ledger.issue(&g, &"a".repeat(64)).await.is_err());
    assert_eq!(before, c(&h, &r).status().await.unwrap());
    let record = h.issue().await.unwrap().record;
    let actual = grant(&h, &record);
    assert_eq!(actual.fence, fence.fence());
    assert_eq!(c(&h, &r).status().await.unwrap().allocations.len(), 3);
    let mut next = actual.clone();
    next.root_generation = 2;
    next.fence += 1;
    assert!(
        h.ledger
            .replace(&actual, &next, &"a".repeat(64))
            .await
            .is_err()
    );
    let coord = c(&h, &r);
    let parent = r.hierarchy.as_ref().unwrap().assignments[0]
        .parent_grant_digest
        .clone();
    assert!(
        coord
            .allocate(
                &"a".repeat(64),
                Some(&parent),
                r.enrollment.scope.clone(),
                1,
                1
            )
            .await
            .is_err()
    );
    assert!(coord.consume(&parent, "parent-attempt").await.is_err());
    assert!(coord.stop().await.is_err());
}
#[tokio::test]
async fn hierarchical_omitted_config_wrong_parent_and_unassigned_identity_refuse() {
    let Some((mut h, r)) = ready(2).await else {
        return;
    };
    let rec = h.issue().await.unwrap().record;
    let g = grant(&h, &rec);
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
            .claim(&g, &rec.grant_digest, "omitted")
            .await
            .is_err()
    );
    let mut changed = r.clone();
    let hcy = changed.hierarchy.as_mut().unwrap();
    hcy.assignments[0].parent_grant_digest = hcy.grants[0].digest().unwrap();
    changed.validate().unwrap();
    let different = configured.clone().with_reservation(changed).unwrap();
    assert!(
        different
            .claim(&g, &rec.grant_digest, "switched-parent")
            .await
            .is_err()
    );
    h.ledger = configured;
    h.f.identity.subject.sub = "unassigned-user".into();
    h.f.proposal["subject"] = json!(h.f.identity.subject);
    h.f.proposal["qid"] = json!("unassigned-operation");
    assert!(h.issue().await.is_err());
    assert_eq!(c(&h, &r).status().await.unwrap().allocations.len(), 3);
}
async fn write_key(h: &Harness, key: &str, value: Option<&[u8]>) {
    assert!(key.starts_with(&format!("{}/", h.prefix)));
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
fn composite_key(h: &Harness, r: &Registration, id: &str) -> String {
    format!(
        "{}/hierarchical-composites/{}/{id}",
        h.prefix,
        URL_SAFE_NO_PAD.encode(&r.root_id)
    )
}
#[tokio::test]
async fn hierarchical_missing_original_records_and_changed_composite_or_leaf_state_refuse() {
    let Some((h, r)) = ready(2).await else { return };
    let rec = h.issue().await.unwrap().record;
    let g = grant(&h, &rec);
    let parent = &r.hierarchy.as_ref().unwrap().grants[0];
    let key = composite_key(&h, &r, &parent.digest().unwrap());
    let original = h.ledger.read_key(&key).await.unwrap().unwrap();
    write_key(&h, &key, None).await;
    assert!(h.issue().await.is_err());
    assert!(
        h.ledger
            .claim(&g, &rec.grant_digest, "missing-parent")
            .await
            .is_err()
    );
    write_key(&h, &key, Some(b"substituted")).await;
    assert!(
        h.ledger
            .claim(&g, &rec.grant_digest, "corrupt-parent")
            .await
            .is_err()
    );
    write_key(&h, &key, Some(&original)).await;
    let root = format!(
        "{}/coordination/{}",
        h.prefix,
        kedgeflow::contracts::digest("coordination-root", &json!(r.root_id)).unwrap()
    );
    let before = h.ledger.read_key(&root).await.unwrap().unwrap();
    let mut v: Value = serde_json::from_slice(&before).unwrap();
    v["allocations"][parent.digest().unwrap()]["state"] = json!("allocated");
    write_key(&h, &root, Some(&serde_json::to_vec(&v).unwrap())).await;
    assert!(
        h.ledger
            .claim(&g, &rec.grant_digest, "executable-parent")
            .await
            .is_err()
    );
    let mut v: Value = serde_json::from_slice(&before).unwrap();
    v["allocations"][&rec.issuance_key]["compensation"] = json!(0);
    write_key(&h, &root, Some(&serde_json::to_vec(&v).unwrap())).await;
    assert!(
        h.ledger
            .claim(&g, &rec.grant_digest, "refund")
            .await
            .is_err()
    );
    write_key(&h, &root, Some(&before)).await;
    h.ledger
        .claim(&g, &rec.grant_digest, "native-original")
        .await
        .unwrap();
    write_key(&h, &key, None).await;
    assert!(
        h.ledger
            .authorize_dispatch(&g, &rec.grant_digest, "native-original")
            .await
            .is_err()
    );
    write_key(&h, &key, Some(&original)).await;
    h.ledger
        .authorize_dispatch(&g, &rec.grant_digest, "native-original")
        .await
        .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchical_stop_races_fence_atomic_cost_issuance_claim_and_dispatch() {
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
        if phase == "dispatch" {
            let rec = issued.as_ref().unwrap();
            direct
                .claim(&grant(&h, rec), &rec.grant_digest, "original-race")
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
                        .claim(&grant(&h, &rec), &rec.grant_digest, "raced-child")
                        .await
                        .map(|_| ())
                }
                "dispatch" => {
                    let rec = issued.unwrap();
                    h.ledger
                        .authorize_dispatch(&grant(&h, &rec), &rec.grant_digest, "original-race")
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
        let state = Coordination::new(direct, &r.root_id)
            .unwrap()
            .status()
            .await
            .unwrap();
        assert!(!state.active);
        let leaves: Vec<_> = state
            .allocations
            .values()
            .filter(|a| a.state != S::Composite)
            .collect();
        match phase {
            "fence-allocation" | "issuance" => assert!(
                leaves.is_empty(),
                "no issued child may lack its atomic cost or vice versa"
            ),
            "attempts" => assert_eq!(leaves[0].state, S::Allocated),
            _ => assert_eq!(leaves[0].state, S::Unknown),
        }
        drop(proxy);
    }
}
#[tokio::test]
async fn hierarchical_native_outcomes_keep_unknown_and_never_refund_children() {
    use async_trait::async_trait;
    use kedgeflow::{
        ledger::{AuthoritativeObservation, OutcomeQuerier},
        recovery::{Candidate, ExecutionRecord, RecoveryWorker},
    };
    use std::sync::atomic::AtomicUsize;
    struct Query(Arc<AtomicUsize>);
    #[async_trait]
    impl OutcomeQuerier for Query {
        async fn query(&self, _: &str) -> kedgeflow::error::Result<AuthoritativeObservation> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(kedgeflow::error::Error::Unavailable(
                "no blind target retry".into(),
            ))
        }
    }
    let Some((mut h, r)) = ready(1).await else {
        return;
    };
    let rec = h.issue().await.unwrap().record;
    let g = grant(&h, &rec);
    let candidate = Candidate {
        grant: g.clone(),
        attempt_id: "original-unknown-child".into(),
    };
    h.ledger
        .claim_recorded(
            &g,
            &rec.grant_digest,
            &candidate.attempt_id,
            &ExecutionRecord {
                signed_grant: rec.signed_grant.clone(),
                tool: "node_drain".into(),
                parameters: h.f.proposal["parameters"].clone(),
            },
        )
        .await
        .unwrap();
    h.ledger.stop_reservation().await.unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    let before = c(&h, &r).status().await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = RecoveryWorker::new(
        h.ledger.clone(),
        GrantVerifier {
            keys: keys(5),
            audience: r.scope.audience.clone(),
        },
        Arc::new(Query(calls.clone())),
        "key-14".into(),
        SigningKey::from_bytes(&[14; 32]),
        "spiffe://test/outcome".into(),
        h.clock.clone(),
    )
    .unwrap();
    let head = worker.recover(&candidate).await.unwrap();
    assert_eq!(head.state, "not_dispatched");
    assert_eq!(
        head.receipt_digest,
        worker.recover(&candidate).await.unwrap().receipt_digest
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(before, c(&h, &r).status().await.unwrap());
    assert_eq!(before.allocations[&rec.issuance_key].state, S::Unknown);
    assert!(
        c(&h, &r)
            .observe(&rec.issuance_key, &candidate.attempt_id, S::ProvenNoEffect)
            .await
            .is_err()
    );
    assert!(
        h.ledger
            .export_lineage(&candidate, &rec.issuance_key)
            .await
            .is_err()
    );
    h.f.proposal["qid"] = json!("new-task-after-known-no-send");
    assert!(h.issue().await.is_err());
}
#[tokio::test]
async fn hierarchical_parent_keys_cannot_replace_input_or_admission_roles() {
    for role in [4u8, 6] {
        let Some(mut h) = Harness::new().await else {
            return;
        };
        let mut r = registration(&h, 1);
        let hierarchy = r.hierarchy.as_mut().unwrap();
        hierarchy.delegation_keys = public(role);
        let mut root = hierarchy.grants[0].payload.clone();
        root.parent_grant_digest = None;
        let root = sign_composite(
            root,
            &format!("key-{role}"),
            &SigningKey::from_bytes(&[role; 32]),
        )
        .unwrap();
        let mut child = hierarchy.grants[1].payload.clone();
        child.parent_grant_digest = Some(root.digest().unwrap());
        let child = sign_composite(
            child,
            &format!("key-{role}"),
            &SigningKey::from_bytes(&[role; 32]),
        )
        .unwrap();
        hierarchy.assignments[0].parent_grant_digest = child.digest().unwrap();
        hierarchy.grants = vec![root, child];
        r.validate().unwrap();
        h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
        h.ledger.enroll_reservation().await.unwrap();
        let installed = h.bootstrap().await;
        assert!(h.post(&h.ack(&installed), true).await.0.is_success());
        assert!(h.issue().await.is_err());
        assert_eq!(c(&h, &r).status().await.unwrap().allocations.len(), 2);
    }
}
#[tokio::test]
async fn hierarchical_parent_validity_contains_every_fresh_leaf_or_issuance_refuses() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let mut r = registration(&h, 1);
    let hierarchy = r.hierarchy.as_mut().unwrap();
    let mut root = hierarchy.grants[0].payload.clone();
    root.expires_at = NOW + 1000;
    let root = sign_composite(root, "key-16", &SigningKey::from_bytes(&[16; 32])).unwrap();
    let mut child = hierarchy.grants[1].payload.clone();
    child.parent_grant_digest = Some(root.digest().unwrap());
    child.expires_at = NOW + 1000;
    let child = sign_composite(child, "key-16", &SigningKey::from_bytes(&[16; 32])).unwrap();
    hierarchy.assignments[0].parent_grant_digest = child.digest().unwrap();
    hierarchy.grants = vec![root, child];
    h.ledger = h.ledger.clone().with_reservation(r.clone()).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    assert!(h.issue().await.is_err());
    assert_eq!(c(&h, &r).status().await.unwrap().allocations.len(), 2);
}
#[tokio::test]
async fn hierarchical_shipping_offline_cli_verifies_compound_profile_without_live_permission() {
    let Some((h, r)) = ready(1).await else { return };
    let rec = h.issue().await.unwrap().record;
    let g = grant(&h, &rec);
    let b = h
        .ledger
        .retained_reservation_binding(&g, &rec.grant_digest)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let registration = dir.path().join("registration.json");
    let binding = dir.path().join("binding.json");
    let grant = dir.path().join("grant.json");
    std::fs::write(&registration, serde_json::to_vec(&r).unwrap()).unwrap();
    std::fs::write(&binding, serde_json::to_vec(&b).unwrap()).unwrap();
    std::fs::write(&grant, rec.signed_grant).unwrap();
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-reservation"))
            .arg("--registration")
            .arg(&registration)
            .arg("--grant")
            .arg(&grant)
            .arg("--binding")
            .arg(&binding)
            .output()
            .unwrap()
    };
    let out = run();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["profile"], HPROFILE);
    assert_eq!(value["execution_authority"], false);
    assert_eq!(value["live_budget_verified"], false);
    assert_eq!(
        value["historical_issuer_statement"]["parent_grant_digest"],
        json!(b.payload.parent_grant_digest)
    );
    let mut wrong = r;
    wrong.hierarchy.as_mut().unwrap().delegation_keys = public(15);
    std::fs::write(&registration, serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(!run().status.success());
}
