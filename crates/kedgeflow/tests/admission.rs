include!("support/admission_fixture.rs");

#[test]
fn exact_signed_chain_can_supply_certificate_constrained_issuance() {
    let f = Fixture::new();
    let p = f.packet();
    let inputs = f
        .trust
        .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
        .unwrap();
    let (verifier, cert, mut grant) = f.authority(&p);
    let cert = signed("certificate", cert, 3);
    grant.certificate_digest = record_hash(&cert);
    let raw = sign_grant(&grant, "key-5", &SigningKey::from_bytes(&[5; 32])).unwrap();
    verifier
        .validate_inputs(&inputs, &cert, &raw, &CLOCK)
        .unwrap();
    assert!(
        verifier
            .validate_inputs(&inputs, &cert, &raw, &Time(NOW + 30000))
            .is_err()
    );
}

#[test]
fn authentic_signatures_do_not_make_wrong_identity_parameters_or_registry_current() {
    for (field, value) in [
        ("/tenant", json!("other-tenant")),
        ("/subject/sub", json!("other-subject")),
        ("/workload_id", json!("spiffe://test/other")),
        ("/delegation/dpop_jkt", json!("x".repeat(43))),
        ("/action/digest", json!("a".repeat(64))),
        ("/parameters/expected_version", json!(242)),
        ("/created_at", json!(NOW + 1)),
        ("/baseline_state/0/expires_at", json!(NOW)),
        ("/workflow", json!({})),
    ] {
        let mut f = Fixture::new();
        *f.proposal.pointer_mut(field).unwrap() = value;
        assert!(
            f.trust
                .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
                .is_err(),
            "{field}"
        );
    }
    let mut f = Fixture::new();
    f.proposal["parameters"]["unexpected"] = json!(true);
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
    let mut f = Fixture::new();
    f.descriptor["ownership_epoch"] = json!(6);
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
    let mut f = Fixture::new();
    f.identity.scopes.clear();
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
}

#[test]
fn stale_missing_unapproved_or_violated_evidence_cannot_supply_inputs() {
    for (field, value) in [
        ("/provider_id", json!("unregistered-provider")),
        ("/provider_version", json!("2.0")),
        ("/state_digest", json!("a".repeat(64))),
        ("/state_scope/0/incarnation", json!("recreated")),
        ("/question_ref/digest", json!("a".repeat(64))),
        ("/result_schema/digest", json!("a".repeat(64))),
        ("/result/available_slots", json!(0)),
        ("/result/version", json!("242")),
        ("/observed_at", json!(NOW + 1)),
        ("/observed_at", json!(NOW - 60000)),
        ("/expires_at", json!(NOW)),
    ] {
        let mut f = Fixture::new();
        *f.evidence.pointer_mut(field).unwrap() = value;
        assert!(
            f.trust
                .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
                .is_err(),
            "{field}"
        );
    }
    let mut f = Fixture::new();
    f.evidence["result"]["extra"] = json!(true);
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
    let f = Fixture::new();
    let mut p = f.packet();
    p.evidence.clear();
    assert!(
        f.trust
            .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
            .is_err()
    );
    let mut p = f.packet();
    p.evidence.push(p.evidence[0].clone());
    assert!(
        f.trust
            .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
            .is_err()
    );
    let mut p = f.packet();
    p.evidence[0] = signed("evidence", f.evidence.clone(), 1);
    assert!(
        f.trust
            .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
            .is_err()
    );
}

#[test]
fn valid_manifest_signature_cannot_substitute_a_witness_or_policy() {
    for field in ["/witnesses/0/witness/digest", "/policy/digest"] {
        let f = Fixture::new();
        let mut p = f.packet();
        let mut manifest: Value =
            serde_json::from_slice::<Value>(&p.manifest).unwrap()["payload"].clone();
        *manifest.pointer_mut(field).unwrap() = json!("a".repeat(64));
        p.manifest = signed("manifest", manifest, 3);
        assert!(
            f.trust
                .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
                .is_err()
        );
    }
}

#[test]
fn certificate_and_grant_must_match_the_independently_verified_chain() {
    for field in [
        "/constraints/resources/0/incarnation",
        "/constraints/parameters_digest",
        "/discharges/0/witness_refs/0/digest",
    ] {
        let f = Fixture::new();
        let p = f.packet();
        let inputs = f
            .trust
            .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
            .unwrap();
        let (verifier, mut cert, mut grant) = f.authority(&p);
        *cert.pointer_mut(field).unwrap() = json!(if field.contains("incarnation") {
            "recreated".to_owned()
        } else {
            "c".repeat(64)
        });
        cert["constraint_digest"] = json!(digest("constraints", &cert["constraints"]).unwrap());
        grant.resources = serde_json::from_value(cert["constraints"]["resources"].clone()).unwrap();
        grant.parameters_digest = cert["constraints"]["parameters_digest"]
            .as_str()
            .unwrap()
            .into();
        grant.constraint_digest = cert["constraint_digest"].as_str().unwrap().into();
        let cert = signed("certificate", cert, 3);
        grant.certificate_digest = record_hash(&cert);
        let raw = sign_grant(&grant, "key-5", &SigningKey::from_bytes(&[5; 32])).unwrap();
        assert!(
            verifier
                .validate_inputs(&inputs, &cert, &raw, &CLOCK)
                .is_err()
        );
    }
}

#[test]
fn registered_schemas_are_closed_and_external_resolution_is_disabled() {
    assert!(ClosedObjectSchema::new(&json!({"type":"object"})).is_err());
    for uri in ["https://127.0.0.1:1/schema", "file:///etc/passwd"] {
        assert!(ClosedObjectSchema::new(&json!({"type":"object","additionalProperties":false,"properties":{"x":{"$ref":uri}}})).is_err());
    }
    let f = Fixture::new();
    let raw = signed("evidence", json!({"wid":"only-id"}), 4);
    assert!(verify_record(&raw, "evidence", &keys(4)).is_err());
    let mut p = f.proposal.clone();
    p.as_object_mut().unwrap().remove("workflow");
    assert!(verify_record(&signed("proposal", p, 1), "proposal", &keys(1)).is_err());
}

#[test]
fn evidence_results_use_ternary_server_selected_comparisons() {
    let p = EvidencePredicate::IntegerAtLeast {
        field: "available".into(),
        minimum: 2,
    };
    assert_eq!(
        p.evaluate(&json!({"available":2})),
        EvidenceVerdict::Satisfied
    );
    assert_eq!(
        p.evaluate(&json!({"available":1,"satisfied":true})),
        EvidenceVerdict::Violated
    );
    assert_eq!(
        p.evaluate(&json!({"available":"2"})),
        EvidenceVerdict::Unknown
    );
    assert_eq!(p.evaluate(&json!({})), EvidenceVerdict::Unknown);
}

#[test]
fn pinned_rust_schema_accepts_all_thirteen_unchanged_signed_vectors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let registry: Value =
        serde_json::from_slice(&std::fs::read(root.join("public-test-keys.json")).unwrap())
            .unwrap();
    let kinds: Value =
        serde_json::from_slice(&std::fs::read(root.join("fixture-digests.json")).unwrap()).unwrap();
    assert_eq!(kinds.as_object().unwrap().len(), 13);
    for kind in kinds.as_object().unwrap().keys() {
        let raw = std::fs::read(root.join(format!("{kind}.json"))).unwrap();
        let envelope: Envelope = serde_json::from_slice(&raw).unwrap();
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(registry[&envelope.key_id]["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let keys = BTreeMap::from([(
            envelope.key_id,
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap(),
        )]);
        verify_record(&raw, kind, &keys).unwrap();
    }
}

#[tokio::test]
async fn verified_chain_issues_and_consumes_one_real_etcd_allowance() {
    use kedgeflow::{
        error::Error,
        ledger::{AuthorityLedger, EtcdLedger},
    };
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            assert_ne!(
                std::env::var("KF_REQUIRE_ETCD").as_deref(),
                Ok("1"),
                "required etcd endpoint missing"
            );
            eprintln!("SKIP admission integration: ETCD_ENDPOINT absent");
            return;
        }
    };
    let f = Fixture::new();
    let p = f.packet();
    let inputs = f
        .trust
        .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
        .unwrap();
    let (verifier, cert, mut grant) = f.authority(&p);
    let cert = signed("certificate", cert, 3);
    grant.certificate_digest = record_hash(&cert);
    let raw = sign_grant(&grant, "key-5", &SigningKey::from_bytes(&[5; 32])).unwrap();
    let admitted = verifier
        .validate_inputs(&inputs, &cert, &raw, &CLOCK)
        .unwrap();
    let namespace = format!(
        "/kf-chain-tests/{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let ledger = EtcdLedger::new(
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        endpoint,
        namespace,
    )
    .unwrap();
    ledger.publish_policy(&grant).await.unwrap();
    let issued = ledger.issue_admitted(&admitted, &CLOCK).await.unwrap();
    assert!(!issued.reused);
    let verified = verifier
        .grants
        .verify(issued.record.signed_grant.as_bytes(), NOW)
        .unwrap();
    let attempt = ledger
        .claim(&verified.grant, &verified.digest, "chain-attempt")
        .await
        .unwrap();
    let reused = ledger.issue_admitted(&admitted, &CLOCK).await.unwrap();
    assert!(reused.reused);
    assert_eq!(issued.record, reused.record);
    assert!(matches!(
        ledger
            .claim(&verified.grant, &verified.digest, "duplicate-attempt")
            .await,
        Err(Error::NonceConsumed)
    ));
    assert_eq!(
        ledger
            .status(&verified.grant, "chain-attempt")
            .await
            .unwrap(),
        attempt
    );
}

const LEAF_PERMIT: &str = r#"permit(principal, action == KedgeFlow::Action::"admit", resource)
when { context.tenant == "tenant-42" && context.workload_id == "spiffe://test/agent"
       && context.obligation_ids.contains("capacity") && context.ownership_epoch == 5 };"#;

fn cedar_fixture(source: &str) -> (Fixture, CedarPolicyDefinition) {
    let mut f = Fixture::new();
    let definition = CedarPolicyDefinition {
        tenant: f.trust.tenant.clone(),
        policy_id: f.trust.policy.id.clone(),
        cedar: source.into(),
        obligation_manifest_digest: f.trust.obligation_manifest_digest.clone(),
        max_certificate_lifetime_ms: 5000,
    };
    f.trust.policy = definition.reference(7).unwrap();
    (f, definition)
}

fn controller(f: &Fixture, definition: CedarPolicyDefinition, key: u8) -> AdmissionController {
    AdmissionController::new(
        CedarAdmissionPolicy::new(definition, f.trust.policy.clone()).unwrap(),
        format!("key-{key}"),
        SigningKey::from_bytes(&[key; 32]),
    )
    .unwrap()
}

#[test]
fn cedar_registration_requires_exact_pin_and_strict_leaf_schema() {
    for source in [
        "permit(broken);",
        "permit(principal,action,resource) when { context.agent_says_ok };",
        "permit(principal,action,resource) when { context.policy_epoch == true };",
        "permit(principal == ?principal,action,resource);",
    ] {
        let (f, definition) = cedar_fixture(source);
        assert!(
            CedarAdmissionPolicy::new(definition, f.trust.policy).is_err(),
            "{source}"
        );
    }
    let (f, mut definition) = cedar_fixture(LEAF_PERMIT);
    definition.cedar = "permit(principal,action,resource);".into();
    assert!(CedarAdmissionPolicy::new(definition, f.trust.policy).is_err());
    let (f, mut definition) = cedar_fixture(LEAF_PERMIT);
    definition.max_certificate_lifetime_ms = 0;
    let pin = definition.reference(7).unwrap();
    assert!(CedarAdmissionPolicy::new(definition, pin).is_err());
    assert!(CedarAdmissionPolicy::new(cedar_fixture(LEAF_PERMIT).1, f.trust.policy).is_ok());
}

#[test]
fn cedar_default_deny_forbid_and_verified_context_gate_certificate_production() {
    for (source, allowed) in [
        (LEAF_PERMIT.to_owned(), true),
        (String::new(), false),
        (
            format!("{LEAF_PERMIT}\nforbid(principal,action,resource);"),
            false,
        ),
        (
            r#"permit(principal,action,resource) when { context.tenant == "other-tenant" };"#
                .into(),
            false,
        ),
        (
            r#"permit(principal,action,resource) when { context.subject_id == "other-user" };"#
                .into(),
            false,
        ),
    ] {
        let (f, definition) = cedar_fixture(&source);
        let inputs = f
            .trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .unwrap();
        assert_eq!(
            controller(&f, definition, 6)
                .prepare(&inputs, &CLOCK)
                .is_ok(),
            allowed,
            "{source}"
        );
    }
}

#[test]
fn cedar_evaluation_error_denies_even_when_another_policy_permits() {
    let source = format!(
        "{LEAF_PERMIT}\npermit(principal,action,resource) when {{ 9223372036854775807 + context.now_ms > 0 }};"
    );
    let (f, definition) = cedar_fixture(&source);
    let inputs = f
        .trust
        .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
        .unwrap();
    let error = controller(&f, definition, 6)
        .prepare(&inputs, &CLOCK)
        .err()
        .unwrap();
    assert!(error.to_string().contains("evaluation errors"));
}

#[test]
fn registered_obligations_bind_comparisons_keys_and_freshness() {
    for change in 0..4 {
        let mut f = Fixture::new();
        let r = f.trust.evidence.get_mut("capacity").unwrap();
        match change {
            0 => {
                r.predicates = vec![EvidencePredicate::BooleanEquals {
                    field: "satisfied".into(),
                    expected: true,
                }]
            }
            1 => r.keys = keys(8),
            2 => r.max_age_ms += 1,
            3 => r.obligation.predicate_digest = "a".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            f.trust
                .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
                .is_err()
        );
    }
    let mut f = Fixture::new();
    f.trust
        .evidence
        .get_mut("capacity")
        .unwrap()
        .obligation
        .predicate_digest = "a".repeat(64);
    // Publishing a new manifest pin alone cannot hide an incorrect predicate pin.
    f.trust.obligation_manifest_digest = f.trust.registered_obligations_digest().unwrap();
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
}

#[test]
fn producer_refuses_expired_inputs_stale_policy_and_shared_input_role_keys() {
    let (f, definition) = cedar_fixture(LEAF_PERMIT);
    let inputs = f
        .trust
        .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
        .unwrap();
    for key in 1..=4 {
        assert!(
            controller(&f, definition.clone(), key)
                .prepare(&inputs, &CLOCK)
                .is_err()
        );
    }
    let c = controller(&f, definition.clone(), 6);
    assert!(c.prepare(&inputs, &Time(NOW - 1)).is_err());
    assert!(c.prepare(&inputs, &Time(NOW + 30000)).is_err());
    let mut stale = definition.clone();
    stale.tenant = "other-tenant".into();
    let installed = stale.reference(7).unwrap();
    let wrong_tenant = AdmissionController::new(
        CedarAdmissionPolicy::new(stale, installed).unwrap(),
        "key-6".into(),
        SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    assert!(wrong_tenant.prepare(&inputs, &CLOCK).is_err());
    let other_policy = AdmissionController::new(
        CedarAdmissionPolicy::new(definition.clone(), definition.reference(8).unwrap()).unwrap(),
        "key-6".into(),
        SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    assert!(other_policy.prepare(&inputs, &CLOCK).is_err());
}

async fn admission_ledger(label: &str) -> Option<kedgeflow::ledger::EtcdLedger> {
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            assert_ne!(
                std::env::var("KF_REQUIRE_ETCD").as_deref(),
                Ok("1"),
                "required etcd endpoint missing"
            );
            eprintln!("SKIP Cedar admission integration: ETCD_ENDPOINT absent");
            return None;
        }
    };
    let namespace = format!(
        "/kf-cedar-tests/{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    Some(
        kedgeflow::ledger::EtcdLedger::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint,
            namespace,
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn certificate_validity_intersects_freshness_at_the_persistence_boundary() {
    let (f, definition) = cedar_fixture(LEAF_PERMIT);
    let last_valid = Time(NOW + 29999);
    let inputs = f
        .trust
        .verify_inputs(&f.identity, f.packet().borrowed(), &last_valid)
        .unwrap();
    let prepared = controller(&f, definition, 6)
        .prepare(&inputs, &last_valid)
        .unwrap();
    // The 5-second policy TTL is capped by the final millisecond of evidence
    // freshness. Refusal must happen before attempting the unavailable ledger.
    let ledger = kedgeflow::ledger::EtcdLedger::new(
        reqwest::Client::new(),
        "http://127.0.0.1:9",
        "/kf-expired-certificate",
    )
    .unwrap();
    let error = ledger
        .admit(&prepared, &Time(NOW + 30000))
        .await
        .err()
        .unwrap();
    assert!(matches!(error, kedgeflow::error::Error::Refused(_)));
}

fn grant_for_certificate(
    f: &Fixture,
    packet: &Packet,
    certificate: &str,
) -> (IssuanceVerifier, Grant) {
    let (mut verifier, _, mut grant) = f.authority(packet);
    verifier.admission_keys = keys(6);
    let env: Envelope = serde_json::from_str(certificate).unwrap();
    grant.certificate_digest = record_digest(&env).unwrap();
    grant.constraint_digest = env.payload["constraint_digest"].as_str().unwrap().into();
    grant.expires_at = env.payload["expires_at"].as_i64().unwrap();
    (verifier, grant)
}

#[tokio::test]
async fn concurrent_cedar_admission_returns_one_certificate_then_one_allowance() {
    use kedgeflow::ledger::AuthorityLedger;
    let Some(ledger) = admission_ledger("concurrent").await else {
        return;
    };
    let (f, definition) = cedar_fixture(LEAF_PERMIT);
    let packet = f.packet();
    let inputs = f
        .trust
        .verify_inputs(&f.identity, packet.borrowed(), &CLOCK)
        .unwrap();
    let (_, _, grant) = f.authority(&packet);
    ledger.publish_policy(&grant).await.unwrap();
    let c = controller(&f, definition, 6);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let prepared = c.prepare(&inputs, &CLOCK).unwrap();
        let replica = ledger.clone();
        tasks.spawn(async move { replica.admit(&prepared, &CLOCK).await.unwrap() });
    }
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.unwrap());
    }
    assert_eq!(results.iter().filter(|r| !r.reused).count(), 1);
    let original = &results[0].record;
    assert!(results.iter().all(|r| &r.record == original));
    assert_eq!(original.admitted_at, NOW);
    assert_eq!(original.expires_at, NOW + 5000);
    let env = verify_record(
        original.signed_certificate.as_bytes(),
        "certificate",
        &keys(6),
    )
    .unwrap();
    assert_eq!(
        env.payload["constraint_digest"],
        digest("constraints", &env.payload["constraints"]).unwrap()
    );
    assert_eq!(env.payload["constraints"]["max_attempts"], 1);
    assert!(env.payload["lease_digest"].is_null());
    let (verifier, grant) = grant_for_certificate(&f, &packet, &original.signed_certificate);
    let raw = sign_grant(&grant, "key-5", &SigningKey::from_bytes(&[5; 32])).unwrap();
    let admitted = verifier
        .validate_inputs(
            &inputs,
            original.signed_certificate.as_bytes(),
            &raw,
            &CLOCK,
        )
        .unwrap();
    let issued = ledger.issue_admitted(&admitted, &CLOCK).await.unwrap();
    let v = verifier
        .grants
        .verify(issued.record.signed_grant.as_bytes(), NOW)
        .unwrap();
    ledger
        .claim(&v.grant, &v.digest, "cedar-attempt")
        .await
        .unwrap();
    // Reverification after a lost reply must reuse the old signed certificate,
    // even though a new preparation uses a fresh ID and a later clock/TTL.
    let later = Time(NOW + 1000);
    let inputs = f
        .trust
        .verify_inputs(&f.identity, packet.borrowed(), &later)
        .unwrap();
    let reused = ledger
        .admit(&c.prepare(&inputs, &later).unwrap(), &later)
        .await
        .unwrap();
    assert!(reused.reused);
    assert_eq!(&reused.record, original);
    let admitted = verifier
        .validate_inputs(
            &inputs,
            reused.record.signed_certificate.as_bytes(),
            &raw,
            &later,
        )
        .unwrap();
    assert_eq!(
        ledger
            .issue_admitted(&admitted, &later)
            .await
            .unwrap()
            .record,
        issued.record
    );
    assert!(matches!(
        ledger.claim(&v.grant, &v.digest, "duplicate").await,
        Err(kedgeflow::error::Error::NonceConsumed)
    ));
}

#[tokio::test]
async fn expired_persisted_admission_cannot_be_refreshed_by_retry() {
    use kedgeflow::ledger::AuthorityLedger;
    let Some(ledger) = admission_ledger("expiry").await else {
        return;
    };
    let (f, definition) = cedar_fixture(LEAF_PERMIT);
    let packet = f.packet();
    let inputs = f
        .trust
        .verify_inputs(&f.identity, packet.borrowed(), &CLOCK)
        .unwrap();
    let (_, _, grant) = f.authority(&packet);
    ledger.publish_policy(&grant).await.unwrap();
    let c = controller(&f, definition, 6);
    let prepared = c.prepare(&inputs, &CLOCK).unwrap();
    let original = ledger.admit(&prepared, &CLOCK).await.unwrap();
    let later = Time(NOW + 5000);
    assert!(ledger.admit(&prepared, &later).await.is_err());
    let inputs = f
        .trust
        .verify_inputs(&f.identity, packet.borrowed(), &later)
        .unwrap();
    let new_candidate = c.prepare(&inputs, &later).unwrap();
    let error = ledger.admit(&new_candidate, &later).await.err().unwrap();
    assert!(error.to_string().contains("original admission expired"));
    // An unchanged read at the last valid millisecond still proves retention.
    assert_eq!(
        ledger
            .admit(&prepared, &Time(NOW + 4999))
            .await
            .unwrap()
            .record,
        original.record
    );
}

#[tokio::test]
async fn admission_rebinding_and_stale_control_state_refuse() {
    use kedgeflow::ledger::AuthorityLedger;
    let Some(ledger) = admission_ledger("binding").await else {
        return;
    };
    let (mut f, definition) = cedar_fixture(LEAF_PERMIT);
    let packet = f.packet();
    let inputs = f
        .trust
        .verify_inputs(&f.identity, packet.borrowed(), &CLOCK)
        .unwrap();
    let (_, _, grant) = f.authority(&packet);
    ledger.publish_policy(&grant).await.unwrap();
    let c = controller(&f, definition, 6);
    let prepared = c.prepare(&inputs, &CLOCK).unwrap();
    let original = ledger.admit(&prepared, &CLOCK).await.unwrap();
    f.evidence["result"]["available_slots"] = json!(4);
    let changed = f.packet();
    let changed_inputs = f
        .trust
        .verify_inputs(&f.identity, changed.borrowed(), &CLOCK)
        .unwrap();
    let error = ledger
        .admit(&c.prepare(&changed_inputs, &CLOCK).unwrap(), &CLOCK)
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("binding conflict"));
    assert_eq!(
        ledger.admit(&prepared, &CLOCK).await.unwrap().record,
        original.record
    );
    // Test policy and ownership updates independently, so neither can mask
    // the other's serialization check. Both creation and reuse must refuse.
    f.proposal["qid"] = json!("test:fresh-operation");
    let fresh_inputs = f
        .trust
        .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
        .unwrap();
    for control in ["policy", "ownership"] {
        let control_ledger = admission_ledger(control).await.unwrap();
        control_ledger.publish_policy(&grant).await.unwrap();
        control_ledger.admit(&prepared, &CLOCK).await.unwrap();
        let mut next = grant.clone();
        if control == "policy" {
            next.policy.epoch += 1;
        } else {
            next.ownership_epoch += 1;
        }
        control_ledger.publish_policy(&next).await.unwrap();
        assert!(
            control_ledger.admit(&prepared, &CLOCK).await.is_err(),
            "{control} reuse"
        );
        assert!(
            control_ledger
                .admit(&c.prepare(&fresh_inputs, &CLOCK).unwrap(), &CLOCK)
                .await
                .is_err(),
            "{control} create"
        );
    }
}

#[test]
fn sql_named_action_binds_closed_schema_resource_and_baseline() {
    let mut f = Fixture::new();
    f.sql();
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &Time(NOW))
            .is_ok()
    );
    for field in [
        "resource",
        "version",
        "extra",
        "reservation",
        "schema",
        "action-version",
    ] {
        let mut changed = Fixture::new();
        changed.sql();
        match field {
            "resource" => changed.proposal["parameters"]["resource_id"] = json!("other"),
            "version" => changed.proposal["parameters"]["expected_version"] = json!(242),
            "extra" => changed.proposal["parameters"]["fence"] = json!(1),
            "reservation" => changed.proposal["parameters"]["reservation"] = json!("bad space"),
            "schema" => {
                changed.descriptor["parameter_schema"]["properties"]["reservation"] =
                    json!({"type":"string"});
                let pin = kedgeflow::contracts::digest(
                    "parameter-schema",
                    &changed.descriptor["parameter_schema"],
                )
                .unwrap();
                changed.descriptor["parameter_schema_digest"] = json!(pin);
                changed.descriptor["rendering"]["parameter_schema_digest"] = json!(pin);
                changed.repin_descriptor();
            }
            _ => {
                changed.descriptor["version"] = json!("2");
                changed.proposal["action"]["version"] = json!("2");
                changed.repin_descriptor();
            }
        }
        assert!(
            changed
                .trust
                .verify_inputs(&changed.identity, changed.packet().borrowed(), &Time(NOW))
                .is_err(),
            "{field}"
        );
    }
}
