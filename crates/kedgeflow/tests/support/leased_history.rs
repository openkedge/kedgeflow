//! Managed control history composition with real etcd and software audit keys.
use super::*;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    admission::{EvidencePredicate, StoredAdmissionPacket},
    contracts::digest,
    control_bindings::{ControlBindingsBundle, verify_control_bindings},
    leases::LeaseTrust,
};
fn configure(f: &mut Fixture) {
    let mut r = f.trust.evidence["capacity"].clone();
    r.provider_id = "provider:eligibility".into();
    r.keys = keys(30);
    r.obligation.stage = "static".into();
    r.question.id = "question:eligibility".into();
    r.result_schema_ref.id = "schema:eligibility".into();
    r.result_schema = json!({"type":"object","additionalProperties":false,"properties":{"eligible":{"type":"boolean"}},"required":["eligible"]});
    r.result_schema_ref.digest = digest("result-schema", &r.result_schema).unwrap();
    r.predicates = vec![EvidencePredicate::BooleanEquals {
        field: "eligible".into(),
        expected: true,
    }];
    r.obligation.predicate_digest = digest("evidence-predicate", &json!(r.predicates)).unwrap();
    f.trust.evidence.insert("eligibility".into(), r);
    f.trust.leases = Some(LeaseTrust {
        keys: keys(6),
        max_lifetime_ms: 4000,
        jit_max_age_ms: 2000,
    });
    f.trust.obligation_manifest_digest = f.trust.registered_obligations_digest().unwrap();
}
fn packet(f: &Fixture, static_only: bool, lease: Option<&str>) -> StoredAdmissionPacket {
    let proposal = fixture::signed("proposal", f.proposal.clone(), 1);
    let descriptor = fixture::signed("ctd", f.descriptor.clone(), 2);
    let pd = fixture::record_hash(&proposal);
    let r = &f.trust.evidence["eligibility"];
    let mut e = f.evidence.clone();
    e["wid"] = json!("w:eligibility");
    e["proposal_digest"] = json!(pd);
    e["provider_id"] = json!(r.provider_id);
    e["question_ref"] = json!(r.question);
    e["result_schema"] = json!(r.result_schema_ref);
    e["result"] = json!({"eligible":true});
    e["observed_at"] = json!(NOW - 5);
    e["expires_at"] = json!(NOW + 10000);
    let static_raw = fixture::signed("evidence", e.clone(), 30);
    let entry = |id: &str, p: &Value, raw: &[u8]| json!({"witness":{"id":p["wid"],"schema":serde_json::from_slice::<Value>(raw).unwrap()["schema"],"digest":fixture::record_hash(raw)},"obligation_id":id,"execution_relevant":true,"expires_at":p["expires_at"]});
    let mut entries = vec![entry("eligibility", &e, &static_raw)];
    let mut witnesses = vec![String::from_utf8(static_raw).unwrap()];
    if !static_only {
        let mut jit = f.evidence.clone();
        jit["proposal_digest"] = json!(pd);
        jit["observed_at"] = json!(NOW + 1);
        let raw = fixture::signed("evidence", jit.clone(), 4);
        entries.push(entry("capacity", &jit, &raw));
        witnesses.push(String::from_utf8(raw).unwrap());
    }
    let manifest = fixture::signed(
        "manifest",
        json!({"mid":if static_only{"static"}else{"full"},"proposal_digest":pd,"policy":f.trust.policy,"witnesses":entries,"assembled_at":if static_only{NOW}else{NOW+1}}),
        3,
    );
    StoredAdmissionPacket {
        proposal: String::from_utf8(proposal).unwrap(),
        descriptor: String::from_utf8(descriptor).unwrap(),
        manifest: String::from_utf8(manifest).unwrap(),
        witnesses,
        lease: lease.map(str::to_owned),
    }
}
impl HistoryHarness {
    async fn leased() -> Option<Self> {
        let h = Harness::with_setup(None, NOW, configure).await?;
        h.ledger
            .enroll_lease_member(&h.f.trust, &h.f.identity.subject)
            .await
            .unwrap();
        let installed = h.bootstrap().await;
        assert!(h.post(&h.ack(&installed), true).await.0.is_success());
        let controller = AdmissionController::new(
            CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
            "key-6".into(),
            SigningKey::from_bytes(&[6; 32]),
        )
        .unwrap();
        let sp = packet(&h.f, true, None);
        let ev: Vec<_> = sp.witnesses.iter().map(|r| r.as_bytes().to_vec()).collect();
        let lease = h
            .ledger
            .prevalidate_lease(
                &h.f.trust,
                &controller,
                &h.f.identity,
                kedgeflow::admission::AdmissionPacket {
                    proposal: sp.proposal.as_bytes(),
                    descriptor: sp.descriptor.as_bytes(),
                    manifest: sp.manifest.as_bytes(),
                    evidence: &ev,
                    lease: None,
                },
                &Time(NOW),
            )
            .await
            .unwrap();
        h.clock.0.store(NOW + 1, Ordering::SeqCst);
        let full = packet(&h.f, false, Some(&lease));
        let ev: Vec<_> = full
            .witnesses
            .iter()
            .map(|r| r.as_bytes().to_vec())
            .collect();
        let inputs =
            h.f.trust
                .verify_inputs(
                    &h.f.identity,
                    kedgeflow::admission::AdmissionPacket {
                        proposal: full.proposal.as_bytes(),
                        descriptor: full.descriptor.as_bytes(),
                        manifest: full.manifest.as_bytes(),
                        evidence: &ev,
                        lease: Some(lease.as_bytes()),
                    },
                    &Time(NOW + 1),
                )
                .unwrap();
        let cert = h
            .ledger
            .admit(
                &controller.prepare(&inputs, &Time(NOW + 1)).unwrap(),
                &Time(NOW + 1),
            )
            .await
            .unwrap()
            .record;
        let verifier = GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        };
        let issued = GrantAuthority::new(
            IssuanceVerifier {
                tenant: h.f.trust.tenant.clone(),
                admission_keys: keys(6),
                grants: verifier.clone(),
            },
            "key-5".into(),
            SigningKey::from_bytes(&[5; 32]),
        )
        .unwrap()
        .issue(
            &h.ledger,
            &inputs,
            cert.signed_certificate.as_bytes(),
            &Time(NOW + 1),
        )
        .await
        .unwrap()
        .record;
        let g = verifier
            .verify_retained(issued.signed_grant.as_bytes())
            .unwrap();
        let c = Candidate {
            grant: g.grant,
            attempt_id: "leased-history".into(),
        };
        h.ledger
            .claim_recorded(
                &c.grant,
                &g.digest,
                &c.attempt_id,
                &ExecutionRecord {
                    signed_grant: issued.signed_grant,
                    tool: h.tool().name,
                    parameters: h.f.proposal["parameters"].clone(),
                },
            )
            .await
            .unwrap();
        RecoveryWorker::new(
            h.ledger.clone(),
            verifier,
            Arc::new(Pending),
            "outcome-14".into(),
            SigningKey::from_bytes(&[14; 32]),
            "spiffe://test/outcome".into(),
            Arc::new(Time(NOW + 120000)),
        )
        .unwrap()
        .recover(&c)
        .await
        .unwrap();
        let key =
            h.f.trust
                .operation_key(&h.f.identity, full.proposal.as_bytes())
                .unwrap();
        let mut trust: Value = serde_json::from_slice(include_bytes!(
            "../../../../config/control-history-trust.example.json"
        ))
        .unwrap();
        trust["namespace"] = json!(h.ledger.namespace());
        trust["operation"]["policy"]["cedar"] = json!(h.definition.cedar);
        let encoded = |keys: &BTreeMap<String, ed25519_dalek::VerifyingKey>| {
            keys.iter()
                .map(|(id, k)| (id.clone(), STANDARD.encode(k.as_bytes())))
                .collect::<BTreeMap<_, _>>()
        };
        trust["operation"]["leases"] =
            json!({"keys":encoded(&keys(6)),"max_lifetime_ms":4000,"jit_max_age_ms":2000});
        let r = &h.f.trust.evidence["eligibility"];
        trust["operation"]["evidence"]["eligibility"] = json!({"obligation":r.obligation,"provider_id":r.provider_id,"provider_version":r.provider_version,"keys":encoded(&r.keys),"question":r.question,"result_schema_ref":r.result_schema_ref,"result_schema":r.result_schema,"max_age_ms":r.max_age_ms,"predicates":r.predicates});
        trust["historical"][0]["trust"] = trust["operation"].clone();
        trust["historical"][0]["registration"] = json!(h.registration);
        Some(Self {
            h,
            c,
            key,
            trust,
            grant_digest: g.digest,
        })
    }
}
fn resign(b: &mut ControlHistoryBundle) {
    b.checkpoint.payload.lineage_digest =
        digest("control-history-lineage", &json!(b.lineage)).unwrap();
    let c = &mut b.checkpoint;
    let mut raw = format!("KedgeFlow:{}\0", c.profile).into_bytes();
    raw.extend(
        canonical(
            &json!({"profile":c.profile,"kind":c.kind,"key_id":c.key_id,"payload":c.payload}),
        )
        .unwrap(),
    );
    c.signature = URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[17; 32]).sign(&raw).to_bytes());
}
#[tokio::test]
async fn leased_history_and_control_bindings_native_offline_cli_and_cross_version_refusal() {
    let Some(h) = HistoryHarness::leased().await else {
        return;
    };
    let b = h.bundle().await;
    assert_eq!(b.profile, kedgeflow::control_history::LEASE_PROFILE);
    h.verify(&b).unwrap();
    let out = cli(&b, &h.trust);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bindings =
        h.h.ledger
            .export_control_bindings(
                &h.c,
                &h.key,
                &HistoryHarness::observer(),
                &Time(NOW + 120000),
            )
            .await
            .unwrap();
    assert_eq!(bindings.profile, kedgeflow::control_bindings::LEASE_PROFILE);
    let trust = ControlHistoryTrustConfig::decode(&serde_json::to_vec(&h.trust).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    verify_control_bindings(&bindings, &trust).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let tp = dir.path().join("trust.json");
    let bp = dir.path().join("bundle.json");
    std::fs::write(&tp, serde_json::to_vec(&h.trust).unwrap()).unwrap();
    std::fs::write(&bp, serde_json::to_vec(&bindings).unwrap()).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-control-bindings"))
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
    h.h.ledger
        .withdraw_lease_member(&h.h.f.trust, &h.h.f.identity.subject)
        .await
        .unwrap();
    h.verify(&h.bundle().await).unwrap();
    for field in ["profile", "checkpoint", "nested", "generation"] {
        let mut v = json!(b);
        match field {
            "profile" => v["profile"] = json!(kedgeflow::control_history::PROFILE),
            "checkpoint" => v["checkpoint"]["profile"] = json!(kedgeflow::control_history::PROFILE),
            "nested" => v["lineage"]["profile"] = json!(kedgeflow::lineage::PROFILE),
            "generation" => {
                for i in 0..2 {
                    v["lineage"]["lease_authority"][i]["member"]["generation"] = json!(3);
                    v["lineage"]["lease_authority"][i]["cache"]["member"]["generation"] = json!(3);
                }
            }
            _ => unreachable!(),
        }
        let mut changed: ControlHistoryBundle = serde_json::from_value(v).unwrap();
        resign(&mut changed);
        assert!(h.verify(&changed).is_err(), "{field}");
    }
    for path in ["profile", "checkpoint", "history"] {
        let mut v = json!(bindings);
        match path {
            "profile" => v["profile"] = json!(kedgeflow::control_bindings::PROFILE),
            "checkpoint" => {
                v["checkpoint"]["profile"] = json!(kedgeflow::control_bindings::PROFILE)
            }
            "history" => v["history"]["profile"] = json!(kedgeflow::control_history::PROFILE),
            _ => unreachable!(),
        };
        assert!(ControlBindingsBundle::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    for (schema, v) in [
        (
            include_str!("../../../../spec/drafts/control-history-v0.1.schema.json"),
            json!(b),
        ),
        (
            include_str!("../../../../spec/drafts/control-bindings-v0.1.schema.json"),
            json!(bindings),
        ),
    ] {
        assert!(
            !jsonschema::validator_for(&serde_json::from_str::<Value>(schema).unwrap())
                .unwrap()
                .is_valid(&v)
        );
    }
}
