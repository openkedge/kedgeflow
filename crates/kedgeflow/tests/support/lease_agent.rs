//! Official SDK client lease state across separate Node processes; fixture providers.
use super::*;
use kedgeflow::admission::{EvidencePredicate, EvidenceRequirement};
use std::path::Path;
pub(super) fn configure(f: &mut Fixture) {
    let mut r = f.trust.evidence["capacity"].clone();
    r.provider_id = "provider:eligibility".into();
    r.keys = keys(30);
    r.obligation.stage = "static".into();
    r.question.id = "question:eligibility".into();
    r.result_schema_ref.id = "schema:eligibility".into();
    r.result_schema = json!({"type":"object","additionalProperties":false,"properties":{"eligible":{"type":"boolean"}},"required":["eligible"]});
    r.result_schema_ref.digest =
        kedgeflow::contracts::digest("result-schema", &r.result_schema).unwrap();
    r.predicates = vec![EvidencePredicate::BooleanEquals {
        field: "eligible".into(),
        expected: true,
    }];
    r.obligation.predicate_digest =
        kedgeflow::contracts::digest("evidence-predicate", &json!(r.predicates)).unwrap();
    f.trust.evidence.insert("eligibility".into(), r);
    f.trust.leases = Some(kedgeflow::leases::LeaseTrust {
        keys: keys(6),
        max_lifetime_ms: 4000,
        jit_max_age_ms: 2000,
    });
    f.trust.obligation_manifest_digest = f.trust.registered_obligations_digest().unwrap();
}
pub(super) struct LeaseProvider {
    pub base: Arc<Provider>,
    pub static_rule: Option<EvidenceRequirement>,
    pub static_calls: AtomicUsize,
}
pub(super) async fn evidence(
    State(p): State<Arc<LeaseProvider>>,
    Extension(workload): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    if body["operation"] == "baseline" {
        return super::evidence(
            State(p.base.clone()),
            Extension(workload),
            headers,
            Json(body),
        )
        .await;
    }
    if body["operation"] == "jit" {
        let static_packet = body["staticPacket"].clone();
        let Json(mut full) = super::evidence(
            State(p.base.clone()),
            Extension(workload),
            headers,
            Json(body),
        )
        .await?;
        let mut manifest = kedgeflow::schema::verify_record(
            full["manifest"].as_str().unwrap().as_bytes(),
            "manifest",
            &keys(3),
        )
        .unwrap()
        .payload;
        let original = kedgeflow::schema::verify_record(
            static_packet["manifest"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?
                .as_bytes(),
            "manifest",
            &keys(3),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        manifest["witnesses"]
            .as_array_mut()
            .unwrap()
            .extend(original.payload["witnesses"].as_array().unwrap().clone());
        full["manifest"] =
            json!(String::from_utf8(fixture::signed("manifest", manifest, 3)).unwrap());
        full["witnesses"].as_array_mut().unwrap().extend(
            static_packet["witnesses"]
                .as_array()
                .ok_or(StatusCode::BAD_REQUEST)?
                .clone(),
        );
        return Ok(Json(full));
    }
    if body["operation"] != "static" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let identity = p
        .base
        .auth
        .authenticate_at(&headers, &workload, p.base.clock.now_ms() / 1000)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !identity.scopes.contains("kf.evidence") || workload.as_str() != "spiffe://test/agent" {
        return Err(StatusCode::FORBIDDEN);
    }
    let proposal = kedgeflow::schema::verify_record(
        body["proposal"]
            .as_str()
            .ok_or(StatusCode::BAD_REQUEST)?
            .as_bytes(),
        "proposal",
        &keys(1),
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let pd = kedgeflow::contracts::record_digest(&proposal).unwrap();
    if body["proposal_digest"] != pd
        || proposal.payload["subject"] != json!(identity.subject)
        || proposal.payload["action"]["digest"] != p.base.descriptor_digest
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let r = p.static_rule.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let mut e = p.base.evidence.clone();
    let observed = *p.base.target.state.lock().await;
    e["state_digest"] = json!(
        kedgeflow::contracts::digest(
            "mock-state",
            &json!({"version":observed.0,"available_slots":observed.2})
        )
        .unwrap()
    );
    e["wid"] = json!("w:eligibility");
    e["proposal_digest"] = json!(pd);
    e["provider_id"] = json!(r.provider_id);
    e["question_ref"] = json!(r.question);
    e["result_schema"] = json!(r.result_schema_ref);
    e["result"] = json!({"eligible":true});
    e["observed_at"] = json!(p.base.clock.now_ms());
    e["expires_at"] = json!(p.base.clock.now_ms() + 10000);
    let raw = fixture::signed("evidence", e.clone(), 30);
    let manifest = fixture::signed(
        "manifest",
        json!({"mid":"static-provider-manifest","proposal_digest":pd,"policy":p.base.policy,"witnesses":[{"witness":{"id":e["wid"],"schema":serde_json::from_slice::<Value>(&raw).unwrap()["schema"],"digest":fixture::record_hash(&raw)},"obligation_id":"eligibility","execution_relevant":true,"expires_at":e["expires_at"]}],"assembled_at":p.base.clock.now_ms()}),
        3,
    );
    p.static_calls.fetch_add(1, Ordering::SeqCst);
    Ok(Json(
        json!({"manifest":String::from_utf8(manifest).unwrap(),"witnesses":[String::from_utf8(raw).unwrap()]}),
    ))
}
pub(super) fn registration(h: &Harness, url: &str) -> Value {
    let obligations: BTreeMap<_,_> = h.f.trust.evidence.iter().map(|(id,r)| {
        let keys: BTreeMap<_,_> = r.keys.iter().map(|(id,k)|(id.clone(),URL_SAFE_NO_PAD.encode(k.as_bytes()))).collect();
        (id.clone(),json!({"stage":r.obligation.stage,"predicate_digest":r.obligation.predicate_digest,"execution_relevant":r.obligation.execution_relevant,"provider_id":r.provider_id,"provider_version":r.provider_version,"keys":keys,"max_age_ms":r.max_age_ms}))
    }).collect();
    json!({"url":url,"scope":"kf.lease","policy":h.f.trust.policy,"ownershipEpoch":h.f.trust.ownership_epoch,"maxLifetimeMs":4000,"jitMaxAgeMs":2000,"maxProposalAgeMs":h.f.trust.max_proposal_age_ms,"obligations":obligations})
}
async fn node(file: &Path, config: &Value) -> Value {
    std::fs::write(file, serde_json::to_vec(config).unwrap()).unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(25),
        tokio::process::Command::new(
            std::env::var("KF_SDK_NODE").unwrap_or_else(|_| "node".into()),
        )
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/sdk/lease-agent.mjs"))
        .arg(file)
        .kill_on_drop(true)
        .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "lease SDK failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["status"], "PASS");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    v
}
pub(super) async fn qualify(
    mode: &str,
    h: &Harness,
    config: &mut Value,
    provider: &Arc<Provider>,
    lp: &Arc<LeaseProvider>,
    file: &Path,
) {
    let mode = mode.strip_prefix("lease:").unwrap();
    if mode == "automatic" {
        config["phase"] = json!("execute");
        config["fault"] = json!("none");
        let first = node(file, config).await;
        assert_eq!(first["state"], "committed");
        let second = node(file, config).await;
        assert_eq!(second["state"], "committed");
        assert_eq!(second["admissions"], 0);
        assert_eq!(second["issues"], 0);
        assert_eq!(second["dispatches"], 0);
        assert_eq!(provider.target.effects.load(Ordering::SeqCst), 1);
        assert_eq!(lp.static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.baseline_calls.load(Ordering::SeqCst), 1);
        return;
    }

    config["phase"] = json!("prepare");
    config["fault"] = json!(if mode == "lost-prevalidate" {
        mode
    } else {
        "none"
    });
    let prepared = node(file, config).await;
    assert_eq!(
        prepared["state"],
        if mode == "lost-prevalidate" {
            "unavailable"
        } else {
            "prevalidated"
        }
    );
    assert_eq!(lp.static_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.baseline_calls.load(Ordering::SeqCst), 1);
    assert!(
        h.ledger
            .read_key(&format!(
                "{}/fence-counter/{}",
                h.ledger.namespace(),
                kedgeflow::contracts::digest(
                    "fence-resource",
                    &json!({"tenant":h.f.trust.tenant,"resource":h.registration.scope.resource})
                )
                .unwrap()
            ))
            .await
            .unwrap()
            .is_none()
    );
    config["fault"] = json!("none");
    let retried = node(file, config).await;
    assert_eq!(retried["state"], "prevalidated");
    if mode != "lost-prevalidate" {
        assert_eq!(prepared["lease"], retried["lease"]);
        assert!(
            retried["wire"]
                .as_array()
                .unwrap()
                .iter()
                .all(|w| matches!(w["method"].as_str(), Some("server/discover" | "tools/list")))
        );
    }
    if mode == "lost-prevalidate" {
        assert_eq!(prepared["lost_lease"], retried["lease"]);
    }
    assert_eq!(retried["lease_issued_at"], NOW);
    assert_eq!(retried["lease_expires_at"], NOW + 4000);
    assert_eq!(lp.static_calls.load(Ordering::SeqCst), 1);
    let now = NOW + if mode == "expired" { 4000 } else { 500 };
    h.clock.0.store(now, Ordering::SeqCst);
    config["now"] = json!(now);
    if mode == "withdrawn" {
        h.ledger
            .withdraw_lease_member(&h.f.trust, &h.f.identity.subject)
            .await
            .unwrap();
    }
    if mode == "replaced" {
        h.ledger
            .replace_lease_member(&h.f.trust, &h.f.identity.subject, 1)
            .await
            .unwrap();
    }
    if mode == "changed-delegation" {
        let old = config["token"].as_str().unwrap();
        let parts: Vec<_> = old.split('.').collect();
        let mut payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        payload["scope"] = json!(format!("{} kf.other", payload["scope"].as_str().unwrap()));
        config["token"] = json!(jwt(json!({"alg":"EdDSA","typ":"at+jwt"}), payload, 7));
    }
    config["phase"] = json!("execute");
    config["fault"] = json!(mode);
    let first = node(file, config).await;
    let ambiguous = matches!(mode, "lost-admit" | "lost-issue" | "persistence-lost");
    let refused = matches!(
        mode,
        "expired" | "withdrawn" | "replaced" | "changed-delegation"
    );
    if matches!(mode, "lost-jit" | "boundary-persistence-lost") {
        assert_eq!(first["state"], "unissued");
        assert_eq!(first["retained_phase"], "ready");
        assert_eq!(first["admissions"], 0);
        h.clock.0.store(now + 1, Ordering::SeqCst);
        config["now"] = json!(now + 1);
        config["fault"] = json!("none");
    } else if !ambiguous && !refused {
        assert_eq!(first["state"], "committed");
    } else {
        assert_eq!(
            first["state"],
            if matches!(mode, "lost-issue" | "persistence-lost") {
                "unclaimed"
            } else {
                "unissued"
            }
        );
    }
    let second = node(file, config).await;
    let effects = usize::from(!ambiguous && !refused);
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        if matches!(mode, "expired" | "changed-delegation") {
            0
        } else if matches!(mode, "lost-jit" | "boundary-persistence-lost") {
            2
        } else {
            1
        }
    );
    assert_eq!(lp.static_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.baseline_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.target.effects.load(Ordering::SeqCst), effects);
    assert_eq!(provider.target.calls.load(Ordering::SeqCst), effects);
    if !matches!(mode, "lost-jit" | "boundary-persistence-lost") {
        assert_eq!(second["admissions"], 0);
        assert_eq!(second["issues"], 0);
        assert_eq!(second["dispatches"], 0);
    }
    if !refused {
        assert_eq!(second["retained_phase"], "authority_started");
    }
    if effects == 1 {
        assert_eq!(second["state"], "committed");
        assert_eq!(second["lease"], retried["lease"]);
    }
    // A fresh status-only delegation in another process can disclose history
    // after expiry/revocation; it never re-enters lease/JIT/admission acquisition.
    h.revoke(RevocationTarget::Domain).await;
    h.clock.0.store(NOW + 61000, Ordering::SeqCst);
    config["now"] = json!(NOW + 61000);
    config["phase"] = json!("query");
    config["fault"] = json!("none");
    let old = config["token"].as_str().unwrap();
    let parts: Vec<_> = old.split('.').collect();
    let mut payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    payload["scope"] = json!("kf.status");
    payload["iat"] = json!((NOW + 61000) / 1000);
    payload["exp"] = json!((NOW + 61000) / 1000 + 60);
    config["token"] = json!(jwt(json!({"alg":"EdDSA","typ":"at+jwt"}), payload, 7));
    let history = node(file, config).await;
    assert_eq!(history["state"], second["state"]);
    assert_eq!(history["admissions"], 0);
    assert_eq!(history["issues"], 0);
    assert_eq!(history["dispatches"], 0);
    assert!(history["wire"].as_array().unwrap().iter().all(|w| matches!(
        w["method"].as_str(),
        Some("server/discover" | "status" | "kedgeflow/status")
    )));
}
#[tokio::test]
async fn official_agent_lease_preparation_recreated_client_and_fresh_jit_commit() {
    for mode in ["normal", "automatic"] {
        super::run(&format!("lease:{mode}")).await;
    }
}
#[tokio::test]
async fn official_agent_lease_lost_prevalidation_reuses_original_cache() {
    super::run("lease:lost-prevalidate").await;
}
#[tokio::test]
async fn official_agent_lease_lost_jit_recollects_only_before_authority() {
    for mode in ["lost-jit", "boundary-persistence-lost"] {
        super::run(&format!("lease:{mode}")).await;
    }
}
#[tokio::test]
async fn official_agent_lease_lost_authority_and_persistence_stay_query_only() {
    for mode in ["lost-admit", "lost-issue", "persistence-lost"] {
        super::run(&format!("lease:{mode}")).await;
    }
}
#[tokio::test]
async fn official_agent_lease_expiry_withdrawal_and_replacement_refuse_new_authority() {
    for mode in ["expired", "withdrawn", "replaced", "changed-delegation"] {
        super::run(&format!("lease:{mode}")).await;
    }
}
