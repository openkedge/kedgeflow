//! Fresh native admission/issuer/claim/broker followed by shipping one-shot CLI.
//! Provider/evidence identities are generated fixtures; the target and Terraform
//! backend are real and the mutation credential is private runner material.
use super::*;
use async_trait::async_trait;
use axum::{Extension, Json, Router, extract::State, http::HeaderMap, routing::post};
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    auth::{Identity, WorkloadIdentity},
    broker_authorization::{
        BrokerAuthorizer, BrokerRegistration, ExchangeIdentityProvider, ExchangeRequest,
        VerifiedExchangeIdentity,
    },
    clock::{Clock, SystemClock},
    contracts::digest,
    error::Result,
    recovery::ExecutionRecord,
    target_token::{ReferenceTokenMinter, TargetTokenMinter},
    terraform_apply as apply,
    terraform_plan::{self, Manifest},
    tls,
};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
};

struct Provider(Identity);
#[async_trait]
impl ExchangeIdentityProvider for Provider {
    async fn verify(
        &self,
        subject: &str,
        actor: &str,
        now: i64,
    ) -> Result<VerifiedExchangeIdentity> {
        assert_eq!(subject, self.0.access_token);
        assert_eq!(actor, "fixture-actor");
        Ok(VerifiedExchangeIdentity {
            identity: self.0.clone(),
            subject_valid_until: now + 60000,
            actor_valid_until: now + 60000,
        })
    }
}
#[derive(Clone)]
struct Relay {
    origin: String,
}
async fn relay(
    State(p): State<Relay>,
    Extension(w): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(v): Json<Value>,
) -> Json<Value> {
    assert_eq!(w.as_str(), "spiffe://test/gateway");
    assert_eq!(headers["authorization"], "fixture-terraform-ledger-token");
    Json(
        reqwest::Client::new()
            .post(format!("{}/v3/kv/txn", p.origin))
            .json(&v)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap(),
    )
}
fn write(root: &Path, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}
fn configure(f: &mut Fixture, m: &Manifest, inspection: &terraform_plan::Inspection) {
    let resource =
        json!({"id":format!("terraform:{}",inspection.manifest_digest),"incarnation":m.target.uid});
    f.descriptor["action"] = json!(apply::ACTION);
    f.descriptor["version"] = json!("1.0");
    f.descriptor["adapter_contract"] = apply::adapter_contract();
    f.descriptor["parameter_schema"] = apply::parameter_schema(
        &inspection.manifest_digest,
        &inspection.effect_digest,
        resource["id"].as_str().unwrap(),
    )
    .unwrap();
    let pin = digest("parameter-schema", &f.descriptor["parameter_schema"]).unwrap();
    f.descriptor["parameter_schema_digest"] = json!(pin);
    f.descriptor["rendering"]["parameter_schema_digest"] = json!(pin);
    f.descriptor["concurrency"]["predicate_descriptor"]["clauses"][0] =
        json!({"kind":"version_eq","resource":resource,"expected_version":"1"});
    f.descriptor["concurrency"]["coverage"] = apply::coverage();
    f.trust.required_scope = "terraform:apply".into();
    f.identity.scopes.insert("terraform:apply".into());
    f.proposal["delegation"]["scopes"] = json!(["terraform:apply"]);
    f.proposal["action"]["id"] = json!(apply::ACTION);
    f.proposal["action"]["version"] = json!("1.0");
    f.proposal["resources"] = json!([resource]);
    f.proposal["parameters"] = json!({"node":resource["id"],"expected_version":1,"manifest_digest":inspection.manifest_digest,"effect_digest":inspection.effect_digest});
    f.proposal["baseline_state"][0]["resource"] = resource.clone();
    f.proposal["baseline_state"][0]["version"] = json!("1");
    f.evidence["state_scope"] = json!([resource]);
    f.evidence["result"]["version"] = json!("1");
    let requirement = f.trust.evidence.get_mut("capacity").unwrap();
    requirement.predicates = vec![kedgeflow::admission::EvidencePredicate::StringEquals {
        field: "version".into(),
        expected: "1".into(),
    }];
    requirement.obligation.predicate_digest =
        digest("evidence-predicate", &json!(requirement.predicates)).unwrap();
    f.trust.obligation_manifest_digest = f.trust.registered_obligations_digest().unwrap();
    f.repin_descriptor();
}
async fn cli(config: &Path, root: &Path, command: &[&str], discard: bool) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-terraform-apply"));
    child
        .arg("--material-root")
        .arg(root)
        .arg("--config")
        .arg(config)
        .args(command)
        .kill_on_drop(true);
    // The shipping runner must keep newly created backend material private even
    // when its administrative caller has the usual permissive process mask.
    unsafe {
        child.as_std_mut().pre_exec(|| {
            rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o022));
            Ok(())
        });
    }
    if discard {
        child.stdout(Stdio::null());
    }
    tokio::time::timeout(Duration::from_secs(35), child.output())
        .await
        .unwrap()
        .unwrap()
}
async fn run(mode: &str) {
    let Ok(capsule) = std::env::var("KF_TERRAFORM_CAPSULE") else {
        assert_ne!(
            std::env::var("KF_REQUIRE_TERRAFORM").as_deref(),
            Ok("1"),
            "required real Terraform fixture absent"
        );
        eprintln!("SKIP Terraform execution: owned fixture absent");
        return;
    };
    let capsule = PathBuf::from(capsule);
    let manifest_file = capsule.join("manifest.json");
    let m = Manifest::decode(&std::fs::read(&manifest_file).unwrap()).unwrap();
    let inspection = terraform_plan::inspect(&capsule, &manifest_file)
        .await
        .unwrap();
    let now = SystemClock.now_ms();
    let Some(mut h) = Harness::with_native_timing(
        None,
        now,
        |f| configure(f, &m, &inspection),
        None,
        None,
        None,
        None,
        Some(30000),
    )
    .await
    else {
        return;
    };
    h.f.identity.delegation_digest = digest("delegation", &h.f.proposal["delegation"]).unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let tool = h.tool();
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ledger_url = format!("https://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/v3/kv/txn", post(relay))
        .with_state(Relay {
            origin: std::env::var("ETCD_ENDPOINT").unwrap(),
        });
    let server = tls::server_config_pem(
        h.gateway_pki.server.as_bytes(),
        h.gateway_pki.server_key.as_bytes(),
        h.gateway_pki.ca.as_bytes(),
    )
    .unwrap();
    let _server = live_agent::Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, server, router)
            .await
            .unwrap()
    }));
    let ca = write(&root, "ledger-ca.pem", &h.gateway_pki.ca);
    let cert = write(&root, "gateway.pem", &h.gateway_pki.client);
    let key = write(&root, "gateway.key", &h.gateway_pki.client_key);
    let ledger_token = write(&root, "ledger.token", "fixture-terraform-ledger-token");
    let secret = PathBuf::from(std::env::var("KF_TERRAFORM_SECRET_ROOT").unwrap());
    let pins = apply::Pins {
        profile: apply::PROFILE.into(),
        material_root: capsule.clone(),
        manifest_file: manifest_file.clone(),
        backend_root: PathBuf::from(std::env::var("KF_TERRAFORM_BACKEND_ROOT").unwrap()),
        secret_root: secret.clone(),
        writer_token_file: secret.join("writer.token"),
        observer_token_file: secret.join("observer.token"),
        manifest_digest: inspection.manifest_digest.clone(),
        inspection_sha256: inspection.inspection_sha256.clone(),
        effect_digest: inspection.effect_digest.clone(),
        tool: tool.clone(),
        parameter_schema: h.f.descriptor["parameter_schema"].clone(),
        gateway_workload: "spiffe://test/gateway".into(),
        target_audience: "https://terraform-runner.test/apply".into(),
        target_scope: "terraform:apply".into(),
    };
    let public = |n: u8| json!({format!("key-{n}"):STANDARD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let config=write(&root,"config.json",serde_json::to_vec(&json!({"pins":pins,"ledger":{"endpoint":ledger_url,"prefix":h.ledger.namespace(),"ca":ca,"certificate":cert,"private_key":key,"token_file":ledger_token,"restore_gate":null},"gateway_audience":h.registration.scope.audience,"grant_keys":public(5),"token_issuer":"https://terraform-broker.test/exchange","target_keys":public(29)})).unwrap());
    let issued = h.issue().await.unwrap();
    h.clock.0.store(0, Ordering::SeqCst);
    let grants = GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    };
    let verified = grants
        .verify(issued.record.signed_grant.as_bytes(), SystemClock.now_ms())
        .unwrap();
    let g = &verified.grant;
    let id = "terraform-original-attempt";
    h.ledger
        .claim_recorded(
            g,
            &verified.digest,
            id,
            &ExecutionRecord {
                signed_grant: issued.record.signed_grant.clone(),
                tool: tool.name.clone(),
                parameters: h.f.proposal["parameters"].clone(),
            },
        )
        .await
        .unwrap();
    let registration = BrokerRegistration {
        gateway_workload: pins.gateway_workload.clone(),
        target_audience: pins.target_audience.clone(),
        target_scope: pins.target_scope.clone(),
        max_lifetime_ms: 30000,
        tool: tool.clone(),
    };
    let broker = BrokerAuthorizer::new(
        registration,
        grants.clone(),
        h.ledger.clone(),
        Arc::new(Provider(h.f.identity.clone())),
        Arc::new(SystemClock),
    )
    .unwrap();
    let der = rustls_pemfile::certs(&mut std::io::Cursor::new(h.gateway_pki.client.as_bytes()))
        .next()
        .unwrap()
        .unwrap();
    let gateway = WorkloadIdentity::from_verified_cert_der(&der).unwrap();
    let exchange = ExchangeRequest {
        subject_token: h.f.identity.access_token.clone(),
        actor_token: "fixture-actor".into(),
        signed_grant: issued.record.signed_grant.clone(),
        grant_digest: verified.digest.clone(),
        attempt_id: id.into(),
        audience: pins.target_audience.clone(),
        scope: pins.target_scope.clone(),
    };
    let permit = broker.authorize(&exchange, &gateway).await.unwrap();
    let credential = ReferenceTokenMinter::new(
        "https://terraform-broker.test/exchange".into(),
        "key-29".into(),
        SigningKey::from_bytes(&[29; 32]),
    )
    .unwrap()
    .mint(&permit, SystemClock.now_ms())
    .await
    .unwrap();
    h.ledger
        .authorize_dispatch(g, &verified.digest, id)
        .await
        .unwrap();
    if mode == "revoked" {
        h.revoke(RevocationTarget::Domain).await;
    }
    if mode == "missing-writer" {
        std::fs::rename(secret.join("writer.token"), secret.join("writer.saved")).unwrap();
    }
    let request = apply::Request {
        profile: apply::PROFILE.into(),
        signed_grant: issued.record.signed_grant.clone(),
        attempt_id: id.into(),
        parameters: h.f.proposal["parameters"].clone(),
        target_credential: credential,
    };
    let request_path = write(&root, "request.json", serde_json::to_vec(&request).unwrap());
    if mode == "backend-drift" {
        let path = m.backend_state_path.as_ref().unwrap();
        let mut state: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        state["serial"] = json!(state["serial"].as_u64().unwrap() + 1);
        std::fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
    }
    let before = std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap();
    let backend_lock = if mode == "backend-locked" {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(m.backend_state_path.as_ref().unwrap())
            .unwrap();
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).unwrap();
        Some(file)
    } else {
        None
    };
    let output = cli(
        &config,
        &root,
        &["execute", "--request", request_path.to_str().unwrap()],
        mode == "lost-reply",
    )
    .await;
    let after = std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap();
    let state_before: Value = serde_json::from_slice(&before).unwrap();
    let state_after: Value = serde_json::from_slice(&after).unwrap();
    let public_output = PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap());
    std::fs::write(public_output.join("backend-observation.json"), serde_json::to_vec_pretty(&json!({
        "before":{"sha256":hex::encode(Sha256::digest(&before)),"lineage":state_before["lineage"],"serial":state_before["serial"]},
        "after":{"sha256":hex::encode(Sha256::digest(&after)),"lineage":state_after["lineage"],"serial":state_after["serial"]}
    })).unwrap()).unwrap();
    if mode == "revoked" || mode == "backend-drift" {
        assert!(!output.status.success());
        assert_eq!(
            std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap(),
            before
        );
        assert!(
            h.ledger
                .read_key(&format!(
                    "{}/terraform/{}/intent",
                    h.ledger.namespace(),
                    inspection.manifest_digest
                ))
                .await
                .unwrap()
                .is_none()
        );
        println!(
            "TERRAFORM APPLY PASS: mode={mode}; refused before native intent; no additional backend or target effect"
        );
        return;
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let queried = cli(&config, &root, &["query", "--attempt-id", id], false).await;
    assert!(
        queried.status.success(),
        "{}",
        String::from_utf8_lossy(&queried.stderr)
    );
    let report: Value = serde_json::from_slice(&queried.stdout).unwrap();
    let part = |s: &str| URL_SAFE_NO_PAD.encode(s.as_bytes());
    let base = format!(
        "{}/domains/{}/roots/{}",
        h.ledger.namespace(),
        part(&g.conflict_domain),
        part(&g.root_id)
    );
    let native: kedgeflow::ledger::Attempt = serde_json::from_slice(
        &h.ledger
            .read_key(&format!("{base}/attempts/{}", part(id)))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(native.status, report["status"].as_str().unwrap());
    assert_eq!(
        h.ledger
            .read_key(&format!("{base}/outbox/{}", part(id)))
            .await
            .unwrap()
            .unwrap(),
        native.status.as_bytes()
    );
    assert_eq!(report["intent"]["attempt_id"], id);
    assert_eq!(report["intent"]["grant_digest"], verified.digest);
    drop(backend_lock);
    if mode == "missing-writer" || mode == "backend-locked" {
        assert_eq!(report["status"], "unknown");
        assert_eq!(report["intent"]["state"], "unknown");
        if mode == "missing-writer" {
            std::fs::rename(secret.join("writer.saved"), secret.join("writer.token")).unwrap();
        }
        assert_eq!(
            std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap(),
            before
        );
    } else {
        assert_eq!(report["status"], "committed", "{report}");
        assert_eq!(report["observed_postcondition"], true);
    }
    let stable = std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap();
    if mode == "missing-writer" || mode == "backend-locked" {
        // The original obstacle is gone and writer access is available. A retry
        // must still query the retained unknown rather than launch Terraform.
        let retry = cli(
            &config,
            &root,
            &["execute", "--request", request_path.to_str().unwrap()],
            false,
        )
        .await;
        assert!(
            retry.status.success(),
            "{}",
            String::from_utf8_lossy(&retry.stderr)
        );
        let retry: Value = serde_json::from_slice(&retry.stdout).unwrap();
        assert_eq!(retry["intent"], report["intent"]);
        assert_eq!(retry["replayed"], true);
        assert_eq!(
            std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap(),
            stable
        );
    }
    assert!(broker.authorize(&exchange, &gateway).await.is_err());
    assert!(matches!(
        h.ledger.claim(g, &verified.digest, "replacement").await,
        Err(kedgeflow::error::Error::NonceConsumed)
    ));
    // Recovery remains query-only even after current authority and writer access
    // disappear. It cannot acquire another execution opportunity.
    h.revoke(RevocationTarget::Domain).await;
    std::fs::rename(secret.join("writer.token"), secret.join("writer.saved")).unwrap();
    let replay = cli(
        &config,
        &root,
        &["execute", "--request", request_path.to_str().unwrap()],
        false,
    )
    .await;
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["intent"], report["intent"]);
    assert_eq!(replay["replayed"], true);
    assert_eq!(
        std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap(),
        stable
    );
    assert!(broker.authorize(&exchange, &gateway).await.is_err());
    assert!(
        h.ledger
            .claim(g, &verified.digest, "replacement")
            .await
            .is_err()
    );
    let mut altered = request;
    altered.parameters["effect_digest"] = json!("a".repeat(64));
    let altered_path = write(&root, "altered.json", serde_json::to_vec(&altered).unwrap());
    assert!(
        !cli(
            &config,
            &root,
            &["execute", "--request", altered_path.to_str().unwrap()],
            false
        )
        .await
        .status
        .success()
    );
    std::fs::write(
        public_output.join("native-report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "TERRAFORM APPLY PASS: mode={mode}; fresh Cedar admission and issuer, one original claim/permit/intent; shipping CLI query and exact replay do not reapply; status={}",
        report["status"]
    );
}
#[tokio::test]
async fn native_real_plan_original_apply_and_lost_reply() {
    run("lost-reply").await;
}
#[tokio::test]
async fn native_real_plan_revocation_before_intent_refuses() {
    run("revoked").await;
}
#[tokio::test]
async fn native_real_plan_missing_writer_keeps_unknown_without_retry() {
    run("missing-writer").await;
}
#[tokio::test]
async fn native_real_plan_backend_lock_keeps_unknown_without_reapply() {
    run("backend-locked").await;
}
#[tokio::test]
async fn native_real_plan_changed_backend_refuses_before_intent() {
    run("backend-drift").await;
}
