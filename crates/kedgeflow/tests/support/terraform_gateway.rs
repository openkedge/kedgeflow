//! Official SDK through the shipping protected gateway and broker binaries.
//! Fresh generated identity/evidence roles; real saved plan, backend and target.
use super::*;
use kedgeflow::{
    auth::DualAuthenticator,
    contracts::{Grant, canonical},
    control::{ControlPermissions, ControlService},
    issuance::{GrantAuthority, IssuanceVerifier},
    policy::{AdmissionController, CedarAdmissionPolicy},
    terraform_adapter,
};
use std::sync::atomic::AtomicUsize;
use tokio::sync::Mutex;
#[path = "terraform_backend.rs"]
mod backend;
#[path = "terraform_fault.rs"]
mod fault;

struct Native {
    origin: String,
    claims: AtomicUsize,
    permits: AtomicUsize,
    dispatches: AtomicUsize,
    intents: AtomicUsize,
    intent_requests: AtomicUsize,
    intent_outcomes: AtomicUsize,
    outcomes: AtomicUsize,
    boundary: Arc<fault::Boundary>,
}
async fn native(
    State(n): State<Arc<Native>>,
    Extension(w): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(v): Json<Value>,
) -> std::result::Result<Json<Value>, axum::http::StatusCode> {
    assert!(["spiffe://test/gateway", "spiffe://test/broker"].contains(&w.as_str()));
    assert_eq!(headers["authorization"], "fixture-terraform-ledger-token");
    if fault::has_write(&v, "started") {
        n.intent_requests.fetch_add(1, Ordering::SeqCst);
    }
    n.boundary.before(&v).await?;
    n.boundary.forwarding(&v).await;
    let answer: Value = reqwest::Client::new()
        .post(format!("{}/v3/kv/txn", n.origin))
        .json(&v)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    if answer["succeeded"] == true {
        for row in v["success"].as_array().into_iter().flatten() {
            if let Some(put) = row.get("request_put") {
                let key = String::from_utf8(STANDARD.decode(put["key"].as_str().unwrap()).unwrap())
                    .unwrap();
                let value = STANDARD.decode(put["value"].as_str().unwrap()).unwrap();
                if key.contains("/nonces/") {
                    n.claims.fetch_add(1, Ordering::SeqCst);
                }
                if key.ends_with("/credential-permit") {
                    n.permits.fetch_add(1, Ordering::SeqCst);
                }
                if key.contains("/outbox/") && value == b"dispatch_authorized" {
                    n.dispatches.fetch_add(1, Ordering::SeqCst);
                }
                if key.contains("/outbox/")
                    && [b"committed".as_slice(), b"unknown", b"not_dispatched"]
                        .contains(&value.as_slice())
                {
                    n.outcomes.fetch_add(1, Ordering::SeqCst);
                }
                if (key.contains("/terraform/") || key.contains("/terraform-pair/"))
                    && key.ends_with("/intent")
                    && serde_json::from_slice::<Value>(&value).unwrap()["state"] == "started"
                {
                    n.intents.fetch_add(1, Ordering::SeqCst);
                }
                if (key.contains("/terraform/") || key.contains("/terraform-pair/"))
                    && key.ends_with("/intent")
                    && serde_json::from_slice::<Value>(&value).unwrap()["state"] != "started"
                {
                    n.intent_outcomes.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }
    n.boundary.after(&v, &answer).await?;
    Ok(Json(answer))
}
fn counts(n: &Native) -> [usize; 4] {
    [&n.claims, &n.permits, &n.dispatches, &n.intents].map(|v| v.load(Ordering::SeqCst))
}
async fn serve(
    listener: tokio::net::TcpListener,
    pki: &support::Pki,
    router: Router,
) -> live_agent::Running {
    let tls = tls::server_config_pem(
        pki.server.as_bytes(),
        pki.server_key.as_bytes(),
        pki.ca.as_bytes(),
    )
    .unwrap();
    live_agent::Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, tls, router)
            .await
            .unwrap()
    }))
}
async fn spawn(bin: &str, root: &Path, config: &Path, log: &str) -> tokio::process::Child {
    let out = std::fs::File::create(root.join(log)).unwrap();
    let mut command = tokio::process::Command::new(bin);
    command
        .arg("--config")
        .arg(config)
        .arg("--custody-root")
        .arg(root)
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .kill_on_drop(true);
    command.spawn().unwrap()
}
async fn ready(
    address: std::net::SocketAddr,
    child: &mut tokio::process::Child,
    root: &Path,
    log: &str,
) {
    let started = tokio::time::Instant::now();
    // Startup can run two separately bounded 20-second local inspections.
    // This wait does not extend a grant or any execution/dispatch deadline.
    for _ in 0..450 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "shipping service exited {status}: {}",
                std::fs::read_to_string(root.join(log)).unwrap()
            );
        }
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            eprintln!(
                "FIXTURE {log} listener ready in {} ms",
                started.elapsed().as_millis()
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "service {log} did not listen within 45 seconds: {}",
        std::fs::read_to_string(root.join(log)).unwrap()
    );
}
async fn node(root: &Path, config: &Path) -> Value {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = tokio::time::timeout(
        Duration::from_secs(90),
        tokio::process::Command::new(
            std::env::var("KF_SDK_NODE").unwrap_or_else(|_| "node".into()),
        )
        .arg(repo.join("tests/sdk/live-agent.mjs"))
        .arg(config)
        .kill_on_drop(true)
        .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "SDK failed: {}\ngateway: {}\nbroker: {}",
        String::from_utf8_lossy(&output.stderr),
        std::fs::read_to_string(root.join("gateway.log")).unwrap_or_default(),
        std::fs::read_to_string(root.join("broker.log")).unwrap_or_default()
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
async fn run(mode: &str) {
    run_profile(mode, false).await;
}
async fn run_profile(mode: &str, is_pair: bool) {
    use crate::terraform_pair_execution::{audit, certify_audit, restore_second_write};
    use kedgeflow::{terraform_pair, terraform_pair_apply as pair};
    let Ok(capsule) = std::env::var("KF_TERRAFORM_CAPSULE") else {
        assert_ne!(std::env::var("KF_REQUIRE_TERRAFORM").as_deref(), Ok("1"));
        eprintln!("SKIP Terraform SDK: fixture absent");
        return;
    };
    assert!(
        std::env::var("ETCD_ENDPOINT").is_ok(),
        "explicit Terraform fixture requires native etcd"
    );
    let capsule = PathBuf::from(capsule);
    let manifest_file = capsule.join("manifest.json");
    let raw = std::fs::read(&manifest_file).unwrap();
    let pair_manifest = is_pair.then(|| terraform_pair::Manifest::decode(&raw).unwrap());
    // First-member metadata is used only by the legacy fault helpers below.
    // Pair inspection and execution always use the full original capsule.
    let (m, manifest_digest, effect_digest, inspection_sha256) = if let Some(m) = &pair_manifest {
        let i = terraform_pair::inspect(&capsule, &manifest_file)
            .await
            .unwrap();
        let first = &m.members[0];
        (
            Manifest {
                profile: terraform_plan::EXECUTION_PROFILE.into(),
                terraform_version: m.terraform_version.clone(),
                provider_version: m.provider_version.clone(),
                platform: m.platform.clone(),
                workspace_id: m.workspace_id.clone(),
                backend: m.backend.clone(),
                backend_state_path: Some(m.backend_state_path.clone()),
                files: m.files.clone(),
                target: first.target.clone(),
                before_revision: first.before_revision.clone(),
                after_revision: first.after_revision.clone(),
            },
            i.manifest_digest,
            i.effect_digest,
            i.inspection_sha256,
        )
    } else {
        let m = Manifest::decode(&raw).unwrap();
        let i = terraform_plan::inspect(&capsule, &manifest_file)
            .await
            .unwrap();
        (m, i.manifest_digest, i.effect_digest, i.inspection_sha256)
    };
    let scope = if is_pair {
        pair::SCOPE
    } else {
        "terraform:apply"
    };
    let runner_profile = if is_pair {
        pair::PROFILE
    } else {
        apply::PROFILE
    };
    let adapter_profile = if is_pair {
        terraform_adapter::PAIR_PROFILE
    } else {
        terraform_adapter::PROFILE
    };
    let intent_kind = if is_pair {
        "terraform-pair"
    } else {
        "terraform"
    };
    let partial = mode.starts_with("partial");
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_address = gateway_listener.local_addr().unwrap();
    drop(gateway_listener);
    let gateway_url = format!("https://{gateway_address}/mcp");
    // Broker and gateway share the enrolled transport CA and have distinct roles.
    let mut all = support::dual_pki_for_workloads(&[
        "spiffe://test/operator",
        "spiffe://test/gateway",
        "spiffe://test/agent",
        "spiffe://test/broker",
    ]);
    let broker_pki = all.pop().unwrap();
    let pkis = all;
    let now = SystemClock.now_ms();
    let Some(h) = Harness::with_native_timing(
        Some(&gateway_url),
        now,
        |f| {
            let resource = if let Some(m) = &pair_manifest {
                json!(pair::resource(m, &manifest_digest).unwrap())
            } else {
                json!({"id":format!("terraform:{manifest_digest}"),"incarnation":m.target.uid})
            };
            configure_binding(
                f,
                resource,
                &manifest_digest,
                &effect_digest,
                if is_pair { pair::ACTION } else { apply::ACTION },
                if is_pair {
                    pair::adapter_contract()
                } else {
                    apply::adapter_contract()
                },
                scope,
            );
        },
        None,
        Some(pkis),
        None,
        None,
        Some(20000),
    )
    .await
    else {
        return;
    };
    h.clock.0.store(0, Ordering::SeqCst);
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let leaf = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let leaf_origin = format!("https://{}", leaf.local_addr().unwrap());
    let admit = format!("{leaf_origin}/admit");
    let issue = format!("{leaf_origin}/issue");
    let status = format!("{leaf_origin}/status");
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_url = format!(
        "https://{}/evidence",
        evidence_listener.local_addr().unwrap()
    );
    let auth = |url: &str| {
        DualAuthenticator::new(
            &h.f.identity.subject.iss,
            AUD,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
    };
    let grants = GrantVerifier {
        keys: keys(5),
        audience: gateway_url.clone(),
    };
    let control = Arc::new(
        ControlService::new(
            Arc::new(h.f.trust.clone()),
            AdmissionController::new(
                CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
                "key-6".into(),
                SigningKey::from_bytes(&[6; 32]),
            )
            .unwrap(),
            GrantAuthority::new(
                IssuanceVerifier {
                    tenant: h.f.trust.tenant.clone(),
                    admission_keys: keys(6),
                    grants: grants.clone(),
                },
                "key-5".into(),
                SigningKey::from_bytes(&[5; 32]),
            )
            .unwrap(),
            h.ledger.clone(),
            h.clock.clone(),
            auth(&admit),
            auth(&issue),
            ControlPermissions {
                subjects: vec![h.f.identity.subject.clone()],
                admission_scope: "kf.admit".into(),
                issuance_scope: "kf.issue".into(),
            },
        )
        .unwrap()
        .with_status(auth(&status), "kf.status".into())
        .unwrap(),
    );
    let _control = serve(leaf, &h.agent_pki, control.router()).await;
    let provider = Arc::new(live_agent::Provider {
        workload_id: h.f.identity.workload_id.clone(),
        auth: auth(&evidence_url),
        clock: h.clock.clone(),
        evidence: h.f.evidence.clone(),
        policy: h.f.trust.policy.clone(),
        descriptor_digest: h.f.trust.descriptor_digest.clone(),
        calls: AtomicUsize::new(0),
        baseline_calls: AtomicUsize::new(0),
        target: Arc::new(live_agent::Target {
            calls: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            state: Mutex::new((1, 0, 3)),
        }),
        resource: h.registration.scope.resource.clone(),
    });
    let _provider = serve(
        evidence_listener,
        &h.agent_pki,
        Router::new()
            .route("/evidence", post(live_agent::evidence))
            .with_state(provider.clone()),
    )
    .await;
    let ledger_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ledger_url = format!("https://{}", ledger_listener.local_addr().unwrap());
    let metrics = Arc::new(Native {
        origin: std::env::var("ETCD_ENDPOINT").unwrap(),
        claims: AtomicUsize::new(0),
        permits: AtomicUsize::new(0),
        dispatches: AtomicUsize::new(0),
        intents: AtomicUsize::new(0),
        intent_requests: AtomicUsize::new(0),
        intent_outcomes: AtomicUsize::new(0),
        outcomes: AtomicUsize::new(0),
        boundary: Arc::new(fault::Boundary::new(mode)),
    });
    let _ledger = serve(
        ledger_listener,
        &h.gateway_pki,
        Router::new()
            .route("/v3/kv/txn", post(native))
            .with_state(metrics.clone()),
    )
    .await;
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_address = broker_listener.local_addr().unwrap();
    drop(broker_listener);
    let broker_url = format!("https://{broker_address}/exchange");
    let mut tool = h.tool();
    tool.admission_endpoint = admit.clone();
    let secret = PathBuf::from(std::env::var("KF_TERRAFORM_SECRET_ROOT").unwrap());
    let target_audience = "https://terraform-runner.test/apply";
    let pins = apply::Pins {
        profile: runner_profile.into(),
        material_root: capsule.clone(),
        manifest_file,
        backend_root: PathBuf::from(std::env::var("KF_TERRAFORM_BACKEND_ROOT").unwrap()),
        secret_root: secret.clone(),
        writer_token_file: secret.join("writer.token"),
        observer_token_file: secret.join("observer.token"),
        manifest_digest: manifest_digest.clone(),
        effect_digest: effect_digest.clone(),
        inspection_sha256: inspection_sha256.clone(),
        tool: tool.clone(),
        parameter_schema: h.f.descriptor["parameter_schema"].clone(),
        gateway_workload: "spiffe://test/gateway".into(),
        target_audience: target_audience.into(),
        target_scope: scope.into(),
    };
    let ca = write(&root, "ca.pem", &h.gateway_pki.ca);
    let cert = write(&root, "gateway.pem", &h.gateway_pki.client);
    let key = write(&root, "gateway.key", &h.gateway_pki.client_key);
    let broker_cert = write(&root, "broker.pem", &broker_pki.client);
    let broker_key = write(&root, "broker.key", &broker_pki.client_key);
    let native_token = write(&root, "ledger.token", "fixture-terraform-ledger-token");
    let public = |n: u8| json!({format!("key-{n}"):STANDARD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let mut identity = exchange::Fixture::new();
    identity.snapshot.issuer = h.f.identity.subject.iss.clone();
    identity.snapshot.subject_audience = AUD.into();
    identity.snapshot.actor_audience = broker_url.clone();
    identity.snapshot.not_before = now;
    identity.snapshot.expires_at = now + 180000;
    identity.snapshot.subject_keys[0].kid = "key-7".into();
    identity.snapshot.subject_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    identity.snapshot.subject_keys[0].not_before = now;
    identity.snapshot.subject_keys[0].expires_at = now + 180000;
    identity.snapshot.actor_keys[0].not_before = now;
    identity.snapshot.actor_keys[0].expires_at = now + 180000;
    identity.snapshot.registrations[0].subject = h.f.identity.subject.clone();
    identity.snapshot.registrations[0].allowed_scopes =
        format!("{scope} kf.admit kf.issue kf.status kf.evidence")
            .split_whitespace()
            .map(String::from)
            .collect();
    let actor = identity.actor_token(
        json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),
        json!({"sub":"spiffe://test/agent","aud":broker_url,"exp":now/1000+180,"iat":now/1000}),
    );
    let broker_config=write(&root,"broker.json",serde_json::to_vec(&json!({"listen":broker_address,"external_url":broker_url,"certificate":broker_cert,"private_key":broker_key,"workload_ca":ca,"etcd_endpoint":ledger_url,"etcd_prefix":h.ledger.namespace(),"etcd_ca":ca,"etcd_certificate":broker_cert,"etcd_private_key":broker_key,"etcd_token_file":native_token,"gateway_audience":gateway_url,"delegation_audience":AUD,"grant_keys":public(5),"registration":{"gateway_workload":"spiffe://test/gateway","target_audience":target_audience,"target_scope":scope,"max_lifetime_ms":20000,"tool":tool},"identity_snapshot_file":write(&root,"identity.json",serde_json::to_vec(&identity.snapshot).unwrap()),"identity_epoch_floor_file":write(&root,"identity.floor","1"),"target_key_id":"key-29","target_signing_key_file":write(&root,"target.seed",STANDARD.encode([29;32])),"target_verification_keys":public(29),"allow_unmanaged_fixture":false,"installed_trust_digest":h.registration.trust_digest})).unwrap());
    let gateway_config=write(&root,"gateway.json",serde_json::to_vec(&json!({"listen":gateway_address,"external_url":gateway_url,"delegation_audience":AUD,"certificate":cert,"private_key":key,"workload_ca":ca,"grant_key_id":"key-5","grant_public_key_base64":public(5)["key-5"],"oidc_issuer":h.f.identity.subject.iss,"oidc_public_key_base64":public(7)["key-7"],"etcd_endpoints":[ledger_url],"etcd_prefix":h.ledger.namespace(),"etcd_ca":ca,"etcd_token_file":native_token,"require_control":true,"broker_endpoint":broker_url,"broker_ca":ca,"target_url":target_audience,"target_audience":target_audience,"target_scope":scope,"actor_workload":"spiffe://test/agent","actor_token_file":write(&root,"actor.jwt",actor),"target_ca":ca,"tools":[tool],"terraform_adapter":{"profile":adapter_profile,"pins":pins,"token_issuer":broker_url,"target_keys":public(29)}})).unwrap());
    if mode == "missing-writer" {
        std::fs::rename(secret.join("writer.token"), secret.join("writer.saved")).unwrap();
    }
    let mut broker = spawn(
        env!("CARGO_BIN_EXE_kf-broker"),
        &root,
        &broker_config,
        "broker.log",
    )
    .await;
    ready(broker_address, &mut broker, &root, "broker.log").await;
    let mut gateway = spawn(
        env!("CARGO_BIN_EXE_kf-proxy"),
        &root,
        &gateway_config,
        "gateway.log",
    )
    .await;
    ready(gateway_address, &mut gateway, &root, "gateway.log").await;
    let public_sdk = |n: u8| json!({format!("key-{n}"):URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
    let token = |scopes: &str| {
        let now = SystemClock.now_ms();
        jwt(
            json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
            json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":AUD,"exp":now/1000+120,"iat":now/1000,"scope":scopes,"cnf":{"jkt":jkt}}),
            7,
        )
    };
    let expected = if let Some(state) = fault::expected(mode) {
        state
    } else if mode == "missing-writer" || partial {
        "unknown"
    } else {
        "committed"
    };
    let mut sdk = json!({"mode":if mode=="lost" || mode=="partial-lost" {"lost"} else {"normal"},"realtime":true,"token":token(&format!("{scope} kf.admit kf.issue kf.status kf.evidence")),"expectedState":expected,"storeDirectory":root.join("operations"),"evidenceUrl":evidence_url,"tls":{"ca":h.agent_pki.ca,"cert":h.agent_pki.client,"key":h.agent_pki.client_key},"proposalTemplate":h.f.proposal,
        "config":{"gatewayUrl":gateway_url,"admissionUrl":admit,"issuanceUrl":issue,"statusUrl":status,"delegationAudience":AUD,"workloadId":"spiffe://test/agent","subject":h.f.identity.subject,"tenant":h.f.trust.tenant,"toolName":tool.name,"descriptor":String::from_utf8(fixture::signed("ctd",h.f.descriptor.clone(),2)).unwrap(),"descriptorDigest":h.f.trust.descriptor_digest,"registryKeys":public_sdk(2),"proposalKeys":public_sdk(1),"manifestKeys":public_sdk(3),"evidenceKeys":public_sdk(4),"admissionKeys":public_sdk(6),"issuerKeys":public_sdk(5),"proposalKeyId":"key-1","authorizationKey":public_sdk(7)["key-7"],"terraform":{"profile":adapter_profile,"manifestDigest":manifest_digest,"effectDigest":effect_digest,"inspectionSha256":inspection_sha256,"resource":tool.resource}}});
    if let Some(m) = &pair_manifest {
        let mut registration = sdk["config"]
            .as_object_mut()
            .unwrap()
            .remove("terraform")
            .unwrap();
        registration["members"] = json!(
            m.members
                .iter()
                .map(|m| json!({"id":m.id,"target_uid":m.target.uid}))
                .collect::<Vec<_>>()
        );
        sdk["config"]["terraformPair"] = registration;
    }
    if fault::expected(mode).is_some() {
        sdk["executeOnly"] = json!(true);
    }
    let file = write(&root, "sdk.json", serde_json::to_vec(&sdk).unwrap());
    let (first, injection) = if fault::expected(mode).is_some() {
        tokio::join!(
            node(&root, &file),
            fault::intervene(mode, &metrics, &h, &mut gateway, &root, &m)
        )
    } else {
        (node(&root, &file).await, Value::Null)
    };
    if mode == "suspend" {
        assert!(
            [
                json!("unavailable"),
                json!("dispatch_authorized"),
                json!("not_dispatched")
            ]
            .contains(&first["state"])
        );
    } else if !fault::killed(mode) {
        assert_eq!(first["state"], expected);
    }
    if is_pair {
        assert_eq!(first["guard_level"], "Level_C");
        assert_eq!(first["target_atomic"], false);
        assert_eq!(first["lost_reply_injected"], mode.ends_with("lost"));
        assert_eq!(
            first["lost_reply_bytes"].as_u64().unwrap() > 0,
            mode.ends_with("lost")
        );
    }
    let expected_counts = [
        1,
        1,
        1,
        usize::from(!matches!(
            mode,
            "revoke-at-intent" | "target-drift" | "suspend" | "backend-before-check"
        )),
    ];
    assert_eq!(counts(&metrics), expected_counts);
    let retained = fault::retained(&root);
    let verified = grants
        .verify_retained(retained["grant"].as_str().unwrap().as_bytes())
        .unwrap();
    let g: Grant = verified.grant;
    let mut native_status = h
        .ledger
        .execution_status(&g, &verified.digest)
        .await
        .unwrap();
    if mode == "suspend" {
        for _ in 0..50 {
            if native_status.state == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            native_status = h
                .ledger
                .execution_status(&g, &verified.digest)
                .await
                .unwrap();
        }
        let out = PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap());
        std::fs::write(out.join("resume-observation.json"),serde_json::to_vec_pretty(&json!({"first":first,"native_state":native_status.state,"injection":injection,"counters":fault::counters(&metrics)})).unwrap()).unwrap();
    }
    assert_eq!(native_status.state, expected);
    backend::complete(mode, &metrics, &injection, &m, g.expires_at).await;
    let intent_bytes = h
        .ledger
        .read_key(&format!(
            "{}/{}/{}/intent",
            h.ledger.namespace(),
            intent_kind,
            manifest_digest
        ))
        .await
        .unwrap();
    let intent: Value = intent_bytes
        .as_ref()
        .map(|v| serde_json::from_slice(v).unwrap())
        .unwrap_or(Value::Null);
    if expected_counts[3] == 1 {
        assert_eq!(intent["attempt_id"], json!(native_status.attempt_id));
        assert_eq!(intent["grant_digest"], verified.digest);
    } else {
        assert!(intent.is_null());
    }
    if !fault::killed(mode) && mode != "suspend" {
        assert_eq!(first["attempt_id"], json!(native_status.attempt_id));
    }
    let audit_before = if let Some(m) = &pair_manifest {
        assert_eq!(
            intent["state"],
            if partial {
                "partial_observed"
            } else {
                "applied"
            }
        );
        let events = audit(m).await;
        certify_audit(m, &events, partial);
        if partial {
            restore_second_write(m).await;
        }
        events
    } else {
        vec![]
    };
    let counters = fault::counters(&metrics);
    if fault::expected(mode).is_some() {
        fault::certify(mode, &metrics, &intent);
    }
    backend::certify(mode, &intent);
    if fault::expected(mode).is_some() {
        let out = PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap());
        std::fs::write(out.join("checkpoint-observation.json"),serde_json::to_vec_pretty(&json!({"mode":mode,"injection":injection,"native_state":native_status.state,"intent":intent,"counters":counters})).unwrap()).unwrap();
    }
    let backend = std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap();
    if gateway.try_wait().unwrap().is_none() {
        gateway.kill().await.unwrap();
        gateway.wait().await.unwrap();
    }
    broker.kill().await.unwrap();
    broker.wait().await.unwrap();
    if mode != "revoke-at-intent" {
        h.revoke(RevocationTarget::Domain).await;
    }
    let delay = (g.expires_at - SystemClock.now_ms()).max(0) as u64 + 25;
    assert!(delay < 25000);
    tokio::time::sleep(Duration::from_millis(delay)).await;
    if mode != "missing-writer" {
        std::fs::rename(secret.join("writer.token"), secret.join("writer.saved")).unwrap();
    }
    gateway = spawn(
        env!("CARGO_BIN_EXE_kf-proxy"),
        &root,
        &gateway_config,
        "gateway.log",
    )
    .await;
    ready(gateway_address, &mut gateway, &root, "gateway.log").await;
    sdk["mode"] = json!("resume");
    sdk.as_object_mut().unwrap().remove("executeOnly");
    sdk["token"] = json!(token("kf.status"));
    write(&root, "sdk.json", serde_json::to_vec(&sdk).unwrap());
    let resumed = node(&root, &file).await;
    assert_eq!(resumed["attempt_id"], json!(native_status.attempt_id));
    assert_eq!(resumed["grant_digest"], verified.digest);
    assert_eq!(counts(&metrics), expected_counts);
    assert_eq!(fault::counters(&metrics), counters);
    assert_eq!(
        h.ledger
            .read_key(&format!(
                "{}/{}/{}/intent",
                h.ledger.namespace(),
                intent_kind,
                manifest_digest
            ))
            .await
            .unwrap(),
        intent_bytes
    );
    assert_eq!(
        std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap(),
        backend
    );
    let audit_after = if let Some(m) = &pair_manifest {
        audit(m).await
    } else {
        vec![]
    };
    assert_eq!(audit_before, audit_after);
    gateway.kill().await.unwrap();
    gateway.wait().await.unwrap();
    let output = PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap());
    if is_pair {
        std::fs::write(
            output.join("audit-events.json"),
            serde_json::to_vec_pretty(&audit_before).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("audit-events-after-query.json"),
            serde_json::to_vec_pretty(&audit_after).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("sdk-registration.json"),
            serde_json::to_vec_pretty(&sdk["config"]["terraformPair"]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("sdk-descriptor.json"),
            serde_json::to_vec_pretty(&h.f.descriptor).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("sdk-grant-payload.json"),
            serde_json::to_vec_pretty(&g).unwrap(),
        )
        .unwrap();
    }
    if fault::expected(mode).is_some() {
        fault::verify_checkpoint(mode, &metrics.boundary.record().await);
    }
    std::fs::write(output.join("sdk-native-report.json"),serde_json::to_vec_pretty(&json!({"mode":mode,"pair":is_pair,"audit_before_queries":audit_before,"audit_after_queries":audit_after,"permissions_restored":partial,"retained_history_unchanged":true,"first":first,"resumed":resumed,"native_counts":{"claims":1,"permits":1,"dispatches":1,"intents":expected_counts[3]},"counters":counters,"injection":injection,"checkpoint":metrics.boundary.record().await,"intent":intent,"native_state":native_status.state,"grant_expired_at_query":SystemClock.now_ms()>=g.expires_at,"domain_revoked_at_query":true,"broker_stopped_at_query":true,"writer_absent_at_query":true,"backend_sha256":hex::encode(Sha256::digest(backend))})).unwrap()).unwrap();
    println!(
        "TERRAFORM SDK PASS: mode={mode}; official SDK; shipping gateway/broker; original claim/permit/dispatch/intent counts={expected_counts:?}; cold query after expiry/revocation without broker/writer; {expected}"
    );
}
#[tokio::test]
async fn official_sdk_shipping_gateway_and_broker_apply_then_cold_query() {
    run("normal").await;
}
#[tokio::test]
async fn official_sdk_lost_apply_reply_never_repeats_effect() {
    run("lost").await;
}
#[tokio::test]
async fn official_sdk_missing_writer_preserves_unknown_after_restart() {
    run("missing-writer").await;
}

#[tokio::test]
async fn official_sdk_pair_apply_and_cold_query() {
    run_profile("normal", true).await;
}
#[tokio::test]
async fn official_sdk_pair_lost_reply_never_reapplies() {
    run_profile("lost", true).await;
}
#[tokio::test]
async fn official_sdk_pair_partial_keeps_unknown() {
    run_profile("partial", true).await;
}
#[tokio::test]
async fn official_sdk_pair_partial_lost_keeps_unknown() {
    run_profile("partial-lost", true).await;
}
