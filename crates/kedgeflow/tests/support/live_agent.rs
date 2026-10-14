//! Actual official SDK + Node Agent Adapter across native mTLS services and
//! real etcd. Evidence, broker and guarded target are explicit software fixtures.
use super::*;
use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use kedgeflow::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::{Authenticator, Identity, WorkloadIdentity},
    broker::{CredentialBroker, TargetCredential},
    clock::Clock,
    control::{ControlPermissions, ControlService},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    gateway::{Gateway, Request, VerifiedCall},
};
use std::sync::atomic::AtomicUsize;
use tokio::{sync::Mutex, time::Instant};

pub(super) struct ClockedAuth(pub(super) DualAuthenticator, pub(super) Arc<TestClock>);
#[async_trait]
impl Authenticator for ClockedAuth {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
        workload: &WorkloadIdentity,
    ) -> Result<Identity> {
        self.0
            .authenticate_at(headers, workload, self.1.now_ms() / 1000)
    }
}
struct Broker(AtomicUsize, Arc<TestClock>);
#[async_trait]
impl CredentialBroker for Broker {
    async fn exchange(&self, c: &VerifiedCall, _: Instant) -> Result<TargetCredential> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(TargetCredential {
            token: "software-target-only".into(),
            audience: "mock-target".into(),
            expires_at_ms: c.grant.expires_at.min(self.1.now_ms() + 3000),
        })
    }
}
pub(super) struct Target {
    pub(super) calls: AtomicUsize,
    pub(super) effects: AtomicUsize,
    pub(super) state: Mutex<(u64, u64, i64)>,
}
#[async_trait]
impl ResourceAdapter for Target {
    async fn dispatch(
        &self,
        c: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_ne!(credential.token, c.identity.access_token);
        let mut state = self.state.lock().await;
        if c.request.params.arguments["expected_version"] != state.0 || c.grant.fence <= state.1 {
            return Ok(AdapterResult {
                status: "state_guard_violation".into(),
                result: json!({"resultType":"complete","content":[]}),
            });
        }
        state.0 += 1;
        state.1 = c.grant.fence;
        state.2 -= 1;
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            status: "committed".into(),
            result: json!({"resultType":"complete","isError":false,"content":[],"structuredContent":{"reserved":true,"kedgeflow_terminal_receipt":{"attempt_id":c.attempt_id,"grant_digest":c.grant_digest,"resource":c.grant.resources[0],"fence":c.grant.fence,"status":"committed","post_version":state.0}}}),
        })
    }
    async fn read(&self, _: &Request, _: &Identity) -> Result<Value> {
        Err(Error::Refused("no read action registered".into()))
    }
}
pub(super) struct Running(pub(super) tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) struct Provider {
    pub(super) auth: DualAuthenticator,
    pub(super) clock: Arc<TestClock>,
    pub(super) evidence: Value,
    pub(super) policy: kedgeflow::contracts::Policy,
    pub(super) descriptor_digest: String,
    pub(super) calls: AtomicUsize,
    pub(super) baseline_calls: AtomicUsize,
    pub(super) target: Arc<Target>,
    pub(super) resource: kedgeflow::contracts::Resource,
}
pub(super) async fn evidence(
    State(p): State<Arc<Provider>>,
    Extension(workload): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let identity = p
        .auth
        .authenticate_at(&headers, &workload, p.clock.now_ms() / 1000)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !identity.scopes.contains("kf.evidence") || workload.as_str() != "spiffe://test/agent" {
        return Err(StatusCode::FORBIDDEN);
    }
    let observed = *p.target.state.lock().await;
    let state_digest = kedgeflow::contracts::digest(
        "mock-state",
        &json!({"version":observed.0,"available_slots":observed.2}),
    )
    .unwrap();
    if body["operation"] == "baseline" {
        if body["parameters"]
            .get("node")
            .or_else(|| body["parameters"].get("resource_id"))
            != Some(&json!(p.resource.id))
        {
            return Err(StatusCode::FORBIDDEN);
        }
        p.baseline_calls.fetch_add(1, Ordering::SeqCst);
        return Ok(Json(
            json!({"resource":p.resource,"version":observed.0.to_string(),"observed_at":p.clock.now_ms(),"expires_at":p.clock.now_ms()+60000,"state_digest":state_digest}),
        ));
    }
    let raw = body["proposal"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let proposal = kedgeflow::schema::verify_record(raw.as_bytes(), "proposal", &keys(1))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let hash = kedgeflow::contracts::record_digest(&proposal).unwrap();
    if body["proposal_digest"] != hash
        || proposal.payload["action"]["digest"] != p.descriptor_digest
        || proposal.payload["parameters"]["expected_version"] != 241
        || proposal.payload["subject"] != serde_json::to_value(&identity.subject).unwrap()
    {
        return Err(StatusCode::FORBIDDEN);
    }
    p.calls.fetch_add(1, Ordering::SeqCst);
    let mut witness = p.evidence.clone();
    witness["proposal_digest"] = json!(hash);
    witness["state_digest"] = json!(state_digest);
    witness["observed_at"] = json!(p.clock.now_ms());
    witness["expires_at"] = json!(p.clock.now_ms() + 30000);
    witness["result"]["version"] = json!(observed.0.to_string());
    witness["result"]["available_slots"] = json!(observed.2);
    witness["result"]["minimum_after"] = json!(observed.2 - 1);
    let signed = fixture::signed("evidence", witness.clone(), 4);
    let manifest = fixture::signed(
        "manifest",
        json!({"mid":"live-provider-manifest","proposal_digest":hash,"policy":p.policy,"witnesses":[{"witness":{"id":witness["wid"],"schema":"https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/Evidence","digest":fixture::record_hash(&signed)},"obligation_id":"capacity","execution_relevant":true,"expires_at":witness["expires_at"]}],"assembled_at":p.clock.now_ms()}),
        3,
    );
    Ok(Json(
        json!({"manifest":String::from_utf8(manifest).unwrap(),"witnesses":[String::from_utf8(signed).unwrap()]}),
    ))
}

async fn run(mode: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !root
        .join("tests/sdk/node_modules/@modelcontextprotocol/client/package.json")
        .is_file()
    {
        assert_ne!(
            std::env::var("KF_REQUIRE_SDK").as_deref(),
            Ok("1"),
            "required pinned SDK missing"
        );
        eprintln!("SKIP live SDK: run npm ci --prefix tests/sdk");
        return;
    }
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!("https://{}/mcp", gateway_listener.local_addr().unwrap());
    let leased = mode.starts_with("lease:");
    let configure: fn(&mut Fixture) = if leased {
        lease_agent::configure
    } else {
        |_| {}
    };
    let Some(mut h) = Harness::with_setup(Some(&gateway_url), NOW, configure).await else {
        return;
    };
    let reserved = mode.starts_with("reserved");
    let audited = mode == "reserved-v2";
    let wire_mode = if mode == "reserved" || audited {
        "normal"
    } else {
        mode.strip_prefix("reserved:").unwrap_or(mode)
    };
    if reserved {
        let mut r = super::reserved_leaf::registration(&h, 1);
        if audited {
            r.profile = kedgeflow::reservation_history::LEAF_PROFILE.into();
        }
        h.ledger = h.ledger.clone().with_reservation(r).unwrap();
        h.ledger.enroll_reservation().await.unwrap();
    }
    if leased {
        h.ledger
            .enroll_lease_member(&h.f.trust, &h.f.identity.subject)
            .await
            .unwrap();
    }
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let leaf = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", leaf.local_addr().unwrap());
    let admit_url = format!("{origin}/admit");
    let issue_url = format!("{origin}/issue");
    let status_url = format!("{origin}/status");
    let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_url = format!(
        "https://{}/evidence",
        provider_listener.local_addr().unwrap()
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
    let mut service = ControlService::new(
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
                grants: GrantVerifier {
                    keys: keys(5),
                    audience: gateway_url.clone(),
                },
            },
            "key-5".into(),
            SigningKey::from_bytes(&[5; 32]),
        )
        .unwrap(),
        h.ledger.clone(),
        h.clock.clone(),
        auth(&admit_url),
        auth(&issue_url),
        ControlPermissions {
            subjects: vec![h.f.identity.subject.clone()],
            admission_scope: "kf.admit".into(),
            issuance_scope: "kf.issue".into(),
        },
    )
    .unwrap()
    .with_status(auth(&status_url), "kf.status".into())
    .unwrap();
    let lease_url = format!("{origin}/leases");
    if leased {
        service = service
            .with_leases(auth(&lease_url), "kf.lease".into())
            .unwrap();
    }
    let service = Arc::new(service);
    let broker = Arc::new(Broker(AtomicUsize::new(0), h.clock.clone()));
    let target = Arc::new(Target {
        calls: AtomicUsize::new(0),
        effects: AtomicUsize::new(0),
        state: Mutex::new((241, 0, 3)),
    });
    let mut tool = h.tool();
    tool.admission_endpoint = admit_url.clone();
    let gateway = Arc::new(Gateway {
        verifier: GrantVerifier {
            keys: keys(5),
            audience: gateway_url.clone(),
        },
        ledger: Arc::new(h.ledger.clone()),
        auth: Arc::new(ClockedAuth(auth(&gateway_url), h.clock.clone())),
        broker: broker.clone(),
        adapter: target.clone(),
        resolver: None,
        tools: BTreeMap::from([(tool.name.clone(), tool.clone())]),
        timeout: Duration::from_secs(5),
        clock: h.clock.clone(),
    });
    let provider = Arc::new(Provider {
        auth: auth(&evidence_url),
        clock: h.clock.clone(),
        evidence: h.f.evidence.clone(),
        policy: h.f.trust.policy.clone(),
        descriptor_digest: h.f.trust.descriptor_digest.clone(),
        calls: AtomicUsize::new(0),
        baseline_calls: AtomicUsize::new(0),
        target: target.clone(),
        resource: h.registration.scope.resource.clone(),
    });
    let tls = kedgeflow::tls::server_config_pem(
        h.agent_pki.server.as_bytes(),
        h.agent_pki.server_key.as_bytes(),
        h.agent_pki.ca.as_bytes(),
    )
    .unwrap();
    let gateway_tls = tls.clone();
    let gateway_endpoint = EndpointPolicy::new(&gateway_url).unwrap();
    let gateway_task = Running(tokio::spawn(async move {
        kedgeflow::server::serve(gateway_listener, gateway_tls, gateway, gateway_endpoint)
            .await
            .unwrap();
    }));
    let leaf_task = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(leaf, tls, service.router())
            .await
            .unwrap();
    }));
    let provider_tls = kedgeflow::tls::server_config_pem(
        h.agent_pki.server.as_bytes(),
        h.agent_pki.server_key.as_bytes(),
        h.agent_pki.ca.as_bytes(),
    )
    .unwrap();
    let lease_provider = Arc::new(lease_agent::LeaseProvider {
        base: provider.clone(),
        static_rule: h.f.trust.evidence.get("eligibility").cloned(),
        static_calls: AtomicUsize::new(0),
    });
    let provider_router = if leased {
        Router::new()
            .route("/evidence", post(lease_agent::evidence))
            .with_state(lease_provider.clone())
    } else {
        Router::new()
            .route("/evidence", post(evidence))
            .with_state(provider.clone())
    };
    let _provider_task = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(provider_listener, provider_tls, provider_router)
            .await
            .unwrap();
    }));
    let _gateway_task = gateway_task;
    let _leaf_task = leaf_task;
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("live-agent.json");
    let public = |n| json!({format!("key-{n}"): URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
    let token = |scope: &str, time: i64| {
        jwt(
            json!({"alg":"EdDSA","typ":"at+jwt"}),
            json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":AUD,"exp":time/1000+60,"iat":time/1000,"scope":scope,"cnf":{"jkt":jkt}}),
            7,
        )
    };
    let mut config = json!({"mode":wire_mode,"now":NOW,"token":token("capacity.reserve kf.admit kf.issue kf.status kf.evidence", NOW),"storeDirectory":directory.path().join("operations"),"evidenceUrl":evidence_url,"tls":{"ca":h.agent_pki.ca,"cert":h.agent_pki.client,"key":h.agent_pki.client_key},"proposalTemplate":h.f.proposal,
        "config":{"gatewayUrl":gateway_url,"admissionUrl":admit_url,"issuanceUrl":issue_url,"statusUrl":status_url,"delegationAudience":AUD,"workloadId":"spiffe://test/agent","subject":h.f.identity.subject,"tenant":h.f.trust.tenant,"toolName":tool.name,"descriptor":String::from_utf8(fixture::signed("ctd",h.f.descriptor.clone(),2)).unwrap(),"descriptorDigest":h.f.trust.descriptor_digest,"registryKeys":public(2),"proposalKeys":public(1),"manifestKeys":public(3),"evidenceKeys":public(4),"admissionKeys":public(6),"issuerKeys":public(5),"proposalKeyId":"key-1","authorizationKey":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes())}});
    if leased {
        config["token"] = json!(token(
            "capacity.reserve kf.admit kf.issue kf.status kf.evidence kf.lease",
            NOW
        ));
        config["config"]["leases"] = lease_agent::registration(&h, &lease_url);
        lease_agent::qualify(mode, &h, &mut config, &provider, &lease_provider, &file).await;
        return;
    }
    let run_node = || {
        let node = std::env::var("KF_SDK_NODE").unwrap_or_else(|_| "node".into());
        let script = root.join("tests/sdk/live-agent.mjs");
        let file = file.clone();
        async move {
            let output = tokio::time::timeout(
                Duration::from_secs(25),
                tokio::process::Command::new(node)
                    .arg(script)
                    .arg(file)
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(
                output.status.success(),
                "live SDK failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["status"], "PASS");
            println!("{}", String::from_utf8_lossy(&output.stdout));
            result
        }
    };
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let expected_effects = usize::from(matches!(wire_mode, "normal" | "lost"));
    let expected_state = if wire_mode == "provider-lost" {
        "unissued"
    } else if expected_effects == 0 {
        "unclaimed"
    } else {
        "committed"
    };
    config["expectedState"] = json!(expected_state);
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let first = run_node().await;
    assert_eq!(target.effects.load(Ordering::SeqCst), expected_effects);
    assert_eq!(target.calls.load(Ordering::SeqCst), expected_effects);
    assert_eq!(broker.0.load(Ordering::SeqCst), expected_effects);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.baseline_calls.load(Ordering::SeqCst), 1);
    // A separate Node process has no session/operation memory. It resolves the
    // same consumed grant after expiry with a renewed status-only delegation.
    if reserved {
        h.ledger.stop_reservation().await.unwrap();
        if audited {
            super::reserved_history::sdk_finalize(&h, &first).await;
        }
        let r = super::reserved_leaf::registration(&h, 1);
        let state = kedgeflow::coordination::Coordination::new(h.ledger.clone(), &r.root_id)
            .unwrap()
            .status()
            .await
            .unwrap();
        assert!(!state.active);
        assert_eq!(state.allocations.len(), 1);
        let a = state.allocations.values().next().unwrap();
        assert_eq!(
            a.state,
            if expected_effects == 0 {
                kedgeflow::coordination::ReservationState::Allocated
            } else if audited {
                kedgeflow::coordination::ReservationState::Committed
            } else {
                kedgeflow::coordination::ReservationState::Unknown
            }
        );
        assert_eq!(a.attempt_id.as_deref(), first["attempt_id"].as_str());
        assert_eq!((a.forward, a.compensation), (1, 1));
    }
    h.revoke(RevocationTarget::Domain).await;
    let resumed_at = NOW + if expected_effects == 0 { 61000 } else { 6000 };
    h.clock.0.store(resumed_at, Ordering::SeqCst);
    config["mode"] = json!("resume");
    config["now"] = json!(resumed_at);
    config["token"] = json!(token("kf.status", resumed_at));
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let resumed = run_node().await;
    assert_eq!(resumed["attempt_id"], first["attempt_id"]);
    assert_eq!(resumed["grant_digest"], first["grant_digest"]);
    assert_eq!(target.effects.load(Ordering::SeqCst), expected_effects);
    assert_eq!(target.calls.load(Ordering::SeqCst), expected_effects);
    assert_eq!(broker.0.load(Ordering::SeqCst), expected_effects);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.baseline_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn official_agent_acquires_live_admission_and_resolves_expired_status_after_restart() {
    run("normal").await;
}
#[tokio::test]
async fn official_agent_lost_execution_reply_resolves_without_second_effect() {
    run("lost").await;
}

#[tokio::test]
async fn official_agent_lost_issuer_reply_resolves_unclaimed_after_expiry_and_restart() {
    run("issuer-lost").await;
}
#[tokio::test]
async fn official_agent_failed_grant_persistence_resolves_without_dispatch() {
    run("persistence-lost").await;
}
#[tokio::test]
async fn official_agent_lost_provider_reply_resolves_unissued_without_recollection() {
    run("provider-lost").await;
}

#[path = "lease_agent.rs"]
mod lease_agent;

#[tokio::test]
async fn reserved_leaf_official_sdk_native_tls_claim_and_query_only_restart() {
    run("reserved").await;
}

#[tokio::test]
async fn reserved_leaf_official_sdk_lost_execution_reply_preserves_original_claim() {
    run("reserved:lost").await;
}
#[tokio::test]
async fn reserved_leaf_official_sdk_lost_issuer_reply_preserves_unclaimed_allocation() {
    run("reserved:issuer-lost").await;
}

#[tokio::test]
async fn reserved_history_official_sdk_native_receipt_refinement_and_offline_audit() {
    run("reserved-v2").await;
}
