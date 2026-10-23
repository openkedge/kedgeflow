//! Official MCP SDK, native authority/broker/gateway, shipping physical controller.
//! SQL predecessor and owner commands remain explicit host orchestration.
use super::*;
use crate::live_agent::{ClockedAuth, Running};
use axum::{
    Extension, Json, Router,
    extract::State as HttpState,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use kedgeflow::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::{Identity, WorkloadIdentity},
    broker::{Rfc8693Broker, TargetCredential, WorkloadAssertion},
    broker_authorization::{BrokerAuthorizer, BrokerRegistration, ExchangePermit},
    broker_service::BrokerService,
    control::{ControlPermissions, ControlService},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    gateway::{Gateway, Request, VerifiedCall},
    target_token::{ReferenceTokenMinter, TargetTokenMinter, TargetTokenVerifier},
};

const SCOPES: &str = "node.drain kf.admit kf.issue kf.status kf.evidence";
struct Links {
    gateway: tokio::net::TcpListener,
    control: tokio::net::TcpListener,
    provider: tokio::net::TcpListener,
    broker: tokio::net::TcpListener,
}
impl Links {
    async fn new() -> Self {
        async fn bind() -> tokio::net::TcpListener {
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap()
        }
        Self {
            gateway: bind().await,
            control: bind().await,
            provider: bind().await,
            broker: bind().await,
        }
    }
    fn gateway(&self) -> String {
        format!("https://{}/mcp", self.gateway.local_addr().unwrap())
    }
    fn broker(&self) -> String {
        format!("https://{}/exchange", self.broker.local_addr().unwrap())
    }
}
struct Actor(String);
#[async_trait::async_trait]
impl WorkloadAssertion for Actor {
    async fn assertion(&self, workload: &str) -> Result<String> {
        if workload != "spiffe://test/agent" {
            return Err(Error::Refused("fixed actor".into()));
        }
        Ok(self.0.clone())
    }
}
struct Minter(ReferenceTokenMinter, AtomicUsize);
#[async_trait::async_trait]
impl TargetTokenMinter for Minter {
    async fn mint(&self, permit: &ExchangePermit, at: i64) -> Result<String> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.mint(permit, at).await
    }
}
struct Dispatch {
    inner: kedgeflow::kube_drain_adapter::Adapter,
    calls: AtomicUsize,
    discard_reply: bool,
}
#[async_trait::async_trait]
impl ResourceAdapter for Dispatch {
    fn kube_drain_contract(&self) -> Option<&kd::Contract> {
        self.inner.kube_drain_contract()
    }
    async fn dispatch(
        &self,
        call: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let started = now();
        let result = self.inner.dispatch(call, credential).await.map_err(|error| {
            eprintln!("physical SDK original target dispatch: {error}; elapsed_ms={}; original_grant_remaining_ms={}",now()-started,call.grant.expires_at-now());
            error
        })?;
        if self.discard_reply {
            return Err(Error::Unknown(
                "fixture discards original accepted target reply at adapter boundary".into(),
            ));
        }
        Ok(result)
    }
    async fn read(&self, request: &Request, identity: &Identity) -> Result<Value> {
        self.inner.read(request, identity).await
    }
}
struct Source {
    auth: DualAuthenticator,
    api: Arc<Api>,
    contract: kd::Contract,
    descriptor: String,
    evidence: Value,
    policy: kedgeflow::contracts::Policy,
    baselines: AtomicUsize,
    collections: AtomicUsize,
}
async fn evidence(
    HttpState(s): HttpState<Arc<Source>>,
    Extension(workload): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let identity = s
        .auth
        .authenticate_at(&headers, &workload, now() / 1000)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if workload.as_str() != "spiffe://test/agent"
        || !identity.scopes.contains("kf.evidence")
        || body.as_object().is_none_or(|o| o.len() != 2)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let inventory = s
        .api
        .inventory(&s.contract)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    inventory
        .availability(&s.contract)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let parameters = json!({"node":s.contract.node.name,"expected_version":s.contract.generation});
    let resource = s.contract.resource().unwrap();
    let state_digest = s.contract.digest().unwrap();
    let at = now();
    if body["operation"] == "baseline" {
        if body["parameters"] != parameters {
            return Err(StatusCode::FORBIDDEN);
        }
        s.baselines.fetch_add(1, Ordering::SeqCst);
        return Ok(Json(
            json!({"resource":resource,"version":s.contract.generation.to_string(),"observed_at":at,"expires_at":at+30000,"state_digest":state_digest}),
        ));
    }
    let raw = body["proposal"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let proposal = kedgeflow::schema::verify_record(raw.as_bytes(), "proposal", &keys(1))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let pd = kedgeflow::contracts::record_digest(&proposal).unwrap();
    if body["proposal_digest"] != pd
        || proposal.payload["action"]["digest"] != s.descriptor
        || proposal.payload["parameters"] != parameters
        || proposal.payload["resources"] != json!([resource])
        || proposal.payload["subject"] != json!(identity.subject)
        || proposal.payload["workload_id"] != identity.workload_id
        || digest("delegation", &proposal.payload["delegation"]).unwrap()
            != identity.delegation_digest
        || proposal.payload["baseline_state"][0]["state_digest"] != state_digest
    {
        return Err(StatusCode::FORBIDDEN);
    }
    s.collections.fetch_add(1, Ordering::SeqCst);
    let mut e = s.evidence.clone();
    e["proposal_digest"] = json!(pd);
    e["state_digest"] = json!(state_digest);
    e["observed_at"] = json!(at);
    e["expires_at"] = json!(at + 30000);
    e["result"] = json!({"available_replicas":inventory.available,"minimum_available":s.contract.workload.minimum_available,"contract_generation":s.contract.generation.to_string(),"satisfied":true});
    let witness = String::from_utf8(fixture::signed("evidence", e.clone(), 4)).unwrap();
    let reference = json!({"id":e["wid"],"schema":"https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/Evidence","digest":fixture::record_hash(witness.as_bytes())});
    let manifest = json!({"mid":"actual-kube-sdk-manifest","proposal_digest":pd,"policy":s.policy,"witnesses":[{"witness":reference,"obligation_id":"capacity","execution_relevant":true,"expires_at":e["expires_at"]}],"assembled_at":at});
    Ok(Json(
        json!({"manifest":String::from_utf8(fixture::signed("manifest",manifest,3)).unwrap(),"witnesses":[witness]}),
    ))
}
struct Serving {
    config: Value,
    directory: tempfile::TempDir,
    source: Arc<Source>,
    minter: Arc<Minter>,
    dispatch: Arc<Dispatch>,
    _servers: Vec<Running>,
}
fn js_keys(n: u8) -> Value {
    json!({format!("key-{n}"):URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())})
}
fn token(h: &Harness) -> String {
    let at = now();
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
    jwt(
        json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
        json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":crate::AUD,"exp":at/1000+60,"iat":at/1000,"scope":SCOPES,"cnf":{"jkt":jkt}}),
        7,
    )
}
async fn serve(r: &Ready, process: &ProcessFixture, links: Links, discard_reply: bool) -> Serving {
    let h = &r.physical;
    let gateway_url = links.gateway();
    let broker_url = links.broker();
    let control = format!("https://{}", links.control.local_addr().unwrap());
    let admit = format!("{control}/admit");
    let issue = format!("{control}/issue");
    let status = format!("{control}/status");
    let evidence_url = format!("https://{}/evidence", links.provider.local_addr().unwrap());
    let auth = |url: &str| {
        DualAuthenticator::new(
            &h.f.identity.subject.iss,
            crate::AUD,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
    };
    let grants = || GrantVerifier {
        keys: keys(5),
        audience: gateway_url.clone(),
    };
    let issuer = GrantAuthority::new(
        IssuanceVerifier {
            tenant: h.f.trust.tenant.clone(),
            admission_keys: keys(6),
            grants: grants(),
        },
        "key-5".into(),
        SigningKey::from_bytes(&[5; 32]),
    )
    .unwrap();
    let service = Arc::new(
        ControlService::new(
            Arc::new(h.f.trust.clone()),
            AdmissionController::new(
                CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
                "key-6".into(),
                SigningKey::from_bytes(&[6; 32]),
            )
            .unwrap(),
            issuer,
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
    let mut tool = h.tool();
    tool.required_scope = h.f.trust.required_scope.clone();
    tool.admission_endpoint = admit.clone();
    let at = now();
    let mut identities = crate::exchange::Fixture::new();
    identities.snapshot.issuer = h.f.identity.subject.iss.clone();
    identities.snapshot.subject_audience = crate::AUD.into();
    identities.snapshot.actor_audience = broker_url.clone();
    identities.snapshot.not_before = at - 1000;
    identities.snapshot.expires_at = at + 120000;
    identities.snapshot.subject_keys[0].kid = "key-7".into();
    identities.snapshot.subject_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    identities.snapshot.subject_keys[0].not_before = at - 1000;
    identities.snapshot.subject_keys[0].expires_at = at + 120000;
    identities.snapshot.actor_keys[0].not_before = at - 1000;
    identities.snapshot.actor_keys[0].expires_at = at + 120000;
    identities.snapshot.registrations[0].subject = h.f.identity.subject.clone();
    identities.snapshot.registrations[0].allowed_scopes =
        SCOPES.split_whitespace().map(str::to_owned).collect();
    let actor = identities.actor_token(
        json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),
        json!({"sub":"spiffe://test/agent","aud":broker_url,"iat":at/1000,"exp":at/1000+60}),
    );
    let target = format!("{}/accept", process.endpoint);
    let minter = Arc::new(Minter(
        ReferenceTokenMinter::new(
            broker_url.clone(),
            "key-29".into(),
            SigningKey::from_bytes(&[29; 32]),
        )
        .unwrap(),
        AtomicUsize::new(0),
    ));
    let broker = Arc::new(
        BrokerService::new(
            BrokerAuthorizer::new(
                BrokerRegistration {
                    gateway_workload: "spiffe://test/gateway".into(),
                    target_audience: target.clone(),
                    target_scope: "node:drain".into(),
                    max_lifetime_ms: 5000,
                    tool: tool.clone(),
                },
                grants(),
                h.ledger.clone(),
                Arc::new(identities.provider()),
                h.clock.clone(),
            )
            .unwrap(),
            &broker_url,
            minter.clone(),
            TargetTokenVerifier::new(broker_url.clone(), keys(29)).unwrap(),
            h.clock.clone(),
        )
        .unwrap(),
    );
    let pin = r.r.composition.as_ref().unwrap().nodes[1]
        .physical
        .as_ref()
        .unwrap()
        .clone();
    let adapter = kedgeflow::kube_drain_adapter::Adapter::new(
        &target,
        process.gateway_transport.clone(),
        kedgeflow::kube_drain_adapter::Config {
            profile: kd::PROFILE.into(),
            trust: pin,
            token_issuer: broker_url.clone(),
            target_keys: public(29),
            gateway_workload: "spiffe://test/gateway".into(),
            target_audience: target.clone(),
            target_scope: "node:drain".into(),
        },
        grants(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let dispatch = Arc::new(Dispatch {
        inner: adapter,
        calls: AtomicUsize::new(0),
        discard_reply,
    });
    let gateway = Arc::new(Gateway {
        verifier: grants(),
        ledger: Arc::new(h.ledger.clone()),
        auth: Arc::new(ClockedAuth(auth(&gateway_url), h.clock.clone())),
        broker: Arc::new(
            Rfc8693Broker::new(
                &broker_url,
                target,
                "node:drain".into(),
                process.gateway_transport.clone(),
                Arc::new(Actor(actor)),
                h.clock.clone(),
                Duration::from_secs(5),
            )
            .unwrap(),
        ),
        adapter: dispatch.clone(),
        resolver: None,
        tools: BTreeMap::from([(tool.name.clone(), tool.clone())]),
        timeout: Duration::from_secs(5),
        clock: h.clock.clone(),
    });
    gateway.validate().unwrap();
    let fixture = PathBuf::from(std::env::var("KF_KUBE_FIXTURE").unwrap());
    let read_api = Arc::new(
        Api::new(
            &r.contract.api_origin,
            &r.api_ca,
            std::fs::read_to_string(fixture.join("observer.token")).unwrap(),
            Arc::new(SystemClock),
        )
        .unwrap(),
    );
    let source = Arc::new(Source {
        auth: auth(&evidence_url),
        api: read_api,
        contract: r.contract.clone(),
        descriptor: h.f.trust.descriptor_digest.clone(),
        evidence: h.f.evidence.clone(),
        policy: h.f.trust.policy.clone(),
        baselines: AtomicUsize::new(0),
        collections: AtomicUsize::new(0),
    });
    let tls = kedgeflow::tls::server_config_pem(
        h.agent_pki.server.as_bytes(),
        h.agent_pki.server_key.as_bytes(),
        h.agent_pki.ca.as_bytes(),
    )
    .unwrap();
    let controller_tls = kedgeflow::tls::server_config_pem(
        &std::fs::read(process.directory.path().join("server.pem")).unwrap(),
        &std::fs::read(process.directory.path().join("server.key")).unwrap(),
        &std::fs::read(process.directory.path().join("etcd-ca.pem")).unwrap(),
    )
    .unwrap();
    let endpoint = EndpointPolicy::new(&gateway_url).unwrap();
    let gateway_tls = tls.clone();
    let control_tls = tls.clone();
    let a = Running(tokio::spawn(async move {
        kedgeflow::server::serve(links.gateway, gateway_tls, gateway, endpoint)
            .await
            .unwrap();
    }));
    let b = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(links.control, control_tls, service.router())
            .await
            .unwrap();
    }));
    let c = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(links.broker, controller_tls, broker.router())
            .await
            .unwrap();
    }));
    let provider = source.clone();
    let d = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(
            links.provider,
            tls,
            Router::new()
                .route("/evidence", post(evidence))
                .with_state(provider),
        )
        .await
        .unwrap();
    }));
    let directory = tempfile::tempdir().unwrap();
    let cfg = json!({"mode":"normal","expectedState":if discard_reply {"unknown"} else {"accepted"},"registration":r.r,"runnerStoreDirectory":directory.path().join("runner"),"preparedDirectory":directory.path().join("prepared"),
      "physical":{"token":token(h),"storeDirectory":directory.path().join("physical"),"evidenceUrl":evidence_url,"tls":{"ca":h.agent_pki.ca,"cert":h.agent_pki.client,"key":h.agent_pki.client_key},"proposalTemplate":h.f.proposal,
       "config":{"gatewayUrl":gateway_url,"admissionUrl":admit,"issuanceUrl":issue,"statusUrl":status,"delegationAudience":crate::AUD,"workloadId":"spiffe://test/agent","subject":h.f.identity.subject,"tenant":h.f.trust.tenant,"toolName":tool.name,"descriptor":String::from_utf8(fixture::signed("ctd",h.f.descriptor.clone(),2)).unwrap(),"descriptorDigest":h.f.trust.descriptor_digest,"registryKeys":js_keys(2),"proposalKeys":js_keys(1),"manifestKeys":js_keys(3),"evidenceKeys":js_keys(4),"admissionKeys":js_keys(6),"issuerKeys":js_keys(5),"proposalKeyId":"key-1","authorizationKey":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),
       "drain":{"profile":kd::PROFILE,"contractDigest":r.contract.digest().unwrap(),"node":r.contract.node.name,"generation":r.contract.generation,"resource":r.contract.resource().unwrap()}}}});
    let mut cfg = cfg;
    for (name, f) in [
        ("predecessor", &r.sql.forward),
        ("predecessorInverse", &r.sql.inverse),
    ] {
        let mut other = cfg["physical"].clone();
        other["storeDirectory"] = json!(directory.path().join(name));
        other["proposalTemplate"] = f.f.proposal.clone();
        other["tls"] =
            json!({"ca":f.agent_pki.ca,"cert":f.agent_pki.client,"key":f.agent_pki.client_key});
        other["config"]["gatewayUrl"] = json!(f.registration.scope.audience);
        other["config"]["delegationAudience"] =
            f.f.proposal["delegation"]["token_audience"].clone();
        other["config"]["descriptor"] =
            json!(String::from_utf8(fixture::signed("ctd", f.f.descriptor.clone(), 2)).unwrap());
        other["config"]["descriptorDigest"] = json!(f.f.trust.descriptor_digest);
        other["config"].as_object_mut().unwrap().remove("drain");
        if name == "predecessorInverse" {
            let op = &r.sql.contract.forward_operation_key;
            let original: kedgeflow::ledger::IssuanceRecord = serde_json::from_slice(
                &r.sql
                    .forward
                    .ledger
                    .read_key(&format!("{}/issuance/{op}", r.r.namespace))
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            let parameters = json!({"resource_id":r.sql.pin.resource.id,"expected_version":242,"forward_grant_digest":original.grant_digest,"forward_attempt_id":format!("forward-{}",r.sql.pin.resource.id),"restore_state_digest":r.sql.contract.restore_state_digest});
            other["proposalTemplate"]["parameters"] = parameters.clone();
            other["config"]["compensation"] = json!({"profile":kedgeflow::compensation_execution::PROFILE,"contractDigest":r.sql.contract.digest().unwrap(),"parameters":parameters});
        }
        cfg[name] = other;
    }
    Serving {
        config: cfg,
        directory,
        source,
        minter,
        dispatch,
        _servers: vec![a, b, c, d],
    }
}

async fn run_node(file: PathBuf) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = tokio::time::timeout(
        Duration::from_secs(40),
        tokio::process::Command::new(
            std::env::var("KF_SDK_NODE").unwrap_or_else(|_| "node".into()),
        )
        .arg(root.join("tests/sdk/kube-drain-live.mjs"))
        .arg(file)
        .kill_on_drop(true)
        .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "official physical SDK failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn recovery_material(r: &Ready, process: &ProcessFixture) -> Value {
    let config: Value = serde_json::from_slice(&std::fs::read(&process.config).unwrap()).unwrap();
    let key = process.directory.path().join("outcome.key");
    std::fs::write(&key, STANDARD.encode([14; 32])).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    json!({
        "family":{"registration":r.r,"child_id":"child-1"},"reservation":r.r.child("child-1").unwrap().reservation,
        "etcd_endpoint":config["family"]["etcd_endpoint"],"etcd_prefix":r.r.namespace,
        "etcd_ca":config["family"]["etcd_ca"],"etcd_certificate":config["family"]["etcd_certificate"],"etcd_private_key":config["family"]["etcd_private_key"],"etcd_token_file":config["family"]["etcd_token_file"],
        "gateway_audience":r.physical.registration.scope.audience,"grant_keys":public(5),
        "query_url":format!("{}/query",process.endpoint),"query_ca":config["family"]["etcd_ca"],
        "query_certificate":process.directory.path().join("query-client.pem"),"query_private_key":process.directory.path().join("query-client.key"),"query_token_file":config["query_token_file"],
        "receipt_key_id":"key-14","receipt_signing_key_file":key,"source_id":"spiffe://test/outcome","page_size":8,"poll_interval_ms":100
    })
}
async fn run(discard_reply: bool) {
    let links = Links::new().await;
    let gateway = links.gateway();
    let broker = links.broker();
    let mut r = Box::pin(setup_physical_options(None, Some(&gateway))).await;
    let process = ProcessFixture::with_broker(
        &r,
        if discard_reply {
            Pause::AfterCas
        } else {
            Pause::PassThrough
        },
        &broker,
    )
    .await;
    let mut child = process.start().await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let mut serving = serve(&r, &process, links, discard_reply).await;
    serving.config["state"] = json!(r.saga.status().await.unwrap());
    // SQL/owner fixture preparation can outlast the installation's ordinary
    // ten-second ACK. Renew it before any SDK admission or original grant.
    // This does not extend the original five-second execution budget.
    Box::pin(refresh(&r.physical)).await;
    let file = serving.directory.path().join("sdk.json");
    std::fs::write(&file, canonical(&serving.config).unwrap()).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let first = if discard_reply {
        let mut task = tokio::spawn(run_node(file.clone()));
        let completed = tokio::select! {
            result=&mut task => {
                let result=result.unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(4),process.gate.pending.notified()).await.is_ok(),"original Pending absent; SDK={result}; controller={:?}; worker={}",r.controller.state().await,std::fs::read_to_string(process.directory.path().join("process.log")).unwrap());
                Some(result)
            },
            result=tokio::time::timeout(Duration::from_secs(15),process.gate.pending.notified()) => { result.unwrap(); None }
        };
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        process.gate.release.notify_one();
        match completed {
            Some(v) => v,
            None => task.await.unwrap(),
        }
    } else {
        run_node(file.clone()).await
    };
    assert_eq!(first["status"], "PASS");
    let op = &r.r.composition.as_ref().unwrap().nodes[1].operation_key;
    let record: kedgeflow::ledger::IssuanceRecord = serde_json::from_slice(
        &r.physical
            .ledger
            .read_key(&format!("{}/issuance/{op}", r.r.namespace))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let grant = GrantVerifier {
        keys: keys(5),
        audience: gateway,
    }
    .verify_retained(record.signed_grant.as_bytes())
    .unwrap();
    assert_eq!(first["grant_digest"], grant.digest);
    let candidate = kedgeflow::recovery::Candidate {
        grant: grant.grant,
        attempt_id: first["attempt_id"].as_str().unwrap().into(),
    };
    let mut traces = vec![first];
    let mut restarted = None;
    if discard_reply {
        assert_eq!(
            r.controller
                .state()
                .await
                .unwrap()
                .unwrap()
                .body
                .steps
                .len(),
            1
        );
        stop_root_now(&r, 401).await;
        restarted = Some(process.start().await);
    } else {
        let until = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let state = r.controller.state().await;
            let inventory = r.api.inventory(&r.contract).await.unwrap();
            if state
                .as_ref()
                .ok()
                .and_then(|s| s.as_ref())
                .is_some_and(|s| {
                    s.body.physical_status(&r.contract, &inventory).unwrap() == "observed_completed"
                })
            {
                break;
            }
            assert!(
                std::time::Instant::now() < until,
                "shipping controller did not complete original drain: {state:?}"
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
    let material = recovery_material(&r, &process);
    let recovery_file = process.directory.path().join("recovery.json");
    std::fs::write(&recovery_file, canonical(&material).unwrap()).unwrap();
    std::fs::set_permissions(&recovery_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let recovered = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-recover"))
            .arg("--config")
            .arg(&recovery_file)
            .arg("--once")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        recovered.status.success(),
        "shipping physical recovery failed: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let sweep: Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(sweep["examined"], 1);
    assert_eq!(sweep["reported"], 1);
    assert_eq!(sweep["unavailable"], 0);
    let worker = kedgeflow::recovery_config::RecoveryConfig::decode(&canonical(&material).unwrap())
        .unwrap()
        .worker()
        .await
        .unwrap();
    let receipt = worker.recover(&candidate).await.unwrap();
    assert_eq!(receipt.state, "committed"); // Native controller acceptance only.
    if discard_reply {
        let snapshot = r.physical.ledger.export_outcomes(&candidate).await.unwrap();
        let evidence = &snapshot.evidence[&receipt.evidence_digest];
        assert_eq!(evidence["kind"], "authoritative_query");
        assert!(
            evidence["observation"]["TargetReference"]
                .as_str()
                .unwrap()
                .starts_with("kube-controller-accepted:")
        );
        let remaining = candidate.grant.expires_at - now();
        if remaining > 0 {
            assert!(remaining <= 5000);
            tokio::time::sleep(Duration::from_millis(remaining as u64 + 1)).await;
        }
        serving.config["mode"] = json!("resume");
        serving.config["expectedState"] = json!("accepted");
        serving.config["physical"]["token"] = json!(token(&r.physical));
        std::fs::write(&file, canonical(&serving.config).unwrap()).unwrap();
        let resume = run_node(file).await;
        assert_eq!(resume["attempt_id"], candidate.attempt_id);
        traces.push(resume);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let state = r.controller.state().await.unwrap().unwrap();
        assert!(state.body.steps[0].response.is_none());
        assert!(r.controller.close_unstarted().await.is_err());
        assert!(
            !r.api
                .inventory(&r.contract)
                .await
                .unwrap()
                .target(&r.contract)
                .unwrap()
                .unschedulable
        );
    }
    assert_eq!(serving.minter.1.load(Ordering::SeqCst), 1);
    assert_eq!(serving.dispatch.calls.load(Ordering::SeqCst), 1);
    assert_eq!(serving.source.baselines.load(Ordering::SeqCst), 1);
    assert_eq!(serving.source.collections.load(Ordering::SeqCst), 1);
    let aggregate = r
        .saga
        .export(&super::super::super::observer("family-observer", 33))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.r.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        report.status,
        if discard_reply {
            "unresolved"
        } else {
            "forward_completed"
        }
    );
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    let name = if discard_reply {
        "kube-drain-sdk-unknown"
    } else {
        "kube-drain-sdk-completed"
    };
    retain(&r, name, &aggregate);
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        std::fs::write(PathBuf::from(out).join(name).join("wire.json"),canonical(&json!({"traces":traces,"shipping_recovery":sweep,"native_broker_mints":1,"native_adapter_dispatches":1,"provider_baselines":1,"provider_collections":1,"native_status":"committed controller acceptance","physical_status":report.nodes["child-1"].physical_status,"scope":"actual official MCP SDK, selected native family/control/broker/gateway and shipping controller; provider reads actual API with readonly SA; generated co-located identities; SQL predecessor/owner commands on host; lost case discards real accepted reply at adapter boundary"})).unwrap()).unwrap();
    }
    if let Some(ref mut child) = restarted {
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
    if !discard_reply {
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_official_sdk_native_gateway_reports_acceptance_separately_from_observed_completion()
 {
    run(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_official_sdk_lost_acceptance_reply_recovers_original_query_after_root_stop()
 {
    run(true).await;
}
