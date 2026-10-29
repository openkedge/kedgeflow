//! Shipping read-only source against actual SQL/native/Kubernetes fixture.
//! This case does not enable the shipping managed controller or SDK.
use super::*;
use axum::{
    Extension, Json, Router,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    auth::WorkloadIdentity, current_reservation as source,
    current_reservation_provider::HeadRecord, managed_drain_journal::QueryKind,
    managed_drain_preflight as preflight, managed_drain_store::Store,
};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
const QUERY: &str = "owned-current-sql-controller-credential-000000000";
const EVIDENCE: &str = "owned-current-sql-assembler-credential-0000000000";
const CONTROLLER_ETCD: &str = "owned-managed-controller-native-credential-000000000";
const SUPERVISOR_ETCD: &str = "owned-managed-supervisor-native-credential-0000000";
const OUTCOME_ETCD: &str = "owned-managed-outcome-native-credential-000000000";
const CONTROL_ETCD: &str = "owned-managed-control-native-credential-000000000";
const BROKER_ETCD: &str = "owned-managed-broker-native-credential-0000000000";
const GATEWAY_ETCD: &str = "owned-managed-gateway-native-credential-000000000";
const ETCD: &str = "owned-current-sql-native-source-credential-000000";
#[derive(Default)]
struct AckRace {
    armed: std::sync::atomic::AtomicBool,
    refused: std::sync::atomic::AtomicUsize,
}
#[derive(Default)]
struct PendingPause {
    armed: std::sync::atomic::AtomicBool,
    intercepted: std::sync::atomic::AtomicUsize,
    release: tokio::sync::Notify,
}
#[derive(Default)]
struct PreflightPause {
    armed: std::sync::atomic::AtomicBool,
    intercepted: std::sync::atomic::AtomicUsize,
    committed: std::sync::Mutex<Option<Value>>,
    release: tokio::sync::Notify,
}
struct SourceProcess {
    preflight_pause: Arc<PreflightPause>,
    pending_pause: Arc<PendingPause>,
    ack_race: Arc<AckRace>,
    directory: tempfile::TempDir,
    config: PathBuf,
    endpoint: String,
    controller: reqwest::Client,
    assembler: reqwest::Client,
    wrong: reqwest::Client,
    _relay: support::HttpsServer,
}
impl SourceProcess {
    fn command(&self, operation: &str) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-current-reservation"));
        c.arg("--material-root")
            .arg(self.directory.path().canonicalize().unwrap())
            .arg("--config")
            .arg(&self.config)
            .arg(operation)
            .kill_on_drop(true);
        c
    }
    async fn new(r: &Ready, identity: &[support::Pki], listen: std::net::SocketAddr) -> Self {
        let backend = std::env::var("ETCD_ENDPOINT").unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ack_race = Arc::new(AckRace::default());
        let race = ack_race.clone();
        let pending_pause = Arc::new(PendingPause::default());
        let pause = pending_pause.clone();
        let preflight_pause = Arc::new(PreflightPause::default());
        let preflight = preflight_pause.clone();
        let preflight_prefix = format!(
            "{}/preflight/events/",
            Store::new(r.physical.ledger.clone())
                .unwrap()
                .context
                .base()
        );
        let epoch_key = format!("{}/family/saga/epoch", r.r.namespace);
        let relay = support::serve_tls(
            &identity[2],
            Router::new().route(
                "/v3/kv/txn",
                post(
                    move |Extension(workload): Extension<WorkloadIdentity>,
                          headers: HeaderMap,
                          Json(v): Json<Value>| {
                        let backend = backend.clone();
                        let client = client.clone();
                        let race = race.clone();
                        let pause = pause.clone();
                        let epoch_key = epoch_key.clone();
                        let preflight = preflight.clone();
                        let preflight_prefix = preflight_prefix.clone();
                        async move {
                            let token = headers.get("authorization").and_then(|v| v.to_str().ok());
                            if !matches!(
                                (workload.as_str(), token),
                                ("spiffe://test/current-sql-provider", Some(ETCD))
                                    | ("spiffe://test/physical-supervisor", Some(SUPERVISOR_ETCD))
                                    | ("spiffe://test/drain-controller", Some(CONTROLLER_ETCD))
                                    | ("spiffe://test/gateway", Some(GATEWAY_ETCD))
                                    | ("spiffe://test/control-authority", Some(CONTROL_ETCD))
                                    | ("spiffe://test/token-broker", Some(BROKER_ETCD))
                                    | ("spiffe://test/outcome", Some(OUTCOME_ETCD))
                            ) {
                                return Err(StatusCode::UNAUTHORIZED);
                            }
                            let preflight_claim = if preflight.armed.load(Ordering::SeqCst)
                                && workload.as_str() == "spiffe://test/current-sql-provider"
                            {
                                v["success"].as_array().and_then(|ops| ops.iter().find_map(|op| {
                                    let key = STANDARD.decode(op["request_put"]["key"].as_str()?).ok()?;
                                    if !key.starts_with(preflight_prefix.as_bytes()) {return None;}
                                    let bytes = STANDARD.decode(op["request_put"]["value"].as_str()?).ok()?;
                                    serde_json::from_slice::<Value>(&bytes).ok()
                                }))
                            } else {None};
                            let hold_preflight = preflight_claim.is_some() && preflight.armed.swap(false,Ordering::SeqCst);
                            let pending = v["success"].as_array().is_some_and(|ops| ops.iter().any(|op| {
                                op["request_put"]["value"].as_str()
                                    .and_then(|raw| STANDARD.decode(raw).ok())
                                    .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                                    .is_some_and(|record| record["kind"] == "controller_state"
                                        && record["body"]["steps"].as_array().is_some_and(|steps|
                                            steps.last().is_some_and(|step| step["response"].is_null())))
                            }));
                            if pending && pause.armed.swap(false, Ordering::SeqCst) {
                                // A controlled transport barrier BEFORE the real native
                                // Pending CAS. After SIGKILL release a transport failure;
                                // never forward the held write or invent a native reply.
                                pause.intercepted.fetch_add(1, Ordering::SeqCst);
                                pause.release.notified().await;
                                return Err(StatusCode::SERVICE_UNAVAILABLE);
                            }
                            let acknowledgement = v["success"].as_array().is_some_and(|ops| ops.iter().any(|op| {
                                op["request_put"]["value"].as_str()
                                    .and_then(|raw| STANDARD.decode(raw).ok())
                                    .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                                    .is_some_and(|record| record["record_kind"] == "acknowledgement")
                            }));
                            let inject = acknowledgement && race.armed.swap(false, Ordering::SeqCst);
                            if inject {
                                // Change the actual native epoch after the original ACK
                                // transaction captured it. The real etcd CAS must refuse.
                                let key = STANDARD.encode(&epoch_key);
                                let read: Value = client.post(format!("{backend}/v3/kv/txn"))
                                    .json(&json!({"compare":[],"success":[{"request_range":{"key":key}}],"failure":[]}))
                                    .send().await.unwrap().json().await.unwrap();
                                let raw = read["responses"][0]["response_range"]["kvs"][0]["value"].as_str().unwrap();
                                let mut epoch: Value = serde_json::from_slice(&STANDARD.decode(raw).unwrap()).unwrap();
                                epoch["sequence"] = json!(epoch["sequence"].as_u64().unwrap()+1);
                                epoch["nonce"] = json!(hex::encode(rand::random::<[u8;32]>()));
                                let _: Value = client.post(format!("{backend}/v3/kv/txn"))
                                    .json(&json!({"compare":[{"key":key,"target":"VALUE","result":"EQUAL","value":raw}],"success":[{"request_put":{"key":key,"value":STANDARD.encode(canonical(&epoch).unwrap())}}],"failure":[]}))
                                    .send().await.unwrap().json().await.unwrap();
                            }
                            let response = client
                                .post(format!("{backend}/v3/kv/txn"))
                                .json(&v)
                                .send()
                                .await
                                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                                .json::<Value>()
                                .await
                                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                            if inject {
                                // Protobuf JSON omits false scalar defaults.
                                assert!(response.get("header").is_some());
                                assert!(!response["succeeded"].as_bool().unwrap_or(false),
                                    "native ACK epoch race must be real");
                                race.refused.fetch_add(1, Ordering::SeqCst);
                            }
                            if hold_preflight {
                                assert_eq!(response["succeeded"],true,"preflight claim must actually commit before reply loss");
                                *preflight.committed.lock().unwrap() = preflight_claim;
                                preflight.intercepted.fetch_add(1,Ordering::SeqCst);
                                preflight.release.notified().await;
                                // The source is killed while this real committed
                                // claim's reply is held. Never synthesize success.
                                return Err(StatusCode::SERVICE_UNAVAILABLE);
                            }
                            Ok(Json(response))
                        }
                    },
                ),
            ),
        )
        .await;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = directory.path().canonicalize().unwrap();
        let write = |name: &str, raw: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, raw).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let e =
            r.r.composition
                .as_ref()
                .unwrap()
                .node("child-1")
                .unwrap()
                .physical
                .as_ref()
                .unwrap()
                .operating
                .as_ref()
                .unwrap();
        let reg = &e.current_sql;
        let head = source::Signed::sign(
            "storage_head",
            source::StorageHead {
                storage_id: reg.storage.storage_id.clone(),
                generation: reg.storage.generation,
                sequence: 1,
                resource: reg.resource.clone(),
                boundary_digest: digest("sql-storage-boundary", &json!(reg.storage)).unwrap(),
                published_at: now(),
                expires_at: r.r.expires_at,
            },
            &reg.storage.owner,
            "key-95",
            &SigningKey::from_bytes(&[95; 32]),
        )
        .unwrap();
        let record = HeadRecord {
            profile: source::PROFILE.into(),
            registration_digest: reg.digest().unwrap(),
            current_digest: head.digest().unwrap(),
            minimum_sequence: 1,
            head,
        };
        let head_file = write("storage-head.json", &serde_json::to_vec(&record).unwrap());
        let ca = write("ca.pem", identity[2].ca.as_bytes());
        let cert = write("server.pem", identity[2].server.as_bytes());
        let key = write("server.key", identity[2].server_key.as_bytes());
        let ec = write("etcd-client.pem", identity[2].client.as_bytes());
        let ek = write("etcd-client.key", identity[2].client_key.as_bytes());
        let et = write("etcd.token", ETCD.as_bytes());
        let signer = write("provider.key", STANDARD.encode([94; 32]).as_bytes());
        let qt = write("query.token", QUERY.as_bytes());
        let etoken = write("evidence.token", EVIDENCE.as_bytes());
        let mut database = r.database.clone();
        database.socket_directory = std::fs::canonicalize(&database.socket_directory).unwrap();
        database.executor_user = "kf_inverse_executor".into();
        database.query_user = "kf_inverse_reader".into();
        let config=write("source.json",&serde_json::to_vec(&json!({"profile":source::PROFILE,"material_root":dir,"family":{"registration":r.r,"etcd_endpoint":relay.url,"etcd_prefix":r.r.namespace,"etcd_ca":ca,"etcd_certificate":ec,"etcd_private_key":ek,"etcd_token_file":et,"restore_gate":null},"child_id":"child-1","database":{"connection":database,"barrier_user":"kf_inverse_barrier"},"postgres_peer_uid":rustix::process::geteuid().as_raw(),"storage_head_file":head_file,"provider_key_id":"key-94","provider_key_file":signer,"query_token_file":qt,"evidence_token_file":etoken,"listen":listen,"certificate":cert,"private_key":key,"workload_ca":ca})).unwrap());
        let client = |i: &support::Pki| {
            kedgeflow::tls::pinned_http_client_pem(
                i.ca.as_bytes(),
                i.client.as_bytes(),
                i.client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap()
        };
        Self {
            preflight_pause,
            pending_pause,
            ack_race,
            directory,
            config,
            endpoint: format!("https://{listen}"),
            controller: client(&identity[0]),
            assembler: client(&identity[1]),
            wrong: client(&identity[3]),
            _relay: relay,
        }
    }
    async fn start(&self) -> tokio::process::Child {
        let check = self.command("check").output().await.unwrap();
        assert!(
            check.status.success(),
            "source check: {}",
            String::from_utf8_lossy(&check.stderr)
        );
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.path().join("source.log"))
            .unwrap();
        let mut child = self
            .command("serve")
            .stdout(std::process::Stdio::null())
            .stderr(stderr)
            .spawn()
            .unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "source exited: {}",
                std::fs::read_to_string(self.directory.path().join("source.log")).unwrap()
            );
            if self
                .controller
                .post(format!("{}/current", self.endpoint))
                .bearer_auth(QUERY)
                .json(&json!({}))
                .send()
                .await
                .is_ok()
            {
                break;
            }
            assert!(std::time::Instant::now() < until);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        child
    }
}
fn proposal_packet(h: &Harness, evidence: &kedgeflow::contracts::Envelope) -> fixture::Packet {
    let mut packet = h.f.packet();
    let mut witnesses = Vec::new();
    for (obligation, raw) in [
        ("capacity", packet.evidence[0].clone()),
        (source::OBLIGATION, canonical(&json!(evidence)).unwrap()),
    ] {
        let e: Value = serde_json::from_slice(&raw).unwrap();
        witnesses.push(json!({"witness":{"id":e["payload"]["wid"],"schema":e["schema"],"digest":fixture::record_hash(&raw)},"obligation_id":obligation,"execution_relevant":true,"expires_at":e["payload"]["expires_at"]}));
        if obligation == source::OBLIGATION {
            packet.evidence.push(raw);
        }
    }
    packet.manifest = fixture::signed(
        "manifest",
        json!({"mid":"managed-current-sql-manifest","proposal_digest":fixture::record_hash(&packet.proposal),"policy":h.f.trust.policy,"witnesses":witnesses,"assembled_at":now()}),
        3,
    );
    packet
}
async fn issue_packet(h: &Harness, packet: &fixture::Packet) -> kedgeflow::ledger::IssuanceRecord {
    let clock = SystemClock;
    let inputs =
        h.f.trust
            .verify_inputs(&h.f.identity, packet.borrowed(), &clock)
            .unwrap();
    let controller = AdmissionController::new(
        CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
        "key-6".into(),
        SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    let cert = h
        .ledger
        .admit(&controller.prepare(&inputs, &clock).unwrap(), &clock)
        .await
        .unwrap()
        .record
        .signed_certificate;
    Box::pin(crate::hierarchical_leaf::issuer(h).issue(&h.ledger, &inputs, cert.as_bytes(), &clock))
        .await
        .unwrap()
        .record
}
async fn sql_rows(r: &Ready) -> Value {
    r.sql.admin.query_one("SELECT jsonb_build_object('resource',(SELECT jsonb_agg(to_jsonb(r) ORDER BY resource_id) FROM kf_reservation.resource r WHERE tenant=$1),'forward',(SELECT jsonb_agg(to_jsonb(a) ORDER BY attempt_id) FROM kf_reservation.attempt a WHERE tenant=$1),'snapshot',(SELECT jsonb_agg(to_jsonb(s) ORDER BY contract_digest) FROM kf_compensation.snapshot s WHERE tenant=$1),'inverse',(SELECT jsonb_agg(to_jsonb(a) ORDER BY attempt_id) FROM kf_compensation.attempt a WHERE tenant=$1))", &[&r.r.tenant]).await.unwrap().get(0)
}
async fn setup_source(
    policy: Option<kedgeflow::physical_operations::Policy>,
) -> (
    Ready,
    Vec<support::Pki>,
    SourceProcess,
    tokio::process::Child,
) {
    setup_source_for(policy, "https://kube-target.test/accept".into()).await
}
async fn setup_source_for(
    policy: Option<kedgeflow::physical_operations::Policy>,
    target_audience: String,
) -> (
    Ready,
    Vec<support::Pki>,
    SourceProcess,
    tokio::process::Child,
) {
    setup_source_gateway(policy, target_audience, None).await
}
async fn setup_source_gateway(
    policy: Option<kedgeflow::physical_operations::Policy>,
    target_audience: String,
    gateway: Option<&str>,
) -> (
    Ready,
    Vec<support::Pki>,
    SourceProcess,
    tokio::process::Child,
) {
    Box::pin(setup_source_deployment(
        policy,
        target_audience,
        gateway,
        false,
    ))
    .await
}
async fn setup_source_deployment(
    policy: Option<kedgeflow::physical_operations::Policy>,
    target_audience: String,
    gateway: Option<&str>,
    all_services: bool,
) -> (
    Ready,
    Vec<support::Pki>,
    SourceProcess,
    tokio::process::Child,
) {
    assert!(!all_services || gateway.is_some());
    let mut workloads = vec![
        "spiffe://test/drain-controller",
        "spiffe://test/evidence-assembler",
        "spiffe://test/current-sql-provider",
        "spiffe://test/wrong-source-role",
        "spiffe://test/physical-supervisor",
        "spiffe://test/incident-sink",
        "spiffe://test/gateway",
        "spiffe://test/outcome",
    ];
    if all_services {
        workloads.extend([
            "spiffe://test/control-authority",
            "spiffe://test/token-broker",
            "spiffe://test/acceptance-relay",
        ]);
    }
    let identity = if gateway.is_some() {
        support::dual_pki_for_workloads(&workloads)
    } else {
        support::pki_for_workloads(&workloads)
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let transport = kedgeflow::tls::pinned_client_pem(
        identity[0].ca.as_bytes(),
        identity[0].client.as_bytes(),
        identity[0].client_key.as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let mut r = Box::pin(setup_physical_mode(
        None,
        gateway,
        Some(ManagedOptions {
            target_audience,
            policy,
            source_endpoint: format!("https://{address}/current"),
            evidence_endpoint: format!("https://{address}/evidence"),
            transport,
            token: QUERY.into(),
        }),
    ))
    .await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let process = SourceProcess::new(&r, &identity, address).await;
    drop(listener);
    let child = process.start().await;
    (r, identity, process, child)
}
#[tokio::test]
async fn kube_drain_real_managed_current_sql_shipping_source_original_binding_and_one_use_queries()
{
    let (mut r, _, process, mut child) = Box::pin(setup_source(None)).await;
    let before_rows = sql_rows(&r).await;
    fresh(&mut r.physical);
    let read_api = Api::new(
        &r.contract.api_origin,
        &r.api_ca,
        std::fs::read_to_string(
            Path::new(&std::env::var("KF_KUBE_FIXTURE").unwrap()).join("observer.token"),
        )
        .unwrap(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let inventory = read_api.inventory(&r.contract).await.unwrap();
    inventory.availability(&r.contract).unwrap();
    r.physical.f.evidence["result"] = json!({"available_replicas":inventory.available,"minimum_available":r.contract.workload.minimum_available,"contract_generation":r.contract.generation.to_string(),"satisfied":true});
    r.physical.f.evidence["observed_at"] = json!(now());
    r.physical.f.evidence["expires_at"] = json!(now() + 30000);
    let e =
        r.r.composition
            .as_ref()
            .unwrap()
            .node("child-1")
            .unwrap()
            .physical
            .as_ref()
            .unwrap()
            .operating
            .as_ref()
            .unwrap()
            .clone();
    let proposal = String::from_utf8(r.physical.f.packet().proposal).unwrap();
    let request = preflight::Request {
        profile: source::PROFILE.into(),
        enrollment_digest: e.digest().unwrap(),
        signed_proposal: proposal,
        requested_at: now(),
    };
    let bad = process
        .wrong
        .post(format!("{}/evidence", process.endpoint))
        .bearer_auth(EVIDENCE)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), reqwest::StatusCode::UNAUTHORIZED);
    for (client, token) in [(&process.assembler, QUERY), (&process.controller, EVIDENCE)] {
        let response = client
            .post(format!("{}/evidence", process.endpoint))
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
    for field in ["tenant", "qid"] {
        let mut proposal = r.physical.f.proposal.clone();
        proposal[field] = json!("substituted");
        let mut changed = request.clone();
        changed.signed_proposal =
            String::from_utf8(fixture::signed("proposal", proposal, 1)).unwrap();
        let response = process
            .assembler
            .post(format!("{}/evidence", process.endpoint))
            .bearer_auth(EVIDENCE)
            .json(&changed)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    }
    let response = process
        .assembler
        .post(format!("{}/evidence", process.endpoint))
        .bearer_auth(EVIDENCE)
        .json(&request)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let raw: Value = response.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "preflight: {raw}");
    let evidence: preflight::Evidence = serde_json::from_value(raw).unwrap();
    assert_eq!(
        evidence.statement.body.claim.sequence, 1,
        "rejected requests cannot consume source slots"
    );
    let store = Store::new(r.physical.ledger.clone()).unwrap();
    evidence
        .statement
        .validate_admission(&store.context, now())
        .unwrap();
    let repeated: Value = process
        .assembler
        .post(format!("{}/evidence", process.endpoint))
        .bearer_auth(EVIDENCE)
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(repeated, json!(evidence));
    let packet = proposal_packet(&r.physical, &evidence.evidence);
    Box::pin(refresh(&r.physical)).await;
    let record = Box::pin(issue_packet(&r.physical, &packet)).await;
    let candidate = Box::pin(native::claim(
        &r.physical,
        &record,
        "managed-source-original",
    ))
    .await;
    Box::pin(r.physical.ledger.authorize_dispatch(
        &candidate.grant,
        &record.grant_digest,
        &candidate.attempt_id,
    ))
    .await
    .unwrap();
    let reserved = store.reserve_query(QueryKind::Accept, now()).await.unwrap();
    let q = source::Query {
        profile: source::PROFILE.into(),
        enrollment_digest: e.digest().unwrap(),
        origin: reserved.origin.clone(),
        reservation_digest: reserved.slot.reservation_digest.clone(),
        requested_at: now(),
    };
    let send = || {
        process
            .controller
            .post(format!("{}/current", process.endpoint))
            .bearer_auth(QUERY)
            .json(&q)
            .send()
    };
    let (left, right) = tokio::join!(send(), send());
    let (left, right) = (left.unwrap(), right.unwrap());
    let (response, refused) = if left.status() == reqwest::StatusCode::OK {
        (left, right)
    } else {
        (right, left)
    };
    assert_eq!(refused.status(), reqwest::StatusCode::FORBIDDEN);
    let status = response.status();
    let raw: Value = response.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "query: {raw}");
    let witness: source::Witness = serde_json::from_value(raw).unwrap();
    let (_, sql) = store.context.validate_origin(&reserved.origin).unwrap();
    witness
        .validate_current(
            &e,
            &reserved.origin,
            &q.reservation_digest,
            now(),
            &sql,
            &witness.body.sql.forward_outcome.request.grant_digest,
        )
        .unwrap();
    let response = process
        .controller
        .post(format!("{}/current", process.endpoint))
        .bearer_auth(QUERY)
        .json(&q)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let audit = kedgeflow::current_reservation_audit::Bundle::collect(
        &store,
        evidence.clone(),
        q.clone(),
        witness.clone(),
        now(),
    )
    .await
    .unwrap();
    let trust = kedgeflow::current_reservation_audit::Trust {
        profile: source::PROFILE.into(),
        selection: store.context.selection.clone(),
    };
    let verification = audit.verify(&trust).unwrap();
    assert_eq!(verification["native_history_verified"], false);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let mut restarted = process.start().await;
    assert!(
        now() < witness.body.source_claim.expires_at,
        "restart replay must exercise a live original slot"
    );
    let response = process
        .controller
        .post(format!("{}/current", process.endpoint))
        .bearer_auth(QUERY)
        .json(&q)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    restarted.kill().await.unwrap();
    restarted.wait().await.unwrap();
    store
        .unavailable(&reserved, now(), "refused")
        .await
        .unwrap();
    let status = store.status().await.unwrap().unwrap();
    assert!(status.unresolved());
    assert_eq!(status.before_queries, 1);
    assert!(!status.accepted);
    for field in [
        "forward_reservation_root_id",
        "forward_execution_root_id",
        "observation_digest",
    ] {
        let mut changed = audit.clone();
        changed.admission.evidence.payload["result"][field] = json!("substituted");
        changed.admission.evidence = serde_json::from_slice(&fixture::signed(
            "evidence",
            changed.admission.evidence.payload.clone(),
            94,
        ))
        .unwrap();
        let proposal = serde_json::from_str(&audit.authorization.packet.proposal).unwrap();
        assert!(
            changed
                .admission
                .validate(&store.context, &proposal, candidate.grant.issued_at)
                .is_err()
        );
        assert!(changed.verify(&trust).is_err());
    }
    let mut changed = audit.clone();
    changed.query.requested_at += 1;
    assert!(changed.verify(&trust).is_err());
    let mut changed = audit.clone();
    changed.witness.body.sql.observed_version += 1;
    changed.witness = source::Signed::sign(
        "reservation_observation",
        changed.witness.body.clone(),
        &e.current_sql.provider,
        "key-94",
        &SigningKey::from_bytes(&[94; 32]),
    )
    .unwrap();
    assert!(changed.verify(&trust).is_err());
    let mut changed = audit.clone();
    changed
        .authorization
        .packet
        .witnesses
        .retain(|raw| !raw.contains("observation_digest"));
    assert!(changed.verify(&trust).is_err());
    let mut unknown = json!(audit);
    unknown["unknown"] = json!(true);
    assert!(
        kedgeflow::current_reservation_audit::Bundle::decode(&canonical(&unknown).unwrap())
            .is_err()
    );
    let mut old = trust.clone();
    old.profile = "KF-CURRENT-SQL-RESERVATION-0.1-draft".into();
    assert!(audit.verify(&old).is_err());
    let after_rows = sql_rows(&r).await;
    assert_eq!(
        after_rows, before_rows,
        "source requests cannot alter SQL resources/outcomes/snapshots"
    );
    if let Ok(output) = std::env::var("KF_CONFORMANCE_ARTIFACTS") {
        let out = PathBuf::from(output).join("managed-current-sql-source");
        std::fs::create_dir_all(&out).unwrap();
        for (name, value) in [
            ("bundle.json", json!(audit)),
            ("trust.json", json!(trust)),
            ("verification.json", verification),
            (
                "target-rows.json",
                json!({"before":before_rows,"after":after_rows}),
            ),
        ] {
            std::fs::write(out.join(name), canonical(&value).unwrap()).unwrap();
        }
        std::fs::write(
            out.join("admission.json"),
            canonical(&json!(evidence)).unwrap(),
        )
        .unwrap();
        std::fs::write(
            out.join("witness.json"),
            canonical(&json!(witness)).unwrap(),
        )
        .unwrap();
        std::fs::write(out.join("registration.json"), canonical(&json!(e)).unwrap()).unwrap();
        std::fs::write(out.join("status.json"),canonical(&json!({"scope":"shipping readonly source; actual peer SQL, native original dispatch/source claims, verified mTLS and real API availability; no managed controller/SDK mutation qualification","operating":status,"source_restart":true,"current_query_replay":"refused including live-slot service restart","concurrent_query":"one source claim/result, other refused","preflight_reply_replay":"original unchanged source result"})).unwrap()).unwrap();
    }
}

#[path = "kube_drain_supervisor.rs"]
mod supervisor;

#[path = "kube_drain_managed_process.rs"]
mod managed_process;

#[path = "kube_drain_preflight_boundaries.rs"]
mod preflight_boundaries;
