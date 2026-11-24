//! Opt-in real Keycloak/SPIRE -> shipping control/broker/gateway/SQL -> SDK recovery.
//! Administrative PKI, evidence and the TLS ledger relay remain same-host fixtures.
use super::*;
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    auth::WorkloadIdentity,
    clock::{Clock, SystemClock},
    exchange_identity::{ActorKey, SubjectKey, TrustSnapshot},
    postgres_store::{PostgresStore, ReservationStore, UnixDatabase},
    tls,
};
use live_agent::{Provider, Running, Target};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::AtomicUsize,
};
use tokio::sync::Mutex;

const APP: &str = "spiffe://pilot.kedgeflow.test/gateway";
const ISSUER: &str = "https://keycloak:8443/realms/kedgeflow-pilot";
const DELEGATION: &str = "urn:kedgeflow:delegated-admission";
const QUERY_TOKEN: &str = "selfhosted-sql-original-query-only-00000000000000000000";

struct Root(PathBuf);
impl Root {
    fn new(parent: &Path, name: &str) -> Self {
        let p = parent.join(name);
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p.canonicalize().unwrap())
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }
    fn transport(&self, p: &support::Pki, incoming: &str) -> Value {
        json!({"certificate":self.write("identity.pem",&p.client),
            "private_key":self.write("identity.key",&p.client_key),
            "workload_ca":self.write("incoming.pem",incoming)})
    }
    fn native(&self, p: &support::Pki, url: &str, prefix: &str, role: &str) -> Value {
        json!({"etcd_endpoint":url,"etcd_prefix":prefix,
            "etcd_ca":self.write("native-ca.pem",&p.ca),
            "etcd_certificate":self.0.join("identity.pem"),
            "etcd_private_key":self.0.join("identity.key"),
            "etcd_token_file":self.write("native.token",role)})
    }
    fn restore(&self, p: &support::Pki, url: &str, prefix: &str, role: &str) -> Value {
        json!({"endpoint":url,"prefix":prefix,
            "ca":self.write("witness-ca.pem",&p.ca),
            "certificate":self.0.join("identity.pem"),
            "private_key":self.0.join("identity.key"),
            "token_file":self.write("witness.token",format!("{role}-witness"))})
    }
}
struct Shipping {
    child: Option<tokio::process::Child>,
    systemd: Option<Value>,
    binary: &'static str,
    config: PathBuf,
    address: std::net::SocketAddr,
    extra: Vec<String>,
    log: PathBuf,
}
impl Shipping {
    fn systemd_command(action: &str, binary: &str, config: &Path) -> std::process::Command {
        let mut command = std::process::Command::new("python3");
        command
            .arg(std::env::var("KF_SYSTEMD_PILOT_HELPER").unwrap())
            .args(["--action", action, "--state"])
            .arg(std::env::var("KF_SYSTEMD_PILOT_STATE").unwrap())
            .arg("--role")
            .arg(Path::new(binary).file_name().unwrap())
            .arg("--material")
            .arg(config.parent().unwrap());
        command
    }
    async fn stop(&mut self) {
        if self.systemd.take().is_some() {
            assert!(
                tokio::process::Command::from(Self::systemd_command(
                    "stop",
                    self.binary,
                    &self.config
                ))
                .status()
                .await
                .unwrap()
                .success()
            );
        } else if let Some(mut child) = self.child.take() {
            child.kill().await.unwrap();
        }
    }
    async fn start(
        root: &Root,
        binary: &'static str,
        config: &Value,
        address: std::net::SocketAddr,
        mut extra: Vec<String>,
        managed: bool,
    ) -> Self {
        if managed {
            if !extra.iter().any(|arg| arg == "--custody-root") {
                extra.extend([
                    "--custody-root".into(),
                    root.0.to_string_lossy().into_owned(),
                ]);
            }
            extra.push("--require-managed".into());
        }
        let file = root.write("config.json", canonical(config).unwrap());
        let log = root.0.join("service.log");
        if std::env::var_os("KF_SYSTEMD_PILOT_STATE").is_some() {
            assert!(managed, "systemd backend requires strict managed launch");
            let output =
                tokio::process::Command::from(Self::systemd_command("start", binary, &file))
                    .output()
                    .await
                    .unwrap();
            assert!(
                output.status.success(),
                "systemd start refused: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut service = Self {
                child: None,
                systemd: Some(serde_json::from_slice(&output.stdout).unwrap()),
                binary,
                config: file,
                address,
                extra,
                log,
            };
            service.ready().await;
            return service;
        }
        let checked = tokio::process::Command::new(binary)
            .arg("--config")
            .arg(&file)
            .args(&extra)
            .arg("--check")
            .output()
            .await
            .unwrap();
        assert!(
            checked.status.success(),
            "shipping check refused: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        let child = tokio::process::Command::new(binary)
            .arg("--config")
            .arg(&file)
            .args(&extra)
            .stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut s = Self {
            child: Some(child),
            systemd: None,
            binary,
            config: file,
            address,
            extra,
            log,
        };
        s.ready().await;
        s
    }
    async fn ready(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            assert!(
                self.child
                    .as_mut()
                    .is_none_or(|child| child.try_wait().unwrap().is_none()),
                "shipping process exited: {}",
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
            if tokio::net::TcpStream::connect(self.address).await.is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "shipping readiness expired"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn restart(&mut self) {
        if self.systemd.is_some() {
            assert!(
                tokio::process::Command::from(Self::systemd_command(
                    "restart",
                    self.binary,
                    &self.config
                ))
                .status()
                .await
                .unwrap()
                .success()
            );
            self.ready().await;
            return;
        }
        self.child.as_mut().unwrap().kill().await.unwrap();
        self.child = Some(
            tokio::process::Command::new(self.binary)
                .arg("--config")
                .arg(&self.config)
                .args(&self.extra)
                .stdout(std::process::Stdio::null())
                .stderr(
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&self.log)
                        .unwrap(),
                )
                .kill_on_drop(true)
                .spawn()
                .unwrap(),
        );
        self.ready().await;
    }
}
impl Drop for Shipping {
    fn drop(&mut self) {
        if self.systemd.take().is_some() {
            let _ = Self::systemd_command("stop", self.binary, &self.config).output();
        }
    }
}
async fn reserve(path: &str) -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}{path}", l.local_addr().unwrap());
    (l, url)
}
async fn serve(
    l: tokio::net::TcpListener,
    p: &support::Pki,
    incoming: &str,
    router: Router,
) -> Running {
    let tls = tls::server_config_pem(
        p.client.as_bytes(),
        p.client_key.as_bytes(),
        incoming.as_bytes(),
    )
    .unwrap();
    Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(l, tls, router)
            .await
            .unwrap()
    }))
}
struct Relay {
    origin: String,
    realm: &'static str,
}
async fn relay(
    State(p): State<Arc<Relay>>,
    Extension(w): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let role = match w.as_str() {
        "spiffe://test/operator" => "operator",
        "spiffe://test/gateway" => "gateway",
        "spiffe://test/control" => "control",
        "spiffe://test/issuer" => "issuer",
        "spiffe://test/broker" => "broker",
        _ => return Err(StatusCode::FORBIDDEN),
    };
    let token = format!("{role}-{}", p.realm);
    if headers.get("authorization").and_then(|h| h.to_str().ok()) != Some(token.as_str()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let response = reqwest::Client::new()
        .post(format!("{}/v3/kv/txn", p.origin))
        .json(&body)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(
        response.json().await.map_err(|_| StatusCode::BAD_GATEWAY)?,
    ))
}
struct BrokerRelay {
    upstream: String,
    host: String,
    client: reqwest::Client,
    calls: AtomicUsize,
    successes: AtomicUsize,
}
async fn broker_relay(
    State(p): State<Arc<BrokerRelay>>,
    Extension(w): Extension<WorkloadIdentity>,
    request: Request,
) -> std::result::Result<axum::response::Response, StatusCode> {
    if w.as_str() != "spiffe://test/gateway" {
        return Err(StatusCode::FORBIDDEN);
    }
    let bytes = to_bytes(request.into_body(), 1 << 20)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    p.calls.fetch_add(1, Ordering::SeqCst);
    let response = p
        .client
        .post(&p.upstream)
        .header("host", &p.host)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(bytes)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = response.status();
    if status == StatusCode::OK {
        p.successes.fetch_add(1, Ordering::SeqCst);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((
        status,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        bytes,
    )
        .into_response())
}
fn encoded(n: u8) -> Value {
    json!({format!("key-{n}"):STANDARD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())})
}
fn selected() -> Value {
    json!({"profile":kedgeflow::auth::KEYCLOAK_PILOT_PROFILE,"client_id":"kf-pilot-agent"})
}
fn subject_key(packet: &Value) -> (&Value, Vec<u8>) {
    let k = packet["keycloak_jwks"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["alg"] == "EdDSA" && k["crv"] == "Ed25519" && k["use"] == "sig")
        .unwrap();
    (k, URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap())
}
async fn permits(h: &Harness) -> Value {
    let snapshot =
        sql_failure::prefix_snapshot(&std::env::var("ETCD_ENDPOINT").unwrap(), &h.prefix).await;
    let values: Vec<_> = snapshot["kvs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|kv| {
            String::from_utf8(STANDARD.decode(kv["key"].as_str().unwrap()).unwrap())
                .unwrap()
                .ends_with("/credential-permit")
        })
        .map(|kv| kv["value"].clone())
        .collect();
    json!(values)
}

async fn run_case(input: &Path, bundle: &Value, lost: bool, managed: bool) -> Value {
    let split_control = std::env::var_os("KF_SYSTEMD_PILOT_STATE").is_some();
    let packet: Value =
        serde_json::from_slice(&std::fs::read(input.join("packet.json")).unwrap()).unwrap();
    let workflow: Value =
        serde_json::from_slice(&std::fs::read(input.join("workflow.json")).unwrap()).unwrap();
    let broker_url = workflow["broker_url"].as_str().unwrap();
    let parsed = reqwest::Url::parse(broker_url).unwrap();
    assert_eq!(parsed.scheme(), "https");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/exchange");
    assert!(parsed.query().is_none());
    let broker_address = format!("127.0.0.1:{}", parsed.port().unwrap());
    let public_broker_listener = tokio::net::TcpListener::bind(&broker_address)
        .await
        .unwrap();
    let (gateway_listener, gateway_url) = reserve("/mcp").await;
    let gateway_address = gateway_listener.local_addr().unwrap();
    let now = SystemClock.now_ms();
    let native = support::dual_pki_for_workloads(&[
        "spiffe://test/operator",
        "spiffe://test/gateway",
        "spiffe://test/agent",
        "spiffe://test/control",
        "spiffe://test/broker",
        "spiffe://test/sql-target",
        "spiffe://test/recovery",
        "spiffe://test/issuer",
    ]);
    let witness = if managed {
        Some(support::witness::WitnessProcess::start().await)
    } else {
        None
    };
    let witness_prefix = format!("/selfhosted-witness-{:x}", rand::random::<u64>());
    let (witness_listener, witness_url) = reserve("").await;
    let witness_relay = if let Some(witness) = &witness {
        Some(
            serve(
                witness_listener,
                &native[1],
                &native[1].ca,
                Router::new()
                    .route("/v3/kv/txn", post(relay))
                    .with_state(Arc::new(Relay {
                        origin: witness.endpoint.clone(),
                        realm: "witness",
                    })),
            )
            .await,
        )
    } else {
        drop(witness_listener);
        None
    };
    let gate = if managed {
        Some(
            kedgeflow::restore::RestoreGate::new(
                EtcdLedger::new(
                    tls::pinned_http_client_pem(
                        native[0].ca.as_bytes(),
                        native[0].client.as_bytes(),
                        native[0].client_key.as_bytes(),
                        Duration::from_secs(5),
                    )
                    .unwrap(),
                    &witness_url,
                    &witness_prefix,
                )
                .unwrap()
                .with_auth_token("operator-witness")
                .unwrap(),
            )
            .unwrap(),
        )
    } else {
        None
    };
    let h = Harness::with_native_timing(
        Some(&gateway_url),
        now,
        |f| {
            f.sql();
            let resource = format!("selfhosted-{:x}", rand::random::<u64>());
            f.identity.subject = kedgeflow::contracts::Subject {
                iss: ISSUER.into(),
                sub: "d0b36f01-1188-4f01-907a-000000000001".into(),
            };
            f.identity.workload_id = APP.into();
            f.trust.proposal_workload_id = APP.into();
            f.proposal["subject"] = json!(f.identity.subject);
            f.proposal["workload_id"] = json!(APP);
            f.proposal["resources"][0]["id"] = json!(resource);
            f.proposal["parameters"]["resource_id"] = json!(resource);
            f.proposal["baseline_state"][0]["resource"]["id"] = json!(resource);
            f.evidence["state_scope"][0]["id"] = json!(resource);
            f.descriptor["adapter_contract"]["guard_scope"] = json!([resource]);
            f.descriptor["concurrency"]["predicate_descriptor"]["clauses"][0]["resource"]["id"] =
                json!(resource);
            f.repin_descriptor();
        },
        gate.clone(),
        Some(native[..3].to_vec()),
        None,
        None,
        Some(5000),
    )
    .await
    .expect("required real etcd");
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    h.clock.0.store(0, Ordering::SeqCst);
    let database = UnixDatabase {
        socket_directory: PathBuf::from(
            std::env::var("KF_POSTGRES_TEST_SOCKET").expect("required SQL"),
        )
        .canonicalize()
        .unwrap(),
        port: 5432,
        database: "postgres".into(),
        executor_user: "kf_executor".into(),
        query_user: "kf_reader".into(),
    };
    let db = sql_leaf::owner(&database).await;
    let resource = &h.registration.scope.resource;
    db.execute(
        "INSERT INTO kf_reservation.resource VALUES($1,$2,$3,$4,241,0,'unreserved',true)",
        &[
            &h.f.trust.tenant,
            &h.registration.scope.conflict_domain,
            &resource.id,
            &resource.incarnation,
        ],
    )
    .await
    .unwrap();
    let (relay_listener, relay_url) = reserve("").await;
    let _native_relay = serve(
        relay_listener,
        &native[1],
        &native[1].ca,
        Router::new()
            .route("/v3/kv/txn", post(relay))
            .with_state(Arc::new(Relay {
                origin: std::env::var("ETCD_ENDPOINT").unwrap(),
                realm: "native",
            })),
    )
    .await;
    let (control_reservation, admit) = reserve("/admit").await;
    let control_address = control_reservation.local_addr().unwrap();
    let origin = admit.strip_suffix("/admit").unwrap();
    let (issuer_reservation, issuer_address, issue) = if split_control {
        let (listener, url) = reserve("/issue").await;
        let address = listener.local_addr().unwrap();
        (Some(listener), address, url)
    } else {
        (None, control_address, format!("{origin}/issue"))
    };
    let status = format!("{origin}/status");
    let (evidence_listener, evidence_url) = reserve("/evidence").await;
    let (target_reservation, target_url) = reserve("/dispatch").await;
    let target_address = target_reservation.local_addr().unwrap();
    let query_url = target_url.replace("/dispatch", "/query");
    let (broker_reservation, broker_internal) = reserve("/exchange").await;
    let internal_address = broker_reservation.local_addr().unwrap();
    let (key, raw) = subject_key(&packet);
    let public_key = STANDARD.encode(&raw);
    let spire_ca = std::fs::read_to_string(input.join("x509/bundle.0.pem")).unwrap();
    let incoming = format!("{}{}", native[1].ca, spire_ca);
    let directory = tempfile::tempdir().unwrap();
    let dir = directory.path().canonicalize().unwrap();
    if std::env::var_os("KF_SYSTEMD_PILOT_STATE").is_some() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let control = Root::new(&dir, "control");
    let broker = Root::new(&dir, "broker");
    let gateway = Root::new(&dir, "gateway");
    let target = Root::new(&dir, "target");
    let evidence:BTreeMap<_,_>=h.f.trust.evidence.iter().map(|(id,e)|(id.clone(),json!({
        "review":e.review,"obligation":e.obligation,"provider_id":e.provider_id,"provider_version":e.provider_version,
        "keys":e.keys.iter().map(|(k,v)|(k.clone(),STANDARD.encode(v.as_bytes()))).collect::<BTreeMap<_,_>>(),
        "question":e.question,"result_schema_ref":e.result_schema_ref,"result_schema":e.result_schema,
        "max_age_ms":e.max_age_ms,"predicates":e.predicates}))).collect();
    let trust = &h.f.trust;
    let mut control_config = control.transport(&native[3], &incoming);
    control_config.as_object_mut().unwrap().extend(
        control
            .native(&native[3], &relay_url, &h.prefix, "control-native")
            .as_object()
            .unwrap()
            .clone(),
    );
    control_config.as_object_mut().unwrap().extend(json!({"identity_profile":selected(),"listen":control_address,
        "admission_url":admit,"issuance_url":issue,"status_url":status,"status_scope":"kf.status",
        "delegation_audience":DELEGATION,"gateway_audience":gateway_url,"oidc_issuer":ISSUER,"oidc_public_key_base64":public_key,
        "require_control":true,"admission_key_id":"key-6","admission_signing_key_file":control.write("admission.seed",STANDARD.encode([6;32])),
        "issuer_key_id":"key-5","issuer_signing_key_file":control.write("issuer.seed",STANDARD.encode([5;32])),
        "tenant":trust.tenant,"workload_id":APP,"subjects":[h.f.identity.subject],"admission_scope":"kf.admit","issuance_scope":"kf.issue",
        "action_scope":trust.required_scope,"proposal_keys":encoded(1),"registry_keys":encoded(2),"manifest_keys":encoded(3),
        "descriptor_digest":trust.descriptor_digest,"ownership_epoch":trust.ownership_epoch,"max_proposal_age_ms":trust.max_proposal_age_ms,
        "policy":{"id":trust.policy.id,"epoch":trust.policy.epoch,"cedar":h.definition.cedar,"max_certificate_lifetime_ms":5000},"evidence":evidence}).as_object().unwrap().clone());
    let loaded =
        kedgeflow::control_config::ControlConfig::decode(&canonical(&control_config).unwrap())
            .unwrap();
    assert_eq!(
        kedgeflow::governance::trust_digest(&loaded.registration().unwrap().0, &keys(6), &keys(5))
            .unwrap(),
        h.registration.trust_digest
    );
    let mut tool = h.tool();
    tool.name = "postgres_reserve".into();
    tool.admission_endpoint = admit.clone();
    let registration = json!({"tenant":trust.tenant,"conflict_domain":tool.conflict_domain,"action":tool.action,"resource":resource,
        "adapter_contract":tool.adapter_contract,"predicate_id":tool.predicate_id,"predicate_version":tool.predicate_version,
        "gateway_workload":"spiffe://test/gateway","query_workload":"spiffe://test/recovery","target_audience":target_url,"target_scope":"reservation:write"});
    let mut actor_keys = Vec::new();
    for k in bundle["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| k["use"] == "jwt-svid")
    {
        assert_eq!(k["crv"], "P-256");
        let mut point = vec![4];
        point.extend(URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap());
        point.extend(URL_SAFE_NO_PAD.decode(k["y"].as_str().unwrap()).unwrap());
        actor_keys.push(ActorKey {
            kid: k["kid"].as_str().unwrap().into(),
            trust_domain: "pilot.kedgeflow.test".into(),
            alg: "ES256".into(),
            r#use: "jwt-svid".into(),
            public_key: URL_SAFE_NO_PAD.encode(point),
            not_before: now - 5000,
            expires_at: now + 120000,
        });
    }
    let snapshot = TrustSnapshot {
        profile: kedgeflow::exchange_identity::PROFILE.into(),
        epoch: 1,
        not_before: now - 5000,
        expires_at: now + 120000,
        issuer: ISSUER.into(),
        subject_audience: DELEGATION.into(),
        actor_audience: broker_url.into(),
        subject_keys: vec![SubjectKey {
            kid: key["kid"].as_str().unwrap().into(),
            public_key: URL_SAFE_NO_PAD.encode(&raw),
            not_before: now - 5000,
            expires_at: now + 120000,
        }],
        actor_keys,
        registrations: vec![kedgeflow::shared_auth::SubjectWorkload {
            subject: h.f.identity.subject.clone(),
            workload_id: APP.into(),
            allowed_scopes: "capacity.reserve kf.admit kf.issue kf.status kf.evidence"
                .split_whitespace()
                .map(String::from)
                .collect(),
        }],
        withdrawn_subject_tokens: vec![],
    };
    snapshot.validate().unwrap();
    let mut broker_config = broker.transport(&native[4], &native[1].ca);
    broker_config.as_object_mut().unwrap().extend(
        broker
            .native(&native[4], &relay_url, &h.prefix, "broker-native")
            .as_object()
            .unwrap()
            .clone(),
    );
    broker_config.as_object_mut().unwrap().extend(json!({"identity_profile":selected(),"listen":internal_address,"external_url":broker_url,
        "gateway_audience":gateway_url,"delegation_audience":DELEGATION,"grant_keys":encoded(5),
        "registration":{"gateway_workload":"spiffe://test/gateway","target_audience":target_url,"target_scope":"reservation:write","max_lifetime_ms":3000,"tool":tool},
        "identity_snapshot_file":broker.write("identity.json",canonical(&json!(snapshot)).unwrap()),"identity_epoch_floor_file":broker.write("identity.floor","1"),
        "target_key_id":"key-29","target_signing_key_file":broker.write("target.seed",STANDARD.encode([29;32])),
        "target_verification_keys":encoded(29),"allow_unmanaged_fixture":false,"installed_trust_digest":h.registration.trust_digest}).as_object().unwrap().clone());
    if lost || managed {
        let (signed, head) = kedgeflow::identity_refresh::sign_snapshot(
            snapshot,
            "selfhosted-pilot-refresh".into(),
            "key-47".into(),
            &SigningKey::from_bytes(&[47; 32]),
        )
        .unwrap();
        let config = broker_config.as_object_mut().unwrap();
        config.remove("identity_snapshot_file");
        config.remove("identity_epoch_floor_file");
        config.insert("identity_refresh".into(), json!({
            "authority_id":"selfhosted-pilot-refresh","issuer":ISSUER,"authority_keys":encoded(47),
            "signed_snapshot_file":broker.write("identity.signed.json",canonical(&json!(signed)).unwrap()),
            "head_file":broker.write("identity.head.json",canonical(&json!(head)).unwrap()),
            "minimum_epoch_file":broker.write("identity.minimum","1")
        }));
    }
    let mut target_config = target.transport(&native[5], &native[1].ca);
    target_config.as_object_mut().unwrap().extend(json!({"listen":target_address,"dispatch_url":target_url,"query_url":query_url,"database":database,
        "gateway_audience":gateway_url,"grant_keys":encoded(5),"token_issuer":broker_url,"target_keys":encoded(29),
        "query_token_file":target.write("query.token",QUERY_TOKEN),"registration":registration}).as_object().unwrap().clone());
    let mut gateway_config = gateway.transport(&native[1], &incoming);
    let n = gateway.native(&native[1], &relay_url, &h.prefix, "gateway-native");
    gateway_config
        .as_object_mut()
        .unwrap()
        .extend(n.as_object().unwrap().clone());
    gateway_config
        .as_object_mut()
        .unwrap()
        .remove("etcd_endpoint");
    gateway_config
        .as_object_mut()
        .unwrap()
        .remove("etcd_certificate");
    gateway_config
        .as_object_mut()
        .unwrap()
        .remove("etcd_private_key");
    gateway_config.as_object_mut().unwrap().extend(json!({"identity_profile":selected(),"listen":gateway_address,"external_url":gateway_url,
        "delegation_audience":DELEGATION,"grant_key_id":"key-5","grant_public_key_base64":encoded(5)["key-5"],
        "oidc_issuer":ISSUER,"oidc_public_key_base64":public_key,"etcd_endpoints":[relay_url],"require_control":true,
        "broker_endpoint":broker_url,"broker_ca":gateway.write("broker-ca.pem",&native[1].ca),"target_audience":target_url,"target_scope":"reservation:write",
        "actor_workload":APP,"actor_token_file":gateway.write("actor.jwt",packet["actor_token"].as_str().unwrap()),
        "target_url":target_url,"target_ca":gateway.write("target-ca.pem",&native[1].ca),"tools":[tool],
        "postgres_adapter":{"profile":kedgeflow::leaf_action::PROFILE,"registration":registration,"token_issuer":broker_url,"target_keys":encoded(29)}}).as_object().unwrap().clone());
    if managed {
        let shared = json!({"capacity":128,"registrations":[{
            "subject":h.f.identity.subject,"workload_id":APP,
            "allowed_scopes":["capacity.reserve","kf.admit","kf.issue","kf.status","kf.evidence"]
        }]});
        control_config["shared_auth"] = shared.clone();
        gateway_config["shared_auth"] = shared;
        control_config["restore_gate"] =
            control.restore(&native[3], &witness_url, &witness_prefix, "control");
        broker_config["restore_gate"] =
            broker.restore(&native[4], &witness_url, &witness_prefix, "broker");
        gateway_config["restore_gate"] =
            gateway.restore(&native[1], &witness_url, &witness_prefix, "gateway");
        gateway_config["enforcement"] = json!({
            "control_url":h.url,"control_ca":gateway.write("control-ca.pem",&native[1].ca),
            "installation_keys":encoded(12),"component_id":"gateway-test",
            "workload_id":"spiffe://test/gateway",
            "acknowledgement_key_file":gateway.write("ack.seed",STANDARD.encode([9;32]))
        });
    }
    let auth = DualAuthenticator::new(
        ISSUER,
        DELEGATION,
        &evidence_url,
        raw.clone().try_into().unwrap(),
    )
    .unwrap()
    .with_keycloak_pilot("kf-pilot-agent")
    .unwrap();
    let provider = Arc::new(Provider {
        workload_id: APP.into(),
        auth,
        clock: h.clock.clone(),
        evidence: h.f.evidence.clone(),
        policy: trust.policy.clone(),
        descriptor_digest: trust.descriptor_digest.clone(),
        calls: AtomicUsize::new(0),
        baseline_calls: AtomicUsize::new(0),
        target: Arc::new(Target {
            calls: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            state: Mutex::new((241, 0, 3)),
        }),
        resource: resource.clone(),
    });
    let _provider = serve(
        evidence_listener,
        &native[2],
        &incoming,
        Router::new()
            .route("/evidence", post(live_agent::evidence))
            .with_state(provider.clone()),
    )
    .await;
    drop(control_reservation);
    // Build independent protected roots: no process receives its peer's private
    // signer, TLS identity or authority token. Shared public trust is identical.
    let issuer = split_control.then(|| Root::new(&dir, "issuer"));
    let issuer_config = issuer.as_ref().map(|issuer| {
        fn rebase(value: &mut Value, old: &str, new: &str) {
            match value {
                Value::String(text) if text.starts_with(old) => *text = text.replacen(old, new, 1),
                Value::Object(map) => map.values_mut().for_each(|v| rebase(v, old, new)),
                Value::Array(list) => list.iter_mut().for_each(|v| rebase(v, old, new)),
                _ => (),
            }
        }
        let mut config = control_config.clone();
        rebase(
            &mut config,
            control.0.to_str().unwrap(),
            issuer.0.to_str().unwrap(),
        );
        // Only the public CA files are shared; private material is generated or
        // registered separately for this role.
        for name in ["incoming.pem", "native-ca.pem", "witness-ca.pem"] {
            issuer.write(name, std::fs::read(control.0.join(name)).unwrap());
        }
        config.as_object_mut().unwrap().extend(
            issuer
                .transport(&native[7], &incoming)
                .as_object()
                .unwrap()
                .clone(),
        );
        config.as_object_mut().unwrap().extend(
            issuer
                .native(&native[7], &relay_url, &h.prefix, "issuer-native")
                .as_object()
                .unwrap()
                .clone(),
        );
        config["restore_gate"] =
            issuer.restore(&native[7], &witness_url, &witness_prefix, "issuer");
        config["runtime_role"] = json!("issuer");
        config["listen"] = json!(issuer_address);
        config["status_url"] = json!(issue.replace("/issue", "/status"));
        config["admission_verification_key_base64"] = encoded(6)["key-6"].clone();
        config["issuer_verification_key_base64"] = encoded(5)["key-5"].clone();
        config
            .as_object_mut()
            .unwrap()
            .remove("admission_signing_key_file");
        config["issuer_signing_key_file"] =
            json!(issuer.write("issuer.seed", STANDARD.encode([5; 32])));
        control_config["runtime_role"] = json!("admission");
        control_config["admission_verification_key_base64"] = encoded(6)["key-6"].clone();
        control_config["issuer_verification_key_base64"] = encoded(5)["key-5"].clone();
        control_config
            .as_object_mut()
            .unwrap()
            .remove("issuer_signing_key_file");
        std::fs::remove_file(control.0.join("issuer.seed")).unwrap();
        config
    });
    let mut control_child = Shipping::start(
        &control,
        env!("CARGO_BIN_EXE_kf-control"),
        &control_config,
        control_address,
        vec![],
        managed,
    )
    .await;
    drop(issuer_reservation);
    let mut issuer_child = if let (Some(root), Some(config)) = (&issuer, &issuer_config) {
        Some(
            Shipping::start(
                root,
                env!("CARGO_BIN_EXE_kf-control"),
                config,
                issuer_address,
                vec![],
                managed,
            )
            .await,
        )
    } else {
        None
    };
    drop(broker_reservation);
    let mut broker_child = Shipping::start(
        &broker,
        env!("CARGO_BIN_EXE_kf-broker"),
        &broker_config,
        internal_address,
        vec![],
        managed,
    )
    .await;
    drop(target_reservation);
    let mut target_child = Shipping::start(
        &target,
        env!("CARGO_BIN_EXE_kf-postgres-target"),
        &target_config,
        target_address,
        vec![
            "--custody-root".into(),
            target.0.to_string_lossy().into_owned(),
            "--postgres-peer-uid".into(),
            std::env::var("KF_POSTGRES_TEST_PEER_UID")
                .unwrap_or_else(|_| rustix::process::geteuid().as_raw().to_string()),
        ],
        managed,
    )
    .await;
    let observer = Arc::new(BrokerRelay {
        upstream: broker_internal,
        host: parsed.authority().into(),
        client: tls::pinned_http_client_pem(
            native[1].ca.as_bytes(),
            native[1].client.as_bytes(),
            native[1].client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap(),
        calls: AtomicUsize::new(0),
        successes: AtomicUsize::new(0),
    });
    let mut broker_proxy = serve(
        public_broker_listener,
        &native[4],
        &native[1].ca,
        Router::new()
            .fallback(broker_relay)
            .with_state(observer.clone()),
    )
    .await;
    drop(gateway_listener);
    let mut gateway_child = Shipping::start(
        &gateway,
        env!("CARGO_BIN_EXE_kf-proxy"),
        &gateway_config,
        gateway_address,
        vec![],
        managed,
    )
    .await;
    let public = |n| json!({format!("key-{n}"):URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let operations = dir.join("operations");
    let file = dir.join("agent.json");
    let mut agent = json!({"mode":if lost{"lost"}else{"normal"},"realtime":true,"expectedState":"committed","token":packet["subject_token"],"dpopSeed":packet["dpop_seed"],
        "storeDirectory":operations,"evidenceUrl":evidence_url,"tls":{"ca":native[1].ca,"cert":std::fs::read_to_string(input.join("x509/svid.0.pem")).unwrap(),"key":std::fs::read_to_string(input.join("x509/svid.0.key")).unwrap()},
        "proposalTemplate":h.f.proposal,"config":{"identityProfile":{"profile":kedgeflow::auth::KEYCLOAK_PILOT_PROFILE,"clientId":"kf-pilot-agent"},
            "gatewayUrl":gateway_url,"admissionUrl":admit,"issuanceUrl":issue,"statusUrl":status,"delegationAudience":DELEGATION,"workloadId":APP,"subject":h.f.identity.subject,
            "tenant":trust.tenant,"toolName":"postgres_reserve","descriptor":String::from_utf8(fixture::signed("ctd",h.f.descriptor.clone(),2)).unwrap(),"descriptorDigest":trust.descriptor_digest,
            "registryKeys":public(2),"proposalKeys":public(1),"manifestKeys":public(3),"evidenceKeys":public(4),"admissionKeys":public(6),"issuerKeys":public(5),"proposalKeyId":"key-1","authorizationKey":URL_SAFE_NO_PAD.encode(&raw)}});
    let root = std::env::var_os("KF_SELFHOSTED_SOURCE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let agent_owner = std::env::var("KF_SYSTEMD_AGENT_UID").ok().map(|uid| {
        let uid: u32 = uid.parse().unwrap();
        let gid: u32 = std::env::var("KF_SYSTEMD_AGENT_GID")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(uid, 0);
        std::fs::create_dir(&operations).unwrap();
        std::fs::set_permissions(&operations, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::chown(&operations, Some(uid), Some(gid)).unwrap();
        (uid, gid)
    });
    let run = || async {
        let mut command = tokio::process::Command::new("node");
        if let Some((uid, gid)) = agent_owner {
            std::os::unix::fs::chown(&file, Some(uid), Some(gid)).unwrap();
            command.uid(uid).gid(gid);
        }
        let output = command
            .arg(root.join("tests/sdk/live-agent.mjs"))
            .arg(&file)
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "official SDK failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    std::fs::write(&file, canonical(&agent).unwrap()).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let first = run().await;
    let retained: Value = serde_json::from_slice(
        &std::fs::read(operations.join(format!(
            "{}.json",
            hex::encode(Sha256::digest(b"sdk:live-operation"))
        )))
        .unwrap(),
    )
    .unwrap();
    let grants = GrantVerifier {
        keys: keys(5),
        audience: gateway_url.clone(),
    };
    let issued = grants
        .verify(
            retained["grant"].as_str().unwrap().as_bytes(),
            SystemClock.now_ms(),
        )
        .unwrap();
    let original_permits = permits(&h).await;
    assert_eq!(original_permits.as_array().unwrap().len(), 1);
    let sql = PostgresStore::new(database).unwrap();
    let original = sql
        .lookup(&trust.tenant, first["attempt_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.request.grant_digest, issued.digest);
    assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(observer.successes.load(Ordering::SeqCst), 1);
    h.revoke(RevocationTarget::Domain).await;
    let remaining = issued.grant.expires_at - SystemClock.now_ms();
    if remaining >= 0 {
        tokio::time::sleep(Duration::from_millis(remaining as u64 + 20)).await;
    }
    gateway_child.restart().await;
    agent["mode"] = json!("resume");
    std::fs::write(&file, canonical(&agent).unwrap()).unwrap();
    let resumed = run().await;
    assert_eq!(resumed["attempt_id"], first["attempt_id"]);
    assert_eq!(resumed["grant_digest"], first["grant_digest"]);
    assert_eq!(permits(&h).await, original_permits);
    assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(observer.successes.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.baseline_calls.load(Ordering::SeqCst), 1);
    let row=db.query_one("SELECT version,last_fence,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&trust.tenant,&resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 242);
    assert_eq!(row.get::<_, i64>(1), issued.grant.fence as i64);
    assert_eq!(row.get::<_, String>(2), "booking:pilot");
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM kf_reservation.attempt WHERE tenant=$1 AND root_id=$2",
            &[&trust.tenant, &issued.grant.root_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    if let Some(gate) = &gate {
        gate.check(&h.ledger).await.unwrap();
    }
    let result = json!({"lost_sdk_reply":lost,"identity_mode":if lost || managed {"signed_refresh"} else {"pinned_snapshot"},"managed_launch":managed,"state":resumed["state"],"attempt_id":first["attempt_id"],"grant_digest":issued.digest,
        "sql_version":242,"sql_attempts":count,"broker_exchanges":observer.successes.load(Ordering::SeqCst),
        "permit_unchanged":true,"actual_grant_expiry":true,"domain_stopped":true,"shipping_gateway_restart":true,
        "first_wire":first["wire"],"resume_wire":resumed["wire"]});
    let runtime = json!({"gateway":gateway_child.systemd,"control":control_child.systemd,"admission":control_child.systemd,"issuer":issuer_child.as_ref().map(|c| &c.systemd),
        "broker":broker_child.systemd,"sql_target":target_child.systemd,"agent_uid":agent_owner.map(|o|o.0)});
    gateway_child.stop().await;
    control_child.stop().await;
    if let Some(child) = &mut issuer_child {
        child.stop().await;
    }
    broker_child.stop().await;
    target_child.stop().await;
    // Abort and join before the next case reuses the actor's exact audience port.
    broker_proxy.0.abort();
    let _ = (&mut broker_proxy.0).await;
    drop(witness_relay);
    let mut result = result;
    result["runtime"] = runtime;
    result
}

#[tokio::test]
async fn shipping_keycloak_spire_sql() {
    run(false).await;
}

#[tokio::test]
async fn shipping_managed_keycloak_spire_sql() {
    run(true).await;
}

async fn run(managed: bool) {
    let input = PathBuf::from(
        std::env::var("KF_SELFHOSTED_INPUT").expect("explicit real-provider input required"),
    );
    let bundle: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("KF_SELFHOSTED_BUNDLE").unwrap()).unwrap(),
    )
    .unwrap();
    let mut cases = Vec::new();
    for lost in [false, true] {
        cases.push(run_case(&input, &bundle, lost, managed).await);
    }
    let binaries = [
        ("kf-control", env!("CARGO_BIN_EXE_kf-control")),
        ("kf-broker", env!("CARGO_BIN_EXE_kf-broker")),
        ("kf-proxy", env!("CARGO_BIN_EXE_kf-proxy")),
        (
            "kf-postgres-target",
            env!("CARGO_BIN_EXE_kf-postgres-target"),
        ),
    ]
    .into_iter()
    .map(|(name, path)| {
        (
            name,
            hex::encode(Sha256::digest(
                std::fs::read(
                    std::env::var_os("KF_SYSTEMD_BINARY_DIR")
                        .map(PathBuf::from)
                        .map(|directory| directory.join(name))
                        .unwrap_or_else(|| PathBuf::from(path)),
                )
                .unwrap(),
            )),
        )
    })
    .collect::<std::collections::BTreeMap<_, _>>();
    let report = json!({"status":if managed {"passed_managed_sql_workflow"}else{"passed_sql_workflow"},"profile":kedgeflow::auth::KEYCLOAK_PILOT_PROFILE,"cases":cases,
        "shipping_binaries":["kf-control","kf-broker","kf-proxy","kf-postgres-target"],
        "binary_sha256":binaries,
        "scope":"Same-host generated administration/evidence/native TLS relay, real Keycloak/SPIRE credentials and actual SQL"});
    std::fs::write(
        PathBuf::from(std::env::var("KF_SELFHOSTED_OUTPUT").unwrap()).join("sql-workflow.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "self-hosted SQL PASS: two fresh shipping workflows, original broker permit/SQL attempt, query-only restart after domain stop and actual grant expiry"
    );
}
