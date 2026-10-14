//! Native control HTTP endpoints with real TLS/DPoP and real etcd. Enrollment,
//! policy installation and signing keys are explicit synthetic boundaries.
#[allow(unused_imports, dead_code)]
#[path = "support/admission_fixture.rs"]
mod fixture;
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use fixture::{Fixture, NOW, Time, keys, record_hash, signed};
use kedgeflow::{
    auth::{DualAuthenticator, WorkloadIdentity},
    contracts::{Grant, GrantVerifier, canonical, digest},
    control::{ControlPermissions, ControlService},
    issuance::{GrantAuthority, IssuanceVerifier},
    ledger::{AuthorityLedger, EtcdLedger},
    policy::{AdmissionController, CedarAdmissionPolicy, CedarPolicyDefinition},
    schema::verify_record,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

const AUDIENCE: &str = "urn:kedgeflow:control-test";
const POLICY: &str = r#"permit(principal, action == KedgeFlow::Action::"admit", resource)
when { context.tenant == "tenant-42" && context.workload_id == "spiffe://test/agent" && context.obligation_ids.contains("capacity") };"#;

fn jwt(header: Value, claims: Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    )
}

struct Credentials {
    token: String,
    proof_key: SigningKey,
    jwk: Value,
    delegation: Value,
    issuer: String,
    jti: AtomicU64,
    now_ms: i64,
}
impl Credentials {
    fn new(subject: &kedgeflow::contracts::Subject, scope: &str) -> Self {
        Self::new_at(subject, scope, NOW)
    }
    fn new_at(subject: &kedgeflow::contracts::Subject, scope: &str, now_ms: i64) -> Self {
        let proof_key = SigningKey::from_bytes(&[8; 32]);
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(proof_key.verifying_key().as_bytes())});
        let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()));
        let token = jwt(
            json!({"alg":"EdDSA","typ":"at+jwt"}),
            json!({"iss":subject.iss,"sub":subject.sub,"aud":AUDIENCE,"exp":now_ms/1000+60,"iat":now_ms/1000,"scope":scope,"cnf":{"jkt":jkt}}),
            &SigningKey::from_bytes(&[7; 32]),
        );
        let delegation = json!({"access_token_digest":hex::encode(Sha256::digest(token.as_bytes())),"dpop_jkt":jkt,"authorization_server":subject.iss,"token_audience":AUDIENCE,"scopes":scope.split_whitespace().collect::<Vec<_>>(),"expires_at":now_ms+60000});
        Self {
            token,
            proof_key,
            jwk,
            delegation,
            issuer: subject.iss.clone(),
            jti: AtomicU64::new(1),
            now_ms,
        }
    }
    fn headers(&self, url: &str) -> http::HeaderMap {
        let proof = jwt(
            json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":self.jwk}),
            json!({"jti":format!("proof-{}-{}",rand::random::<u64>(),self.jti.fetch_add(1,Ordering::SeqCst)),"htm":"POST","htu":url,"iat":self.now_ms/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(self.token.as_bytes()))}),
            &self.proof_key,
        );
        let mut h = http::HeaderMap::new();
        h.insert(
            "authorization",
            format!("DPoP {}", self.token).parse().unwrap(),
        );
        h.insert("dpop", proof.parse().unwrap());
        h
    }
    fn auth(&self, url: &str) -> DualAuthenticator {
        DualAuthenticator::new(
            &self.issuer,
            AUDIENCE,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
    }
}

struct Harness {
    f: Fixture,
    credentials: Arc<Credentials>,
    ledger: EtcdLedger,
    prefix: String,
    pki: support::Pki,
    definition: CedarPolicyDefinition,
}
struct Running {
    admit: String,
    issue: String,
    status: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Harness {
    async fn new() -> Option<Self> {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(e) => e,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP control: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let mut f = Fixture::new();
        let credentials = Arc::new(Credentials::new(
            &f.identity.subject,
            "capacity.reserve kf.admit kf.issue",
        ));
        let pki = support::pki();
        let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(pki.client.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        let workload = WorkloadIdentity::from_verified_cert_der(cert.as_ref()).unwrap();
        let setup = credentials.auth("https://control.test/admission");
        f.identity = setup
            .authenticate_at(
                &credentials.headers("https://control.test/admission"),
                &workload,
                NOW / 1000,
            )
            .unwrap();
        f.proposal["delegation"] = credentials.delegation.clone();
        let definition = CedarPolicyDefinition {
            tenant: f.trust.tenant.clone(),
            policy_id: f.trust.policy.id.clone(),
            cedar: POLICY.into(),
            obligation_manifest_digest: f.trust.obligation_manifest_digest.clone(),
            max_certificate_lifetime_ms: 5000,
        };
        f.trust.policy = definition.reference(7).unwrap();
        let prefix = format!(
            "/kf-control-tests/{}-{}",
            std::process::id(),
            rand::random::<u64>()
        );
        let ledger = EtcdLedger::new(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint,
            &prefix,
        )
        .unwrap();
        Some(Self {
            f,
            credentials,
            ledger,
            prefix,
            pki,
            definition,
        })
    }
    fn bootstrap(&self) -> Grant {
        let (_, _, mut grant) = self.f.authority(&self.f.packet());
        grant.conflict_domain = self.f.descriptor["concurrency"]["conflict_domain"]
            .as_str()
            .unwrap()
            .into();
        grant
    }
    async fn start(&self) -> Running {
        self.start_with_shared(false).await
    }
    async fn start_with_shared(&self, shared: bool) -> Running {
        let auth = |url: &str| {
            let auth = self.credentials.auth(url);
            if shared {
                auth.with_shared_replay(
                    self.ledger.clone(),
                    kedgeflow::shared_auth::SharedAuthConfig {
                        capacity: 16,
                        registrations: vec![kedgeflow::shared_auth::SubjectWorkload {
                            subject: self.f.identity.subject.clone(),
                            workload_id: self.f.identity.workload_id.clone(),
                            allowed_scopes: std::collections::BTreeSet::from([
                                "capacity.reserve".into(),
                                "kf.admit".into(),
                                "kf.issue".into(),
                                "kf.status".into(),
                            ]),
                        }],
                    },
                )
                .unwrap()
            } else {
                auth
            }
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let admit = format!("{origin}/admission");
        let issue = format!("{origin}/issuance");
        let status = format!("{origin}/status");
        let controller = AdmissionController::new(
            CedarAdmissionPolicy::new(self.definition.clone(), self.f.trust.policy.clone())
                .unwrap(),
            "key-6".into(),
            SigningKey::from_bytes(&[6; 32]),
        )
        .unwrap();
        let issuer = GrantAuthority::new(
            IssuanceVerifier {
                tenant: self.f.trust.tenant.clone(),
                admission_keys: keys(6),
                grants: GrantVerifier {
                    keys: keys(5),
                    audience: self.f.descriptor["gateway_audience"]
                        .as_str()
                        .unwrap()
                        .into(),
                },
            },
            "key-5".into(),
            SigningKey::from_bytes(&[5; 32]),
        )
        .unwrap();
        let service = Arc::new(
            ControlService::new(
                Arc::new(self.f.trust.clone()),
                controller,
                issuer,
                self.ledger.clone(),
                Arc::new(Time(NOW)),
                auth(&admit),
                auth(&issue),
                ControlPermissions {
                    subjects: vec![self.f.identity.subject.clone()],
                    admission_scope: "kf.admit".into(),
                    issuance_scope: "kf.issue".into(),
                },
            )
            .unwrap()
            .with_status(auth(&status), "kf.status".into())
            .unwrap(),
        );
        let tls = kedgeflow::tls::server_config_pem(
            self.pki.server.as_bytes(),
            self.pki.server_key.as_bytes(),
            self.pki.ca.as_bytes(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, tls, service.router())
                .await
                .unwrap();
        });
        Running {
            admit,
            issue,
            status,
            task,
        }
    }
    fn client(&self) -> reqwest::Client {
        kedgeflow::tls::pinned_http_client_pem(
            self.pki.ca.as_bytes(),
            self.pki.client.as_bytes(),
            self.pki.client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap()
    }
    fn admission(&self, id: &str) -> Value {
        let p = self.f.packet();
        json!({"profile":kedgeflow::control::PROFILE,"operation":"admit","request_id":id,"proposal":String::from_utf8(p.proposal).unwrap(),"descriptor":String::from_utf8(p.descriptor).unwrap(),"manifest":String::from_utf8(p.manifest).unwrap(),"witnesses":p.evidence.into_iter().map(|e|String::from_utf8(e).unwrap()).collect::<Vec<_>>()})
    }
    fn issuance(&self, id: &str, certificate: &str) -> Value {
        json!({"profile":kedgeflow::control::PROFILE,"operation":"issue","request_id":id,"proposal":String::from_utf8(self.f.packet().proposal).unwrap(),"certificate":certificate})
    }
    fn counter_key(&self) -> String {
        let d = digest(
            "fence-resource",
            &json!({"tenant":self.f.trust.tenant,"resource":self.f.proposal["resources"][0]}),
        )
        .unwrap();
        format!("{}/fence-counter/{d}", self.prefix)
    }
    async fn post(&self, url: &str, value: &Value) -> (reqwest::StatusCode, Value) {
        post(&self.client(), &self.credentials, url, value).await
    }
}

async fn post(
    client: &reqwest::Client,
    credentials: &Credentials,
    url: &str,
    value: &Value,
) -> (reqwest::StatusCode, Value) {
    let response = client
        .post(url)
        .headers(credentials.headers(url))
        .json(value)
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    let schema: Value = serde_json::from_str(
        if value["profile"] == kedgeflow::operation_status::PROFILE {
            include_str!("../../../spec/drafts/operation-status-v0.1.schema.json")
        } else {
            include_str!("../../../spec/drafts/leaf-control-v0.1.schema.json")
        },
    )
    .unwrap();
    assert!(
        jsonschema::validator_for(&schema).unwrap().is_valid(&value),
        "{value}"
    );
    (status, value)
}

#[tokio::test]
async fn native_admission_issuance_restarts_and_concurrent_retries_conserve_one_allowance() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
    let server = h.start().await;
    let (status, admitted) = h.post(&server.admit, &h.admission("a-1")).await;
    assert!(status.is_success(), "{admitted}");
    let certificate = admitted["certificate"].as_str().unwrap();
    verify_record(certificate.as_bytes(), "certificate", &keys(6)).unwrap();
    let key =
        h.f.trust
            .operation_key(&h.f.identity, h.f.packet().proposal.as_slice())
            .unwrap();
    let bundle = h.ledger.admission_bundle(&key, &Time(NOW)).await.unwrap();
    assert_eq!(bundle.record.signed_certificate, certificate);
    assert_eq!(bundle.packet.proposal, h.admission("x")["proposal"]);
    // Recreate the service with no per-operation memory; new URL-bound proofs
    // still resolve the original chain and certificate in the shared ledger.
    drop(server);
    let server = h.start().await;
    let (_, retry) = h.post(&server.admit, &h.admission("a-new-id")).await;
    assert_eq!(retry["certificate"], certificate);
    let body = h.issuance("i-1", certificate);
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..16 {
        let client = h.client();
        let credentials = h.credentials.clone();
        let url = server.issue.clone();
        let mut body = body.clone();
        body["request_id"] = json!(format!("i-{i}"));
        tasks.spawn(async move { post(&client, &credentials, &url, &body).await });
    }
    let mut issued = Vec::new();
    while let Some(result) = tasks.join_next().await {
        let (status, body) = result.unwrap();
        assert!(status.is_success(), "{body}");
        issued.push(body);
    }
    assert_eq!(issued.iter().filter(|r| r["reused"] == false).count(), 1);
    let raw = issued[0]["grant"].as_str().unwrap();
    assert!(issued.iter().all(|r| r["grant"] == raw));
    let v = GrantVerifier {
        keys: keys(5),
        audience: h.f.descriptor["gateway_audience"].as_str().unwrap().into(),
    }
    .verify(raw.as_bytes(), NOW)
    .unwrap();
    verify_record(raw.as_bytes(), "grant", &keys(5)).unwrap();
    assert_eq!(v.grant.fence, 1);
    assert_eq!(
        h.ledger.read_key(&h.counter_key()).await.unwrap().unwrap(),
        b"1"
    );
    assert!(v.grant.root_id.starts_with("kf-root-"));
    assert!(v.grant.gid.starts_with("kf-grant-"));
    assert!(v.grant.nonce.starts_with("kf-nonce-"));
    h.ledger
        .claim(&v.grant, &v.digest, "native-attempt")
        .await
        .unwrap();
    let (_, retry) = h.post(&server.issue, &body).await;
    assert_eq!(retry["grant"], raw);
    assert_eq!(retry["reused"], true);
    assert!(matches!(
        h.ledger.claim(&v.grant, &v.digest, "retry-attempt").await,
        Err(kedgeflow::error::Error::NonceConsumed)
    ));
    assert_eq!(
        h.ledger.read_key(&h.counter_key()).await.unwrap().unwrap(),
        b"1"
    );
}

#[tokio::test]
async fn control_permissions_proofs_closed_payloads_and_certificate_substitution_refuse_before_allocation()
 {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
    let server = h.start().await;
    let client = h.client();
    let mut body = h.admission("a");
    body["root_id"] = json!("caller-root");
    assert_eq!(
        h.post(&server.admit, &body).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    let no_issue = Credentials::new(&h.f.identity.subject, "capacity.reserve kf.admit");
    assert_eq!(
        post(&client, &no_issue, &server.issue, &h.issuance("x", "{} "))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    let other = Credentials::new(
        &kedgeflow::contracts::Subject {
            iss: h.credentials.issuer.clone(),
            sub: "other-subject".into(),
        },
        "capacity.reserve kf.admit kf.issue",
    );
    assert_eq!(
        post(&client, &other, &server.admit, &h.admission("x"))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    let headers = h.credentials.headers(&server.admit);
    let response = client
        .post(&server.admit)
        .headers(headers.clone())
        .json(&h.admission("a"))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let admitted: Value = response.json().await.unwrap();
    let response = client
        .post(&server.admit)
        .headers(headers.clone())
        .json(&h.admission("replay"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let response = client
        .post(&server.issue)
        .headers(headers)
        .json(&h.issuance("wrong-htu", admitted["certificate"].as_str().unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let mut cert: Value = serde_json::from_str(admitted["certificate"].as_str().unwrap()).unwrap();
    cert["payload"]["cid"] = json!("replacement-certificate");
    let replacement = String::from_utf8(signed("certificate", cert["payload"].clone(), 6)).unwrap();
    assert_eq!(
        h.post(&server.issue, &h.issuance("substitution", &replacement))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    let mut body = h.issuance("caller-fence", admitted["certificate"].as_str().unwrap());
    body["fence"] = json!(999999);
    assert_eq!(
        h.post(&server.issue, &body).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    assert!(h.ledger.read_key(&h.counter_key()).await.unwrap().is_none());
    let missing_tls = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(h.pki.ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert!(
        missing_tls
            .post(&server.admit)
            .json(&h.admission("no-mtls"))
            .send()
            .await
            .is_err()
    );
    let unknown = server.admit.replace("/admission", "/publish");
    assert_eq!(
        h.post(&unknown, &h.admission("admin")).await.0,
        reqwest::StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn resource_fences_increase_across_conflict_domains_and_operation_keys() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
    let server = h.start().await;
    let (_, a) = h.post(&server.admit, &h.admission("first")).await;
    let (_, i) = h
        .post(
            &server.issue,
            &h.issuance("first", a["certificate"].as_str().unwrap()),
        )
        .await;
    let first: Value = serde_json::from_str(i["grant"].as_str().unwrap()).unwrap();
    assert_eq!(first["payload"]["fence"], 1);
    drop(server);
    h.f.proposal["qid"] = json!("test:second-operation");
    h.f.descriptor["concurrency"]["conflict_domain"] = json!("domain:second");
    h.f.trust.descriptor_digest = record_hash(&signed("ctd", h.f.descriptor.clone(), 2));
    h.f.proposal["action"]["digest"] = json!(h.f.trust.descriptor_digest);
    h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
    let server = h.start().await;
    let (s, a) = h.post(&server.admit, &h.admission("second")).await;
    assert!(s.is_success(), "{a}");
    let (s, i) = h
        .post(
            &server.issue,
            &h.issuance("second", a["certificate"].as_str().unwrap()),
        )
        .await;
    assert!(s.is_success(), "{i}");
    let second: Value = serde_json::from_str(i["grant"].as_str().unwrap()).unwrap();
    assert_eq!(second["payload"]["fence"], 2);
    assert_ne!(first["payload"]["root_id"], second["payload"]["root_id"]);
    assert_eq!(
        h.ledger.read_key(&h.counter_key()).await.unwrap().unwrap(),
        b"2"
    );
}

#[tokio::test]
async fn missing_or_stale_control_state_blocks_native_admission_and_issuance() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let server = h.start().await;
    assert_eq!(
        h.post(&server.admit, &h.admission("missing-install"))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    let mut next = h.bootstrap();
    h.ledger.publish_policy(&next).await.unwrap();
    let (_, a) = h.post(&server.admit, &h.admission("installed")).await;
    next.policy.epoch += 1;
    h.ledger.publish_policy(&next).await.unwrap();
    assert_eq!(
        h.post(
            &server.issue,
            &h.issuance("stale", a["certificate"].as_str().unwrap())
        )
        .await
        .0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert!(h.ledger.read_key(&h.counter_key()).await.unwrap().is_none());
}

async fn overwrite(h: &Harness, key: &str, value: &str) {
    use base64::engine::general_purpose::STANDARD;
    assert!(key.starts_with(&format!("{}/", h.prefix)));
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v3/kv/txn",
            std::env::var("ETCD_ENDPOINT").unwrap()
        ))
        .json(&json!({
            "compare": [],
            "success": [{"request_put": {
                "key": STANDARD.encode(key), "value": STANDARD.encode(value)
            }}],
            "failure": []
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let result: Value = response.json().await.unwrap();
    assert_eq!(result["succeeded"], true);
}

#[tokio::test]
async fn issuer_reverifies_retained_evidence_and_refuses_tampered_chain() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
    let server = h.start().await;
    let (_, a) = h.post(&server.admit, &h.admission("a")).await;
    let key =
        h.f.trust
            .operation_key(&h.f.identity, &h.f.packet().proposal)
            .unwrap();
    let chain_key = format!("{}/admission-chain/{key}", h.prefix);
    let raw = h.ledger.read_key(&chain_key).await.unwrap().unwrap();
    let mut chain: Value = serde_json::from_slice(&raw).unwrap();
    let mut evidence: Value =
        serde_json::from_str(chain["packet"]["witnesses"][0].as_str().unwrap()).unwrap();
    evidence["payload"]["result"]["available_slots"] = json!(0);
    chain["packet"]["witnesses"][0] = json!(serde_json::to_string(&evidence).unwrap());
    overwrite(&h, &chain_key, &serde_json::to_string(&chain).unwrap()).await;
    let (status, _) = h
        .post(
            &server.issue,
            &h.issuance("tampered", a["certificate"].as_str().unwrap()),
        )
        .await;
    assert!(!status.is_success());
    assert!(h.ledger.read_key(&h.counter_key()).await.unwrap().is_none());
    assert!(
        h.ledger
            .read_key(&format!("{}/issuance/{key}", h.prefix))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn exhausted_counter_and_unregistered_workload_fail_closed() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
    let server = h.start().await;
    let (_, a) = h.post(&server.admit, &h.admission("a")).await;
    let maximum = kedgeflow::contracts::MAX_SAFE_INTEGER.to_string();
    overwrite(&h, &h.counter_key(), &maximum).await;
    assert_eq!(
        h.post(
            &server.issue,
            &h.issuance("exhausted", a["certificate"].as_str().unwrap())
        )
        .await
        .0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.ledger.read_key(&h.counter_key()).await.unwrap().unwrap(),
        maximum.as_bytes()
    );
    drop(server);
    h.f.trust.proposal_workload_id = "spiffe://test/unregistered".into();
    let server = h.start().await;
    assert_eq!(
        h.post(&server.admit, &h.admission("wrong-workload"))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
}

#[test]
fn operator_config_has_closed_roles_and_prints_pins_without_private_material() {
    use kedgeflow::control_config::ControlConfig;
    let raw = include_bytes!("../../../config/control.example.json");
    let cfg = ControlConfig::decode(raw).unwrap();
    let (trust, definition) = cfg.registration().unwrap();
    assert_eq!(trust.policy, definition.reference(7).unwrap());
    assert_eq!(
        trust.obligation_manifest_digest,
        trust.registered_obligations_digest().unwrap()
    );
    assert_eq!(
        trust.descriptor_digest,
        Fixture::new().trust.descriptor_digest
    );
    for field in ["proposal_keys", "manifest_keys"] {
        let mut cfg: Value = serde_json::from_slice(raw).unwrap();
        cfg[field] = cfg["registry_keys"].clone();
        assert!(
            ControlConfig::decode(&serde_json::to_vec(&cfg).unwrap())
                .unwrap()
                .registration()
                .is_err()
        );
    }
    let mut cfg: Value = serde_json::from_slice(raw).unwrap();
    cfg["extra_admin"] = json!(true);
    assert!(ControlConfig::decode(&serde_json::to_vec(&cfg).unwrap()).is_err());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kf-control"))
        .args([
            "--config",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../config/control.example.json"
            ),
            "--print-pins",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pins: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(pins["policy"]["digest"], trust.policy.digest);
    assert!(pins.get("private_key").is_none());
}

#[tokio::test]
async fn native_operation_status_authorizes_history_and_refuses_substitution() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
    let server = h.start().await;
    let current = Credentials::new(&h.f.identity.subject, "kf.status");
    let body = json!({"profile":kedgeflow::operation_status::PROFILE,"operation":"status","request_id":"query-1","proposal":h.admission("x")["proposal"]});
    let client = h.client();
    assert_eq!(
        h.post(&server.status, &body).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    let (_, absent) = post(&client, &current, &server.status, &body).await;
    assert_eq!(absent["state"], "unissued");
    assert!(absent["grant_digest"].is_null());
    assert!(h.ledger.read_key(&h.counter_key()).await.unwrap().is_none());
    let mut unsupported = body.clone();
    unsupported["profile"] = json!("other");
    assert_eq!(
        post(&client, &current, &server.status, &unsupported)
            .await
            .0,
        reqwest::StatusCode::BAD_REQUEST
    );
    let mut headers = current.headers(&server.status);
    headers.insert("Mcp-KedgeFlow-Grant", "unexpected".parse().unwrap());
    assert_eq!(
        client
            .post(&server.status)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .post(&server.status)
            .headers(current.headers(&server.issue))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let (_, admitted) = h.post(&server.admit, &h.admission("a")).await;
    let (_, issued) = h
        .post(
            &server.issue,
            &h.issuance("i", admitted["certificate"].as_str().unwrap()),
        )
        .await;
    let raw = issued["grant"].as_str().unwrap();
    let grant = GrantVerifier {
        keys: keys(5),
        audience: h.f.descriptor["gateway_audience"].as_str().unwrap().into(),
    }
    .verify(raw.as_bytes(), NOW)
    .unwrap();
    let (_, state) = post(&client, &current, &server.status, &body).await;
    assert_eq!(state["state"], "unclaimed", "{state}");
    assert_eq!(state["grant_digest"], grant.digest);
    h.ledger
        .claim(&grant.grant, &grant.digest, "original-attempt")
        .await
        .unwrap();
    drop(server);
    let server = h.start().await;
    let (_, state) = post(&client, &current, &server.status, &body).await;
    assert_eq!(state["state"], "claimed");
    assert_eq!(state["attempt_id"], "original-attempt");
    for field in [
        "tenant",
        "subject",
        "workload_id",
        "delegation",
        "action",
        "parameters",
    ] {
        let mut p = h.f.proposal.clone();
        match field {
            "tenant" | "workload_id" => p[field] = json!("another"),
            "subject" => p[field]["sub"] = json!("another"),
            "delegation" => p[field]["dpop_jkt"] = json!("another"),
            "action" => p[field]["digest"] = json!("0".repeat(64)),
            _ => p[field]["expected_version"] = json!(999),
        }
        let mut bad = body.clone();
        bad["proposal"] = json!(String::from_utf8(signed("proposal", p, 1)).unwrap());
        assert!(
            !post(&client, &current, &server.status, &bad)
                .await
                .0
                .is_success(),
            "{field}"
        );
    }
    let mut bad = body.clone();
    bad["grant"] = json!(raw);
    assert_eq!(
        post(&client, &current, &server.status, &bad).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    let other = Credentials::new(
        &kedgeflow::contracts::Subject {
            iss: h.credentials.issuer.clone(),
            sub: "other".into(),
        },
        "kf.status",
    );
    assert_eq!(
        post(&client, &other, &server.status, &body).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    // Corruption must remain unavailable, never look like absent issuance.
    let key =
        h.f.trust
            .operation_key(&h.f.identity, h.f.packet().proposal.as_slice())
            .unwrap();
    let stored_key = format!("{}/issuance/{key}", h.prefix);
    let mut retained: Value =
        serde_json::from_slice(&h.ledger.read_key(&stored_key).await.unwrap().unwrap()).unwrap();
    retained["signed_grant"] = json!(raw.replace("key-5", "key-4"));
    overwrite(&h, &stored_key, &serde_json::to_string(&retained).unwrap()).await;
    assert_eq!(
        post(&client, &current, &server.status, &body).await.0,
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    overwrite(&h, &format!("{}/issuance/{key}", h.prefix), "{}").await;
    let (code, failure) = post(&client, &current, &server.status, &body).await;
    assert_eq!(code, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failure["code"], "authority_unavailable");
    assert_eq!(
        h.ledger.read_key(&h.counter_key()).await.unwrap().unwrap(),
        b"1"
    );
}

#[tokio::test]
async fn native_admission_consumes_shared_proof_before_idempotent_retry() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
    let server = h.start_with_shared(true).await;
    let headers = h.credentials.headers(&server.admit);
    let client = h.client();
    let first = client
        .post(&server.admit)
        .headers(headers.clone())
        .json(&h.admission("first"))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let first: Value = first.json().await.unwrap();
    assert!(first["certificate"].is_string());
    let replay = client
        .post(&server.admit)
        .headers(headers)
        .json(&h.admission("replayed-proof"))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
    let (status, retry) = h.post(&server.admit, &h.admission("fresh-proof")).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(first["certificate"], retry["certificate"]);
}

#[path = "support/native_review.rs"]
mod native_review;
