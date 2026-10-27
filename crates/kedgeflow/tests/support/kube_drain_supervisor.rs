//! Actual managed controller primitives plus shipping read-only supervision.
//! Shipping managed gateway/controller configuration is not enabled by this case.
use super::*;
use kedgeflow::{
    managed_drain_audit as audit, managed_drain_evidence as mdproof, physical_operations as op,
};
use std::sync::Mutex;
const SINK_TOKEN: &str = "owned-managed-supervisor-sink-credential-000000000";
struct SinkState {
    requests: Mutex<Vec<mdproof::Signed<mdproof::IncidentReport>>>,
    acknowledgement: Mutex<Option<mdproof::Ack>>,
    hold_first: bool,
    release: tokio::sync::Notify,
}
struct SinkServer {
    server: support::HttpsServer,
    pki: Vec<support::Pki>,
    state: Arc<SinkState>,
}
impl SinkServer {
    async fn new(hold_first: bool) -> Self {
        let pki = support::pki_for_workloads(&[
            "spiffe://test/physical-supervisor",
            "spiffe://test/incident-sink",
        ]);
        let state = Arc::new(SinkState {
            requests: Mutex::new(vec![]),
            acknowledgement: Mutex::new(None),
            hold_first,
            release: tokio::sync::Notify::new(),
        });
        let shared = state.clone();
        let server=support::serve_tls(&pki[1], Router::new().route("/incident",post(move |Extension(workload):Extension<WorkloadIdentity>, headers:HeaderMap, Json(report):Json<mdproof::Signed<mdproof::IncidentReport>>| {
            let state=shared.clone();async move {
                if workload.as_str()!="spiffe://test/physical-supervisor" || headers.get("authorization").and_then(|v|v.to_str().ok())!=Some(&format!("Bearer {SINK_TOKEN}")) {return Err(StatusCode::UNAUTHORIZED);}
                let pin=ObserverPin{id:"operating-observer".into(),keys:public(91)};
                report.verify("incident_report",&pin).map_err(|_|StatusCode::FORBIDDEN)?;
                let first={ let mut requests=state.requests.lock().unwrap(); let first=requests.is_empty();
                    if let Some(old)=requests.first(){assert_eq!(json!(old),json!(report),"delivery must preserve exact original report despite reply loss/restart");}
                    requests.push(report.clone());first };
                let ack={let mut saved=state.acknowledgement.lock().unwrap(); saved.get_or_insert_with(||mdproof::Signed::sign("incident_ack", mdproof::Acknowledgement{incident_id:report.body.incident_id.clone(),event_digest:report.body.event_digest.clone(),received_at:now()}, &ObserverPin{id:"fixture-incidents".into(),keys:public(92)},"key-92",&SigningKey::from_bytes(&[92;32])).unwrap()).clone()};
                if first && state.hold_first {state.release.notified().await;}
                Ok(Json(ack))
            }
        }))).await;
        Self { server, pki, state }
    }
    fn policy(&self, duration: u64, before: u64) -> op::Policy {
        op::Policy {
            profile: op::PROFILE.into(),
            tenant: Fixture::new().trust.tenant,
            resource_owner_id: "team:fixture-owner".into(),
            on_call_team_id: "team:fixture-oncall".into(),
            incident_sink: op::IncidentSink {
                id: "fixture-incidents".into(),
                url: format!("{}/incident", self.server.url),
                acknowledgement_keys: public(92),
                maximum_delivery_attempts: 3,
            },
            initial_backoff_ms: 100,
            maximum_backoff_ms: 200,
            maximum_automated_queries: before,
            reconcile_for_ms: duration,
            post_deadline_observation: op::PostDeadline::QueryOnly {
                maximum_queries: 2,
                observe_for_ms: 30000,
            },
            expiry_action: op::ExpiryAction::StopConsequentialWork,
        }
    }
}
struct Process {
    directory: tempfile::TempDir,
    config: PathBuf,
}
impl Process {
    fn new(
        r: &Ready,
        source: &SourceProcess,
        identity: &[support::Pki],
        sink: &SinkServer,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = directory.path().canonicalize().unwrap();
        let write = |name: &str, raw: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, raw).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let signer = |id: &str, n: u8| json!({"id":id,"key_id":format!("key-{n}"),"signing_key_file":write(&format!("observer-{n}.key"),STANDARD.encode([n;32]).as_bytes())});
        let forward = signer("budget-observer", 15);
        let compound = signer("compound-observer", 20);
        let aggregate = signer("aggregate-observer", 34);
        let family = signer("family-observer", 33);
        let observer_key = write(
            "physical-observer.key",
            STANDARD.encode([49; 32]).as_bytes(),
        );
        let operating = write("operating.key", STANDARD.encode([91; 32]).as_bytes());
        let ca = write("etcd-ca.pem", identity[4].ca.as_bytes());
        let cert = write("etcd-client.pem", identity[4].client.as_bytes());
        let key = write("etcd-client.key", identity[4].client_key.as_bytes());
        let token = write("etcd.token", SUPERVISOR_ETCD.as_bytes());
        let api_ca = write("api-ca.pem", &r.api_ca);
        let api_token = write(
            "api.token",
            &std::fs::read(
                Path::new(&std::env::var("KF_KUBE_FIXTURE").unwrap()).join("observer.token"),
            )
            .unwrap(),
        );
        let sink_ca = write("sink-ca.pem", sink.pki[0].ca.as_bytes());
        let sink_cert = write("sink-client.pem", sink.pki[0].client.as_bytes());
        let sink_key = write("sink-client.key", sink.pki[0].client_key.as_bytes());
        let sink_token = write("sink.token", SINK_TOKEN.as_bytes());
        let config=write("supervisor.json",&serde_json::to_vec(&json!({"profile":kedgeflow::managed_drain::PROFILE,"material_root":dir,"child_id":"child-1","operating_key_id":"key-91","operating_key_file":operating,"collector":{"family":{"registration":r.r,"etcd_endpoint":source._relay.url,"etcd_prefix":r.r.namespace,"etcd_ca":ca,"etcd_certificate":cert,"etcd_private_key":key,"etcd_token_file":token,"restore_gate":null},"members":{"child-0":{"forward":forward,"compound":compound},"child-1":{"forward":forward,"compound":null}},"collector":aggregate,"family_observer":family,"physical_observers":{"child-1":{"api":{"material_root":dir,"ca_file":api_ca,"token_file":api_token},"key_id":"key-49","signing_key_file":observer_key}}},"sink":{"ca_file":sink_ca,"certificate_file":sink_cert,"private_key_file":sink_key,"token_file":sink_token}})).unwrap());
        Self { directory, config }
    }
    fn command(&self, action: &str) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-managed-drain-supervisor"));
        c.arg("--material-root")
            .arg(self.directory.path().canonicalize().unwrap())
            .arg("--config")
            .arg(&self.config)
            .arg(action)
            .kill_on_drop(true);
        c
    }
    async fn json(&self, action: &str) -> Value {
        let out = self.command(action).output().await.unwrap();
        assert!(
            out.status.success(),
            "supervisor {action}: {}; retained process diagnostics: {}",
            String::from_utf8_lossy(&out.stderr),
            self.log()
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
    async fn rejects(&self, value: Value) {
        let path = self
            .directory
            .path()
            .canonicalize()
            .unwrap()
            .join("rejected.json");
        std::fs::write(&path, canonical(&value).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-managed-drain-supervisor"))
            .arg("--material-root")
            .arg(self.directory.path().canonicalize().unwrap())
            .arg("--config")
            .arg(&path)
            .arg("check")
            .output()
            .await
            .unwrap();
        assert!(
            !out.status.success(),
            "substituted protected supervisor config must refuse"
        );
    }
    async fn check_negatives(&self, identity: &[support::Pki]) {
        let value: Value = serde_json::from_slice(&std::fs::read(&self.config).unwrap()).unwrap();
        for (field, replacement) in [
            ("profile", json!("KF-MANAGED-KUBE-DRAIN-0.1-draft")),
            ("child_id", json!("child-0")),
            ("operating_key_id", json!("key-94")),
            ("collector", Value::Null),
            ("unknown", json!(true)),
        ] {
            let mut v = value.clone();
            v[field] = replacement;
            self.rejects(v).await;
        }
        let mut v = value.clone();
        v["collector"]["physical_observers"]["child-1"]["api"]["material_root"] =
            json!("/private/tmp");
        self.rejects(v).await;
        let dir = self.directory.path().canonicalize().unwrap();
        for (name, raw) in [
            ("wrong-role.pem", identity[3].client.as_bytes()),
            ("wrong-role.key", identity[3].client_key.as_bytes()),
        ] {
            let p = dir.join(name);
            std::fs::write(&p, raw).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut v = value.clone();
        v["collector"]["family"]["etcd_certificate"] = json!(dir.join("wrong-role.pem"));
        v["collector"]["family"]["etcd_private_key"] = json!(dir.join("wrong-role.key"));
        self.rejects(v).await;
        let mut v = value.clone();
        v["operating_key_file"] = json!(dir.join("../outside.key"));
        self.rejects(v).await;
        let key = dir.join("operating.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
        self.rejects(value).await;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn start(&self) -> tokio::process::Child {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.path().join("supervisor.log"))
            .unwrap();
        self.command("run")
            .stdout(std::process::Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap()
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.path().join("supervisor.log")).unwrap_or_default()
    }
}
async fn authorize(
    r: &mut Ready,
    source: &SourceProcess,
) -> (
    kedgeflow::ledger::IssuanceRecord,
    kedgeflow::recovery::Candidate,
    String,
) {
    use kedgeflow::{
        broker_authorization::{BrokerAuthorizer, BrokerRegistration, ExchangeRequest},
        target_token::{ReferenceTokenMinter, TargetTokenMinter},
    };
    fresh(&mut r.physical);
    let h = &mut r.physical;
    let at = now();
    let expires = at / 1000 + 54;
    let audience = h.f.proposal["delegation"]["token_audience"]
        .as_str()
        .unwrap()
        .to_owned();
    let scope = h.f.trust.required_scope.clone();
    let subject = jwt(
        json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
        json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":audience,"exp":expires,"iat":at/1000,"scope":scope,"cnf":{"jkt":h.f.identity.dpop_jkt}}),
        7,
    );
    h.f.proposal["delegation"] = json!({"access_token_digest":hex::encode(Sha256::digest(subject.as_bytes())),"dpop_jkt":h.f.identity.dpop_jkt,"authorization_server":h.f.identity.subject.iss,"token_audience":audience,"scopes":[scope],"expires_at":expires*1000});
    h.f.identity.access_token = subject.clone();
    h.f.identity.delegation_digest = digest("delegation", &h.f.proposal["delegation"]).unwrap();
    let mut provider = crate::exchange::Fixture::new();
    provider.snapshot.issuer = h.f.identity.subject.iss.clone();
    provider.snapshot.subject_audience = audience;
    provider.snapshot.subject_keys[0].kid = "key-7".into();
    provider.snapshot.subject_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    provider.snapshot.registrations[0].subject = h.f.identity.subject.clone();
    provider.snapshot.registrations[0].allowed_scopes = std::collections::BTreeSet::from([scope]);
    provider.snapshot.not_before = at;
    provider.snapshot.expires_at = at + 120000;
    provider.snapshot.subject_keys[0].not_before = at;
    provider.snapshot.subject_keys[0].expires_at = at + 120000;
    provider.snapshot.actor_keys[0].not_before = at;
    provider.snapshot.actor_keys[0].expires_at = at + 120000;
    let actor=provider.actor_token(json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),json!({"sub":"spiffe://test/agent","aud":"https://broker.test/exchange","exp":at/1000+60,"iat":at/1000}));
    let broker = BrokerAuthorizer::new(
        BrokerRegistration {
            gateway_workload: "spiffe://test/gateway".into(),
            target_audience: "https://kube-target.test/accept".into(),
            target_scope: "node:drain".into(),
            max_lifetime_ms: 5000,
            tool: h.tool(),
        },
        GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        },
        h.ledger.clone(),
        Arc::new(provider.provider()),
        Arc::new(SystemClock),
    )
    .unwrap();
    let read = Api::new(
        &r.contract.api_origin,
        &r.api_ca,
        std::fs::read_to_string(
            Path::new(&std::env::var("KF_KUBE_FIXTURE").unwrap()).join("observer.token"),
        )
        .unwrap(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let inventory = read.inventory(&r.contract).await.unwrap();
    inventory.availability(&r.contract).unwrap();
    h.f.evidence["result"] = json!({"available_replicas":inventory.available,"minimum_available":r.contract.workload.minimum_available,"contract_generation":r.contract.generation.to_string(),"satisfied":true});
    h.f.evidence["observed_at"] = json!(now());
    h.f.evidence["expires_at"] = json!(now() + 30000);
    let enrollment = h.ledger.clone();
    let store = Store::new(enrollment).unwrap();
    let request = preflight::Request {
        profile: source::PROFILE.into(),
        enrollment_digest: store.context.enrollment.digest().unwrap(),
        signed_proposal: String::from_utf8(h.f.packet().proposal).unwrap(),
        requested_at: now(),
    };
    let response = source
        .assembler
        .post(format!("{}/evidence", source.endpoint))
        .bearer_auth(EVIDENCE)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let evidence: preflight::Evidence = response.json().await.unwrap();
    let packet = proposal_packet(h, &evidence.evidence);
    Box::pin(refresh(h)).await;
    let record = Box::pin(issue_packet(h, &packet)).await;
    let candidate = Box::pin(native::claim(h, &record, "managed-supervised-original")).await;
    let permit = Box::pin(broker.authorize(
        &ExchangeRequest {
            subject_token: subject,
            actor_token: actor,
            signed_grant: record.signed_grant.clone(),
            grant_digest: record.grant_digest.clone(),
            attempt_id: candidate.attempt_id.clone(),
            audience: "https://kube-target.test/accept".into(),
            scope: "node:drain".into(),
        },
        &crate::exchange::workload("spiffe://test/gateway"),
    ))
    .await
    .unwrap();
    let token = ReferenceTokenMinter::new(
        "https://broker.test/exchange".into(),
        "key-29".into(),
        SigningKey::from_bytes(&[29; 32]),
    )
    .unwrap()
    .mint(&permit, now())
    .await
    .unwrap();
    Box::pin(h.ledger.authorize_dispatch(
        &candidate.grant,
        &record.grant_digest,
        &candidate.attempt_id,
    ))
    .await
    .unwrap();
    (record, candidate, token)
}
fn save(name: &str, bundle: &audit::Bundle, trust: &audit::Trust, extra: Value) {
    if let Ok(output) = std::env::var("KF_CONFORMANCE_ARTIFACTS") {
        let out = PathBuf::from(output).join(name);
        std::fs::create_dir_all(&out).unwrap();
        for (name, value) in [
            ("bundle.json", json!(bundle)),
            ("trust.json", json!(trust)),
            ("verification.json", bundle.verify(trust).unwrap()),
            ("process.json", extra),
        ] {
            std::fs::write(out.join(name), canonical(&value).unwrap()).unwrap();
        }
    }
}
async fn export(process: &Process, r: &Ready) -> (audit::Bundle, audit::Trust) {
    let bundle: audit::Bundle = serde_json::from_value(process.json("export").await).unwrap();
    let trust = audit::Trust {
        profile: kedgeflow::managed_drain::PROFILE.into(),
        selection: kedgeflow::family::Selection {
            registration: r.r.clone(),
            child_id: "child-1".into(),
        },
    };
    bundle.verify(&trust).unwrap();
    (bundle, trust)
}
#[tokio::test]
async fn kube_drain_real_managed_supervisor_deadline_outbox_lost_sink_reply_sigkill_restart_and_complete_audit()
 {
    let sink = SinkServer::new(true).await;
    let (mut r, identity, source, mut source_child) =
        Box::pin(setup_source(Some(sink.policy(15000, 2)))).await;
    let process = Process::new(&r, &source, &identity, &sink);
    process.json("check").await;
    process.check_negatives(&identity).await;
    let before = sql_rows(&r).await;
    let (_, candidate, _) = Box::pin(authorize(&mut r, &source)).await;
    let store = Store::new(r.physical.ledger.clone()).unwrap();
    assert!(now() < candidate.grant.expires_at);
    assert_eq!(
        process.json("observe").await["observed"],
        false,
        "supervisor cannot steal the original acceptance window"
    );
    assert_eq!(store.status().await.unwrap().unwrap().before_queries, 0);
    let remaining = (candidate.grant.expires_at - now()).max(0) as u64;
    tokio::time::sleep(Duration::from_millis(remaining + 1)).await;
    let initial = process.json("observe").await;
    assert_eq!(initial["observed"], true);
    assert_eq!(
        initial["operating"]["observation"]["native"],
        json!({"state":"missing"})
    );
    assert_eq!(
        initial["operating"]["observation"]["resolution"],
        "unresolved"
    );
    let mut child = process.start();
    let until = std::time::Instant::now() + Duration::from_secs(35);
    loop {
        assert!(child.try_wait().unwrap().is_none(), "{}", process.log());
        if !sink.state.requests.lock().unwrap().is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "deadline/outbox never reached sink: {}",
            process.log()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let opened = store.status().await.unwrap().unwrap();
    assert!(opened.stop_required && opened.unresolved());
    assert!(!opened.accepted);
    let incident = opened.incident.as_ref().unwrap();
    assert_eq!(
        incident.deadline,
        sink.state.requests.lock().unwrap()[0]
            .body
            .original
            .dispatched_at
            + 15000
    );
    assert_eq!(incident.attempts, 1);
    assert!(incident.pending.is_some());
    assert!(incident.acknowledgement_digest.is_none());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    sink.state.release.notify_waiters();
    source.ack_race.armed.store(true, Ordering::SeqCst);
    let mut restarted = process.start();
    let until = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        assert!(restarted.try_wait().unwrap().is_none(), "{}", process.log());
        let state = store
            .status()
            .await
            .unwrap_or_else(|e| {
                panic!("supervisor retained status refused: {e}; {}", process.log())
            })
            .unwrap();
        if state
            .incident
            .as_ref()
            .unwrap()
            .acknowledgement_digest
            .is_some()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "lost sink reply never recovered: {}",
            process.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    restarted.kill().await.unwrap();
    restarted.wait().await.unwrap();
    let status = store.status().await.unwrap().unwrap();
    let i = status.incident.as_ref().unwrap();
    assert_eq!(i.id, incident.id);
    assert_eq!(i.event_digest, incident.event_digest);
    assert_eq!(i.attempts, 2);
    assert!(status.stop_required && status.unresolved());
    assert!(status.before_queries <= 2 && status.after_queries <= 2);
    assert_eq!(sink.state.requests.lock().unwrap().len(), 2);
    assert_eq!(
        source.ack_race.refused.load(Ordering::SeqCst),
        1,
        "signed ACK must survive a real native comparison race without another sink request"
    );
    let (bundle, trust) = export(&process, &r).await;
    let verified = bundle.verify(&trust).unwrap();
    assert_eq!(verified["held_forward"], 2);
    assert_eq!(verified["held_compensation"], 1);
    assert_eq!(verified["execution_authority"], false);
    assert_eq!(verified["native_history_verified"], true);
    assert_eq!(before, sql_rows(&r).await);
    let kedgeflow::managed_drain_store::Material::Aggregate(current) =
        &bundle.evidence.materials[&bundle.evidence.current_aggregate_digest]
    else {
        panic!("retained complete aggregate");
    };
    let member = &current.evidence.current.snapshot.members["child-1"];
    let pending = &member.executions[&store.context.enrollment.operation_key].lineage;
    let node = r.r.composition.as_ref().unwrap().node("child-1").unwrap();
    let mut pins =
        kedgeflow::reserved_lineage::TrustConfig::decode(&canonical(&node.forward_trust).unwrap())
            .unwrap()
            .registration()
            .unwrap()
            .lineage;
    pins.admission.proposal_workload_id = candidate.grant.workload_id.clone();
    let proof = kedgeflow::lineage::verify_lineage(pending, &pins).unwrap();
    assert_eq!(proof.reported_status, "pending");
    assert_eq!(proof.receipts_verified, 0);
    for profile in [
        kedgeflow::lineage::PROFILE,
        kedgeflow::lineage::LEASE_PROFILE,
    ] {
        let mut legacy = pending.clone();
        legacy.profile = profile.into();
        legacy.outcomes.profile = kedgeflow::recovery::PROFILE.into();
        assert!(
            kedgeflow::lineage::verify_lineage(&legacy, &pins).is_err(),
            "receipt-based lineage cannot silently accept pending receipt absence"
        );
    }
    for (field, replacement) in [
        ("profile", json!(kedgeflow::lineage::LEASE_PROFILE)),
        ("receipt", json!("fabricated-receipt")),
        ("evidence", json!({"fabricated":"body"})),
        ("phase", json!("not_dispatched")),
        ("attempt", json!("other-original")),
        ("order", Value::Null),
    ] {
        let mut bad = pending.clone();
        match field {
            "profile" => bad.profile = replacement.as_str().unwrap().into(),
            "receipt" => bad
                .outcomes
                .receipts
                .push(replacement.as_str().unwrap().into()),
            "evidence" => {
                bad.outcomes
                    .evidence
                    .insert("fabricated".into(), replacement);
            }
            "phase" => {
                bad.outcomes.journal[1]["phase"] = replacement;
            }
            "attempt" => {
                bad.outcomes.journal[0]["attempt_id"] = replacement;
            }
            _ => {
                bad.outcomes.journal.swap(0, 1);
            }
        };
        assert!(
            kedgeflow::lineage::verify_lineage(&bad, &pins).is_err(),
            "pending original cannot accept {field} substitution"
        );
    }
    save(
        "managed-supervisor-unknown",
        &bundle,
        &trust,
        json!({"shipping_supervisor":true,"controller_acceptance":false,"sink_retained_before_sigkill":true,"sink_requests":2,"ack_native_cas_races":1,"stable_report":true,"incident_ack_does_not_resolve":true,"operating":status}),
    );
    source_child.kill().await.unwrap();
    source_child.wait().await.unwrap();
}
#[tokio::test]
async fn kube_drain_real_managed_supervisor_actual_controller_sources_physical_completion_and_prefix_audit()
 {
    let sink = SinkServer::new(false).await;
    let (mut r, identity, source, mut source_child) =
        Box::pin(setup_source(Some(sink.policy(30000, 8)))).await;
    let process = Process::new(&r, &source, &identity, &sink);
    process.json("check").await;
    let before = sql_rows(&r).await;
    let (record, candidate, token) = Box::pin(authorize(&mut r, &source)).await;
    let accepted = r
        .controller
        .accept(
            record.signed_grant.clone(),
            candidate.attempt_id.clone(),
            r.physical.f.proposal["parameters"].clone(),
            &token,
        )
        .await
        .unwrap();
    Box::pin(seal_acceptance(&r, &record, &candidate, &accepted)).await;
    let first = process.json("observe").await;
    assert_eq!(
        first["operating"]["observation"]["native"]["status"],
        "committed"
    );
    assert_eq!(
        first["operating"]["observation"]["resolution"],
        "unresolved"
    );
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(220)).await;
        Box::pin(refresh(&r.physical)).await;
        let result = r.controller.advance().await;
        match result {
            Err(error) => {
                let operating = Store::new(r.physical.ledger.clone())
                    .unwrap()
                    .status()
                    .await
                    .unwrap();
                panic!(
                    "managed physical advance refused: {error}; operating={}",
                    json!(operating)
                );
            }
            Ok(state) => {
                let response = state.body.steps.last().and_then(|s| s.response.as_ref());
                assert!(
                    response.is_some_and(|r| (200..300).contains(&r.http_status)),
                    "happy-case API request did not succeed; controller={}",
                    json!(state)
                );
            }
        }
    }
    let mut child = process.start();
    let store = Store::new(r.physical.ledger.clone()).unwrap();
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(child.try_wait().unwrap().is_none(), "{}", process.log());
        let state = store
            .status()
            .await
            .unwrap_or_else(|e| {
                panic!("supervisor retained status refused: {e}; {}", process.log())
            })
            .unwrap();
        if !state.unresolved() {
            break;
        }
        if std::time::Instant::now() >= until {
            panic!(
                "physical completion not independently observed: {}; operating={}; controller={}",
                process.log(),
                json!(state),
                json!(r.controller.state().await.unwrap())
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let (bundle, trust) = export(&process, &r).await;
    let verified = bundle.verify(&trust).unwrap();
    assert_eq!(verified["controller_proofs"], 5);
    assert_eq!(verified["source_claims"], 3);
    assert_eq!(
        verified["physical"]["physical_status"],
        "observed_completed"
    );
    assert_eq!(verified["operating"]["send_checks"], 2);
    assert_eq!(verified["operating"]["incident"], Value::Null);
    assert_eq!(before, sql_rows(&r).await);
    assert!(sink.state.requests.lock().unwrap().is_empty());
    let current = &bundle.evidence.materials[&bundle.evidence.current_aggregate_digest];
    let kedgeflow::managed_drain_store::Material::Aggregate(aggregate) = current else {
        panic!("aggregate")
    };
    for omission in ["send", "claim", "admission", "events"] {
        let mut changed = aggregate.evidence.current.snapshot.clone();
        let member = changed.members.get_mut("child-1").unwrap();
        let native = member.physical.as_mut().unwrap().managed.as_mut().unwrap();
        match omission {
            "send" => {
                let key = native
                    .sources
                    .controls
                    .iter()
                    .find(|(_, p)| p.body.kind == mdproof::ControlKind::Send)
                    .unwrap()
                    .0
                    .clone();
                native.sources.controls.remove(&key);
            }
            "claim" => {
                native.sources.claims.pop_first();
            }
            "admission" => {
                native
                    .sources
                    .admission
                    .statement
                    .body
                    .claim
                    .proposal_digest = "a".repeat(64);
            }
            _ => {
                native.sources.events.remove(1);
            }
        }
        let mut cp = native.checkpoint.body.clone();
        cp.source_digest = digest(
            "managed-drain-native-control-sources",
            &json!(native.sources),
        )
        .unwrap();
        cp.event_count = native.sources.events.len() as u64;
        cp.head_digest = native.sources.events.last().unwrap().digest().unwrap();
        native.checkpoint = mdproof::Signed::sign(
            "native_control_capture",
            cp,
            &store.context.physical.observer,
            "key-49",
            &SigningKey::from_bytes(&[49; 32]),
        )
        .unwrap();
        assert!(
            changed.verify(&r.r).is_err(),
            "validly resigned omission {omission} must refuse"
        );
    }
    let mut changed = bundle.clone();
    changed
        .evidence
        .materials
        .remove(&changed.evidence.current_aggregate_digest);
    changed.checkpoint.body.evidence_digest =
        digest("managed-drain-complete-evidence", &json!(changed.evidence)).unwrap();
    changed.checkpoint = mdproof::Signed::sign(
        "complete_operating_audit",
        changed.checkpoint.body.clone(),
        &store.context.enrollment.operating_observer,
        "key-91",
        &SigningKey::from_bytes(&[91; 32]),
    )
    .unwrap();
    assert!(
        changed.verify(&trust).is_err(),
        "valid operating signer cannot hide a required physical aggregate"
    );
    save(
        "managed-supervisor-completed",
        &bundle,
        &trust,
        json!({"shipping_supervisor":true,"managed_controller":"explicit library constructor; actual SQL source, native authority and Kubernetes API; shipping gateway/controller config still disabled","physical_requests":2,"native_committed_is_acceptance":true,"controller_proofs":5,"source_claims":3,"sql_rows_unchanged":true}),
    );
    source_child.kill().await.unwrap();
    source_child.wait().await.unwrap();
}
