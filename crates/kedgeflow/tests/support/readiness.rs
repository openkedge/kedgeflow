//! Live read-only probes against native managed state and an independent witness.
use super::*;
use kedgeflow::{
    broker_authorization::{
        BrokerAuthorizer, BrokerRegistration, ExchangeIdentityProvider, VerifiedExchangeIdentity,
    },
    broker_service::BrokerService,
    control::{ControlPermissions, ControlService},
    error::Result,
    operations::{Check, Condition, Dependency, Probe},
    outcome_report_service::{OutcomeReportService, ReporterTrust},
    restore::RestoreGate,
    target_token::{TargetTokenMinter, TargetTokenVerifier},
};
struct Identity;
#[async_trait::async_trait]
impl ExchangeIdentityProvider for Identity {
    async fn readiness(&self, _: i64) -> Result<Option<()>> {
        Ok(Some(()))
    }
    async fn verify(&self, _: &str, _: &str, _: i64) -> Result<VerifiedExchangeIdentity> {
        panic!("readiness must not verify/consume an execution request")
    }
}
struct Minter;
struct QualifiedQuery;
#[async_trait::async_trait]
impl kedgeflow::ledger::OutcomeQuerier for QualifiedQuery {
    async fn readiness(&self) -> Result<Option<()>> {
        Ok(Some(()))
    }
    async fn query(&self, _: &str) -> Result<kedgeflow::ledger::AuthoritativeObservation> {
        panic!("monitor must not recover or record a real attempt")
    }
}
#[async_trait::async_trait]
impl TargetTokenMinter for Minter {
    async fn mint(
        &self,
        _: &kedgeflow::broker_authorization::ExchangePermit,
        _: i64,
    ) -> Result<String> {
        panic!("readiness must not mint")
    }
}
fn control(h: &Harness) -> ControlService {
    let auth = |url| {
        DualAuthenticator::new(
            &h.f.identity.subject.iss,
            AUD,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
    };
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
                grants: GrantVerifier {
                    keys: keys(5),
                    audience: h.registration.scope.audience.clone(),
                },
            },
            "key-5".into(),
            SigningKey::from_bytes(&[5; 32]),
        )
        .unwrap(),
        h.ledger.clone(),
        h.clock.clone(),
        auth("https://control.test/admit"),
        auth("https://control.test/issue"),
        ControlPermissions {
            subjects: vec![h.f.identity.subject.clone()],
            admission_scope: "kf.admit".into(),
            issuance_scope: "kf.issue".into(),
        },
    )
    .unwrap()
}
fn broker(h: &Harness) -> BrokerService {
    let authorizer = BrokerAuthorizer::new(
        BrokerRegistration {
            gateway_workload: h.registration.acknowledger.workload_id.clone(),
            target_audience: "urn:target".into(),
            target_scope: "write".into(),
            max_lifetime_ms: 30000,
            tool: h.tool(),
        },
        GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        },
        h.ledger.clone(),
        Arc::new(Identity),
        h.clock.clone(),
    )
    .unwrap();
    BrokerService::new(
        authorizer,
        "https://broker.test/exchange",
        Arc::new(Minter),
        TargetTokenVerifier::new("https://broker.test/exchange".into(), keys(20)).unwrap(),
        h.clock.clone(),
    )
    .unwrap()
}
fn collector(h: &Harness) -> OutcomeReportService {
    OutcomeReportService::new(
        ReporterTrust {
            tenant: h.registration.tenant.clone(),
            conflict_domain: h.registration.scope.conflict_domain.clone(),
            source_id: "spiffe://test/recovery".into(),
            subject: h.f.identity.subject.clone(),
            required_scope: "kf.report".into(),
            grants: GrantVerifier {
                keys: keys(5),
                audience: h.registration.scope.audience.clone(),
            },
            outcome_keys: keys(14),
        },
        h.ledger.clone(),
        DualAuthenticator::new(
            &h.f.identity.subject.iss,
            AUD,
            "https://collector.test/outcomes",
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap(),
        "collector".into(),
        "key-15".into(),
        SigningKey::from_bytes(&[15; 32]),
        h.clock.clone(),
    )
    .unwrap()
}
async fn snapshot(ledger: &EtcdLedger) -> Value {
    use base64::engine::general_purpose::STANDARD;
    let prefix = format!("{}/", ledger.namespace());
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    reqwest::Client::new().post(format!("{endpoint}/v3/kv/range")).json(&json!({"key":STANDARD.encode(&prefix),"range_end":STANDARD.encode(format!("{}0",ledger.namespace()))})).send().await.unwrap().error_for_status().unwrap().json::<Value>().await.unwrap()["kvs"].clone()
}
fn ready(checks: Vec<Check>) -> bool {
    !checks.is_empty() && checks.iter().all(|c| c.condition == Condition::Ready)
}
async fn gateway(h: &Harness) -> Vec<Check> {
    h.ledger
        .gateway_readiness(
            &BTreeMap::from([("tool".into(), h.tool())]),
            &GrantVerifier {
                keys: keys(5),
                audience: h.registration.scope.audience.clone(),
            },
            Some(&kedgeflow::operations_gateway::Pins {
                component_id: h.registration.acknowledger.component_id.clone(),
                workload_id: h.registration.acknowledger.workload_id.clone(),
                installation_keys: keys(12),
            }),
        )
        .await
}
#[tokio::test]
async fn native_readiness_is_read_only_and_keeps_receipts_available_after_execution_stop() {
    if std::env::var("ETCD_ENDPOINT").is_err() {
        assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
        eprintln!("SKIP readiness: ETCD_ENDPOINT absent");
        return;
    }
    let witness = support::witness::WitnessProcess::start().await;
    let gate = RestoreGate::new(
        EtcdLedger::new(
            reqwest::Client::new(),
            &witness.endpoint,
            "/readiness-witness",
        )
        .unwrap(),
    )
    .unwrap();
    let mut h = Harness::with_environment(None, NOW, |_| {}, Some(gate.clone()), None)
        .await
        .unwrap();
    let reservation = super::reserved_leaf::registration(&h, 2);
    h.ledger = h.ledger.clone().with_reservation(reservation).unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let initial_head = gate.check(&h.ledger).await.unwrap();
    let control = control(&h);
    let broker = broker(&h);
    let collector = collector(&h);
    let recovery = kedgeflow::recovery::RecoveryWorker::new(
        h.ledger.clone(),
        GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        },
        Arc::new(QualifiedQuery),
        "outcome-14".into(),
        SigningKey::from_bytes(&[14; 32]),
        "spiffe://test/recovery".into(),
        h.clock.clone(),
    )
    .unwrap();
    assert!(!ready(control.check().await));
    assert!(!ready(broker.check().await));
    assert!(ready(h.service.check().await));
    assert!(ready(collector.check().await));
    let installed = h.bootstrap().await;
    assert!(!ready(control.check().await));
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let before = snapshot(&h.ledger).await;
    let head = gate.check(&h.ledger).await.unwrap();
    for _ in 0..3 {
        assert!(ready(recovery.check().await));
        assert!(ready(gateway(&h).await));
        assert!(ready(control.check().await));
        assert!(ready(broker.check().await));
        assert!(ready(h.service.check().await));
        assert!(ready(collector.check().await));
    }
    assert_eq!(
        snapshot(&h.ledger).await,
        before,
        "probe changed native records or revisions"
    );
    assert_eq!(
        gate.check(&h.ledger).await.unwrap(),
        head,
        "probe reserved witness authority"
    );
    h.clock.0.store(NOW + 60000, Ordering::SeqCst);
    assert!(ready(recovery.check().await));
    assert!(!ready(gateway(&h).await));
    assert!(!ready(control.check().await));
    assert!(!ready(broker.check().await));
    assert!(ready(collector.check().await));
    assert!(ready(h.service.check().await));
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    assert!(ready(control.check().await));
    assert!(ready(broker.check().await));
    h.ledger.stop_reservation().await.unwrap();
    assert!(ready(recovery.check().await));
    assert!(!ready(gateway(&h).await));
    assert!(!ready(control.check().await));
    assert!(!ready(broker.check().await));
    assert!(ready(collector.check().await));
    assert!(ready(h.service.check().await));
    // The administrative credential also expires at this clock boundary.
    // Publish a fresh fixture credential before the privileged revoke call.
    let mut claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(h.token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    claims["iat"] = json!((NOW + 60000) / 1000);
    claims["exp"] = json!((NOW + 120000) / 1000);
    h.token = jwt(json!({"alg":"EdDSA","typ":"at+jwt"}), claims, 7);
    h.revoke(RevocationTarget::Domain).await;
    assert!(ready(recovery.check().await));
    assert!(!ready(gateway(&h).await));
    let before = snapshot(&h.ledger).await;
    let head = gate.check(&h.ledger).await.unwrap();
    assert!(!ready(control.check().await));
    assert!(!ready(broker.check().await));
    assert!(ready(collector.check().await));
    assert!(ready(h.service.check().await));
    assert_eq!(snapshot(&h.ledger).await, before);
    assert_eq!(gate.check(&h.ledger).await.unwrap(), head);
    // Put back the actual earlier marker, modeling stale head restoration.
    // All roles must refuse the mismatch without attempting witness repair.
    use base64::engine::general_purpose::STANDARD;
    reqwest::Client::new().post(format!("{}/v3/kv/put",std::env::var("ETCD_ENDPOINT").unwrap())).json(&json!({"key":STANDARD.encode(format!("{}/restore-gate",h.ledger.namespace())),"value":STANDARD.encode(serde_json::to_vec(&initial_head).unwrap())})).send().await.unwrap().error_for_status().unwrap();
    assert!(!ready(control.check().await));
    assert!(!ready(broker.check().await));
    assert!(!ready(collector.check().await));
    assert!(!ready(recovery.check().await));
    assert!(!ready(gateway(&h).await));
    assert!(!ready(h.service.check().await));
    eprintln!(
        "readiness: native install/ack/expiry/renewal/stop/revocation/stale-marker; probes changed no native records, revisions or witness head"
    );
}
#[tokio::test]
async fn unselected_control_scope_cannot_report_optimistic_ready() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let control = control(&h);
    let checks = control.check().await;
    assert!(checks.iter().any(
        |c| c.dependency == Dependency::ManagedControl && c.condition == Condition::Unverified
    ));
    assert!(!ready(checks));
}

#[tokio::test]
async fn plain_leaf_scope_is_explicit_pinned_and_live_without_a_native_reservation() {
    let Some(h) = Harness::new().await else {
        return;
    };
    for field in ["audience", "digest"] {
        let mut wrong = h.registration.scope.clone();
        if field == "audience" {
            wrong.audience = "https://other.test/mcp".into()
        } else {
            wrong.action.digest = "0".repeat(64)
        }
        assert!(control(&h).with_operations_scope(wrong).is_err());
    }
    let control = control(&h)
        .with_operations_scope(h.registration.scope.clone())
        .unwrap();
    assert!(!ready(control.check().await));
    let installed = h.bootstrap().await;
    assert!(!ready(control.check().await));
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let before = snapshot(&h.ledger).await;
    assert!(ready(control.check().await));
    assert_eq!(snapshot(&h.ledger).await, before);
    h.clock.0.store(NOW + 10000, Ordering::SeqCst);
    assert!(!ready(control.check().await));
}

struct Unused;
#[async_trait::async_trait]
impl kedgeflow::auth::Authenticator for Unused {
    async fn authenticate(
        &self,
        _: &http::HeaderMap,
        _: &kedgeflow::auth::WorkloadIdentity,
    ) -> Result<kedgeflow::auth::Identity> {
        panic!("monitor must not authenticate an application request")
    }
}
#[async_trait::async_trait]
impl kedgeflow::broker::CredentialBroker for Unused {
    async fn exchange(
        &self,
        _: &kedgeflow::gateway::VerifiedCall,
        _: tokio::time::Instant,
    ) -> Result<kedgeflow::broker::TargetCredential> {
        panic!("monitor must not exchange")
    }
}
#[async_trait::async_trait]
impl kedgeflow::adapter::ResourceAdapter for Unused {
    async fn dispatch(
        &self,
        _: &kedgeflow::gateway::VerifiedCall,
        _: &kedgeflow::broker::TargetCredential,
    ) -> Result<kedgeflow::adapter::AdapterResult> {
        panic!("monitor must not dispatch")
    }
    async fn read(
        &self,
        _: &kedgeflow::gateway::Request,
        _: &kedgeflow::auth::Identity,
    ) -> Result<Value> {
        panic!("monitor must not invoke arbitrary tools")
    }
}
#[tokio::test]
async fn gateway_readiness_combines_real_signed_control_and_fresh_upstream_monitors() {
    use kedgeflow::{
        operations::{Report, Role},
        operations_client::RemoteConfig,
        operations_gateway::{GatewayProbe, Pins},
        service_files::ServiceFiles,
    };
    use std::{fs, os::unix::fs::PermissionsExt};
    let Some(h) = Harness::new().await else {
        return;
    };
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let before = snapshot(&h.ledger).await;
    let mode = Arc::new(AtomicU64::new(0));
    let pki = support::pki_with_workload("spiffe://test/monitor");
    let router = |role: Role| {
        let mode = mode.clone();
        let clock = h.clock.clone();
        axum::Router::new().route(
            "/ops",
            axum::routing::get(move || {
                let mode = mode.clone();
                let clock = clock.clone();
                async move {
                    let mode = mode.load(Ordering::SeqCst);
                    let dependencies = if role == Role::Broker {
                        vec![
                            Dependency::AuthorityReads,
                            Dependency::ManagedControl,
                            Dependency::IdentityMaterial,
                        ]
                    } else {
                        vec![Dependency::DatabaseExecution, Dependency::DatabaseQuery]
                    };
                    let mut checks: Vec<Check> = dependencies
                        .into_iter()
                        .map(|dependency| Check::result(dependency, Ok(())))
                        .collect();
                    if (role == Role::Broker && mode == 1) || (role == Role::SqlTarget && mode == 2)
                    {
                        checks[0].condition = Condition::Unavailable;
                    }
                    let ready = checks.iter().all(|c| c.condition == Condition::Ready);
                    let report = Report {
                        profile: kedgeflow::operations::PROFILE.into(),
                        role,
                        scope: "local_prerequisites".into(),
                        checked_at: kedgeflow::clock::Clock::now_ms(clock.as_ref()),
                        elapsed_ms: 0,
                        ready,
                        execution_authority: false,
                        checks,
                    };
                    (
                        if ready {
                            axum::http::StatusCode::OK
                        } else {
                            axum::http::StatusCode::SERVICE_UNAVAILABLE
                        },
                        [("cache-control", "no-store")],
                        axum::Json(report),
                    )
                }
            }),
        )
    };
    let broker = support::serve_tls(&pki, router(Role::Broker)).await;
    let target = support::serve_tls(&pki, router(Role::SqlTarget)).await;
    let temp = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    for (name, data) in [
        ("ca", &pki.ca),
        ("cert", &pki.client),
        ("key", &pki.client_key),
    ] {
        let path = temp.path().join(name);
        fs::write(&path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let files = ServiceFiles::protected(temp.path()).unwrap();
    let remote = |origin: &str| RemoteConfig {
        url: format!("{origin}/ops"),
        ca: temp.path().join("ca"),
        certificate: temp.path().join("cert"),
        private_key: temp.path().join("key"),
    };
    let gateway = Arc::new(kedgeflow::gateway::Gateway {
        verifier: GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        },
        ledger: Arc::new(h.ledger.clone()),
        auth: Arc::new(Unused),
        broker: Arc::new(Unused),
        adapter: Arc::new(Unused),
        resolver: None,
        tools: BTreeMap::from([("tool".into(), h.tool())]),
        timeout: Duration::from_secs(5),
        clock: h.clock.clone(),
    });
    let pins = || Pins {
        component_id: h.registration.acknowledger.component_id.clone(),
        workload_id: h.registration.acknowledger.workload_id.clone(),
        installation_keys: keys(12),
    };
    let probe = GatewayProbe::new(
        gateway.clone(),
        Some(pins()),
        Some(
            remote(&broker.url)
                .load(&files, &format!("{}/exchange", broker.url))
                .await
                .unwrap(),
        ),
        Some(
            remote(&target.url)
                .load(&files, &format!("{}/dispatch", target.url))
                .await
                .unwrap(),
        ),
    );
    assert!(ready(probe.check().await));
    for failed in [1, 2] {
        mode.store(failed, Ordering::SeqCst);
        assert!(!ready(probe.check().await));
    }
    mode.store(0, Ordering::SeqCst);
    assert!(ready(probe.check().await));
    assert!(!ready(
        GatewayProbe::new(gateway.clone(), Some(pins()), None, None)
            .check()
            .await
    ));
    let bad = Pins {
        installation_keys: keys(13),
        ..pins()
    };
    let checks = gateway
        .ledger
        .gateway_readiness(&gateway.tools, &gateway.verifier, Some(&bad))
        .await;
    assert!(!ready(checks));
    assert_eq!(
        snapshot(&h.ledger).await,
        before,
        "gateway readiness modified authority"
    );
}
