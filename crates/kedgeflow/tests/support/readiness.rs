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
    assert!(!ready(control.check().await));
    assert!(!ready(broker.check().await));
    assert!(ready(collector.check().await));
    assert!(ready(h.service.check().await));
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    assert!(ready(control.check().await));
    assert!(ready(broker.check().await));
    h.ledger.stop_reservation().await.unwrap();
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
