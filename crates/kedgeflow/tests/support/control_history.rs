//! Native governance/etcd history and software observer custody qualification.
use super::*;
use async_trait::async_trait;
use kedgeflow::{
    control_history::{ControlHistoryBundle, HistoryObserver},
    control_history_config::ControlHistoryTrustConfig,
    control_history_verify::verify_control_history,
    ledger::{AuthoritativeObservation, OutcomeQuerier},
    recovery::{Candidate, ExecutionRecord, RecoveryWorker},
};
struct Pending;
#[async_trait]
impl OutcomeQuerier for Pending {
    async fn query(&self, _: &str) -> kedgeflow::error::Result<AuthoritativeObservation> {
        panic!("undispatched recovery must not query the target")
    }
}
struct HistoryHarness {
    h: Harness,
    c: Candidate,
    key: String,
    grant_digest: String,
    trust: Value,
}
impl HistoryHarness {
    async fn new() -> Option<Self> {
        Self::with_dispatch(false).await
    }
    async fn with_dispatch(dispatch: bool) -> Option<Self> {
        Self::with_mode(dispatch, false).await
    }
    async fn with_mode(dispatch: bool, renew_between: bool) -> Option<Self> {
        let h = Harness::new().await?;
        let installed = h.bootstrap().await;
        let mut ack = h.ack(&installed);
        if renew_between {
            let mut a: Acknowledgement = serde_json::from_value(
                serde_json::from_str::<Value>(&ack).unwrap()["payload"].clone(),
            )
            .unwrap();
            a.expires_at = NOW + 1;
            ack = sign_control(
                "acknowledge",
                &a,
                "key-9",
                &SigningKey::from_bytes(&[9; 32]),
            )
            .unwrap();
        }
        assert!(h.post(&ack, true).await.0.is_success());
        if renew_between {
            let packet = h.f.packet();
            let inputs =
                h.f.trust
                    .verify_inputs(&h.f.identity, packet.borrowed(), &Time(NOW))
                    .unwrap();
            let controller = AdmissionController::new(
                CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
                "key-6".into(),
                SigningKey::from_bytes(&[6; 32]),
            )
            .unwrap();
            h.ledger
                .admit(
                    &controller.prepare(&inputs, &Time(NOW)).unwrap(),
                    &Time(NOW),
                )
                .await
                .unwrap();
            h.clock.0.store(NOW + 1, Ordering::SeqCst);
            assert!(h.post(&h.ack(&installed), true).await.0.is_success());
        }
        let issue_time = NOW + if renew_between { 2 } else { 1 };
        h.clock.0.store(issue_time, Ordering::SeqCst);
        let issued = h.issue().await.unwrap().record;
        let verifier = GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        };
        let verified = verifier
            .verify_retained(issued.signed_grant.as_bytes())
            .unwrap();
        let c = Candidate {
            grant: verified.grant,
            attempt_id: "history-original".into(),
        };
        let attempt = h
            .ledger
            .claim_recorded(
                &c.grant,
                &verified.digest,
                &c.attempt_id,
                &ExecutionRecord {
                    signed_grant: issued.signed_grant,
                    tool: h.tool().name,
                    parameters: h.f.proposal["parameters"].clone(),
                },
            )
            .await
            .unwrap();
        if dispatch {
            h.clock.0.store(issue_time + 1, Ordering::SeqCst);
            assert!(h.post(&h.ack(&installed), true).await.0.is_success());
            h.ledger
                .authorize_dispatch(&c.grant, &verified.digest, &c.attempt_id)
                .await
                .unwrap();
            h.ledger
                .finish_recorded(
                    &c.grant,
                    &attempt,
                    "committed",
                    &json!({"kind":"software_fixture_outcome","target_evidence":"missing"}),
                )
                .await
                .unwrap();
        }
        RecoveryWorker::new(
            h.ledger.clone(),
            verifier,
            Arc::new(Pending),
            "outcome-14".into(),
            SigningKey::from_bytes(&[14; 32]),
            "spiffe://test/outcome".into(),
            Arc::new(Time(NOW + 120000)),
        )
        .unwrap()
        .recover(&c)
        .await
        .unwrap();
        let key =
            h.f.trust
                .operation_key(&h.f.identity, &h.f.packet().proposal)
                .unwrap();
        let mut trust: Value = serde_json::from_slice(include_bytes!(
            "../../../../config/control-history-trust.example.json"
        ))
        .unwrap();
        trust["namespace"] = json!(h.ledger.namespace());
        trust["operation"]["policy"]["cedar"] = json!(h.definition.cedar);
        trust["historical"][0]["trust"] = trust["operation"].clone();
        trust["historical"][0]["registration"] = json!(h.registration);
        Some(Self {
            h,
            c,
            key,
            trust,
            grant_digest: verified.digest,
        })
    }
    fn observer() -> HistoryObserver {
        HistoryObserver::new(
            "spiffe://test/history-observer".into(),
            "observer-17".into(),
            SigningKey::from_bytes(&[17; 32]),
        )
        .unwrap()
    }
    async fn bundle(&self) -> ControlHistoryBundle {
        self.h
            .ledger
            .export_control_history(&self.c, &self.key, &Self::observer(), &Time(NOW + 120000))
            .await
            .unwrap()
    }
    fn verify(
        &self,
        b: &ControlHistoryBundle,
    ) -> kedgeflow::error::Result<kedgeflow::control_history_verify::ControlHistoryVerification>
    {
        let trust = ControlHistoryTrustConfig::decode(&serde_json::to_vec(&self.trust).unwrap())?
            .registration()?;
        verify_control_history(b, &trust)
    }
    async fn head(&self) -> Value {
        let key = format!(
            "{}/domains/{}/control/history/head",
            self.h.ledger.namespace(),
            URL_SAFE_NO_PAD.encode(self.c.grant.conflict_domain.as_bytes())
        );
        serde_json::from_slice(&self.h.ledger.read_key(&key).await.unwrap().unwrap()).unwrap()
    }
    async fn held(&self) {
        let gd = &self.grant_digest;
        assert!(
            self.h
                .ledger
                .claim(&self.c.grant, gd, "retry")
                .await
                .is_err()
        );
        let nonce_key = format!(
            "{}/domains/{}/roots/{}/nonces/{}",
            self.h.ledger.namespace(),
            URL_SAFE_NO_PAD.encode(self.c.grant.conflict_domain.as_bytes()),
            URL_SAFE_NO_PAD.encode(self.c.grant.root_id.as_bytes()),
            URL_SAFE_NO_PAD.encode(self.c.grant.nonce.as_bytes())
        );
        assert_eq!(
            self.h.ledger.read_key(&nonce_key).await.unwrap().unwrap(),
            self.c.attempt_id.as_bytes()
        );
        let original = self
            .h
            .ledger
            .status(&self.c.grant, &self.c.attempt_id)
            .await
            .unwrap();
        assert_eq!(original.status, "not_dispatched");
        assert_eq!(original.grant_digest, *gd);
        assert!(
            self.h
                .ledger
                .authorize_dispatch(&self.c.grant, gd, &self.c.attempt_id)
                .await
                .is_err()
        );
    }
}
fn reseal(bundle: &mut ControlHistoryBundle) {
    let mut previous = None;
    for (n, event) in bundle.events.iter_mut().enumerate() {
        event.sequence = n as u64 + 1;
        event.previous_digest = previous;
        previous = Some(event.digest().unwrap());
    }
    bundle.checkpoint.payload.event_count = bundle.events.len() as u64;
    bundle.checkpoint.payload.head_digest = previous.unwrap();
    bundle.checkpoint.payload.lineage_digest = kedgeflow::contracts::digest(
        "control-history-lineage",
        &serde_json::to_value(&bundle.lineage).unwrap(),
    )
    .unwrap();
    resign_checkpoint(bundle);
}
fn resign_checkpoint(bundle: &mut ControlHistoryBundle) {
    let c = &mut bundle.checkpoint;
    let mut bytes = b"KedgeFlow:KF-CONTROL-HISTORY-0.1-draft\0".to_vec();
    bytes.extend(
        canonical(
            &json!({"profile":c.profile,"kind":c.kind,"key_id":c.key_id,"payload":c.payload}),
        )
        .unwrap(),
    );
    c.signature = URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[17; 32]).sign(&bytes).to_bytes());
}
fn cli(bundle: &ControlHistoryBundle, trust: &Value) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let bp = dir.path().join("bundle.json");
    let tp = dir.path().join("trust.json");
    std::fs::write(&bp, serde_json::to_vec(bundle).unwrap()).unwrap();
    std::fs::write(&tp, serde_json::to_vec(trust).unwrap()).unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-history"))
        .arg("--trust")
        .arg(tp)
        .arg("--bundle")
        .arg(bp)
        .output()
        .unwrap()
}
async fn overwrite(h: &HistoryHarness, key: &str, value: &str) {
    use base64::engine::general_purpose::STANDARD;
    assert!(key.starts_with(h.h.ledger.namespace()));
    let v:Value=reqwest::Client::new().post(format!("{}/v3/kv/txn",std::env::var("ETCD_ENDPOINT").unwrap()))
        .json(&json!({"compare":[],"success":[{"request_put":{"key":STANDARD.encode(key),"value":STANDARD.encode(value)}}],"failure":[]})).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["succeeded"], true);
}
#[tokio::test]
async fn native_governance_retention_checkpoint_and_expired_offline_process_verify() {
    let Some(h) = HistoryHarness::new().await else {
        return;
    };
    let bundle = h.bundle().await;
    assert_eq!(h.head().await["sequence"], 4);
    let output = cli(&bundle, &h.trust);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["events_verified"], 4);
    assert_eq!(result["installations_verified"], 1);
    assert_eq!(result["acknowledgements_verified"], 1);
    assert_eq!(
        result["matching_installation_digests"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        result["operation_control_state"]
            .as_str()
            .unwrap()
            .contains("not_attested")
    );
    assert_eq!(result["lineage"]["reported_status"], "not_dispatched");
    h.held().await;
}
#[tokio::test]
async fn exact_retries_failed_changes_and_ack_refresh_preserve_immutable_history() {
    let Some(h) = HistoryHarness::new().await else {
        return;
    };
    let first = h.bundle().await;
    for field in ["top", "checkpoint", "event", "control"] {
        let mut value = serde_json::to_value(&first).unwrap();
        let object = match field {
            "top" => &mut value,
            "checkpoint" => &mut value["checkpoint"],
            "event" => &mut value["events"][0],
            _ => &mut value["events"][0]["control"],
        };
        object["unexpected"] = json!(true);
        assert!(ControlHistoryBundle::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut oversize = first.clone();
    oversize.events[0].control.record = "é".repeat((1 << 19) + 1);
    assert!(ControlHistoryBundle::decode(&serde_json::to_vec(&oversize).unwrap()).is_err());
    let head = h.head().await;
    for e in &first.events {
        assert!(
            h.h.post(&e.control.record, e.kind == "acknowledge")
                .await
                .0
                .is_success()
        );
    }
    assert_eq!(h.head().await, head);
    let mut i: Installation = first.events[2].control.payload("install").unwrap();
    i.revision = 3;
    i.expected_revision = 2;
    let bad = sign_control("install", &i, "key-12", &SigningKey::from_bytes(&[12; 32])).unwrap();
    assert!(!h.h.post(&bad, false).await.0.is_success());
    assert_eq!(h.head().await, head);
    h.h.clock.0.store(NOW + 100, Ordering::SeqCst);
    let installed =
        h.h.ledger
            .control_snapshot(&h.c.grant.conflict_domain)
            .await
            .unwrap()
            .0
            .unwrap();
    let renewed = h.h.ack(&installed);
    assert!(h.h.post(&renewed, true).await.0.is_success());
    let full = h.bundle().await;
    assert_eq!(full.events.len(), 5);
    assert_eq!(
        first.events[3].control.record,
        full.events[3].control.record
    );
    assert_eq!(h.verify(&full).unwrap().acknowledgements_verified, 2);
    assert_eq!(h.verify(&first).unwrap().events_verified, 4);
    // Recorded times do not stand in for an operation-bound control sequence.
    h.h.clock.0.store(NOW - 1, Ordering::SeqCst);
    let old_head = h.head().await;
    let raw = sign_control(
        "revoke",
        &Revocation {
            tenant: h.h.registration.tenant.clone(),
            conflict_domain: h.c.grant.conflict_domain.clone(),
            target: RevocationTarget::Root {
                id: "clock-backward".into(),
            },
            revision: 1,
            reason_digest: "a".repeat(64),
        },
        "key-13",
        &SigningKey::from_bytes(&[13; 32]),
    )
    .unwrap();
    assert!(!h.h.post(&raw, false).await.0.is_success());
    assert_eq!(h.head().await, old_head);
}
#[tokio::test]
async fn retained_all_revocation_targets_are_authenticated_without_non_revocation_claims() {
    let Some(h) = HistoryHarness::new().await else {
        return;
    };
    let prefix = h.bundle().await;
    h.h.clock.0.store(NOW + 2, Ordering::SeqCst);
    for target in [
        RevocationTarget::Grant {
            id: h.c.grant.gid.clone(),
        },
        RevocationTarget::Root {
            id: h.c.grant.root_id.clone(),
        },
        RevocationTarget::Domain,
    ] {
        let r = h.h.revoke(target).await;
        let count = h.head().await["sequence"].clone();
        assert!(h.h.post(&r.record, false).await.0.is_success());
        assert_eq!(h.head().await["sequence"], count);
    }
    let result = h.verify(&h.bundle().await).unwrap();
    assert_eq!(result.revocations.len(), 3);
    assert_eq!(result.events_verified, 7);
    assert!(
        result
            .revocations
            .iter()
            .all(|r| r.relation_to_issuance == "after_issuance_by_recorded_clock")
    );
    assert!(result.operation_control_state.contains("not_attested"));
    assert_eq!(h.verify(&prefix).unwrap().revocations.len(), 0);
    h.held().await;
}
#[tokio::test]
async fn omitted_reordered_corrupt_and_re_signed_invalid_control_history_refuse() {
    let Some(h) = HistoryHarness::new().await else {
        return;
    };
    let first = h.bundle().await;
    for field in [
        "missing",
        "reorder",
        "digest",
        "accepted-time",
        "checkpoint",
        "namespace",
        "lineage",
        "observer-key",
    ] {
        let mut b = first.clone();
        match field {
            "missing" => {
                b.events.remove(1);
            }
            "reorder" => b.events.swap(0, 1),
            "digest" => b.events[0].control.digest = "0".repeat(64),
            "accepted-time" => b.events[0].accepted_at += 1,
            "checkpoint" => b.checkpoint.payload.head_digest = "0".repeat(64),
            "namespace" => {
                b.checkpoint.payload.namespace = "/other".into();
                resign_checkpoint(&mut b);
            }
            "lineage" => b.lineage.admission.admitted_at += 1,
            _ => b.checkpoint.key_id = "unknown".into(),
        }
        assert!(h.verify(&b).is_err(), "{field}");
    }
    for field in [
        "revision",
        "issuer-membership",
        "ack-coverage",
        "ack-time",
        "missing-publication",
        "backward-time",
        "wrong-role",
        "policy-definition",
    ] {
        let mut b = first.clone();
        match field {
            "revision" | "issuer-membership" => {
                let mut i: Installation = b.events[2].control.payload("install").unwrap();
                if field == "revision" {
                    i.expected_revision = 1;
                    i.revision = 2;
                } else {
                    i.registration.issuer_keys = keys(16)
                        .iter()
                        .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                        .collect();
                }
                b.events[2].control = verify_control::<Installation>(
                    &sign_control("install", &i, "key-12", &SigningKey::from_bytes(&[12; 32]))
                        .unwrap(),
                    "install",
                    &keys(12),
                )
                .unwrap()
                .1;
            }
            "ack-coverage" | "ack-time" => {
                let mut a: Acknowledgement = b.events[3].control.payload("acknowledge").unwrap();
                if field == "ack-coverage" {
                    a.coverage = "target_writer_coverage".into();
                } else {
                    a.expires_at = NOW;
                }
                b.events[3].control = StoredControl {
                    record: sign_control(
                        "acknowledge",
                        &a,
                        "key-9",
                        &SigningKey::from_bytes(&[9; 32]),
                    )
                    .unwrap(),
                    digest: String::new(),
                };
                let value: Value = serde_json::from_str(&b.events[3].control.record).unwrap();
                b.events[3].control.digest =
                    kedgeflow::contracts::digest("enforcement-record", &value).unwrap();
            }
            "missing-publication" => {
                b.events.remove(1);
            }
            "backward-time" => b.events[1].accepted_at = NOW - 1,
            "wrong-role" => b.events[2].kind = "revoke".into(),
            _ => {
                let mut p: PolicyPublication =
                    b.events[0].control.payload("publish_policy").unwrap();
                p.definition.cedar = "forbid(principal, action, resource);".into();
                b.events[0].control = verify_control::<PolicyPublication>(
                    &sign_control(
                        "publish_policy",
                        &p,
                        "key-10",
                        &SigningKey::from_bytes(&[10; 32]),
                    )
                    .unwrap(),
                    "publish_policy",
                    &keys(10),
                )
                .unwrap()
                .1;
            }
        }
        reseal(&mut b);
        assert!(h.verify(&b).is_err(), "{field}");
    }
    let mut b = first;
    b.events.remove(0);
    assert!(!cli(&b, &h.trust).status.success());
}
#[tokio::test]
async fn missing_legacy_or_corrupt_retained_history_refuses_export_and_genesis() {
    let Some(h) = HistoryHarness::new().await else {
        return;
    };
    let key = format!(
        "{}/domains/{}/control/history/events/{:020}",
        h.h.ledger.namespace(),
        URL_SAFE_NO_PAD.encode(h.c.grant.conflict_domain.as_bytes()),
        4
    );
    overwrite(&h, &key, "{}").await;
    let old_head = h.head().await;
    let raw = sign_control(
        "revoke",
        &Revocation {
            tenant: h.h.registration.tenant.clone(),
            conflict_domain: h.c.grant.conflict_domain.clone(),
            target: RevocationTarget::Root {
                id: "corrupt-head".into(),
            },
            revision: 1,
            reason_digest: "a".repeat(64),
        },
        "key-13",
        &SigningKey::from_bytes(&[13; 32]),
    )
    .unwrap();
    assert!(!h.h.post(&raw, false).await.0.is_success());
    assert_eq!(h.head().await, old_head);
    assert!(
        h.h.ledger
            .export_control_history(
                &h.c,
                &h.key,
                &HistoryHarness::observer(),
                &Time(NOW + 120000)
            )
            .await
            .is_err()
    );
    let head_key = format!(
        "{}/domains/{}/control/history/head",
        h.h.ledger.namespace(),
        URL_SAFE_NO_PAD.encode(h.c.grant.conflict_domain.as_bytes())
    );
    let mut oversized_head = old_head;
    oversized_head["sequence"] = json!(65);
    overwrite(
        &h,
        &head_key,
        &serde_json::to_string(&oversized_head).unwrap(),
    )
    .await;
    let error =
        h.h.ledger
            .export_control_history(
                &h.c,
                &h.key,
                &HistoryHarness::observer(),
                &Time(NOW + 120000),
            )
            .await
            .unwrap_err();
    assert!(error.to_string().contains("no prefix truncation"));
    let legacy = Harness::new().await.unwrap();
    let key = format!(
        "{}/domains/{}/control/register_descriptor",
        legacy.ledger.namespace(),
        URL_SAFE_NO_PAD.encode(legacy.registration.scope.conflict_domain.as_bytes())
    );
    let client = reqwest::Client::new();
    use base64::engine::general_purpose::STANDARD;
    let response:Value=client.post(format!("{}/v3/kv/txn",std::env::var("ETCD_ENDPOINT").unwrap())).json(&json!({"compare":[],"success":[{"request_put":{"key":STANDARD.encode(key),"value":STANDARD.encode("legacy-pointer")}}],"failure":[]})).send().await.unwrap().json().await.unwrap();
    assert_eq!(response["succeeded"], true);
    let pp = sign_control(
        "publish_policy",
        &PolicyPublication {
            registration: legacy.registration.clone(),
            definition: legacy.definition.clone(),
        },
        "key-10",
        &SigningKey::from_bytes(&[10; 32]),
    )
    .unwrap();
    assert!(!legacy.post(&pp, false).await.0.is_success());
}
#[test]
fn public_history_trust_is_closed_bounded_and_rejects_role_confusion() {
    let raw = include_bytes!("../../../../config/control-history-trust.example.json");
    assert!(
        ControlHistoryTrustConfig::decode(raw)
            .unwrap()
            .registration()
            .is_ok()
    );
    let mut v: Value = serde_json::from_slice(raw).unwrap();
    v["observer_keys"] = v["operation"]["grant_keys"].clone();
    assert!(
        ControlHistoryTrustConfig::decode(&serde_json::to_vec(&v).unwrap())
            .unwrap()
            .registration()
            .is_err()
    );
    let mut v: Value = serde_json::from_slice(raw).unwrap();
    v["private_key"] = json!("unexpected");
    assert!(ControlHistoryTrustConfig::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(ControlHistoryTrustConfig::decode(&vec![b' '; (4 << 20) + 1]).is_err());
    assert!(ControlHistoryBundle::decode(&vec![b' '; (32 << 20) + 1]).is_err());
    assert!(ControlHistoryBundle::decode(br#"{"profile":"x","profile":"y"}"#).is_err());
}

struct RecreatedGovernance {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RecreatedGovernance {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn recreated(
    h: &Harness,
    registration: ControlRegistration,
    admission: kedgeflow::admission::AdmissionTrust,
    issuer_keys: BTreeMap<String, ed25519_dalek::VerifyingKey>,
) -> RecreatedGovernance {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}/control", listener.local_addr().unwrap());
    let roles = [
        ("publish_policy", 10),
        ("register_descriptor", 11),
        ("install", 12),
        ("revoke", 13),
        ("query", 0),
    ]
    .into_iter()
    .map(|(kind, key)| {
        (
            kind.into(),
            AdministrativeRole {
                subject: h.f.identity.subject.clone(),
                workload_id: "spiffe://test/operator".into(),
                scope: format!("kf.{kind}"),
                keys: if key == 0 { BTreeMap::new() } else { keys(key) },
            },
        )
    })
    .collect();
    let trust = GovernanceTrust {
        registration,
        admission,
        definition: h.definition.clone(),
        admission_keys: keys(6),
        issuer_keys,
        roles,
    };
    let auth = DualAuthenticator::new(
        &h.f.identity.subject.iss,
        AUD,
        &url,
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    let service =
        Arc::new(GovernanceService::new(trust, h.ledger.clone(), auth, h.clock.clone()).unwrap());
    let tls = kedgeflow::tls::server_config_pem(
        h.gateway_pki.server.as_bytes(),
        h.gateway_pki.server_key.as_bytes(),
        h.gateway_pki.ca.as_bytes(),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, tls, service.router())
            .await
            .unwrap();
    });
    RecreatedGovernance { url, task }
}
async fn post_recreated(
    h: &Harness,
    service: &RecreatedGovernance,
    record: &str,
    ack: bool,
) -> Value {
    let client = if ack { &h.gateway } else { &h.admin };
    let mut request=client.post(&service.url).json(&json!({"profile":PROFILE,"operation":"apply","request_id":"recreated-request","record":record}));
    if !ack {
        let proof = jwt(
            json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":h.jwk}),
            json!({"jti":format!("recreated-{}",h.jti.fetch_add(1,Ordering::SeqCst)),"htm":"POST","htu":service.url,"iat":h.clock.0.load(Ordering::SeqCst)/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(h.token.as_bytes()))}),
            8,
        );
        request = request
            .header("authorization", format!("DPoP {}", h.token))
            .header("dpop", proof);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{value}");
    value
}
#[tokio::test]
async fn approved_issuer_change_and_recreated_native_service_preserve_old_operation_membership() {
    use base64::engine::general_purpose::STANDARD;
    let Some(mut h) = HistoryHarness::new().await else {
        return;
    };
    let old = h.bundle().await;
    let mut config = h.trust["operation"].clone();
    config["policy"]["epoch"] = json!(8);
    config["grant_keys"] = json!({"key-16":STANDARD.encode(SigningKey::from_bytes(&[16;32]).verifying_key().as_bytes())});
    let new_trust = kedgeflow::lineage_config::LineageTrustConfig::decode(
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap()
    .registration()
    .unwrap();
    let mut registration = h.h.registration.clone();
    registration.policy = new_trust.admission.policy.clone();
    registration.issuer_keys = keys(16)
        .iter()
        .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
        .collect();
    registration.trust_digest = trust_digest(&new_trust.admission, &keys(6), &keys(16)).unwrap();
    h.h.clock.0.store(NOW + 100, Ordering::SeqCst);
    let service = recreated(
        &h.h,
        registration.clone(),
        new_trust.admission.clone(),
        keys(16),
    )
    .await;
    let p = sign_control(
        "publish_policy",
        &PolicyPublication {
            registration: registration.clone(),
            definition: h.h.definition.clone(),
        },
        "key-10",
        &SigningKey::from_bytes(&[10; 32]),
    )
    .unwrap();
    let d = sign_control(
        "register_descriptor",
        &DescriptorPublication {
            registration: registration.clone(),
            descriptor: String::from_utf8(h.h.f.packet().descriptor).unwrap(),
        },
        "key-11",
        &SigningKey::from_bytes(&[11; 32]),
    )
    .unwrap();
    let p = post_recreated(&h.h, &service, &p, false).await;
    let d = post_recreated(&h.h, &service, &d, false).await;
    let installation = Installation {
        registration: registration.clone(),
        revision: 2,
        expected_revision: 1,
        policy_publication_digest: p["digest"].as_str().unwrap().into(),
        descriptor_publication_digest: d["digest"].as_str().unwrap().into(),
    };
    let raw = sign_control(
        "install",
        &installation,
        "key-12",
        &SigningKey::from_bytes(&[12; 32]),
    )
    .unwrap();
    let applied = post_recreated(&h.h, &service, &raw, false).await;
    let verifier = GrantVerifier {
        keys: keys(16),
        audience: h.c.grant.audience.clone(),
    };
    let ack = acknowledge_gateway(
        &installation,
        applied["digest"].as_str().unwrap(),
        &[h.h.tool()],
        &verifier,
        &registration.acknowledger.workload_id,
        &SigningKey::from_bytes(&[9; 32]),
        NOW + 100,
    )
    .unwrap();
    post_recreated(&h.h, &service, &ack, true).await;
    h.trust["historical"]
        .as_array_mut()
        .unwrap()
        .push(json!({"registration":registration,"trust":config}));
    let full = h.bundle().await;
    let result = h.verify(&full).unwrap();
    assert_eq!(result.installations_verified, 2);
    assert_eq!(result.events_verified, 8);
    assert_eq!(
        result.matching_installation_digests,
        h.verify(&old).unwrap().matching_installation_digests
    );
    let mut unapproved = h.trust.clone();
    unapproved["historical"].as_array_mut().unwrap().pop();
    assert!(!cli(&full, &unapproved).status.success());
    drop(service);
    h.h.clock.0.store(NOW + 101, Ordering::SeqCst);
    let service = recreated(
        &h.h,
        installation.registration.clone(),
        new_trust.admission,
        keys(16),
    )
    .await;
    let ack = acknowledge_gateway(
        &installation,
        applied["digest"].as_str().unwrap(),
        &[h.h.tool()],
        &verifier,
        &installation.registration.acknowledger.workload_id,
        &SigningKey::from_bytes(&[9; 32]),
        NOW + 101,
    )
    .unwrap();
    post_recreated(&h.h, &service, &ack, true).await;
    let full = h.bundle().await;
    let result = h.verify(&full).unwrap();
    assert_eq!(result.acknowledgements_verified, 3);
    assert_eq!(result.events_verified, 9);
    assert!(cli(&full, &h.trust).status.success());
    assert!(h.h.issue().await.is_err());
    h.held().await;
}

#[path = "control_bindings.rs"]
mod control_bindings_tests;

#[path = "leased_history.rs"]
mod leased_history;
