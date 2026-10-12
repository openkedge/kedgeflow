//! Real retained admission/issuance and etcd recovery. Declared identity,
//! enrollment, target observation and signing custody are software fixtures.
#[allow(unused_imports, dead_code)]
#[path = "support/admission_fixture.rs"]
mod fixture;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use fixture::{Fixture, NOW, Time, keys, signed};
use kedgeflow::{
    error::{Error, Result},
    issuance::{GrantAuthority, IssuanceVerifier},
    ledger::{AuthoritativeObservation, AuthorityLedger, EtcdLedger, OutcomeQuerier},
    lineage::{LineageBundle, LineageTrust, verify_lineage},
    lineage_config::LineageTrustConfig,
    policy::{AdmissionController, CedarAdmissionPolicy},
    recovery::{Candidate, ExecutionRecord, RecoveryWorker},
};
use serde_json::{Value, json};
use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
struct Query {
    candidate: Candidate,
    gd: String,
    committed: AtomicBool,
}
#[async_trait]
impl OutcomeQuerier for Query {
    async fn query(&self, id: &str) -> Result<AuthoritativeObservation> {
        Ok(AuthoritativeObservation {
            attempt_id: id.into(),
            root_id: self.candidate.grant.root_id.clone(),
            grant_digest: self.gd.clone(),
            status: if self.committed.load(Ordering::SeqCst) {
                "committed"
            } else {
                "pending"
            }
            .into(),
            target_reference: "software:capacity:241".into(),
        })
    }
}
struct Harness {
    ledger: EtcdLedger,
    c: Candidate,
    key: String,
    trust: LineageTrust,
    query: Arc<Query>,
}
impl Harness {
    async fn new(dispatched: bool) -> Option<Self> {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(v) => v,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP lineage: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let trust = LineageTrustConfig::decode(include_bytes!(
            "../../../config/lineage-trust.example.json"
        ))
        .unwrap()
        .registration()
        .unwrap();
        let mut f = Fixture::new();
        f.trust = trust.admission.clone();
        let packet = f.packet();
        let ledger = EtcdLedger::new(
            reqwest::Client::new(),
            endpoint,
            format!(
                "/kf-lineage/{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ),
        )
        .unwrap()
        .with_clock(Arc::new(Time(NOW + 120000)));
        let (_, _, bootstrap) = f.authority(&packet);
        ledger.publish_policy(&bootstrap).await.unwrap();
        let inputs = f
            .trust
            .verify_inputs(&f.identity, packet.borrowed(), &Time(NOW))
            .unwrap();
        let controller = AdmissionController::new(
            CedarAdmissionPolicy::new(trust.policy.clone(), trust.admission.policy.clone())
                .unwrap(),
            "key-6".into(),
            SigningKey::from_bytes(&[6; 32]),
        )
        .unwrap();
        let prepared = controller.prepare(&inputs, &Time(NOW)).unwrap();
        let admitted = ledger.admit(&prepared, &Time(NOW)).await.unwrap();
        let authority = GrantAuthority::new(
            IssuanceVerifier {
                tenant: f.trust.tenant.clone(),
                admission_keys: keys(6),
                grants: trust.grants.clone(),
            },
            "key-5".into(),
            SigningKey::from_bytes(&[5; 32]),
        )
        .unwrap();
        let inputs = f
            .trust
            .verify_inputs(&f.identity, packet.borrowed(), &Time(NOW + 1))
            .unwrap();
        let issued = authority
            .issue(
                &ledger,
                &inputs,
                admitted.record.signed_certificate.as_bytes(),
                &Time(NOW + 1),
            )
            .await
            .unwrap()
            .record;
        let verified = trust
            .grants
            .verify_retained(issued.signed_grant.as_bytes())
            .unwrap();
        let c = Candidate {
            grant: verified.grant,
            attempt_id: "lineage-original".into(),
        };
        let execution = ExecutionRecord {
            signed_grant: issued.signed_grant,
            tool: "capacity.reserve".into(),
            parameters: f.proposal["parameters"].clone(),
        };
        ledger
            .claim_recorded(&c.grant, &verified.digest, &c.attempt_id, &execution)
            .await
            .unwrap();
        if dispatched {
            ledger
                .authorize_dispatch(&c.grant, &verified.digest, &c.attempt_id)
                .await
                .unwrap();
        }
        let key = f
            .trust
            .operation_key(&f.identity, &packet.proposal)
            .unwrap();
        let query = Arc::new(Query {
            candidate: c.clone(),
            gd: verified.digest,
            committed: AtomicBool::new(false),
        });
        let h = Self {
            ledger,
            c,
            key,
            trust,
            query,
        };
        h.worker().recover(&h.c).await.unwrap();
        Some(h)
    }
    fn worker(&self) -> RecoveryWorker {
        RecoveryWorker::new(
            self.ledger.clone(),
            self.trust.grants.clone(),
            self.query.clone(),
            "outcome-14".into(),
            SigningKey::from_bytes(&[14; 32]),
            self.trust.source_id.clone(),
            Arc::new(Time(NOW + 120000)),
        )
        .unwrap()
    }
    async fn bundle(&self) -> LineageBundle {
        self.ledger
            .export_lineage(&self.c, &self.key)
            .await
            .unwrap()
    }
    async fn held(&self) {
        assert!(matches!(
            self.ledger
                .claim(&self.c.grant, &self.query.gd, "retry")
                .await,
            Err(Error::NonceConsumed)
        ));
        assert!(
            self.ledger
                .authorize_dispatch(&self.c.grant, &self.query.gd, &self.c.attempt_id)
                .await
                .is_err()
        );
        let mut next = self.c.grant.clone();
        next.root_generation += 1;
        next.fence += 1;
        next.gid.push_str("-next");
        assert!(
            self.ledger
                .replace(&self.c.grant, &next, &self.query.gd)
                .await
                .is_err()
        );
    }
}
fn cli(bundle: &LineageBundle) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.json");
    std::fs::write(&path, serde_json::to_vec(bundle).unwrap()).unwrap();
    Command::new(env!("CARGO_BIN_EXE_kf-verify-lineage"))
        .args([
            "--trust",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../config/lineage-trust.example.json"
            ),
            "--bundle",
        ])
        .arg(path)
        .output()
        .unwrap()
}
#[tokio::test]
async fn expired_retained_admission_export_verifies_in_separate_process_without_reopening_authority()
 {
    let Some(h) = Harness::new(false).await else {
        return;
    };
    assert!(
        h.trust
            .grants
            .verify(
                h.bundle().await.issuance.signed_grant.as_bytes(),
                NOW + 120000
            )
            .is_err()
    );
    // Current policy changes do not select the historical policy or reopen work.
    let mut current = h.c.grant.clone();
    current.policy.epoch += 1;
    h.ledger.publish_policy(&current).await.unwrap();
    let bundle = h.bundle().await;
    let output = cli(&bundle);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["tenant"], "tenant-42");
    assert_eq!(result["admitted_at"], NOW);
    assert_eq!(result["issued_at"], NOW + 1);
    assert_eq!(result["operation_key"], h.key);
    assert_eq!(result["reported_status"], "not_dispatched");
    assert_eq!(result["witnesses_verified"], 1);
    assert_eq!(result["receipts_verified"], 1);
    assert_eq!(result["missing_links"].as_array().unwrap().len(), 5);
    h.held().await;
}
#[tokio::test]
async fn unknown_then_committed_prefix_and_full_chain_verify_with_exact_original_attempt() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let prefix = h.bundle().await;
    assert_eq!(
        verify_lineage(&prefix, &h.trust).unwrap().reported_status,
        "unknown"
    );
    h.query.committed.store(true, Ordering::SeqCst);
    h.worker().recover(&h.c).await.unwrap();
    let full = h.bundle().await;
    let result = verify_lineage(&full, &h.trust).unwrap();
    assert_eq!(result.receipts_verified, 2);
    assert_eq!(result.reported_status, "committed");
    assert_eq!(result.attempt_id, h.c.attempt_id);
    // An exported prefix remains authentic; it makes no latest-head assertion.
    assert_eq!(
        verify_lineage(&prefix, &h.trust).unwrap().reported_status,
        "unknown"
    );
    let mut bad = full.clone();
    bad.outcomes.receipts.reverse();
    assert!(verify_lineage(&bad, &h.trust).is_err());
    let mut bad = full.clone();
    bad.outcomes.receipts.remove(0);
    assert!(verify_lineage(&bad, &h.trust).is_err());
    let mut bad = full;
    bad.outcomes.evidence.clear();
    assert!(verify_lineage(&bad, &h.trust).is_err());
    h.held().await;
}
#[tokio::test]
async fn missing_substituted_signed_links_parameters_and_retained_metadata_refuse() {
    let Some(h) = Harness::new(false).await else {
        return;
    };
    let bundle = h.bundle().await;
    for field in [
        "proposal",
        "descriptor",
        "manifest",
        "witness",
        "certificate",
        "grant",
        "parameters",
        "admission-key",
        "admission-binding",
        "admission-digest",
        "admission-time",
        "expiry",
        "issuance-key",
        "issuance-binding",
        "issuance-digest",
        "execution-grant",
    ] {
        let mut b = bundle.clone();
        match field {
            "proposal" => b.packet.proposal = b.packet.descriptor.clone(),
            "descriptor" => b.packet.descriptor = b.packet.proposal.clone(),
            "manifest" => b.packet.manifest = b.packet.witnesses[0].clone(),
            "witness" => b.packet.witnesses.clear(),
            "certificate" => b.admission.signed_certificate = b.issuance.signed_grant.clone(),
            "grant" => b.issuance.signed_grant = b.admission.signed_certificate.clone(),
            "parameters" => b.outcomes.execution.parameters["expected_version"] = json!(999),
            "admission-key" => b.admission.admission_key = "0".repeat(64),
            "admission-binding" => b.admission.binding_digest = "0".repeat(64),
            "admission-digest" => b.admission.certificate_digest = "0".repeat(64),
            "admission-time" => b.admission.admitted_at += 1,
            "expiry" => b.admission.expires_at += 1,
            "issuance-key" => b.issuance.issuance_key = "0".repeat(64),
            "issuance-binding" => b.issuance.binding_digest = "0".repeat(64),
            "issuance-digest" => b.issuance.grant_digest = "0".repeat(64),
            _ => b.outcomes.execution.signed_grant = b.admission.signed_certificate.clone(),
        }
        assert!(verify_lineage(&b, &h.trust).is_err(), "{field}");
    }
    for field in [
        "top",
        "packet",
        "admission",
        "issuance",
        "outcomes",
        "execution",
    ] {
        let mut value = serde_json::to_value(&bundle).unwrap();
        let carriage = match field {
            "top" => &mut value,
            "execution" => &mut value["outcomes"]["execution"],
            _ => &mut value[field],
        };
        carriage["unexpected"] = json!(true);
        assert!(
            LineageBundle::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut b = bundle;
    let mut oversize = b.clone();
    oversize.packet.proposal = "é".repeat((1 << 19) + 1);
    assert!(LineageBundle::decode(&serde_json::to_vec(&oversize).unwrap()).is_err());
    b.admission.admitted_at += 1;
    assert!(!cli(&b).status.success());
}
#[tokio::test]
async fn valid_signatures_cannot_substitute_identity_tenant_freshness_or_broaden_constraints() {
    let Some(h) = Harness::new(false).await else {
        return;
    };
    let bundle = h.bundle().await;
    for field in [
        "tenant",
        "subject",
        "workload",
        "delegation-audience",
        "delegation-issuer",
        "scope",
        "certificate-time",
        "certificate-ttl",
        "grant-time",
        "grant-backdate",
        "grant-not-yet-valid",
        "grant-constraint",
        "witness-result",
    ] {
        let mut b = bundle.clone();
        let (kind, seed, raw) = match field {
            "certificate-time" | "certificate-ttl" => {
                ("certificate", 6, &mut b.admission.signed_certificate)
            }
            "grant-time" | "grant-backdate" | "grant-not-yet-valid" | "grant-constraint" => {
                ("grant", 5, &mut b.issuance.signed_grant)
            }
            "witness-result" => ("evidence", 4, &mut b.packet.witnesses[0]),
            _ => ("proposal", 1, &mut b.packet.proposal),
        };
        let mut p: Value = serde_json::from_str::<Value>(raw).unwrap()["payload"].clone();
        match field {
            "tenant" => p["tenant"] = json!("other"),
            "subject" => p["subject"]["sub"] = json!("other"),
            "workload" => p["workload_id"] = json!("spiffe://other"),
            "delegation-audience" => p["delegation"]["token_audience"] = json!("other"),
            "delegation-issuer" => {
                p["delegation"]["authorization_server"] = json!("https://other.example.org")
            }
            "scope" => p["delegation"]["scopes"] = json!(["other"]),
            "certificate-time" => p["admitted_at"] = json!(NOW + 60001),
            "certificate-ttl" => p["expires_at"] = json!(NOW + 10000),
            "grant-time" => p["issued_at"] = json!(NOW + 60001),
            "grant-backdate" => p["issued_at"] = json!(NOW - 1),
            "grant-not-yet-valid" => p["valid_from"] = json!(NOW + 2),
            "grant-constraint" => p["parameters_digest"] = json!("0".repeat(64)),
            _ => p["result"]["available_slots"] = json!(0),
        }
        *raw = String::from_utf8(if kind == "grant" {
            kedgeflow::contracts::sign_grant(
                &serde_json::from_value(p).unwrap(),
                "key-5",
                &SigningKey::from_bytes(&[5; 32]),
            )
            .unwrap()
        } else {
            signed(kind, p, seed)
        })
        .unwrap();
        if field == "witness-result" {
            // Repair the manifest reference so rejection must evaluate the
            // approved predicate over this correctly signed provider record.
            let e: kedgeflow::contracts::Envelope =
                serde_json::from_str(&b.packet.witnesses[0]).unwrap();
            let mut manifest: Value =
                serde_json::from_str::<Value>(&b.packet.manifest).unwrap()["payload"].clone();
            manifest["witnesses"][0]["witness"]["digest"] =
                json!(kedgeflow::contracts::record_digest(&e).unwrap());
            b.packet.manifest = String::from_utf8(signed("manifest", manifest, 3)).unwrap();
        }
        let error = verify_lineage(&b, &h.trust).unwrap_err();
        if field == "witness-result" {
            assert!(
                error
                    .to_string()
                    .contains("required evidence predicate violated or unknown")
            );
        } else if field == "certificate-ttl" {
            assert!(
                error
                    .to_string()
                    .contains("certificate exceeds approved lifetime")
            );
        }
    }
}
#[tokio::test]
async fn wrong_historical_trust_roles_and_unsigned_journal_correlations_refuse() {
    let Some(mut h) = Harness::new(true).await else {
        return;
    };
    let bundle = h.bundle().await;
    for field in [
        "tenant",
        "subject",
        "policy",
        "ownership",
        "descriptor",
        "outcome-key",
        "admission-key",
        "role-overlap",
    ] {
        let trust = LineageTrustConfig::decode(include_bytes!(
            "../../../config/lineage-trust.example.json"
        ))
        .unwrap()
        .registration()
        .unwrap();
        h.trust = trust;
        match field {
            "tenant" => h.trust.admission.tenant = "other".into(),
            "subject" => h.trust.subjects[0].sub = "other".into(),
            "policy" => {
                h.trust.policy.cedar = "forbid(principal, action, resource);".into();
                h.trust.admission.policy = h.trust.policy.reference(7).unwrap();
            }
            "ownership" => h.trust.admission.ownership_epoch += 1,
            "descriptor" => h.trust.admission.descriptor_digest = "0".repeat(64),
            "outcome-key" => h.trust.outcome_keys = keys(15),
            "admission-key" => h.trust.admission_keys = keys(15),
            _ => h.trust.outcome_keys = keys(6),
        }
        assert!(verify_lineage(&bundle, &h.trust).is_err(), "{field}");
    }
    h.trust =
        LineageTrustConfig::decode(include_bytes!("../../../config/lineage-trust.example.json"))
            .unwrap()
            .registration()
            .unwrap();
    for field in ["missing", "duplicate", "attempt", "root", "grant", "extra"] {
        let mut b = bundle.clone();
        match field {
            "missing" => b
                .outcomes
                .journal
                .retain(|v| v["phase"] != "dispatch_authorized"),
            "duplicate" => b.outcomes.journal.push(b.outcomes.journal[0].clone()),
            "attempt" => b.outcomes.journal[0]["attempt_id"] = json!("other"),
            "root" => b.outcomes.journal[0]["root_id"] = json!("other"),
            "grant" => b.outcomes.journal[0]["grant_digest"] = json!("0".repeat(64)),
            _ => b.outcomes.journal[0]["command"] = json!("retry"),
        }
        assert!(verify_lineage(&b, &h.trust).is_err(), "{field}");
    }
    // Repair the manifest policy pin to reach evaluation itself. Refusal must
    // come from Cedar, before the later certificate/metadata binding checks.
    h.trust.policy.cedar = "forbid(principal, action, resource);".into();
    h.trust.admission.policy = h.trust.policy.reference(7).unwrap();
    let mut denied = bundle;
    let mut manifest: Value =
        serde_json::from_str::<Value>(&denied.packet.manifest).unwrap()["payload"].clone();
    manifest["policy"] = json!(h.trust.admission.policy);
    denied.packet.manifest = String::from_utf8(signed("manifest", manifest, 3)).unwrap();
    assert!(
        verify_lineage(&denied, &h.trust)
            .unwrap_err()
            .to_string()
            .contains("Cedar denied admission or reported evaluation errors")
    );
}
#[tokio::test]
async fn export_refuses_wrong_operation_and_legacy_missing_admission_chain() {
    let Some(h) = Harness::new(false).await else {
        return;
    };
    assert!(
        h.ledger
            .export_lineage(&h.c, &"0".repeat(64))
            .await
            .is_err()
    );
    let mut other = h.c.clone();
    other.grant.proposal_digest = "0".repeat(64);
    assert!(h.ledger.export_lineage(&other, &h.key).await.is_err());
    let legacy = EtcdLedger::new(
        reqwest::Client::new(),
        std::env::var("ETCD_ENDPOINT").unwrap(),
        format!("/kf-lineage-legacy/{}", rand::random::<u64>()),
    )
    .unwrap();
    legacy.publish_policy(&h.c.grant).await.unwrap();
    legacy.issue(&h.c.grant, &h.query.gd).await.unwrap();
    assert!(legacy.export_lineage(&h.c, &h.key).await.is_err());
    h.held().await;
}
#[test]
fn historical_registration_is_closed_public_only_and_decode_bounds_are_enforced() {
    let raw = include_bytes!("../../../config/lineage-trust.example.json");
    assert!(
        LineageTrustConfig::decode(raw)
            .unwrap()
            .registration()
            .is_ok()
    );
    let mut v: Value = serde_json::from_slice(raw).unwrap();
    v["private_key"] = json!("unexpected");
    assert!(LineageTrustConfig::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(LineageTrustConfig::decode(&vec![b' '; (1 << 20) + 1]).is_err());
    assert!(LineageBundle::decode(&vec![b' '; (16 << 20) + 1]).is_err());
    assert!(LineageBundle::decode(br#"{"profile":"x","profile":"y"}"#).is_err());
    // No URL or private signing material is accepted as a key/schema resolver.
    let mut v: Value = serde_json::from_slice(raw).unwrap();
    v["evidence"]["capacity"]["result_schema"]["$ref"] =
        json!("https://untrusted.example.org/schema");
    assert!(
        LineageTrustConfig::decode(&serde_json::to_vec(&v).unwrap())
            .unwrap()
            .registration()
            .is_err()
    );
}
