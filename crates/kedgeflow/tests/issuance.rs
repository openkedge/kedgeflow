//! M2a checks: typed certificate binding and real-etcd atomic operation issuance.
//! No policy evaluator, external identity or target-effect claim is made here.

#[path = "support/domain.rs"]
mod domain;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    contracts::{Envelope, Grant, canonical, digest, record_digest, sign_grant, signature_input},
    error::Error,
    issuance::{AdmissionContext, AdmittedIssuance, IssuanceVerifier, RequiredObligation},
    ledger::{AuthorityLedger, EtcdLedger},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tokio::{sync::Barrier, task::JoinSet};

struct FixedClock(i64);
impl kedgeflow::clock::Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.0
    }
}
const CLOCK: FixedClock = FixedClock(domain::NOW);

struct Fixture {
    context: AdmissionContext,
    certificate: Value,
    grant: Grant,
    verifier: IssuanceVerifier,
    admission_key: SigningKey,
    issuer_key: SigningKey,
}

fn sign_certificate(payload: Value, key: &SigningKey) -> Envelope {
    let mut envelope = Envelope {
        profile: "KF-JSON-0.2".into(),
        kind: "certificate".into(),
        schema: "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/AdmissionCertificate"
            .into(),
        key_id: "admission-test".into(),
        payload,
        signature: String::new(),
    };
    envelope.signature =
        URL_SAFE_NO_PAD.encode(key.sign(&signature_input(&envelope).unwrap()).to_bytes());
    envelope
}

impl Fixture {
    fn new() -> Self {
        let (call, verifier) = domain::call();
        let grant = call.grant;
        let mut cert: Value =
            serde_json::from_str::<Value>(include_str!("../../../fixtures/certificate.json"))
                .unwrap()["payload"]
                .clone();
        for field in [
            "proposal_digest",
            "delegation_digest",
            "subject",
            "workload_id",
            "policy",
            "ownership_epoch",
            "evidence_manifest_digest",
        ] {
            cert[field] = serde_json::to_value(&grant).unwrap()[field].clone();
        }
        cert["descriptor_digest"] = json!(grant.action.digest);
        cert["lease_digest"] = Value::Null;
        cert["admitted_at"] = json!(domain::NOW - 1);
        cert["expires_at"] = json!(grant.expires_at);
        cert["constraints"] = json!({
            "action": grant.action, "resources": grant.resources,
            "parameters_digest": grant.parameters_digest, "predicate_descriptor": grant.predicate_descriptor,
            "adapter_contract": grant.adapter_contract, "audience": grant.audience,
            "max_attempts": 1, "expires_at": grant.expires_at, "saga_budget": null
        });
        cert["constraint_digest"] = json!(digest("constraints", &cert["constraints"]).unwrap());
        let mut obligations = BTreeMap::new();
        for discharge in cert["discharges"].as_array_mut().unwrap() {
            discharge["observed_at"] = json!(domain::NOW - 2);
            discharge["expires_at"] = json!(grant.expires_at);
            obligations.insert(
                discharge["obligation_id"].as_str().unwrap().into(),
                RequiredObligation {
                    predicate_digest: discharge["predicate_digest"].as_str().unwrap().into(),
                    stage: discharge["stage"].as_str().unwrap().into(),
                    execution_relevant: discharge["execution_relevant"].as_bool().unwrap(),
                },
            );
        }
        let context = AdmissionContext {
            tenant: "test-tenant".into(),
            qid: "stable-proposal".into(),
            subject: grant.subject.clone(),
            workload_id: grant.workload_id.clone(),
            dpop_jkt: grant.dpop_jkt.clone(),
            proposal_digest: grant.proposal_digest.clone(),
            delegation_digest: grant.delegation_digest.clone(),
            descriptor_digest: grant.action.digest.clone(),
            obligation_manifest_digest: cert["obligation_manifest_digest"].as_str().unwrap().into(),
            evidence_manifest_digest: grant.evidence_manifest_digest.clone(),
            policy: grant.policy.clone(),
            ownership_epoch: grant.ownership_epoch,
            audience: grant.audience.clone(),
            conflict_domain: grant.conflict_domain.clone(),
            obligations,
        };
        let admission_key = SigningKey::from_bytes(&[8; 32]);
        Self {
            context,
            certificate: cert,
            grant,
            verifier: IssuanceVerifier {
                tenant: "test-tenant".into(),
                admission_keys: BTreeMap::from([(
                    "admission-test".into(),
                    admission_key.verifying_key(),
                )]),
                grants: verifier,
            },
            admission_key,
            issuer_key: SigningKey::from_bytes(&[6; 32]),
        }
    }

    fn signed(&self) -> (Vec<u8>, Grant, Vec<u8>) {
        let cert = sign_certificate(self.certificate.clone(), &self.admission_key);
        let signed_certificate = canonical(&serde_json::to_value(&cert).unwrap()).unwrap();
        let mut grant = self.grant.clone();
        grant.certificate_digest = record_digest(&cert).unwrap();
        grant.constraint_digest = self.certificate["constraint_digest"]
            .as_str()
            .unwrap()
            .into();
        let signed_grant = sign_grant(&grant, "test-key", &self.issuer_key).unwrap();
        (signed_certificate, grant, signed_grant)
    }

    fn admitted(&self) -> AdmittedIssuance {
        let (cert, _, grant) = self.signed();
        self.verifier
            .validate(&self.context, &cert, &grant, domain::NOW)
            .unwrap()
    }

    fn ledger(&self, label: &str) -> Option<EtcdLedger> {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(value) if !value.is_empty() => value,
            _ => {
                assert_ne!(
                    std::env::var("KF_REQUIRE_ETCD").as_deref(),
                    Ok("1"),
                    "KF_REQUIRE_ETCD=1 requires a real etcd endpoint"
                );
                eprintln!("SKIP issuance integration: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Some(
            EtcdLedger::new(
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
                endpoint,
                format!("/kf-issuance-tests/{}-{label}-{suffix}", std::process::id()),
            )
            .unwrap(),
        )
    }
}

#[test]
fn valid_certificate_binds_narrower_grant_and_distinct_signing_roles() {
    let f = Fixture::new();
    f.admitted();
    let (cert, mut grant, _) = f.signed();
    grant.expires_at -= 1000;
    let raw = sign_grant(&grant, "test-key", &f.issuer_key).unwrap();
    f.verifier
        .validate(&f.context, &cert, &raw, domain::NOW)
        .unwrap();
    let wrong = sign_certificate(f.certificate.clone(), &f.issuer_key);
    let raw_cert = canonical(&serde_json::to_value(wrong).unwrap()).unwrap();
    assert!(
        f.verifier
            .validate(&f.context, &raw_cert, &raw, domain::NOW)
            .is_err()
    );
    let mut same = Fixture::new();
    same.verifier
        .admission_keys
        .insert("admission-test".into(), same.issuer_key.verifying_key());
    assert!(
        same.verifier
            .validate(&same.context, &cert, &raw, domain::NOW)
            .is_err()
    );
    let mut cross_tenant = f.context.clone();
    cross_tenant.tenant = "another-tenant".into();
    assert!(
        f.verifier
            .validate(&cross_tenant, &cert, &raw, domain::NOW)
            .is_err()
    );
}

#[test]
fn malformed_stale_or_incomplete_certificates_refuse() {
    let invalid = [
        ("unknown field", "/surprise", json!(true)),
        ("wrong proposal", "/proposal_digest", json!("a".repeat(64))),
        (
            "wrong descriptor",
            "/descriptor_digest",
            json!("a".repeat(64)),
        ),
        ("wrong identity", "/subject/sub", json!("different")),
        ("wrong ownership", "/ownership_epoch", json!(999)),
        ("future admission", "/admitted_at", json!(domain::NOW + 1)),
        ("expired", "/expires_at", json!(domain::NOW)),
        ("multiple attempts", "/constraints/max_attempts", json!(2)),
        (
            "bad constraint digest",
            "/constraint_digest",
            json!("a".repeat(64)),
        ),
        (
            "unknown obligation",
            "/discharges/0/obligation_id",
            json!("untrusted"),
        ),
        ("unknown result", "/discharges/0/result", json!("unknown")),
        (
            "stale discharge",
            "/discharges/0/expires_at",
            json!(domain::NOW),
        ),
        (
            "future observation",
            "/discharges/0/observed_at",
            json!(domain::NOW),
        ),
        ("no witness", "/discharges/0/witness_refs", json!([])),
        (
            "bad witness digest",
            "/discharges/0/witness_refs/0/digest",
            json!("invalid"),
        ),
        (
            "invalid schema URI",
            "/discharges/0/witness_refs/0/schema",
            json!("not a URI"),
        ),
        (
            "unknown nested field",
            "/discharges/0/witness_refs/0/unexpected",
            json!(true),
        ),
        ("missing coverage", "/discharges", json!([])),
        ("unsupported lease", "/lease_digest", json!("a".repeat(64))),
    ];
    for (label, path, replacement) in invalid {
        let mut f = Fixture::new();
        if matches!(label, "unknown field" | "unknown nested field") {
            let (parent, name) = path.rsplit_once('/').unwrap();
            let target = if parent.is_empty() {
                &mut f.certificate
            } else {
                f.certificate.pointer_mut(parent).unwrap()
            };
            target
                .as_object_mut()
                .unwrap()
                .insert(name.into(), replacement);
        } else {
            *f.certificate.pointer_mut(path).unwrap() = replacement;
        }
        let (cert, _, grant) = f.signed();
        assert!(
            f.verifier
                .validate(&f.context, &cert, &grant, domain::NOW)
                .is_err(),
            "{label}"
        );
    }
    for field in ["lease_digest", "discharges", "constraint_digest"] {
        let mut f = Fixture::new();
        f.certificate.as_object_mut().unwrap().remove(field);
        let envelope = sign_certificate(f.certificate.clone(), &f.admission_key);
        let raw = canonical(&serde_json::to_value(envelope).unwrap()).unwrap();
        let (_, _, grant) = Fixture::new().signed();
        assert!(
            f.verifier
                .validate(&f.context, &raw, &grant, domain::NOW)
                .is_err(),
            "missing {field}"
        );
    }
    let mut f = Fixture::new();
    let duplicate = f.certificate["discharges"][0].clone();
    f.certificate["discharges"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    let (cert, _, grant) = f.signed();
    assert!(
        f.verifier
            .validate(&f.context, &cert, &grant, domain::NOW)
            .is_err()
    );
}

#[test]
fn changed_or_broadened_grants_refuse() {
    let f = Fixture::new();
    let (cert, grant, _) = f.signed();
    let invalid = [
        ("/parameters_digest", json!("a".repeat(64))),
        ("/certificate_digest", json!("a".repeat(64))),
        ("/evidence_manifest_digest", json!("a".repeat(64))),
        ("/dpop_jkt", json!("changed-proof-key")),
        ("/conflict_domain", json!("other-domain")),
        ("/root_generation", json!(2)),
        ("/issued_at", json!(domain::NOW - 2)),
        ("/expires_at", json!(grant.expires_at + 1)),
        (
            "/predicate_descriptor/clauses/0/expected_version",
            json!("2"),
        ),
        ("/adapter_contract/commit_point", json!("changed-contract")),
    ];
    for (path, replacement) in invalid {
        let mut value = serde_json::to_value(&grant).unwrap();
        *value.pointer_mut(path).unwrap() = replacement;
        let altered: Grant = serde_json::from_value(value).unwrap();
        let raw = sign_grant(&altered, "test-key", &f.issuer_key).unwrap();
        assert!(
            f.verifier
                .validate(&f.context, &cert, &raw, domain::NOW)
                .is_err(),
            "{path}"
        );
    }
}

#[tokio::test]
async fn concurrent_fresh_roots_return_one_persisted_allowance() {
    let f = Fixture::new();
    let Some(ledger) = f.ledger("concurrent") else {
        return;
    };
    ledger.publish_policy(&f.grant).await.unwrap();
    let mut candidates = Vec::new();
    for replica in 0..16 {
        let mut f = Fixture::new();
        f.grant.root_id = format!("new-root-{replica}");
        f.grant.gid = format!("new-grant-{replica}");
        f.grant.nonce = format!("new-nonce-{replica}");
        f.grant.fence += replica;
        candidates.push(f.admitted());
    }
    let barrier = Arc::new(Barrier::new(candidates.len()));
    let mut jobs = JoinSet::new();
    for candidate in candidates {
        let ledger = ledger.clone();
        let barrier = barrier.clone();
        jobs.spawn(async move {
            barrier.wait().await;
            ledger.issue_admitted(&candidate, &CLOCK).await.unwrap()
        });
    }
    let mut created = 0;
    let mut original = None;
    while let Some(result) = jobs.join_next().await {
        let result = result.unwrap();
        created += usize::from(!result.reused);
        if let Some(record) = &original {
            assert_eq!(record, &result.record);
        }
        original = Some(result.record);
    }
    assert_eq!(created, 1);
    // The ledger must contain only the winner root; all other candidates refuse claim.
    let stored = original.unwrap();
    let winner = f
        .verifier
        .grants
        .verify(stored.signed_grant.as_bytes(), domain::NOW)
        .unwrap();
    ledger
        .claim(&winner.grant, &winner.digest, "winner-attempt")
        .await
        .unwrap();
    for replica in 0..16 {
        let mut f = Fixture::new();
        f.grant.root_id = format!("new-root-{replica}");
        f.grant.gid = format!("new-grant-{replica}");
        f.grant.nonce = format!("new-nonce-{replica}");
        f.grant.fence += replica;
        let (_, candidate, signed) = f.signed();
        let verified = f.verifier.grants.verify(&signed, domain::NOW).unwrap();
        assert!(
            ledger
                .claim(&candidate, &verified.digest, "second-attempt")
                .await
                .is_err()
        );
    }
    let retry = ledger.issue_admitted(&f.admitted(), &CLOCK).await.unwrap();
    assert!(retry.reused);
    assert_eq!(retry.record, stored);
    assert_eq!(
        ledger
            .status(&winner.grant, "winner-attempt")
            .await
            .unwrap()
            .status,
        "claimed"
    );
}

#[tokio::test]
async fn semantic_rebinding_cannot_escape_through_another_domain() {
    let f = Fixture::new();
    let Some(ledger) = f.ledger("rebinding") else {
        return;
    };
    ledger.publish_policy(&f.grant).await.unwrap();
    ledger.issue_admitted(&f.admitted(), &CLOCK).await.unwrap();
    let mut changed = Fixture::new();
    changed.context.conflict_domain = "other-domain".into();
    changed.grant.conflict_domain = changed.context.conflict_domain.clone();
    changed.grant.root_id = "fresh-root".into();
    changed.grant.gid = "fresh-grant".into();
    ledger.publish_policy(&changed.grant).await.unwrap();
    assert!(matches!(
        ledger.issue_admitted(&changed.admitted(), &CLOCK).await,
        Err(Error::Refused(_))
    ));
    let (_, grant, signed) = changed.signed();
    let verified = changed
        .verifier
        .grants
        .verify(&signed, domain::NOW)
        .unwrap();
    assert!(
        ledger
            .claim(&grant, &verified.digest, "invalid-attempt")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stale_policy_blocks_creation_and_duplicate_return() {
    let f = Fixture::new();
    let Some(ledger) = f.ledger("stale") else {
        return;
    };
    ledger.publish_policy(&f.grant).await.unwrap();
    ledger.issue_admitted(&f.admitted(), &CLOCK).await.unwrap();
    let mut updated = f.grant.clone();
    updated.policy.epoch += 1;
    ledger.publish_policy(&updated).await.unwrap();
    assert!(matches!(
        ledger.issue_admitted(&f.admitted(), &CLOCK).await,
        Err(Error::Refused(_))
    ));
    let mut fresh = Fixture::new();
    fresh.context.qid = "different-operation".into();
    fresh.grant.root_id = "different-root".into();
    assert!(matches!(
        ledger.issue_admitted(&fresh.admitted(), &CLOCK).await,
        Err(Error::Refused(_))
    ));
}

#[tokio::test]
async fn changed_certificate_conflicts_but_fresh_admitted_operation_is_independent() {
    let f = Fixture::new();
    let Some(ledger) = f.ledger("certificate") else {
        return;
    };
    ledger.publish_policy(&f.grant).await.unwrap();
    let first = ledger.issue_admitted(&f.admitted(), &CLOCK).await.unwrap();
    let mut changed = Fixture::new();
    changed.certificate["cid"] = json!("new-certificate-same-operation");
    changed.grant.root_id = "new-root".into();
    assert!(matches!(
        ledger.issue_admitted(&changed.admitted(), &CLOCK).await,
        Err(Error::Refused(_))
    ));
    changed.context.qid = "independently-admitted-new-operation".into();
    // A trusted context's qid/proposal link must come from M2b's verified Proposal.
    changed.context.proposal_digest = "b".repeat(64);
    changed.certificate["proposal_digest"] = json!(changed.context.proposal_digest);
    changed.grant.proposal_digest = changed.context.proposal_digest.clone();
    let second = ledger
        .issue_admitted(&changed.admitted(), &CLOCK)
        .await
        .unwrap();
    assert!(!second.reused);
    assert_ne!(first.record.issuance_key, second.record.issuance_key);
}

#[tokio::test]
async fn expired_opaque_candidate_refuses_before_any_ledger_access() {
    let f = Fixture::new();
    let ledger =
        EtcdLedger::new(reqwest::Client::new(), "http://127.0.0.1:1", "/unreachable").unwrap();
    // A validation result held past its deadline is not an authority refresh.
    let expired = FixedClock(f.grant.expires_at);
    assert!(
        matches!(ledger.issue_admitted(&f.admitted(), &expired).await,
        Err(Error::Refused(message)) if message == "issuance candidate no longer valid")
    );
}
