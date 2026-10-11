use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    admission::{
        AdmissionPacket, AdmissionTrust, EvidencePredicate, EvidenceRequirement, EvidenceVerdict,
        RecordReference,
    },
    auth::Identity,
    clock::Clock,
    contracts::{
        Envelope, Grant, GrantVerifier, Policy, canonical, digest, record_digest, sign_grant,
        signature_input,
    },
    issuance::{IssuanceVerifier, RequiredObligation},
    schema::{ClosedObjectSchema, verify_record},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const NOW: i64 = 1_800_000_000_000;
struct Time(i64);
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        self.0
    }
}
const CLOCK: Time = Time(NOW);

fn payload(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap()["payload"].clone()
}
fn signed(kind: &str, payload: Value, key: u8) -> Vec<u8> {
    let definition = match kind {
        "proposal" => "Proposal",
        "ctd" => "ConsequentialToolDescriptor",
        "manifest" => "WitnessManifest",
        "evidence" => "Evidence",
        "certificate" => "AdmissionCertificate",
        _ => panic!("test kind"),
    };
    let mut e = Envelope {
        profile: "KF-JSON-0.2".into(),
        kind: kind.into(),
        schema: format!(
            "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/{definition}"
        ),
        key_id: format!("key-{key}"),
        payload,
        signature: String::new(),
    };
    e.signature = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[key; 32])
            .sign(&signature_input(&e).unwrap())
            .to_bytes(),
    );
    canonical(&serde_json::to_value(e).unwrap()).unwrap()
}
fn keys(key: u8) -> BTreeMap<String, ed25519_dalek::VerifyingKey> {
    BTreeMap::from([(
        format!("key-{key}"),
        SigningKey::from_bytes(&[key; 32]).verifying_key(),
    )])
}
fn record_hash(raw: &[u8]) -> String {
    record_digest(&serde_json::from_slice(raw).unwrap()).unwrap()
}

struct Fixture {
    trust: AdmissionTrust,
    identity: Identity,
    proposal: Value,
    descriptor: Value,
    evidence: Value,
}
struct Packet {
    proposal: Vec<u8>,
    descriptor: Vec<u8>,
    manifest: Vec<u8>,
    evidence: Vec<Vec<u8>>,
}
impl Packet {
    fn borrowed(&self) -> AdmissionPacket<'_> {
        AdmissionPacket {
            proposal: &self.proposal,
            descriptor: &self.descriptor,
            manifest: &self.manifest,
            evidence: &self.evidence,
        }
    }
}
impl Fixture {
    fn new() -> Self {
        let mut descriptor = payload("ctd");
        let mut proposal = payload("proposal");
        let mut evidence = payload("evidence");
        let resource = proposal["resources"][0].clone();
        descriptor["parameter_schema"] = json!({"type":"object","additionalProperties":false,"properties":{"node":{"type":"string"},"expected_version":{"type":"integer","minimum":1}},"required":["node","expected_version"]});
        let schema_digest = digest("parameter-schema", &descriptor["parameter_schema"]).unwrap();
        descriptor["parameter_schema_digest"] = json!(schema_digest);
        descriptor["rendering"]["parameter_schema_digest"] = json!(schema_digest);
        descriptor["adapter_contract"]["guard_primitive"] = json!("FencingToken");
        descriptor["adapter_contract"]["completion_mode"] = json!("dispatch_bound");
        descriptor["adapter_contract"]["idempotency"]["parameter"] = json!("kf_attempt_id");
        descriptor["compensation"] = Value::Null;
        descriptor["compensation_unavailable_reason"] =
            json!("Compensation is outside the leaf profile.");
        let descriptor_digest = record_hash(&signed("ctd", descriptor.clone(), 2));
        proposal["action"]["digest"] = json!(descriptor_digest);
        proposal["parameters"] = json!({"node":resource["id"],"expected_version":241});
        proposal["workflow"] = Value::Null;
        proposal["workload_id"] = json!("spiffe://test/agent");
        proposal["created_at"] = json!(NOW - 10);
        proposal["delegation"]["expires_at"] = json!(NOW + 60000);
        proposal["requested_completion"] = json!("dispatch_bound");
        proposal["baseline_state"][0]["observed_at"] = json!(NOW - 12);
        proposal["baseline_state"][0]["expires_at"] = json!(NOW + 60000);
        evidence["observed_at"] = json!(NOW - 11);
        evidence["expires_at"] = json!(NOW + 30000);
        let result_schema = json!({"type":"object","additionalProperties":false,"properties":{"available_slots":{"type":"integer"},"minimum_after":{"type":"integer"},"version":{"type":"string"},"satisfied":{"type":"boolean"}},"required":["available_slots","minimum_after","version","satisfied"]});
        evidence["result_schema"]["digest"] =
            json!(digest("result-schema", &result_schema).unwrap());
        let policy: Policy = serde_json::from_value(payload("grant")["policy"].clone()).unwrap();
        let requirement = EvidenceRequirement {
            obligation: RequiredObligation {
                predicate_digest: "a".repeat(64),
                stage: "jit".into(),
                execution_relevant: true,
            },
            provider_id: evidence["provider_id"].as_str().unwrap().into(),
            provider_version: "1.0".into(),
            keys: keys(4),
            question: serde_json::from_value(evidence["question_ref"].clone()).unwrap(),
            result_schema_ref: serde_json::from_value(evidence["result_schema"].clone()).unwrap(),
            result_schema,
            max_age_ms: 60000,
            predicates: vec![
                EvidencePredicate::IntegerAtLeast {
                    field: "available_slots".into(),
                    minimum: 2,
                },
                EvidencePredicate::StringEquals {
                    field: "version".into(),
                    expected: "241".into(),
                },
            ],
        };
        let identity = Identity {
            subject: serde_json::from_value(proposal["subject"].clone()).unwrap(),
            workload_id: "spiffe://test/agent".into(),
            dpop_jkt: proposal["delegation"]["dpop_jkt"].as_str().unwrap().into(),
            delegation_digest: digest("delegation", &proposal["delegation"]).unwrap(),
            access_token: "synthetic-identity-boundary".into(),
            scopes: BTreeSet::from(["capacity.reserve".into()]),
        };
        let trust = AdmissionTrust {
            tenant: "tenant-42".into(),
            proposal_keys: keys(1),
            proposal_workload_id: identity.workload_id.clone(),
            registry_keys: keys(2),
            manifest_keys: keys(3),
            descriptor_digest,
            ownership_epoch: 5,
            policy,
            obligation_manifest_digest: "b".repeat(64),
            required_scope: "capacity.reserve".into(),
            max_proposal_age_ms: 60000,
            evidence: BTreeMap::from([("capacity".into(), requirement)]),
        };
        Self {
            trust,
            identity,
            proposal,
            descriptor,
            evidence,
        }
    }
    fn packet(&self) -> Packet {
        let proposal = signed("proposal", self.proposal.clone(), 1);
        let descriptor = signed("ctd", self.descriptor.clone(), 2);
        let mut e = self.evidence.clone();
        e["proposal_digest"] = json!(record_hash(&proposal));
        let evidence = signed("evidence", e.clone(), 4);
        let reference = RecordReference {
            id: e["wid"].as_str().unwrap().into(),
            schema: "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/Evidence".into(),
            digest: record_hash(&evidence),
        };
        let manifest = signed(
            "manifest",
            json!({"mid":"test:manifest","proposal_digest":record_hash(&proposal),"policy":self.trust.policy,"witnesses":[{"witness":serde_json::to_value(&reference).unwrap(),"obligation_id":"capacity","execution_relevant":true,"expires_at":e["expires_at"]}],"assembled_at":NOW-2}),
            3,
        );
        Packet {
            proposal,
            descriptor,
            manifest,
            evidence: vec![evidence],
        }
    }
    fn authority(&self, packet: &Packet) -> (IssuanceVerifier, Value, Grant) {
        let mut cert = payload("certificate");
        let evidence: Value = serde_json::from_slice(&packet.evidence[0]).unwrap();
        cert["proposal_digest"] = json!(record_hash(&packet.proposal));
        cert["delegation_digest"] = json!(self.identity.delegation_digest);
        cert["workload_id"] = json!(self.identity.workload_id);
        cert["descriptor_digest"] = json!(self.trust.descriptor_digest);
        cert["obligation_manifest_digest"] = json!(self.trust.obligation_manifest_digest);
        cert["evidence_manifest_digest"] = json!(record_hash(&packet.manifest));
        cert["admitted_at"] = json!(NOW - 1);
        cert["expires_at"] = json!(NOW + 30000);
        cert["lease_digest"] = Value::Null;
        cert["discharges"] = json!([{"obligation_id":"capacity","predicate_digest":"a".repeat(64),"witness_refs":[{"id":self.evidence["wid"],"schema":evidence["schema"],"digest":record_hash(&packet.evidence[0])}],"result":"satisfied","stage":"jit","execution_relevant":true,"observed_at":NOW-11,"expires_at":NOW+30000}]);
        cert["constraints"] = json!({"action":self.proposal["action"],"resources":self.proposal["resources"],"parameters_digest":digest("parameters", &self.proposal["parameters"]).unwrap(),"predicate_descriptor":self.descriptor["concurrency"]["predicate_descriptor"],"adapter_contract":self.descriptor["adapter_contract"],"audience":self.descriptor["gateway_audience"],"max_attempts":1,"expires_at":NOW+30000,"saga_budget":null});
        cert["constraint_digest"] = json!(digest("constraints", &cert["constraints"]).unwrap());
        let mut grant = payload("grant");
        for field in [
            "proposal_digest",
            "delegation_digest",
            "subject",
            "workload_id",
            "policy",
            "ownership_epoch",
            "evidence_manifest_digest",
            "constraint_digest",
        ] {
            grant[field] = cert[field].clone();
        }
        for field in [
            "action",
            "resources",
            "parameters_digest",
            "predicate_descriptor",
            "adapter_contract",
            "audience",
            "saga_budget",
        ] {
            grant[field] = cert["constraints"][field].clone();
        }
        grant["dpop_jkt"] = json!(self.identity.dpop_jkt);
        grant["parent_grant_digest"] = Value::Null;
        grant["issued_at"] = json!(NOW);
        grant["valid_from"] = json!(NOW);
        grant["expires_at"] = json!(NOW + 30000);
        grant["completion_mode"] = json!("dispatch_bound");
        let verifier = IssuanceVerifier {
            tenant: self.trust.tenant.clone(),
            admission_keys: keys(3),
            grants: GrantVerifier {
                keys: keys(5),
                audience: self.descriptor["gateway_audience"].as_str().unwrap().into(),
            },
        };
        (verifier, cert, serde_json::from_value(grant).unwrap())
    }
}

#[test]
fn exact_signed_chain_can_supply_certificate_constrained_issuance() {
    let f = Fixture::new();
    let p = f.packet();
    let inputs = f
        .trust
        .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
        .unwrap();
    let (verifier, cert, mut grant) = f.authority(&p);
    let cert = signed("certificate", cert, 3);
    grant.certificate_digest = record_hash(&cert);
    let raw = sign_grant(&grant, "key-5", &SigningKey::from_bytes(&[5; 32])).unwrap();
    verifier
        .validate_inputs(&inputs, &cert, &raw, &CLOCK)
        .unwrap();
    assert!(
        verifier
            .validate_inputs(&inputs, &cert, &raw, &Time(NOW + 30000))
            .is_err()
    );
}

#[test]
fn authentic_signatures_do_not_make_wrong_identity_parameters_or_registry_current() {
    for (field, value) in [
        ("/tenant", json!("other-tenant")),
        ("/subject/sub", json!("other-subject")),
        ("/workload_id", json!("spiffe://test/other")),
        ("/delegation/dpop_jkt", json!("x".repeat(43))),
        ("/action/digest", json!("a".repeat(64))),
        ("/parameters/expected_version", json!(242)),
        ("/created_at", json!(NOW + 1)),
        ("/baseline_state/0/expires_at", json!(NOW)),
        ("/workflow", json!({})),
    ] {
        let mut f = Fixture::new();
        *f.proposal.pointer_mut(field).unwrap() = value;
        assert!(
            f.trust
                .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
                .is_err(),
            "{field}"
        );
    }
    let mut f = Fixture::new();
    f.proposal["parameters"]["unexpected"] = json!(true);
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
    let mut f = Fixture::new();
    f.descriptor["ownership_epoch"] = json!(6);
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
    let mut f = Fixture::new();
    f.identity.scopes.clear();
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
}

#[test]
fn stale_missing_unapproved_or_violated_evidence_cannot_supply_inputs() {
    for (field, value) in [
        ("/provider_id", json!("unregistered-provider")),
        ("/provider_version", json!("2.0")),
        ("/state_digest", json!("a".repeat(64))),
        ("/state_scope/0/incarnation", json!("recreated")),
        ("/question_ref/digest", json!("a".repeat(64))),
        ("/result_schema/digest", json!("a".repeat(64))),
        ("/result/available_slots", json!(0)),
        ("/result/version", json!("242")),
        ("/observed_at", json!(NOW + 1)),
        ("/observed_at", json!(NOW - 60000)),
        ("/expires_at", json!(NOW)),
    ] {
        let mut f = Fixture::new();
        *f.evidence.pointer_mut(field).unwrap() = value;
        assert!(
            f.trust
                .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
                .is_err(),
            "{field}"
        );
    }
    let mut f = Fixture::new();
    f.evidence["result"]["extra"] = json!(true);
    assert!(
        f.trust
            .verify_inputs(&f.identity, f.packet().borrowed(), &CLOCK)
            .is_err()
    );
    let f = Fixture::new();
    let mut p = f.packet();
    p.evidence.clear();
    assert!(
        f.trust
            .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
            .is_err()
    );
    let mut p = f.packet();
    p.evidence.push(p.evidence[0].clone());
    assert!(
        f.trust
            .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
            .is_err()
    );
    let mut p = f.packet();
    p.evidence[0] = signed("evidence", f.evidence.clone(), 1);
    assert!(
        f.trust
            .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
            .is_err()
    );
}

#[test]
fn valid_manifest_signature_cannot_substitute_a_witness_or_policy() {
    for field in ["/witnesses/0/witness/digest", "/policy/digest"] {
        let f = Fixture::new();
        let mut p = f.packet();
        let mut manifest: Value =
            serde_json::from_slice::<Value>(&p.manifest).unwrap()["payload"].clone();
        *manifest.pointer_mut(field).unwrap() = json!("a".repeat(64));
        p.manifest = signed("manifest", manifest, 3);
        assert!(
            f.trust
                .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
                .is_err()
        );
    }
}

#[test]
fn certificate_and_grant_must_match_the_independently_verified_chain() {
    for field in [
        "/constraints/resources/0/incarnation",
        "/constraints/parameters_digest",
        "/discharges/0/witness_refs/0/digest",
    ] {
        let f = Fixture::new();
        let p = f.packet();
        let inputs = f
            .trust
            .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
            .unwrap();
        let (verifier, mut cert, mut grant) = f.authority(&p);
        *cert.pointer_mut(field).unwrap() = json!(if field.contains("incarnation") {
            "recreated".to_owned()
        } else {
            "c".repeat(64)
        });
        cert["constraint_digest"] = json!(digest("constraints", &cert["constraints"]).unwrap());
        grant.resources = serde_json::from_value(cert["constraints"]["resources"].clone()).unwrap();
        grant.parameters_digest = cert["constraints"]["parameters_digest"]
            .as_str()
            .unwrap()
            .into();
        grant.constraint_digest = cert["constraint_digest"].as_str().unwrap().into();
        let cert = signed("certificate", cert, 3);
        grant.certificate_digest = record_hash(&cert);
        let raw = sign_grant(&grant, "key-5", &SigningKey::from_bytes(&[5; 32])).unwrap();
        assert!(
            verifier
                .validate_inputs(&inputs, &cert, &raw, &CLOCK)
                .is_err()
        );
    }
}

#[test]
fn registered_schemas_are_closed_and_external_resolution_is_disabled() {
    assert!(ClosedObjectSchema::new(&json!({"type":"object"})).is_err());
    for uri in ["https://127.0.0.1:1/schema", "file:///etc/passwd"] {
        assert!(ClosedObjectSchema::new(&json!({"type":"object","additionalProperties":false,"properties":{"x":{"$ref":uri}}})).is_err());
    }
    let f = Fixture::new();
    let raw = signed("evidence", json!({"wid":"only-id"}), 4);
    assert!(verify_record(&raw, "evidence", &keys(4)).is_err());
    let mut p = f.proposal.clone();
    p.as_object_mut().unwrap().remove("workflow");
    assert!(verify_record(&signed("proposal", p, 1), "proposal", &keys(1)).is_err());
}

#[test]
fn evidence_results_use_ternary_server_selected_comparisons() {
    let p = EvidencePredicate::IntegerAtLeast {
        field: "available".into(),
        minimum: 2,
    };
    assert_eq!(
        p.evaluate(&json!({"available":2})),
        EvidenceVerdict::Satisfied
    );
    assert_eq!(
        p.evaluate(&json!({"available":1,"satisfied":true})),
        EvidenceVerdict::Violated
    );
    assert_eq!(
        p.evaluate(&json!({"available":"2"})),
        EvidenceVerdict::Unknown
    );
    assert_eq!(p.evaluate(&json!({})), EvidenceVerdict::Unknown);
}

#[test]
fn pinned_rust_schema_accepts_all_thirteen_unchanged_signed_vectors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let registry: Value =
        serde_json::from_slice(&std::fs::read(root.join("public-test-keys.json")).unwrap())
            .unwrap();
    let kinds: Value =
        serde_json::from_slice(&std::fs::read(root.join("fixture-digests.json")).unwrap()).unwrap();
    assert_eq!(kinds.as_object().unwrap().len(), 13);
    for kind in kinds.as_object().unwrap().keys() {
        let raw = std::fs::read(root.join(format!("{kind}.json"))).unwrap();
        let envelope: Envelope = serde_json::from_slice(&raw).unwrap();
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(registry[&envelope.key_id]["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let keys = BTreeMap::from([(
            envelope.key_id,
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap(),
        )]);
        verify_record(&raw, kind, &keys).unwrap();
    }
}

#[tokio::test]
async fn verified_chain_issues_and_consumes_one_real_etcd_allowance() {
    use kedgeflow::{
        error::Error,
        ledger::{AuthorityLedger, EtcdLedger},
    };
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            assert_ne!(
                std::env::var("KF_REQUIRE_ETCD").as_deref(),
                Ok("1"),
                "required etcd endpoint missing"
            );
            eprintln!("SKIP admission integration: ETCD_ENDPOINT absent");
            return;
        }
    };
    let f = Fixture::new();
    let p = f.packet();
    let inputs = f
        .trust
        .verify_inputs(&f.identity, p.borrowed(), &CLOCK)
        .unwrap();
    let (verifier, cert, mut grant) = f.authority(&p);
    let cert = signed("certificate", cert, 3);
    grant.certificate_digest = record_hash(&cert);
    let raw = sign_grant(&grant, "key-5", &SigningKey::from_bytes(&[5; 32])).unwrap();
    let admitted = verifier
        .validate_inputs(&inputs, &cert, &raw, &CLOCK)
        .unwrap();
    let namespace = format!(
        "/kf-chain-tests/{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let ledger = EtcdLedger::new(
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        endpoint,
        namespace,
    )
    .unwrap();
    ledger.publish_policy(&grant).await.unwrap();
    let issued = ledger.issue_admitted(&admitted, &CLOCK).await.unwrap();
    assert!(!issued.reused);
    let verified = verifier
        .grants
        .verify(issued.record.signed_grant.as_bytes(), NOW)
        .unwrap();
    let attempt = ledger
        .claim(&verified.grant, &verified.digest, "chain-attempt")
        .await
        .unwrap();
    let reused = ledger.issue_admitted(&admitted, &CLOCK).await.unwrap();
    assert!(reused.reused);
    assert_eq!(issued.record, reused.record);
    assert!(matches!(
        ledger
            .claim(&verified.grant, &verified.digest, "duplicate-attempt")
            .await,
        Err(Error::NonceConsumed)
    ));
    assert_eq!(
        ledger
            .status(&verified.grant, "chain-attempt")
            .await
            .unwrap(),
        attempt
    );
}
