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
    policy::{AdmissionController, CedarAdmissionPolicy, CedarPolicyDefinition},
    schema::{ClosedObjectSchema, verify_record},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const NOW: i64 = 1_800_000_000_000;
pub struct Time(pub i64);
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        self.0
    }
}
pub const CLOCK: Time = Time(NOW);

pub fn payload(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap()["payload"].clone()
}
pub fn signed(kind: &str, payload: Value, key: u8) -> Vec<u8> {
    let definition = match kind {
        "proposal" => "Proposal",
        "ctd" => "ConsequentialToolDescriptor",
        "manifest" => "WitnessManifest",
        "evidence" => "Evidence",
        "certificate" => "AdmissionCertificate",
        "lease" => "AdmissionLease",
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
pub fn keys(key: u8) -> BTreeMap<String, ed25519_dalek::VerifyingKey> {
    BTreeMap::from([(
        format!("key-{key}"),
        SigningKey::from_bytes(&[key; 32]).verifying_key(),
    )])
}
pub fn record_hash(raw: &[u8]) -> String {
    record_digest(&serde_json::from_slice(raw).unwrap()).unwrap()
}

pub struct Fixture {
    pub trust: AdmissionTrust,
    pub identity: Identity,
    pub proposal: Value,
    pub descriptor: Value,
    pub evidence: Value,
}
pub struct Packet {
    pub proposal: Vec<u8>,
    pub descriptor: Vec<u8>,
    pub manifest: Vec<u8>,
    pub evidence: Vec<Vec<u8>>,
}
impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}
impl Packet {
    pub fn borrowed(&self) -> AdmissionPacket<'_> {
        AdmissionPacket {
            lease: None,
            proposal: &self.proposal,
            descriptor: &self.descriptor,
            manifest: &self.manifest,
            evidence: &self.evidence,
        }
    }
}
impl Fixture {
    pub fn sql(&mut self) {
        self.descriptor["action"] = json!(kedgeflow::postgres_action::ACTION);
        self.descriptor["version"] = json!("1.0");
        self.descriptor["parameter_schema"] = kedgeflow::leaf_action::sql_schema();
        let pin = digest("parameter-schema", &self.descriptor["parameter_schema"]).unwrap();
        self.descriptor["parameter_schema_digest"] = json!(pin);
        self.descriptor["rendering"]["parameter_schema_digest"] = json!(pin);
        self.proposal["action"]["id"] = self.descriptor["action"].clone();
        self.proposal["action"]["version"] = json!("1.0");
        self.proposal["parameters"] = json!({"resource_id":self.proposal["resources"][0]["id"],"expected_version":241,"reservation":"booking:pilot"});
        self.repin_descriptor();
    }
    pub fn repin_descriptor(&mut self) {
        self.trust.descriptor_digest = record_hash(&signed("ctd", self.descriptor.clone(), 2));
        self.proposal["action"]["digest"] = json!(self.trust.descriptor_digest);
    }

    pub fn new() -> Self {
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
        let mut requirement = EvidenceRequirement {
            review: None,
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
        requirement.obligation.predicate_digest = digest(
            "evidence-predicate",
            &serde_json::to_value(&requirement.predicates).unwrap(),
        )
        .unwrap();
        let identity = Identity {
            subject: serde_json::from_value(proposal["subject"].clone()).unwrap(),
            workload_id: "spiffe://test/agent".into(),
            dpop_jkt: proposal["delegation"]["dpop_jkt"].as_str().unwrap().into(),
            delegation_digest: digest("delegation", &proposal["delegation"]).unwrap(),
            access_token: "synthetic-identity-boundary".into(),
            scopes: BTreeSet::from(["capacity.reserve".into()]),
        };
        let mut trust = AdmissionTrust {
            leases: None,
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
        trust.obligation_manifest_digest = trust.registered_obligations_digest().unwrap();
        Self {
            trust,
            identity,
            proposal,
            descriptor,
            evidence,
        }
    }
    pub fn packet(&self) -> Packet {
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
    pub fn authority(&self, packet: &Packet) -> (IssuanceVerifier, Value, Grant) {
        let mut cert = payload("certificate");
        let evidence: Value = serde_json::from_slice(&packet.evidence[0]).unwrap();
        cert["proposal_digest"] = json!(record_hash(&packet.proposal));
        cert["delegation_digest"] = json!(self.identity.delegation_digest);
        cert["workload_id"] = json!(self.identity.workload_id);
        cert["policy"] = json!(self.trust.policy);
        cert["descriptor_digest"] = json!(self.trust.descriptor_digest);
        cert["obligation_manifest_digest"] = json!(self.trust.obligation_manifest_digest);
        cert["evidence_manifest_digest"] = json!(record_hash(&packet.manifest));
        cert["admitted_at"] = json!(NOW - 1);
        cert["expires_at"] = json!(NOW + 30000);
        cert["lease_digest"] = Value::Null;
        cert["discharges"] = json!([{"obligation_id":"capacity","predicate_digest":self.trust.evidence["capacity"].obligation.predicate_digest,"witness_refs":[{"id":self.evidence["wid"],"schema":evidence["schema"],"digest":record_hash(&packet.evidence[0])}],"result":"satisfied","stage":"jit","execution_relevant":true,"observed_at":NOW-11,"expires_at":NOW+30000}]);
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
