//! Historical protected selection/discovery boundaries. No native mutation or
//! physical qualification is performed by these pure configuration vectors.
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::HeaderMap;
use kedgeflow::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::{Authenticator, Identity, WorkloadIdentity},
    broker::{CredentialBroker, TargetCredential},
    clock::SystemClock,
    config::Config,
    contracts::{GrantVerifier, Subject},
    error::Result,
    gateway::{Gateway, ToolDescriptor, VerifiedCall},
    ledger::EtcdLedger,
    managed_drain as managed, managed_drain_adapter,
    managed_drain_audit::Trust,
    managed_drain_store::Context,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::time::Instant;
fn context() -> Context {
    let t = Trust::decode(include_bytes!("../../../results/verification/rfc-m8-managed-controller-2026-10-27/native-artifacts/managed-controller-completed/trust.json")).unwrap();
    Context::from_selection(t.selection).unwrap()
}
fn native(c: &Context) -> kedgeflow::reserved_lineage::Trust {
    let n = c
        .selection
        .registration
        .composition
        .as_ref()
        .unwrap()
        .node(&c.selection.child_id)
        .unwrap();
    kedgeflow::reserved_lineage::TrustConfig::decode(&serde_json::to_vec(&n.forward_trust).unwrap())
        .unwrap()
        .registration()
        .unwrap()
}
fn tool(c: &Context) -> ToolDescriptor {
    let native = native(c);
    let s = &native.registration.scope;
    serde_json::from_value(json!({"name":"drain","read_only":false,"required_scope":native.lineage.admission.required_scope,
        "status_scope":"kf.status","action":s.action,"resource":s.resource,"conflict_domain":s.conflict_domain,
        "adapter_contract":s.adapter_contract,"predicate_id":s.predicate_descriptor["id"],"predicate_version":s.predicate_descriptor["version"],
        "version_parameter":"expected_version","fence_parameter":"","admission_endpoint":"https://control.test/admit"})).unwrap()
}
fn adapter_config(c: &Context) -> managed_drain_adapter::Config {
    let gateway = c
        .physical
        .control()
        .unwrap()
        .historical
        .into_iter()
        .find(|h| h.registration.scope.action.id == managed::ACTION)
        .unwrap()
        .registration
        .acknowledger
        .workload_id;
    serde_json::from_value(json!({"profile":managed::PROFILE,"selection":c.selection,"token_issuer":"https://broker.test/exchange",
        "target_keys":{"broker":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[202;32]).verifying_key().as_bytes())},"gateway_workload":gateway})).unwrap()
}
fn verifier(c: &Context) -> GrantVerifier {
    native(c).lineage.grants
}
fn configuration(c: &Context) -> Value {
    let mut v: Value =
        serde_json::from_str(include_str!("../../../config/gateway.example.json")).unwrap();
    let cfg = adapter_config(c);
    let grants = verifier(c);
    let (id, key) = grants.keys.iter().next().unwrap();
    v.as_object_mut().unwrap().remove("enforcement");
    v["external_url"] = json!(grants.audience);
    v["grant_key_id"] = json!(id);
    v["grant_public_key_base64"] = json!(STANDARD.encode(key.as_bytes()));
    v["oidc_public_key_base64"] = v["grant_public_key_base64"].clone();
    v["etcd_prefix"] = json!(c.selection.registration.namespace);
    v["managed_drain_adapter"] = json!(cfg);
    v["family"] = json!(c.selection);
    v["reservation"] = json!(
        c.selection
            .registration
            .child(&c.selection.child_id)
            .unwrap()
            .reservation
    );
    v["target_audience"] = json!(c.enrollment.target_audience);
    v["target_url"] = v["target_audience"].clone();
    v["target_scope"] = json!(c.enrollment.target_scope);
    v["actor_workload"] = json!(native(c).lineage.admission.proposal_workload_id);
    v["tools"] = json!([tool(c)]);
    v
}
#[test]
fn protected_managed_runtime_selection_is_explicit_exact_and_role_separated() {
    let c = context();
    let v = configuration(&c);
    Config::decode(&serde_json::to_vec(&v).unwrap())
        .unwrap()
        .validate()
        .unwrap();
    for case in [
        "missing",
        "null",
        "unknown",
        "legacy",
        "namespace",
        "family",
        "reservation",
        "target",
        "scope",
        "actor",
        "gateway-as-actor",
        "predicate",
        "tool",
        "uncontrolled",
        "read-token",
        "broker-role",
        "controller-role",
    ] {
        let mut bad = v.clone();
        match case {
            "missing" => {
                bad.as_object_mut().unwrap().remove("managed_drain_adapter");
            }
            "null" => bad["managed_drain_adapter"] = Value::Null,
            "unknown" => bad["managed_drain_adapter"]["extra"] = json!(true),
            "legacy" => {
                bad["managed_drain_adapter"]["profile"] = json!(kedgeflow::kube_drain::PROFILE)
            }
            "namespace" => bad["etcd_prefix"] = json!("/other"),
            "family" => bad["family"]["child_id"] = json!("child-0"),
            "reservation" => bad["reservation"]["root_id"] = json!("other"),
            "target" => bad["target_url"] = json!("https://other.test/accept"),
            "scope" => bad["target_scope"] = json!("other"),
            "actor" => bad["actor_workload"] = json!(c.enrollment.controller_workload),
            "gateway-as-actor" => {
                bad["actor_workload"] = bad["managed_drain_adapter"]["gateway_workload"].clone()
            }
            "predicate" => bad["tools"][0]["predicate_version"] = json!("other"),
            "tool" => {
                let t = bad["tools"][0].clone();
                bad["tools"].as_array_mut().unwrap().push(t);
            }
            "uncontrolled" => bad["require_control"] = json!(false),
            "read-token" => bad["read_token_file"] = json!("/unapproved-token"),
            "broker-role" => {
                bad["managed_drain_adapter"]["target_keys"] =
                    json!(c.enrollment.operating_observer.keys)
            }
            "controller-role" => {
                bad["managed_drain_adapter"]["gateway_workload"] =
                    json!(c.enrollment.controller_workload)
            }
            _ => unreachable!(),
        }
        assert!(
            Config::decode(&serde_json::to_vec(&bad).unwrap())
                .and_then(|c| c.validate())
                .is_err(),
            "{case}"
        );
    }
}
struct Auth;
#[async_trait]
impl Authenticator for Auth {
    async fn authenticate(&self, _: &HeaderMap, w: &WorkloadIdentity) -> Result<Identity> {
        let c = context();
        let t = tool(&c);
        Ok(Identity {
            subject: Subject {
                iss: "https://identity.test".into(),
                sub: "reader".into(),
            },
            workload_id: w.as_str().into(),
            dpop_jkt: "read-only-vector".into(),
            delegation_digest: "a".repeat(64),
            access_token: "read-only-vector".into(),
            scopes: [t.required_scope, t.status_scope].into(),
        })
    }
}
struct Broker;
#[async_trait]
impl CredentialBroker for Broker {
    async fn exchange(&self, _: &VerifiedCall, _: Instant) -> Result<TargetCredential> {
        panic!("discovery must never exchange credentials")
    }
}
struct Adapter(Option<Context>);
#[async_trait]
impl ResourceAdapter for Adapter {
    fn managed_drain_context(&self) -> Option<&Context> {
        self.0.as_ref()
    }
    async fn dispatch(&self, _: &VerifiedCall, _: &TargetCredential) -> Result<AdapterResult> {
        panic!("discovery must never dispatch")
    }
    async fn read(&self, _: &kedgeflow::gateway::Request, _: &Identity) -> Result<Value> {
        panic!("discovery must never read target")
    }
}
fn gateway(c: &Context) -> Gateway {
    let ledger = EtcdLedger::new(
        reqwest::Client::new(),
        "http://127.0.0.1:1",
        &c.selection.registration.namespace,
    )
    .unwrap();
    let ledger = c.selection.attach(ledger).unwrap();
    let t = tool(c);
    Gateway {
        verifier: verifier(c),
        ledger: Arc::new(ledger),
        auth: Arc::new(Auth),
        broker: Arc::new(Broker),
        adapter: Arc::new(Adapter(Some(c.clone()))),
        resolver: None,
        tools: BTreeMap::from([(t.name.clone(), t)]),
        timeout: Duration::from_secs(5),
        clock: Arc::new(SystemClock),
    }
}
#[tokio::test]
async fn managed_discovery_requires_actual_native_selection_and_exact_named_adapter() {
    let c = context();
    let g = gateway(&c);
    g.validate().unwrap();
    for case in [
        "no-adapter",
        "no-native-selection",
        "wrong-enrollment",
        "wrong-action",
        "predicate",
        "grant-key",
        "audience",
        "extra-tool",
    ] {
        let mut g = gateway(&c);
        match case {
            "no-adapter" => g.adapter = Arc::new(Adapter(None)),
            "no-native-selection" => {
                g.ledger = Arc::new(
                    EtcdLedger::new(
                        reqwest::Client::new(),
                        "http://127.0.0.1:1",
                        &c.selection.registration.namespace,
                    )
                    .unwrap(),
                )
            }
            "wrong-enrollment" => {
                let mut altered = c.clone();
                altered.enrollment.target_scope = "other".into();
                g.adapter = Arc::new(Adapter(Some(altered)));
            }
            "wrong-action" => {
                g.tools
                    .get_mut("drain")
                    .unwrap()
                    .action
                    .as_mut()
                    .unwrap()
                    .id = kedgeflow::kube_drain::ACTION.into()
            }
            "predicate" => g.tools.get_mut("drain").unwrap().predicate_version = "other".into(),
            "grant-key" => {
                g.verifier.keys = BTreeMap::from([(
                    "other".into(),
                    ed25519_dalek::SigningKey::from_bytes(&[203; 32]).verifying_key(),
                )])
            }
            "audience" => g.verifier.audience = "https://other.test/execute".into(),
            "extra-tool" => {
                let mut t = tool(&c);
                t.name = "other".into();
                g.tools.insert(t.name.clone(), t);
            }
            _ => unreachable!(),
        }
        assert!(g.validate().is_err(), "{case}");
    }
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        "spiffe://test/discovery-reader".try_into().unwrap(),
    )];
    let cert = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    let workload = WorkloadIdentity::from_verified_cert_der(cert.der()).unwrap();
    let discover=g.handle(&HeaderMap::new(),&workload,&serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":kedgeflow::gateway::PROTOCOL_VERSION,"io.modelcontextprotocol/clientCapabilities":{"extensions":{}}}}})).unwrap()).await;
    assert_eq!(
        discover["result"]["capabilities"]["extensions"][managed::EXTENSION],
        json!({"profile":managed::PROFILE,"acceptance_proof_profile":kedgeflow::managed_drain_acceptance::PROFILE,"commit_point":"controller_acceptance","physical_completion":"separate_observation"})
    );
    let list=g.handle(&HeaderMap::new(),&workload,&serde_json::to_vec(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":kedgeflow::gateway::PROTOCOL_VERSION,"io.modelcontextprotocol/clientCapabilities":{"extensions":{}}}}})).unwrap()).await;
    let wire = &list["result"]["tools"][0];
    assert_eq!(
        wire["inputSchema"],
        c.enrollment.schema(&c.physical.contract).unwrap()
    );
    assert_eq!(
        wire["_meta"][managed::EXTENSION],
        json!({"profile":managed::PROFILE,"acceptance_proof_profile":kedgeflow::managed_drain_acceptance::PROFILE,
        "enrollment_digest":c.enrollment.digest().unwrap(),"policy_digest":c.enrollment.policy.digest().unwrap(),"family_registration_digest":c.selection.registration.digest().unwrap(),
        "child_id":c.selection.child_id,"operation_key":c.enrollment.operation_key,"contract_digest":c.physical.contract.digest().unwrap(),"commit_point":"controller_acceptance","physical_completion":"separate_observation"})
    );
}

#[test]
fn standalone_acceptance_verifier_replays_original_sources_and_refuses_omissions() {
    use kedgeflow::{contracts::canonical, managed_drain_audit::Bundle};
    let mut bundle: Bundle = serde_json::from_str(include_str!("../../../results/verification/rfc-m8-managed-controller-2026-10-27/native-artifacts/managed-controller-completed/bundle.json")).unwrap();
    let c = context();
    let kedgeflow::managed_drain_store::Material::Aggregate(aggregate) =
        &bundle.evidence.materials[&bundle.evidence.current_aggregate_digest]
    else {
        panic!("aggregate")
    };
    let member = &aggregate.evidence.current.snapshot.members[&c.selection.child_id];
    let authorization = member.authorizations[&c.enrollment.operation_key].clone();
    let accepted = member
        .physical
        .as_ref()
        .unwrap()
        .controller
        .as_ref()
        .unwrap()
        .body
        .accepted
        .clone();
    let s = &mut bundle.evidence.source;
    let (key, control) = s
        .controls
        .iter()
        .find(|(_, p)| p.body.kind == kedgeflow::managed_drain_evidence::ControlKind::Accepted)
        .map(|(k, p)| (k.clone(), p.clone()))
        .unwrap();
    let end = s.events.iter().position(|e| matches!(&e.change,kedgeflow::managed_drain_journal::Change::ControllerAccepted {proof_digest} if proof_digest == &key)).unwrap()+1;
    s.events.truncate(end);
    let heads = s
        .events
        .iter()
        .map(|e| e.digest().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    s.claims
        .retain(|_, claim| heads.contains(&claim.operating_head_digest));
    s.controls.retain(|k, _| k == &key);
    let mut mechanical = json!(control.body.mechanical_header);
    mechanical["body"] = json!({"accepted":accepted,"steps":[],"closed":null});
    let acceptance = json!({"profile":managed::PROFILE,"enrollment_digest":c.enrollment.digest().unwrap(),"origin":s.origin,"events":s.events,"controller":mechanical,"proof":control});
    let proof = json!({"profile":kedgeflow::managed_drain_acceptance::PROFILE,"enrollment_digest":c.enrollment.digest().unwrap(),"authorization":authorization,"acceptance":acceptance,"sources":s});
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("acceptance.json");
    let trust = directory.path().join("trust.json");
    std::fs::write(
        &trust,
        canonical(&json!({"profile":managed::PROFILE,"selection":c.selection})).unwrap(),
    )
    .unwrap();
    let invoke = |value: &Value| {
        std::fs::write(&path, canonical(value).unwrap()).unwrap();
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-managed-drain-acceptance"))
            .arg("--proof")
            .arg(&path)
            .arg("--trust")
            .arg(&trust)
            .output()
            .unwrap()
    };
    let output = invoke(&proof);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verified: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verified["complete_acceptance_sources"], true);
    assert_eq!(verified["native_history_verified"], false);
    assert_eq!(verified["execution_authority"], false);
    assert_eq!(verified["physical_status"], "unresolved");
    for case in [
        "missing-claim",
        "unknown-source-field",
        "wrong-context",
        "altered-admission",
    ] {
        let mut bad = proof.clone();
        match case {
            "missing-claim" => bad["sources"]["claims"] = json!({}),
            "unknown-source-field" => bad["sources"]["target_selected_trust"] = json!(true),
            "wrong-context" => bad["enrollment_digest"] = json!("a".repeat(64)),
            "altered-admission" => bad["authorization"]["packet"]["witnesses"] = json!([]),
            _ => unreachable!(),
        }
        let output = invoke(&bad);
        assert!(!output.status.success(), "{case}");
        assert!(output.stdout.is_empty(), "{case}");
    }
}
