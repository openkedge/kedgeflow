//! Synthetic identity/broker boundaries for dispatch tests; cryptographic
//! authentication and actual HTTPS clients are checked by separate suites.
use ed25519_dalek::SigningKey;
use kedgeflow::{
    auth::Identity,
    contracts::{Grant, GrantVerifier, digest, sign_grant},
    gateway::{CallParams, MCP_PROFILE, PROTOCOL_VERSION, Request, ToolDescriptor, VerifiedCall},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
pub const NOW: i64 = 1_800_000_000_000;
pub fn call() -> (VerifiedCall, GrantVerifier) {
    let mut g: Grant =
        serde_json::from_value(
            serde_json::from_str::<Value>(include_str!("../../../../fixtures/grant.json")).unwrap()
                ["payload"]
                .clone(),
        )
        .unwrap();
    g.issued_at = NOW;
    g.valid_from = NOW;
    g.expires_at = NOW + 60000;
    g.workload_id = "spiffe://test/agent".into();
    g.saga_budget = Value::Null;
    g.parent_grant_digest = None;
    g.completion_mode = "dispatch_bound".into();
    g.adapter_contract["guard_primitive"] = json!("FencingToken");
    g.adapter_contract["completion_mode"] = json!("dispatch_bound");
    g.adapter_contract["idempotency"]["parameter"] = json!("kf_attempt_id");
    g.predicate_descriptor["clauses"][0]["expected_version"] = json!("1");
    let arguments = json!({"node":g.resources[0].id,"expected_version":1});
    g.parameters_digest = digest("parameters", &arguments).unwrap();
    let identity = Identity {
        subject: g.subject.clone(),
        workload_id: g.workload_id.clone(),
        dpop_jkt: g.dpop_jkt.clone(),
        delegation_digest: g.delegation_digest.clone(),
        access_token: "caller-token-never-forward".into(),
        scopes: BTreeSet::from(["mutate".into(), "read".into(), "kf.status".into()]),
    };
    let tool = ToolDescriptor {
        inverse_contract: None,
        name: "node_drain".into(),
        read_only: false,
        required_scope: "mutate".into(),
        status_scope: "kf.status".into(),
        action: Some(g.action.clone()),
        resource: Some(g.resources[0].clone()),
        conflict_domain: g.conflict_domain.clone(),
        adapter_contract: g.adapter_contract.clone(),
        predicate_id: g.predicate_descriptor["id"].as_str().unwrap().into(),
        predicate_version: "1.0".into(),
        version_parameter: "expected_version".into(),
        fence_parameter: "fence".into(),
        admission_endpoint: "https://admission.test/admit".into(),
    };
    let meta = BTreeMap::from([
        (
            "io.modelcontextprotocol/protocolVersion".into(),
            json!(PROTOCOL_VERSION),
        ),
        (
            "io.modelcontextprotocol/clientCapabilities".into(),
            json!({"extensions":{"io.kedgeflow/governed-mcp":{"profile":MCP_PROFILE},
            "io.kedgeflow/grant-reference":{"profile":"KF-GRANT-REF-0.1"}}}),
        ),
    ]);
    let request = Request {
        jsonrpc: "2.0".into(),
        id: json!(1),
        method: "tools/call".into(),
        params: CallParams {
            name: tool.name.clone(),
            arguments,
            meta,
        },
    };
    let key = SigningKey::from_bytes(&[6; 32]);
    let signed = sign_grant(&g, "test-key", &key).unwrap();
    let verifier = GrantVerifier {
        keys: BTreeMap::from([("test-key".into(), key.verifying_key())]),
        audience: g.audience.clone(),
    };
    let digest = verifier.verify(&signed, NOW).unwrap().digest;
    (
        VerifiedCall {
            request,
            grant: g,
            identity,
            attempt_id: "attempt-transport".into(),
            descriptor: tool,
            grant_digest: digest,
            signed_grant: signed,
        },
        verifier,
    )
}
