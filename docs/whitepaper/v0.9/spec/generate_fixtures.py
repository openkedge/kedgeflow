"""Create reproducible signed OFFLINE TEST fixtures, never deployment credentials."""
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import yaml
from build_schema import BASE, KINDS
from profile import b64, domain, hash_value, jcs, proposal_digest, record_digest, signing_bytes

OUT = Path(__file__).with_name("examples")
OUT.mkdir(exist_ok=True)
NOW = 1791043200000  # 2026-10-03T16:00:00Z, deterministic fixture clock.
EXP = NOW + 60000
SUBJECT = {"iss": "https://login.example.org/tenant-42/v2.0", "sub": "user-73a38d"}
WORKLOAD = "spiffe://example.org/ns/agents/sa/planner"
KEYS = {}
REGISTRY = {}


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def put(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def test_key(role):
    kid = "urn:kf:key:example:" + role + ":test-v1"
    if kid not in KEYS:
        KEYS[kid] = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("PUBLIC OFFLINE TEST SEED: " + kid).encode()).digest())
        REGISTRY[kid] = {"kty": "OKP", "crv": "Ed25519", "x": b64(KEYS[kid].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
                         "authorized_role": role, "test_only": True}
    return kid, KEYS[kid]


def jwt(header, claims, private_key):
    encoded = b64(jcs(header)) + "." + b64(jcs(claims))
    return encoded + "." + b64(private_key.sign(encoded.encode("ascii")))


def sign(kind, payload, role):
    kid, key = test_key(role)
    envelope = {"profile": "KF-JSON-0.2", "kind": kind, "schema": BASE + "#/$defs/" + KINDS[kind],
                "key_id": kid, "payload": payload}
    envelope["signature"] = b64(key.sign(signing_bytes(envelope)))
    put(kind + ".json", envelope)
    return envelope


def record_ref(envelope, rid):
    return {"id": rid, "schema": envelope["schema"], "digest": record_digest(envelope)}


def external_ref(rid, name):
    return {"id": rid, "schema": "urn:kedgeflow:test:" + name + ":1.0", "digest": digest(name + ":" + rid)}


RESOURCE = {"id": "tenant-42:orders-db:capacity-west", "incarnation": "db-2026-09-01"}
POLICY = {"id": "tenant-42:policy:capacity", "epoch": 17, "digest": digest("capacity-policy-epoch-17")}
PREDICATE = {"id": "tenant-42:predicate:capacity-version", "version": "1.0", "language": "kf-conjunction-v1",
             "clauses": [{"kind": "version_eq", "resource": RESOURCE, "expected_version": "241"}]}
ADAPTER = {"level": "Level_A", "guard_primitive": "SQL_CAS", "fence_parameter": "fence", "guard_scope": [RESOURCE["id"]],
           "completion_mode": "commit_bound", "commit_point": "orders-db serializable reservation transaction commit",
           "idempotency": {"mode": "resource_key", "parameter": "operation_id", "retention_ms": 86400000}}
PARAMETERS = {"order_id": "ord-9042", "operation_id": "reserve-ord-9042", "slots": 1}
PARAMETER_SCHEMA = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                    "properties": {"order_id": {"type": "string", "minLength": 1}, "operation_id": {"type": "string", "minLength": 1},
                                   "slots": {"type": "integer", "minimum": 1, "maximum": 1}},
                    "required": ["order_id", "operation_id", "slots"], "additionalProperties": False}
PARAMETER_SCHEMA_DIGEST = hash_value("parameter-schema", PARAMETER_SCHEMA)
TEMPLATE = "Reserve {{ slots }} capacity slot for order {{ order_id }}. Operation: {{ operation_id }}."
TEMPLATE_DIGEST = hashlib.sha256(TEMPLATE.encode()).hexdigest()
RENDERED = "Reserve 1 capacity slot for order ord-9042. Operation: reserve-ord-9042."
RENDERED_DIGEST = hashlib.sha256(RENDERED.encode()).hexdigest()
COMPENSATION_ACTION = {"id": "tenant-42:action:capacity.release", "version": "1.0", "digest": digest("registered-capacity-release-v1")}
COMPENSATION = {"action": COMPENSATION_ACTION, "trigger": "confirmed_partial_commit", "deadline_ms": 300000,
                "max_budget_units": 1, "preauthorization_required": True,
                "semantics": "Release the confirmed reservation if it remains unused; release cannot reverse downstream fulfillment."}
CTD = sign("ctd", {"ctd_version": "1.0", "id": "tenant-42:ctd:capacity.reserve", "version": "1.0", "tenant": "tenant-42",
    "action": "tenant-42:action:capacity.reserve", "parameter_schema": PARAMETER_SCHEMA,
    "parameter_schema_digest": PARAMETER_SCHEMA_DIGEST,
    "rendering": {"id": "tenant-42:render:capacity.reserve", "version": "1.0", "media_type": "text/plain",
                  "template_digest": TEMPLATE_DIGEST, "parameter_schema_digest": PARAMETER_SCHEMA_DIGEST, "locale": "en-US"},
    "consequence_tier": "StateMutating", "consequence_tier_number": 2,
    "consequence_description": "Consumes one shared capacity slot in the orders database; safe admission requires a transaction over all slot writers.",
    "adapter_contract": ADAPTER, "concurrency": {"conflict_domain": "tenant-42:capacity:west", "predicate_descriptor": PREDICATE,
        "coverage": {"coordinated_writers": ["tenant-42:writer:sql-reservation-adapter"], "uncoordinated_writers": [],
                     "inventory_digest": digest("only-registered-capacity-writer")}},
    "compensation": COMPENSATION, "compensation_unavailable_reason": None, "ownership_epoch": 5,
    "gateway_audience": "https://gateway.example.org/execute"}, "ResourceRegistry")
ACTION = {"id": CTD["payload"]["action"], "version": "1.0", "digest": record_digest(CTD)}
PROOF_KID, PROOF_KEY = test_key("DPoPProofKey")
PROOF_JWK = {name: REGISTRY[PROOF_KID][name] for name in ("kty", "crv", "x")}
JKT = b64(hashlib.sha256(jcs(PROOF_JWK)).digest())
TOKEN_KID, TOKEN_KEY = test_key("OAuthAuthorizationServer")
ACCESS_TOKEN = jwt({"typ": "at+jwt", "alg": "EdDSA", "kid": TOKEN_KID},
    {"iss": SUBJECT["iss"], "sub": SUBJECT["sub"], "aud": "https://admission.example.org",
     "iat": NOW // 1000, "exp": (NOW + 300000) // 1000, "jti": "test-delegation-reserve-9042",
     "client_id": "kedgeflow-agent-adapter-test", "scope": "capacity.reserve", "cnf": {"jkt": JKT}}, TOKEN_KEY)
DELEGATION = {"access_token_digest": hashlib.sha256(ACCESS_TOKEN.encode("ascii")).hexdigest(), "dpop_jkt": JKT,
              "authorization_server": SUBJECT["iss"], "token_audience": "https://admission.example.org",
              "scopes": ["capacity.reserve"], "expires_at": NOW + 300000}
DPOP_PROOF = jwt({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": PROOF_JWK},
    {"jti": "test-proof-reserve-9042", "htm": "POST", "htu": "https://admission.example.org/v0.9/propose",
     "iat": NOW // 1000, "ath": b64(hashlib.sha256(ACCESS_TOKEN.encode("ascii")).digest()), "nonce": "test-server-nonce-9042"}, PROOF_KEY)
(OUT / "access-token.jwt").write_text(ACCESS_TOKEN)
(OUT / "dpop-proof.jwt").write_text(DPOP_PROOF)
put("dpop-public-test-key.json", PROOF_JWK)
Q = sign("proposal", {"qid": "tenant-42:q:reserve-ord-9042", "tenant": "tenant-42", "subject": SUBJECT,
    "workload_id": WORKLOAD, "delegation": DELEGATION, "intent": "Reserve one slot before fulfilling order ord-9042.",
    "action": ACTION, "resources": [RESOURCE], "parameters": PARAMETERS, "dependencies": [],
    "baseline_state": [{"resource": RESOURCE, "version": "241", "state_digest": digest("capacity=3;version=241"),
                         "observed_at": NOW, "expires_at": EXP}], "requested_completion": "commit_bound", "created_at": NOW,
    "workflow": {"saga_root_id": "tenant-42:saga:fulfill-ord-9042", "saga_generation": 1,
                 "node_id": "reserve", "allocation_id": "reserve-allocation", "phase": "forward"}}, "AgentAdapter")
QD = proposal_digest(Q)
DD = hash_value("delegation", DELEGATION)
PD = hash_value("parameters", PARAMETERS)
QUESTION = external_ref("tenant-42:question:capacity", "capacity-question")
W = sign("evidence", {"wid": "tenant-42:w:capacity-241", "provider_id": "tenant-42:provider:sql-observer",
    "provider_version": "1.0", "question_ref": QUESTION, "proposal_digest": QD, "state_scope": [RESOURCE],
    "state_digest": digest("capacity=3;version=241"), "result_schema": external_ref("tenant-42:result:capacity", "capacity-result"),
    "result": {"available_slots": 3, "minimum_after": 2, "version": "241", "satisfied": True},
    "observed_at": NOW, "expires_at": EXP, "provenance_refs": [], "exposure_domains": ["tenant-42:orders-db"]}, "EvidenceProvider")
APPROVAL = {"proposal_digest": QD, "policy_epoch": 17, "reviewer": SUBJECT, "rendering_template_digest": TEMPLATE_DIGEST,
    "rendered_digest": RENDERED_DIGEST, "parameters_digest": PD,
    "reviewed_at": NOW + 2000, "expires_at": EXP, "verdict": "approve", "nonce": b64(b"approval-reserve-ord-9042-unique"), "rp_id": "review.example.org"}
HITL = sign("hitl_witness", {"wid": "tenant-42:w:human-approval", "subject": SUBJECT, "approval": APPROVAL,
    "challenge_digest": hashlib.sha256(jcs(APPROVAL)).hexdigest(), "rp_id": "review.example.org", "origin": "https://review.example.org",
    "credential_id": b64(b"offline-webauthn-emulator-credential"), "user_present": True, "user_verified": True,
    "authenticator_policy": {"policy_ref": external_ref("tenant-42:test-policy:webauthn", "offline-emulator-policy"),
        "enrollment_ref": external_ref("tenant-42:test-enrollment:user-73a38d", "offline-emulator-enrollment"),
        "hardware_bound_required": False, "attestation_required": False, "approved_authenticator": True},
    "assertion_ref": external_ref("tenant-42:test-assertion:approval", "offline-emulator-assertion"),
    "assertion_digest": digest("offline-emulator-assertion-not-hardware-evidence"), "sign_count": 1,
    "verification_result": "verified", "verified_at": NOW + 2001, "expires_at": EXP,
    "provider_id": "tenant-42:provider:offline-webauthn-emulator"}, "EvidenceProvider")
MANIFEST = sign("manifest", {"mid": "tenant-42:manifest:reserve", "proposal_digest": QD, "policy": POLICY,
    "witnesses": [{"witness": record_ref(W, W["payload"]["wid"]), "obligation_id": "capacity", "execution_relevant": True, "expires_at": EXP},
                  {"witness": record_ref(HITL, HITL["payload"]["wid"]), "obligation_id": "review", "execution_relevant": False, "expires_at": EXP}],
    "assembled_at": NOW + 2002}, "AdmissionController")
STATIC = {"obligation_id": "identity", "predicate_digest": digest("validated-human-workload-delegation"),
          "witness_refs": [external_ref("tenant-42:w:identity", "identity-verification")], "result": "satisfied", "stage": "static",
          "execution_relevant": False, "observed_at": NOW, "expires_at": NOW + 300000}
LEASE = sign("lease", {"lid": "tenant-42:lease:reserve", "proposal_digest": QD, "delegation_digest": DD, "subject": SUBJECT,
    "workload_id": WORKLOAD, "policy": POLICY, "descriptor_digest": record_digest(CTD), "ownership_epoch": 5,
    "static_discharges": [STATIC], "pending_jit_obligations": ["capacity"], "issued_at": NOW + 1000,
    "expires_at": EXP, "execution_authority": False}, "AdmissionController")
BUDGET = {"saga_root_id": "tenant-42:saga:fulfill-ord-9042", "saga_generation": 1, "allocation_id": "reserve-allocation", "phase": "forward", "units": 1}
CONSTRAINTS = {"action": ACTION, "resources": [RESOURCE], "parameters_digest": PD, "predicate_descriptor": PREDICATE,
    "adapter_contract": ADAPTER, "audience": "https://gateway.example.org/execute", "max_attempts": 1, "expires_at": EXP, "saga_budget": BUDGET}
CAPACITY_DISCHARGE = {"obligation_id": "capacity", "predicate_digest": hash_value("predicate", PREDICATE),
    "witness_refs": [record_ref(W, W["payload"]["wid"])], "result": "satisfied", "stage": "jit",
    "execution_relevant": True, "observed_at": NOW, "expires_at": EXP}
REVIEW_DISCHARGE = {"obligation_id": "review", "predicate_digest": digest("test-approval-no-hardware-policy"),
    "witness_refs": [record_ref(HITL, HITL["payload"]["wid"])], "result": "satisfied", "stage": "static",
    "execution_relevant": False, "observed_at": NOW + 2001, "expires_at": EXP}
C = sign("certificate", {"cid": "tenant-42:c:reserve", "proposal_digest": QD, "delegation_digest": DD,
    "subject": SUBJECT, "workload_id": WORKLOAD, "policy": POLICY, "ownership_epoch": 5,
    "descriptor_digest": record_digest(CTD), "obligation_manifest_digest": digest("identity-capacity-review-obligations"),
    "evidence_manifest_digest": record_digest(MANIFEST), "discharges": [STATIC, CAPACITY_DISCHARGE, REVIEW_DISCHARGE],
    "constraints": CONSTRAINTS, "constraint_digest": hash_value("constraints", CONSTRAINTS),
    "lease_digest": record_digest(LEASE), "admitted_at": NOW + 3000, "expires_at": EXP}, "AdmissionController")
G = sign("grant", {"gid": "tenant-42:g:reserve", "proposal_digest": QD, "certificate_digest": record_digest(C),
    "delegation_digest": DD, "subject": SUBJECT, "workload_id": WORKLOAD, "dpop_jkt": DELEGATION["dpop_jkt"],
    "action": ACTION, "resources": [RESOURCE], "parameters_digest": PD, "policy": POLICY,
    "evidence_manifest_digest": record_digest(MANIFEST), "constraint_digest": C["payload"]["constraint_digest"],
    "ownership_epoch": 5, "predicate_descriptor": PREDICATE, "adapter_contract": ADAPTER,
    "root_id": "tenant-42:root:reserve-ord-9042", "root_generation": 1, "parent_grant_digest": None,
    "saga_budget": BUDGET, "conflict_domain": "tenant-42:capacity:west", "nonce": b64(b"grant-reserve-ord-9042-single-use"),
    "fence": 812, "audience": "https://gateway.example.org/execute", "issued_at": NOW + 3001,
    "valid_from": NOW + 3001, "expires_at": EXP, "completion_mode": "commit_bound"}, "GrantAuthority")
SAGA = sign("saga_root", {"root_id": BUDGET["saga_root_id"], "root_generation": 1, "tenant": "tenant-42", "subject": SUBJECT,
    "workload_id": WORKLOAD, "ownership_epoch": 5, "policy": POLICY, "dag_digest": digest("reserve->fulfill"),
    "nodes": [{"node_id": "reserve", "action": ACTION, "depends_on": [], "allocation_id": "reserve-allocation", "compensation": COMPENSATION},
              {"node_id": "fulfill", "action": {"id": "tenant-42:action:fulfill", "version": "1.0", "digest": digest("fulfill-action-v1")},
               "depends_on": ["reserve"], "allocation_id": "fulfill-allocation", "compensation": None}],
    "allocations": [{"allocation_id": "reserve-allocation", "node_id": "reserve", "child_root_id": G["payload"]["root_id"],
                     "forward_units": 1, "compensation_units": 1, "state": "reserved"},
                    {"allocation_id": "fulfill-allocation", "node_id": "fulfill", "child_root_id": "tenant-42:root:fulfill-ord-9042",
                     "forward_units": 1, "compensation_units": 0, "state": "reserved"}],
    "budget": {"unit": "mutation", "forward_limit": 2, "compensation_reserve": 1, "forward_consumed": 0, "compensation_consumed": 0},
    "status": "active", "created_at": NOW, "expires_at": NOW + 300000, "compensation_deadline": NOW + 600000}, "GrantAuthority")
REMEDIATION = sign("remediation", {"remediation_id": "tenant-42:remediation:reserve", "code": "NEEDS_EVIDENCE", "proposal_digest": QD,
    "action": ACTION, "parameters_digest": PD,
    "obligations": [{"obligation_id": "capacity", "kind": "state", "stage": "jit", "accepted_provider_classes": ["tenant-42:provider-class:sql-observer"],
                     "question_ref": QUESTION, "max_age_ms": 60000, "instruction": "Observe shared capacity and bind its current version to this exact proposal."}],
    "admission_endpoint": "https://admission.example.org/v0.9/propose", "profile": "KF-JSON-0.2",
    "grant_carriage": "Mcp-KedgeFlow-Grant", "expires_at": EXP, "retry_after_admission": True}, "ExecutionGateway")
sign("receipt", {"rid": "tenant-42:receipt:reserve-committed", "proposal_digest": QD, "certificate_digest": record_digest(C),
    "grant_digest": record_digest(G), "root_id": G["payload"]["root_id"], "root_generation": 1,
    "attempt_id": "tenant-42:attempt:reserve-001", "source_id": "tenant-42:adapter:sql-reservation", "source_role": "ResourceAdapter",
    "event_time": NOW + 4000, "status": "committed", "resource_operation_id": PARAMETERS["operation_id"], "observed_version": "242",
    "effect_digest": PD, "error_code": None, "previous_receipt_digest": None, "resolution_evidence": [], "fence": 812,
    "saga_budget": BUDGET}, "ResourceAdapter")
sign("delegation", {"parent_gid": G["payload"]["gid"], "parent_grant_digest": record_digest(G),
    "parent_root_id": G["payload"]["root_id"], "parent_root_generation": 1,
    "child_certificate": external_ref("tenant-42:c:child-review", "child-admission-certificate"), "allocation": BUDGET,
    "requested_audience": G["payload"]["audience"], "requested_expires_at": EXP}, "AgentAdapter")
sign("token_exchange", {"grant_digest": record_digest(G), "attempt_id": "tenant-42:attempt:reserve-001",
    "token_endpoint": "https://sts.example.org/oauth/token", "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token", "subject_token_digest": DELEGATION["access_token_digest"],
    "actor_token_type": "urn:ietf:params:oauth:token-type:jwt", "actor_token_digest": digest("gateway-audience-jwt-svid-test-reference"),
    "resource": "https://orders-db.example.org", "audience": "https://orders-db.example.org", "scopes": ["capacity.reserve"],
    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token", "issued_token_digest": digest("narrow-db-token-test-reference"),
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer", "issued_at": NOW + 3500, "expires_at": EXP}, "ExecutionGateway")
put("public-test-keys.json", REGISTRY)
put("fixture-digests.json", {kind: record_digest(json.loads((OUT / (kind + ".json")).read_text())) for kind in KINDS})
(OUT / "ctd.yaml").write_text(yaml.safe_dump(CTD["payload"], sort_keys=False))
put("a2a-root-reference.json", {"type": "urn:kedgeflow:root-reference:1.0", "root_id": SAGA["payload"]["root_id"],
    "root_generation": 1, "delegation_id": "tenant-42:delegation:fulfill-check", "assurance_profile": "order-fulfillment-v1",
    "cryptographic_profile": "KF-JSON-0.2", "authority_endpoint": "https://control.example.org/kedgeflow/v0.9", "saga_budget": BUDGET})
(OUT / "capacity-review-template.txt").write_text(TEMPLATE)
(OUT / "capacity-review-rendered.txt").write_text(RENDERED)
print(f"Wrote {len(KINDS)} signed test envelopes, test keys, digests, and rendering template.")
