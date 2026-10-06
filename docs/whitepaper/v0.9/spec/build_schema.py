"""Generate the complete proposed KF-JSON-0.2 record schema; no external deps."""
import json
from pathlib import Path

BASE = "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json"
MAX = 9007199254740991


def ref(name):
    return {"$ref": f"#/$defs/{name}"}


def obj(properties, description=None, required=None):
    result = {"type": "object", "properties": properties,
              "required": list(properties) if required is None else required,
              "additionalProperties": False}
    if description:
        result["description"] = description
    return result


def array(items, minimum=0, unique=False):
    result = {"type": "array", "items": items, "minItems": minimum}
    if unique:
        result["uniqueItems"] = True
    return result


def nullable(value):
    return {"anyOf": [value, {"type": "null"}]}


def enum(*values):
    return {"enum": list(values)}


def text(minimum=1):
    return {"type": "string", "minLength": minimum}


def integer(minimum=0):
    return {"type": "integer", "minimum": minimum, "maximum": MAX}


D = {}
D["Id"] = {"type": "string", "minLength": 1, "maxLength": 512,
           "pattern": r"^[A-Za-z0-9][A-Za-z0-9:._/@-]*$"}
D["Digest"] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
D["Base64Url"] = {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"}
D["JwkThumbprint"] = {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$",
                      "description": "Unpadded base64url SHA-256 RFC7638 public-JWK thumbprint."}
D["Ed25519Signature"] = {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
D["Uri"] = {"type": "string", "format": "uri", "minLength": 1}
D["HttpsUri"] = {"type": "string", "format": "uri", "pattern": r"^https://[^/#?]+(?:/[^#]*)?$"}
D["SpiffeId"] = {"type": "string", "format": "uri",
                 "pattern": r"^spiffe://[a-z0-9.-]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$",
                 "description": "SPIFFE workload identity; apply the SPIFFE ID specification's further path and trust-domain validation."}
D["Time"] = {**integer(), "description": "UTC milliseconds since Unix epoch; JSON safe integer."}
D["Epoch"] = integer()
D["Version"] = {"type": "string", "pattern": r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$"}
D["JsonValue"] = {"description": "Application data extension boundary. Numbers are safe integers; decimal quantities use schema-defined strings. A registered closed parameter/result schema MUST also validate this value.",
                  "anyOf": [{"type": "null"}, {"type": "boolean"}, text(0),
                            {"type": "integer", "minimum": -MAX, "maximum": MAX},
                            array(ref("JsonValue")),
                            {"type": "object", "additionalProperties": ref("JsonValue")}]}
D["Parameters"] = {"type": "object", "additionalProperties": ref("JsonValue"),
                   "description": "Exact resolved parameters; independently validate against the registered action parameter schema. Unknown privileged defaults are forbidden."}
D["SubjectIdentity"] = obj({"iss": ref("HttpsUri"), "sub": text()},
                           "Human identity is the OIDC issuer/subject pair, never sub alone or an email display name.")
D["ActionRef"] = obj({"id": ref("Id"), "version": ref("Version"), "digest": ref("Digest")})
D["RecordRef"] = obj({"id": ref("Id"), "schema": ref("Uri"), "digest": ref("Digest")})
D["ResourceRef"] = obj({"id": ref("Id"), "incarnation": text()})
D["PolicyRef"] = obj({"id": ref("Id"), "epoch": ref("Epoch"), "digest": ref("Digest")})
D["DelegationBinding"] = obj({"access_token_digest": ref("Digest"), "dpop_jkt": ref("JwkThumbprint"),
    "authorization_server": ref("HttpsUri"), "token_audience": ref("Uri"),
    "scopes": array(text(), 1, True), "expires_at": ref("Time")},
    "Reference to an OAuth user-delegation access token bound through cnf.jkt to a validated DPoP proof key. An OIDC ID token is not a delegation token. The signed proposal binds the body independently of DPoP.")
D["BaselineState"] = obj({"resource": ref("ResourceRef"), "version": text(),
    "state_digest": ref("Digest"), "observed_at": ref("Time"), "expires_at": ref("Time")})
D["WorkflowBinding"] = obj({"saga_root_id": ref("Id"), "saga_generation": ref("Epoch"),
    "node_id": ref("Id"), "allocation_id": ref("Id"), "phase": enum("forward", "compensation")})
D["Proposal"] = obj({"qid": ref("Id"), "tenant": ref("Id"), "subject": ref("SubjectIdentity"),
    "workload_id": ref("SpiffeId"), "delegation": ref("DelegationBinding"), "intent": text(),
    "action": ref("ActionRef"), "resources": array(ref("ResourceRef"), 1, True),
    "parameters": ref("Parameters"), "dependencies": array(ref("RecordRef"), 0, True),
    "baseline_state": array(ref("BaselineState"), 0, True),
    "requested_completion": enum("dispatch_bound", "commit_bound"), "created_at": ref("Time"),
    "workflow": nullable(ref("WorkflowBinding"))},
    "Frozen candidate request q. A proposal conveys no execution authority.")
D["VersionPredicate"] = obj({"kind": {"const": "version_eq"}, "resource": ref("ResourceRef"), "expected_version": text()})
D["ReservationPredicate"] = obj({"kind": {"const": "reservation_valid"}, "reservation_id": ref("Id"),
    "ledger": ref("Uri"), "scope": array(ref("Id"), 1, True), "epoch": ref("Epoch"), "expires_at": ref("Time")})
D["PredicateDescriptor"] = obj({"id": ref("Id"), "version": ref("Version"),
    "language": {"const": "kf-conjunction-v1"},
    "clauses": array({"oneOf": [ref("VersionPredicate"), ref("ReservationPredicate")]}, 0, True)},
    "Conjunction over the declared resource scope. Empty conjunction provides no state-invariant protection; unsupported clauses MUST fail closed.")
D["IdempotencyContract"] = obj({"mode": enum("resource_key", "none"), "parameter": nullable(text()),
    "retention_ms": integer()}, "Idempotency is orthogonal to consequence tier, guard level, and completion semantics.")
D["IdempotencyContract"]["allOf"] = [
    {"if": {"properties": {"mode": {"const": "none"}}},
     "then": {"properties": {"parameter": {"type": "null"}, "retention_ms": {"const": 0}}}},
    {"if": {"properties": {"mode": {"const": "resource_key"}}},
     "then": {"properties": {"parameter": text(), "retention_ms": integer(1)}}}]
D["AdapterContract"] = obj({"level": enum("Level_A", "Level_B", "Level_C"),
    "guard_primitive": enum("SQL_CAS", "ETag", "FencingToken", "None"),
    "fence_parameter": nullable(text()), "guard_scope": array(ref("Id"), 0, True),
    "completion_mode": enum("dispatch_bound", "commit_bound"), "commit_point": text(),
    "idempotency": ref("IdempotencyContract")},
    "Level A atomicity applies only to guard_scope and covered mutation paths; local SQL CAS cannot make downstream Kubernetes execution atomic.")
D["AdapterContract"]["allOf"] = [
    {"if": {"properties": {"level": {"const": "Level_A"}}},
     "then": {"properties": {"guard_primitive": enum("SQL_CAS", "ETag", "FencingToken"), "guard_scope": array(ref("Id"), 1, True)}}},
    {"if": {"properties": {"guard_primitive": {"const": "FencingToken"}}},
     "then": {"properties": {"fence_parameter": text()}}}]
D["BudgetReference"] = obj({"saga_root_id": ref("Id"), "saga_generation": ref("Epoch"),
    "allocation_id": ref("Id"), "phase": enum("forward", "compensation"), "units": integer(1)},
    "Atomic allocation debit in the parent composite budget. Delegation must not copy an allowance into another root.")
D["ExecutionConstraints"] = obj({"action": ref("ActionRef"), "resources": array(ref("ResourceRef"), 1, True),
    "parameters_digest": ref("Digest"), "predicate_descriptor": ref("PredicateDescriptor"),
    "adapter_contract": ref("AdapterContract"), "audience": ref("Uri"), "max_attempts": {"const": 1},
    "expires_at": ref("Time"), "saga_budget": nullable(ref("BudgetReference"))})
D["Discharge"] = obj({"obligation_id": ref("Id"), "predicate_digest": ref("Digest"),
    "witness_refs": array(ref("RecordRef"), 1, True), "result": {"const": "satisfied"},
    "stage": enum("static", "jit"), "execution_relevant": {"type": "boolean"},
    "observed_at": ref("Time"), "expires_at": ref("Time")})
D["AdmissionCertificate"] = obj({"cid": ref("Id"), "proposal_digest": ref("Digest"),
    "delegation_digest": ref("Digest"), "subject": ref("SubjectIdentity"), "workload_id": ref("SpiffeId"),
    "policy": ref("PolicyRef"), "ownership_epoch": ref("Epoch"), "descriptor_digest": ref("Digest"),
    "obligation_manifest_digest": ref("Digest"), "evidence_manifest_digest": ref("Digest"),
    "discharges": array(ref("Discharge"), 1, True), "constraints": ref("ExecutionConstraints"),
    "constraint_digest": ref("Digest"), "lease_digest": nullable(ref("Digest")),
    "admitted_at": ref("Time"), "expires_at": ref("Time")},
    "All obligations satisfied under bound policy/evidence/state; certificate is not a grant.")
D["ExecutionGrant"] = obj({"gid": ref("Id"), "proposal_digest": ref("Digest"), "certificate_digest": ref("Digest"),
    "delegation_digest": ref("Digest"), "subject": ref("SubjectIdentity"), "workload_id": ref("SpiffeId"),
    "dpop_jkt": ref("JwkThumbprint"), "action": ref("ActionRef"), "resources": array(ref("ResourceRef"), 1, True),
    "parameters_digest": ref("Digest"), "policy": ref("PolicyRef"), "evidence_manifest_digest": ref("Digest"),
    "constraint_digest": ref("Digest"), "ownership_epoch": ref("Epoch"),
    "predicate_descriptor": ref("PredicateDescriptor"), "adapter_contract": ref("AdapterContract"),
    "root_id": ref("Id"), "root_generation": ref("Epoch"), "parent_grant_digest": nullable(ref("Digest")),
    "saga_budget": nullable(ref("BudgetReference")), "conflict_domain": ref("Id"), "nonce": ref("Base64Url"),
    "fence": ref("Epoch"), "audience": ref("Uri"), "issued_at": ref("Time"), "valid_from": ref("Time"),
    "expires_at": ref("Time"), "completion_mode": enum("dispatch_bound", "commit_bound")},
    "Action-bound, audience-bound, dual-identity-bound authority. Atomic ledger claim and resource-side guards are still mandatory.")
D["RenderingContract"] = obj({"id": ref("Id"), "version": ref("Version"),
    "media_type": enum("text/plain", "text/html"), "template_digest": ref("Digest"),
    "parameter_schema_digest": ref("Digest"), "locale": {"type": "string", "pattern": "^[a-z]{2}(?:-[A-Z]{2})?$"}},
    "Immutable registry template rendering only validated canonical parameters; natural-language agent summaries cannot substitute for this view.")
D["CompensationDescriptor"] = obj({"action": ref("ActionRef"),
    "trigger": enum("confirmed_forward_failure", "confirmed_partial_commit"),
    "deadline_ms": integer(1), "max_budget_units": integer(1),
    "preauthorization_required": {"const": True}, "semantics": text()},
    "A separately admitted compensating operation. This is not a guarantee of an inverse or automatic physical rollback. Unknown effects require reconciliation before compensation.")
D["CoverageInventory"] = obj({"coordinated_writers": array(ref("Id"), 0, True),
    "uncoordinated_writers": array(ref("Id"), 0, True), "inventory_digest": ref("Digest")})
D["ConsequentialToolDescriptor"] = obj({"ctd_version": {"const": "1.0"}, "id": ref("Id"),
    "version": ref("Version"), "tenant": ref("Id"), "action": ref("Id"),
    "parameter_schema": ref("Parameters"), "parameter_schema_digest": ref("Digest"),
    "rendering": ref("RenderingContract"),
    "consequence_tier": enum("ReadOnly", "IdempotentWrite", "StateMutating", "Irreversible"),
    "consequence_tier_number": enum(0, 1, 2, 3), "consequence_description": text(),
    "adapter_contract": ref("AdapterContract"), "concurrency": obj({"conflict_domain": ref("Id"),
        "predicate_descriptor": ref("PredicateDescriptor"), "coverage": ref("CoverageInventory")}),
    "compensation": nullable(ref("CompensationDescriptor")), "compensation_unavailable_reason": nullable(text()),
    "ownership_epoch": ref("Epoch"), "gateway_audience": ref("Uri")},
    "Proposed CTD v1.0 classification. A consequence-tier label is not a safety, idempotency, guard, or completeness guarantee. Inline parameter_schema is separately validated as JSON Schema Draft 2020-12.")
D["ConsequentialToolDescriptor"]["allOf"] = [
    {"if": {"properties": {"consequence_tier": {"const": label}}},
     "then": {"properties": {"consequence_tier_number": {"const": tier}}}}
    for tier, label in enumerate(["ReadOnly", "IdempotentWrite", "StateMutating", "Irreversible"])
] + [{"if": {"properties": {"compensation": {"type": "null"}}},
      "then": {"properties": {"compensation_unavailable_reason": text()}},
      "else": {"properties": {"compensation_unavailable_reason": {"type": "null"}}}}]
D["ApprovalPayload"] = obj({"proposal_digest": ref("Digest"), "policy_epoch": ref("Epoch"),
    "reviewer": ref("SubjectIdentity"), "rendering_template_digest": ref("Digest"),
    "rendered_digest": ref("Digest"), "parameters_digest": ref("Digest"),
    "reviewed_at": ref("Time"), "expires_at": ref("Time"), "verdict": enum("approve", "reject"),
    "nonce": ref("Base64Url"), "rp_id": text()},
    "Server constructs this exact payload. WebAuthn challenge is base64url(SHA256(JCS(payload))); authenticator signs authData plus SHA256(clientDataJSON), not this JSON directly.")
D["AuthenticatorPolicy"] = obj({"policy_ref": ref("RecordRef"), "enrollment_ref": ref("RecordRef"),
    "hardware_bound_required": {"type": "boolean"}, "attestation_required": {"type": "boolean"},
    "approved_authenticator": {"const": True}},
    "User verification alone does not establish hardware binding; verifier applies approved enrollment/attestation policy.")
D["HitlWitness"] = obj({"wid": ref("Id"), "subject": ref("SubjectIdentity"),
    "approval": ref("ApprovalPayload"), "challenge_digest": ref("Digest"),
    "rp_id": text(), "origin": ref("HttpsUri"), "credential_id": ref("Base64Url"),
    "user_present": {"const": True}, "user_verified": {"const": True},
    "authenticator_policy": ref("AuthenticatorPolicy"), "assertion_ref": ref("RecordRef"),
    "assertion_digest": ref("Digest"), "sign_count": integer(), "verification_result": {"const": "verified"},
    "verified_at": ref("Time"), "expires_at": ref("Time"), "provider_id": ref("Id")},
    "Provider-signed verified assertion record W_hitl. Subject is the reviewer and must equal approval.reviewer. Admission verifies provider trust and exact q/policy/rendering bindings. Fixture provider is an offline test emulator, not evidence of a hardware ceremony.")
D["Evidence"] = obj({"wid": ref("Id"), "provider_id": ref("Id"), "provider_version": ref("Version"),
    "question_ref": ref("RecordRef"), "proposal_digest": ref("Digest"),
    "state_scope": array(ref("ResourceRef"), 0, True), "state_digest": ref("Digest"),
    "result_schema": ref("RecordRef"), "result": ref("Parameters"),
    "observed_at": ref("Time"), "expires_at": ref("Time"), "provenance_refs": array(ref("RecordRef"), 0, True),
    "exposure_domains": array(ref("Id"), 1, True)})
D["WitnessEntry"] = obj({"witness": ref("RecordRef"), "obligation_id": ref("Id"),
    "execution_relevant": {"type": "boolean"}, "expires_at": ref("Time")})
D["WitnessManifest"] = obj({"mid": ref("Id"), "proposal_digest": ref("Digest"), "policy": ref("PolicyRef"),
    "witnesses": array(ref("WitnessEntry"), 1, True), "assembled_at": ref("Time")})
D["AdmissionLease"] = obj({"lid": ref("Id"), "proposal_digest": ref("Digest"),
    "delegation_digest": ref("Digest"), "subject": ref("SubjectIdentity"), "workload_id": ref("SpiffeId"),
    "policy": ref("PolicyRef"), "descriptor_digest": ref("Digest"), "ownership_epoch": ref("Epoch"),
    "static_discharges": array(ref("Discharge"), 1, True), "pending_jit_obligations": array(ref("Id"), 1, True),
    "issued_at": ref("Time"), "expires_at": ref("Time"), "execution_authority": {"const": False}},
    "Provisional static validation only; leases neither reserve target capacity nor authorize execution.")
D["Allocation"] = obj({"allocation_id": ref("Id"), "node_id": ref("Id"), "child_root_id": ref("Id"),
    "forward_units": integer(), "compensation_units": integer(),
    "state": enum("reserved", "claimed", "committed", "unknown", "fenced_no_effect", "compensated", "failed", "compensation_failed")})
D["SagaNode"] = obj({"node_id": ref("Id"), "action": ref("ActionRef"),
    "depends_on": array(ref("Id"), 0, True), "allocation_id": ref("Id"),
    "compensation": nullable(ref("CompensationDescriptor"))})
D["SagaExecutionRoot"] = obj({"root_id": ref("Id"), "root_generation": ref("Epoch"),
    "tenant": ref("Id"), "subject": ref("SubjectIdentity"), "workload_id": ref("SpiffeId"),
    "ownership_epoch": ref("Epoch"), "policy": ref("PolicyRef"), "dag_digest": ref("Digest"),
    "nodes": array(ref("SagaNode"), 1, True), "allocations": array(ref("Allocation"), 1, True),
    "budget": obj({"unit": enum("mutation", "usd_micros", "resource_slot"),
        "forward_limit": integer(1), "compensation_reserve": integer(),
        "forward_consumed": integer(), "compensation_consumed": integer()}),
    "status": enum("active", "reconciling", "compensating", "completed", "compensated", "compensation_failed", "unresolved", "failed", "manual_intervention"),
    "created_at": ref("Time"), "expires_at": ref("Time"), "compensation_deadline": ref("Time")},
    "Parent composite authority ledger root. Per-node child effect roots and forward/compensation allocations conserve budget; DAG acyclicity, sums, and atomic transitions are semantic checks.")
D["ObligationRequirement"] = obj({"obligation_id": ref("Id"),
    "kind": enum("identity", "policy", "state", "human_approval", "reservation"),
    "stage": enum("static", "jit"), "accepted_provider_classes": array(ref("Id"), 1, True),
    "question_ref": ref("RecordRef"), "max_age_ms": integer(), "instruction": text()})
D["RemediationContract"] = obj({"remediation_id": ref("Id"), "code": {"const": "NEEDS_EVIDENCE"},
    "proposal_digest": nullable(ref("Digest")), "action": ref("ActionRef"), "parameters_digest": ref("Digest"),
    "obligations": array(ref("ObligationRequirement"), 1, True), "admission_endpoint": ref("HttpsUri"),
    "profile": {"const": "KF-JSON-0.2"}, "grant_carriage": {"const": "Mcp-KedgeFlow-Grant"},
    "expires_at": ref("Time"), "retry_after_admission": {"const": True}},
    "KedgeFlow deployment convention inside MCP JSON-RPC error.data for application code -32001; it is not an MCP-standard grant extension.")
D["Receipt"] = obj({"rid": ref("Id"), "proposal_digest": ref("Digest"), "certificate_digest": ref("Digest"),
    "grant_digest": ref("Digest"), "root_id": ref("Id"), "root_generation": ref("Epoch"),
    "attempt_id": ref("Id"), "source_id": ref("Id"), "source_role": enum("ExecutionGateway", "ResourceAdapter", "OutcomeService"),
    "event_time": ref("Time"), "status": enum("claimed", "not_dispatched", "dispatched", "pending", "committed", "failed", "fenced_no_effect", "unknown", "compensated", "compensation_failed"),
    "resource_operation_id": nullable(text()), "observed_version": nullable(text()),
    "effect_digest": ref("Digest"), "error_code": nullable(enum("STATE_GUARD_VIOLATION", "OUTCOME_UNKNOWN", "REVOKED", "EXPIRED", "RESOURCE_ERROR")),
    "previous_receipt_digest": nullable(ref("Digest")), "resolution_evidence": array(ref("RecordRef"), 0, True),
    "fence": ref("Epoch"), "saga_budget": nullable(ref("BudgetReference"))})
D["Receipt"]["allOf"] = [{"if": {"properties": {"status": {"const": "fenced_no_effect"}}},
    "then": {"properties": {"resolution_evidence": array(ref("RecordRef"), 1, True)}}},
    {"if": {"properties": {"status": enum("failed", "compensation_failed", "not_dispatched")}},
     "then": {"properties": {"error_code": enum("STATE_GUARD_VIOLATION", "OUTCOME_UNKNOWN", "REVOKED", "EXPIRED", "RESOURCE_ERROR")}}}]
D["DelegationRequest"] = obj({"parent_gid": ref("Id"), "parent_grant_digest": ref("Digest"),
    "parent_root_id": ref("Id"), "parent_root_generation": ref("Epoch"),
    "child_certificate": ref("RecordRef"), "allocation": nullable(ref("BudgetReference")),
    "requested_audience": ref("Uri"), "requested_expires_at": ref("Time")},
    "delegate(gid, childCertificate) attenuation request. A single-action transfer retires parent allowance; a saga child requires an atomic existing composite allocation.")
D["TokenExchangeBinding"] = obj({"grant_digest": ref("Digest"), "attempt_id": ref("Id"),
    "token_endpoint": ref("HttpsUri"), "grant_type": {"const": "urn:ietf:params:oauth:grant-type:token-exchange"},
    "subject_token_type": {"const": "urn:ietf:params:oauth:token-type:access_token"},
    "subject_token_digest": ref("Digest"), "actor_token_type": {"const": "urn:ietf:params:oauth:token-type:jwt"},
    "actor_token_digest": ref("Digest"), "resource": ref("Uri"), "audience": ref("Uri"),
    "scopes": array(text(), 1, True), "requested_token_type": {"const": "urn:ietf:params:oauth:token-type:access_token"},
    "issued_token_digest": ref("Digest"), "issued_token_type": {"const": "urn:ietf:params:oauth:token-type:access_token"},
    "token_type": enum("DPoP", "Bearer"), "issued_at": ref("Time"), "expires_at": ref("Time")},
    "Auditable token-exchange request/response binding, not a raw credential store. RFC8693 form-urlencoded wire request contains token values resolved from gateway vault references, never copied to agents. STS must enforce local G attenuation; native AWS/DB credentials require provider-specific brokers.")
D["A2ARootReference"] = obj({"type": {"const": "urn:kedgeflow:root-reference:1.0"},
    "root_id": ref("Id"), "root_generation": ref("Epoch"), "delegation_id": ref("Id"),
    "assurance_profile": ref("Id"), "cryptographic_profile": {"const": "KF-JSON-0.2"},
    "authority_endpoint": ref("HttpsUri"), "saga_budget": nullable(ref("BudgetReference"))},
    "Proposed A2A v1.0 DataPart.data extension. Non-bearer ledger reference; receiver still authenticates, admits, and obtains attenuated child authority.",
    required=["type", "root_id", "root_generation", "delegation_id", "assurance_profile", "authority_endpoint"])

KINDS = {"proposal": "Proposal", "certificate": "AdmissionCertificate", "grant": "ExecutionGrant",
         "ctd": "ConsequentialToolDescriptor", "hitl_witness": "HitlWitness", "evidence": "Evidence",
         "manifest": "WitnessManifest", "lease": "AdmissionLease", "saga_root": "SagaExecutionRoot",
         "remediation": "RemediationContract", "receipt": "Receipt", "delegation": "DelegationRequest",
         "token_exchange": "TokenExchangeBinding"}
for kind, name in KINDS.items():
    D[name + "Envelope"] = obj({"profile": {"const": "KF-JSON-0.2"}, "kind": {"const": kind},
        "schema": {"const": BASE + "#/$defs/" + name}, "key_id": ref("Id"),
        "payload": ref(name), "signature": ref("Ed25519Signature")})

SCHEMA = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": BASE,
          "title": "KedgeFlow v0.9 proposed KF-JSON-0.2 record profile",
          "description": "Closed signed record envelopes. This proposal is not an adopted industry standard. Validation is necessary but does not authenticate, authorize, canonicalize, establish truth, or provide transactional guarantees.",
          "oneOf": [ref(name + "Envelope") for name in KINDS.values()], "$defs": D}

if __name__ == "__main__":
    Path(__file__).with_name("kedgeflow.schema.json").write_text(json.dumps(SCHEMA, indent=2) + "\n")
    # Complete, semantically identical serialization for the whitepaper listing.
    # Compact leaf objects and pack scalar arrays; long annotation strings remain
    # single JSON strings, which the LaTeX listing wraps without changing bytes.
    def pretty(value, depth=0):
        compact = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        pad = "  " * depth
        if len(pad + compact) <= 118 or not isinstance(value, (dict, list)):
            return [pad + compact]
        if isinstance(value, dict):
            result = [pad + "{"]
            entries = list(value.items())
            for index, (key, item) in enumerate(entries):
                item_lines = pretty(item, depth + 1)
                first = item_lines[0].lstrip()
                prefix = "  " * (depth + 1) + json.dumps(key) + ": "
                result.append(prefix + first)
                result.extend(item_lines[1:])
                if index + 1 < len(entries):
                    result[-1] += ","
            result.append(pad + "}")
            return result
        result = [pad + "["]
        if all(not isinstance(item, (dict, list)) for item in value):
            line = "  " * (depth + 1)
            for index, item in enumerate(value):
                token = json.dumps(item) + ("," if index + 1 < len(value) else "")
                if len(line + token) > 118 and line.strip():
                    result.append(line.rstrip())
                    line = "  " * (depth + 1)
                line += token
            if line.strip():
                result.append(line)
        else:
            for index, item in enumerate(value):
                result.extend(pretty(item, depth + 1))
                if index + 1 < len(value):
                    result[-1] += ","
        result.append(pad + "]")
        return result
    Path(__file__).with_name("schema-paper.json").write_text("\n".join(pretty(SCHEMA)) + "\n")
