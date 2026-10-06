"""Validate schema, signed fixtures, and the explicit offline fixture bindings.

This is a specification conformance harness, not a production admission service,
WebAuthn verifier, OAuth validator, or ledger implementation.
"""
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
import yaml
from build_schema import KINDS
from profile import b64, hash_value, jcs, loads, proposal_digest, record_digest, signing_bytes, unb64

ROOT = Path(__file__).parent
SCHEMA = loads((ROOT / "kedgeflow.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
ROLES = {"proposal": "AgentAdapter", "certificate": "AdmissionController", "grant": "GrantAuthority",
         "ctd": "ResourceRegistry", "hitl_witness": "EvidenceProvider", "evidence": "EvidenceProvider",
         "manifest": "AdmissionController", "lease": "AdmissionController", "saga_root": "GrantAuthority",
         "remediation": "ExecutionGateway", "receipt": "ResourceAdapter", "delegation": "AgentAdapter",
         "token_exchange": "ExecutionGateway"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_envelope(envelope, keys):
    VALIDATOR.validate(envelope)
    key = keys.get(envelope["key_id"])
    require(key is not None, "signer is absent from authenticated fixture registry")
    require(key["authorized_role"] == ROLES[envelope["kind"]], "signer role cannot issue this kind")
    Ed25519PublicKey.from_public_bytes(unb64(key["x"])).verify(unb64(envelope["signature"]), signing_bytes(envelope))


def check_hitl(witness, proposal, policy, template_digest, approved_origin, hardware_required=False, rendered_digest=None):
    approval = witness["approval"]
    require(approval["proposal_digest"] == proposal_digest(proposal), "approval does not bind exact proposal")
    require(approval["policy_epoch"] == policy["epoch"], "approval does not bind active policy epoch")
    require(approval["parameters_digest"] == hash_value("parameters", proposal["payload"]["parameters"]), "reviewed parameters differ")
    require(approval["rendering_template_digest"] == template_digest, "unregistered rendering template")
    if rendered_digest is not None:
        require(approval["rendered_digest"] == rendered_digest, "reviewed rendering bytes differ")
    require(witness["challenge_digest"] == hashlib.sha256(jcs(approval)).hexdigest(), "WebAuthn challenge mismatch")
    require(witness["rp_id"] == approval["rp_id"], "RP binding mismatch")
    require(witness["origin"] == approved_origin, "origin is absent from the approved exact-origin policy")
    host = urlparse(approved_origin).hostname
    require(host == witness["rp_id"] or host.endswith("." + witness["rp_id"]), "origin is outside RP domain")
    require(approval["verdict"] == "approve", "human rejected proposal")
    require(witness["subject"] == approval["reviewer"], "reviewer identity differs from signed challenge")
    require(approval["reviewed_at"] <= witness["verified_at"] < approval["expires_at"], "approval validity mismatch")
    require(witness["user_present"] and witness["user_verified"], "UP/UV checks missing")
    if hardware_required:
        # Negative conformance check only. The real provider also validates
        # authenticator enrollment/attestation against independent trusted data.
        require(witness["authenticator_policy"]["hardware_bound_required"] and witness["authenticator_policy"]["attestation_required"],
                "hardware-bound policy not satisfied by this offline emulator fixture")


def check_saga(payload):
    nodes = {node["node_id"]: node for node in payload["nodes"]}
    allocations = {item["allocation_id"]: item for item in payload["allocations"]}
    require(len(nodes) == len(payload["nodes"]), "duplicate DAG node IDs")
    require(len(allocations) == len(payload["allocations"]), "duplicate allocation IDs")
    require(len({item["child_root_id"] for item in allocations.values()}) == len(allocations), "child root reused by two allocations")
    visiting, visited = set(), set()

    def walk(node_id):
        require(node_id in nodes, "unresolved dependency")
        require(node_id not in visiting, "DAG cycle")
        if node_id in visited:
            return
        visiting.add(node_id)
        node = nodes[node_id]
        require(node["allocation_id"] in allocations, "missing node allocation")
        require(allocations[node["allocation_id"]]["node_id"] == node_id, "allocation assigned to wrong node")
        for parent in node["depends_on"]:
            walk(parent)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in nodes:
        walk(node_id)
    budget = payload["budget"]
    require(sum(item["forward_units"] for item in allocations.values()) <= budget["forward_limit"], "forward budget overallocated")
    require(sum(item["compensation_units"] for item in allocations.values()) <= budget["compensation_reserve"], "compensation reserve overallocated")
    require(budget["forward_consumed"] <= budget["forward_limit"], "forward budget exceeded")
    require(budget["compensation_consumed"] <= budget["compensation_reserve"], "compensation reserve exceeded")


def check_fixture_bindings(fixtures):
    q, c, g, ctd = [fixtures[key] for key in ("proposal", "certificate", "grant", "ctd")]
    qp, cp, gp, dp = [record["payload"] for record in (q, c, g, ctd)]
    for payload in (cp, gp, fixtures["manifest"]["payload"], fixtures["lease"]["payload"], fixtures["evidence"]["payload"]):
        require(payload["proposal_digest"] == proposal_digest(q), "proposal binding mismatch")
    for payload in (cp, gp):
        require(payload["subject"] == qp["subject"], "human subject binding mismatch")
        require(payload["workload_id"] == qp["workload_id"], "workload binding mismatch")
        require(payload["delegation_digest"] == hash_value("delegation", qp["delegation"]), "delegation binding mismatch")
    require(gp["dpop_jkt"] == qp["delegation"]["dpop_jkt"], "DPoP proof-key mismatch")
    require(gp["certificate_digest"] == record_digest(c), "certificate binding mismatch")
    require(gp["parameters_digest"] == hash_value("parameters", qp["parameters"]), "parameters binding mismatch")
    require(cp["descriptor_digest"] == record_digest(ctd), "descriptor binding mismatch")
    require(qp["action"]["digest"] == record_digest(ctd), "proposal action descriptor mismatch")
    require(cp["constraint_digest"] == hash_value("constraints", cp["constraints"]), "constraints digest mismatch")
    require(gp["constraint_digest"] == cp["constraint_digest"], "grant constraints binding mismatch")
    require(cp["evidence_manifest_digest"] == record_digest(fixtures["manifest"]), "manifest binding mismatch")
    require(gp["evidence_manifest_digest"] == cp["evidence_manifest_digest"], "grant evidence binding mismatch")
    require(cp["lease_digest"] == record_digest(fixtures["lease"]), "lease binding mismatch")
    require(gp["issued_at"] <= gp["valid_from"] < gp["expires_at"] <= cp["expires_at"], "grant/certificate time ordering")
    require(cp["admitted_at"] < cp["expires_at"], "certificate time ordering")
    require(gp["completion_mode"] == gp["adapter_contract"]["completion_mode"], "completion mode mismatch")
    for field in ("action", "resources", "parameters_digest", "predicate_descriptor", "adapter_contract", "audience", "saga_budget"):
        require(gp[field] == cp["constraints"][field], "grant broadened certificate field " + field)
    for discharge in cp["discharges"]:
        if discharge["execution_relevant"]:
            require(gp["expires_at"] <= discharge["expires_at"], "grant outlives execution witness")
    parameter_schema = dp["parameter_schema"]
    Draft202012Validator.check_schema(parameter_schema)
    Draft202012Validator(parameter_schema).validate(qp["parameters"])
    require(dp["parameter_schema_digest"] == hash_value("parameter-schema", parameter_schema), "parameter schema digest mismatch")
    template = (ROOT / "examples" / "capacity-review-template.txt").read_bytes()
    require(dp["rendering"]["template_digest"] == hashlib.sha256(template).hexdigest(), "rendering digest mismatch")
    rendered = (ROOT / "examples" / "capacity-review-rendered.txt").read_bytes()
    check_hitl(fixtures["hitl_witness"]["payload"], q, cp["policy"], dp["rendering"]["template_digest"],
               "https://review.example.org", rendered_digest=hashlib.sha256(rendered).hexdigest())
    saga = fixtures["saga_root"]["payload"]
    check_saga(saga)
    require(gp["saga_budget"]["saga_root_id"] == saga["root_id"], "saga root mismatch")
    require(gp["saga_budget"]["saga_generation"] == saga["root_generation"], "saga generation mismatch")
    allocation = next(item for item in saga["allocations"] if item["allocation_id"] == gp["saga_budget"]["allocation_id"])
    require(allocation["child_root_id"] == gp["root_id"], "grant has wrong allocated child root")
    require(gp["saga_budget"]["units"] <= allocation["forward_units"], "grant exceeds child allocation")
    receipt = fixtures["receipt"]["payload"]
    require(receipt["grant_digest"] == record_digest(g), "receipt grant binding mismatch")
    require(receipt["effect_digest"] == gp["parameters_digest"], "receipt effect binding mismatch")


def check_identity_vectors(proposal, keys):
    examples = ROOT / "examples"
    token = (examples / "access-token.jwt").read_text()
    proof = (examples / "dpop-proof.jwt").read_text()
    token_header, token_claims, token_signature = token.split(".")
    header, claims = loads(unb64(token_header)), loads(unb64(token_claims))
    require(header["typ"] == "at+jwt" and header["alg"] == "EdDSA", "test token is not the declared OAuth access token")
    key = keys[header["kid"]]
    require(key["authorized_role"] == "OAuthAuthorizationServer", "untrusted OAuth fixture signer")
    Ed25519PublicKey.from_public_bytes(unb64(key["x"])).verify(unb64(token_signature), (token_header + "." + token_claims).encode("ascii"))
    delegation = proposal["payload"]["delegation"]
    require(hashlib.sha256(token.encode("ascii")).hexdigest() == delegation["access_token_digest"], "raw access-token digest mismatch")
    require({"iss": claims["iss"], "sub": claims["sub"]} == proposal["payload"]["subject"], "OAuth issuer/subject mismatch")
    require(claims["aud"] == delegation["token_audience"], "OAuth audience mismatch")
    require(claims["exp"] * 1000 == delegation["expires_at"], "OAuth expiry mismatch")
    require(claims["scope"].split() == delegation["scopes"], "OAuth scope mismatch")
    jwk = loads((examples / "dpop-public-test-key.json").read_text())
    require(b64(hashlib.sha256(jcs(jwk)).digest()) == delegation["dpop_jkt"], "RFC7638 JWK thumbprint mismatch")
    require(claims["cnf"]["jkt"] == delegation["dpop_jkt"], "OAuth cnf.jkt binding mismatch")
    proof_header, proof_claims, proof_signature = proof.split(".")
    ph, pc = loads(unb64(proof_header)), loads(unb64(proof_claims))
    require(ph["typ"] == "dpop+jwt" and ph["alg"] == "EdDSA" and ph["jwk"] == jwk, "DPoP public-key context mismatch")
    Ed25519PublicKey.from_public_bytes(unb64(jwk["x"])).verify(unb64(proof_signature), (proof_header + "." + proof_claims).encode("ascii"))
    require(pc["ath"] == b64(hashlib.sha256(token.encode("ascii")).digest()), "DPoP access-token hash mismatch")
    require(pc["htm"] == "POST" and pc["htu"] == "https://admission.example.org/v0.9/propose", "DPoP request binding mismatch")
    require(pc["jti"] and pc["nonce"], "DPoP unique ID/server nonce missing")


def validate_all():
    Draft202012Validator.check_schema(SCHEMA)
    require(SCHEMA == loads((ROOT / "schema-paper.json").read_text()), "paper listing changed schema semantics")
    examples = ROOT / "examples"
    keys = loads((examples / "public-test-keys.json").read_text())
    fixtures = {kind: loads((examples / (kind + ".json")).read_text()) for kind in KINDS}
    for envelope in fixtures.values():
        verify_envelope(envelope, keys)
    check_fixture_bindings(fixtures)
    check_identity_vectors(fixtures["proposal"], keys)
    require(yaml.safe_load((examples / "ctd.yaml").read_text()) == fixtures["ctd"]["payload"], "CTD YAML differs from signed JSON payload")
    a2a_schema = {"$ref": "#/$defs/A2ARootReference", "$defs": SCHEMA["$defs"]}
    Draft202012Validator(a2a_schema, format_checker=FormatChecker()).validate(loads((examples / "a2a-root-reference.json").read_text()))
    expected = loads((examples / "fixture-digests.json").read_text())
    require(expected == {kind: record_digest(record) for kind, record in fixtures.items()}, "published digest vector mismatch")
    return fixtures, keys


if __name__ == "__main__":
    fixtures, _ = validate_all()
    print(f"PASS: Draft 2020-12 schema, complete paper-listing equality, {len(fixtures)} Ed25519 signed envelopes, all declared fixture bindings, OAuth/DPoP vectors, CTD YAML, A2A reference.")
