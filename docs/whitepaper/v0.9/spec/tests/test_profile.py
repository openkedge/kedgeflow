import copy
from pathlib import Path
import sys
import unittest
from cryptography.exceptions import InvalidSignature
from jsonschema.exceptions import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from profile import jcs, loads, proposal_digest
from validate import VALIDATOR, check_hitl, check_identity_vectors, check_saga, validate_all, verify_envelope


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures, cls.keys = validate_all()

    def test_all_fixtures_and_paper_schema(self):
        self.assertEqual(len(self.fixtures), 13)

    def test_closed_envelope_and_grant_payload(self):
        for path in ((), ("payload",), ("payload", "subject"), ("payload", "policy"), ("payload", "adapter_contract")):
            record = copy.deepcopy(self.fixtures["grant"])
            target = record
            for field in path:
                target = target[field]
            target["unexpected_authority"] = True
            with self.subTest(path=path), self.assertRaises(ValidationError):
                VALIDATOR.validate(record)

    def test_grant_required_security_fields(self):
        for field in ("subject", "workload_id", "dpop_jkt", "delegation_digest", "ownership_epoch", "fence", "root_generation", "saga_budget", "constraint_digest", "evidence_manifest_digest"):
            record = copy.deepcopy(self.fixtures["grant"])
            del record["payload"][field]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                VALIDATOR.validate(record)

    def test_oidc_subject_requires_issuer(self):
        record = copy.deepcopy(self.fixtures["proposal"])
        del record["payload"]["subject"]["iss"]
        with self.assertRaises(ValidationError):
            VALIDATOR.validate(record)

    def test_id_token_is_not_delegation_field(self):
        record = copy.deepcopy(self.fixtures["proposal"])
        record["payload"]["delegation"]["id_token"] = "not-access-authority"
        with self.assertRaises(ValidationError):
            VALIDATOR.validate(record)

    def test_workload_requires_spiffe_id(self):
        record = copy.deepcopy(self.fixtures["proposal"])
        record["payload"]["workload_id"] = "https://agent.example.org"
        with self.assertRaises(ValidationError):
            VALIDATOR.validate(record)

    def test_consequence_label_tier_mapping(self):
        record = copy.deepcopy(self.fixtures["ctd"])
        record["payload"]["consequence_tier_number"] = 0
        with self.assertRaises(ValidationError):
            VALIDATOR.validate(record)

    def test_level_a_cannot_declare_no_guard(self):
        record = copy.deepcopy(self.fixtures["grant"])
        record["payload"]["adapter_contract"]["guard_primitive"] = "None"
        with self.assertRaises(ValidationError):
            VALIDATOR.validate(record)

    def test_null_compensation_requires_reason(self):
        record = copy.deepcopy(self.fixtures["ctd"])
        record["payload"]["compensation"] = None
        with self.assertRaises(ValidationError):
            VALIDATOR.validate(record)

    def test_lease_cannot_grant_execution(self):
        record = copy.deepcopy(self.fixtures["lease"])
        record["payload"]["execution_authority"] = True
        with self.assertRaises(ValidationError):
            VALIDATOR.validate(record)

    def test_no_effect_receipt_requires_evidence(self):
        record = copy.deepcopy(self.fixtures["receipt"])
        record["payload"]["status"] = "fenced_no_effect"
        with self.assertRaises(ValidationError):
            VALIDATOR.validate(record)

    def test_failure_receipts_require_diagnostic_and_do_not_claim_no_effect(self):
        for status in ("failed", "compensation_failed", "not_dispatched"):
            record = copy.deepcopy(self.fixtures["receipt"])
            record["payload"]["status"] = status
            record["payload"]["error_code"] = None
            with self.subTest(status=status), self.assertRaises(ValidationError):
                VALIDATOR.validate(record)
            record["payload"]["error_code"] = "RESOURCE_ERROR"
            VALIDATOR.validate(record)

    def test_payload_change_invalidates_signature(self):
        record = copy.deepcopy(self.fixtures["grant"])
        record["payload"]["fence"] += 1
        with self.assertRaises(InvalidSignature):
            verify_envelope(record, self.keys)

    def test_untrusted_issuer_and_wrong_role(self):
        record = self.fixtures["grant"]
        with self.assertRaises(ValueError):
            verify_envelope(record, {})
        registry = copy.deepcopy(self.keys)
        registry[record["key_id"]]["authorized_role"] = "AgentAdapter"
        with self.assertRaises(ValueError):
            verify_envelope(record, registry)

    def test_approval_exact_json_and_policy(self):
        witness = copy.deepcopy(self.fixtures["hitl_witness"]["payload"])
        witness["approval"]["policy_epoch"] += 1
        with self.assertRaises(ValueError):
            check_hitl(witness, self.fixtures["proposal"], self.fixtures["certificate"]["payload"]["policy"],
                       self.fixtures["ctd"]["payload"]["rendering"]["template_digest"], "https://review.example.org")

    def test_approval_reviewer_and_rendered_bytes(self):
        for mutation in ("reviewer", "rendered_digest"):
            witness = copy.deepcopy(self.fixtures["hitl_witness"]["payload"])
            if mutation == "reviewer":
                witness["approval"]["reviewer"]["sub"] = "another-human"
            else:
                witness["approval"]["rendered_digest"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_hitl(witness, self.fixtures["proposal"], self.fixtures["certificate"]["payload"]["policy"],
                           self.fixtures["ctd"]["payload"]["rendering"]["template_digest"], "https://review.example.org",
                           rendered_digest=self.fixtures["hitl_witness"]["payload"]["approval"]["rendered_digest"])

    def test_dpop_proof_key_and_oauth_subject_binding(self):
        for mutation in ("dpop_jkt", "iss"):
            proposal = copy.deepcopy(self.fixtures["proposal"])
            if mutation == "dpop_jkt":
                proposal["payload"]["delegation"]["dpop_jkt"] = "A" * 43
            else:
                proposal["payload"]["subject"]["iss"] = "https://different-issuer.example.org"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_identity_vectors(proposal, self.keys)

    def test_uv_emulator_does_not_satisfy_hardware_policy(self):
        with self.assertRaises(ValueError):
            check_hitl(self.fixtures["hitl_witness"]["payload"], self.fixtures["proposal"], self.fixtures["certificate"]["payload"]["policy"],
                       self.fixtures["ctd"]["payload"]["rendering"]["template_digest"], "https://review.example.org", hardware_required=True)

    def test_saga_budget_and_cycle_rejected(self):
        for mutation in ("budget", "cycle", "root_reuse"):
            saga = copy.deepcopy(self.fixtures["saga_root"]["payload"])
            if mutation == "budget":
                saga["allocations"][0]["forward_units"] = 3
            elif mutation == "cycle":
                saga["nodes"][0]["depends_on"] = ["fulfill"]
            else:
                saga["allocations"][1]["child_root_id"] = saga["allocations"][0]["child_root_id"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_saga(saga)

    def test_strict_json_and_jcs_domain(self):
        for raw in ('{"a":1,"a":2}', '{"a":1.0}', '{"a":NaN}', '{"a":9007199254740992}', '{"a":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                loads(raw)
        self.assertEqual(jcs({"z": 2, "a": "\n"}), b'{"a":"\\n","z":2}')
        # JCS uses UTF-16 ordering: astral U+1F600 sorts before BMP U+E000.
        self.assertEqual(jcs({"\ue000": 1, "\U0001f600": 2}), '{"😀":2,"\ue000":1}'.encode())
        with self.assertRaises(ValueError):
            jcs(1.0)

    def test_proposal_key_rotation_does_not_change_identity(self):
        rotated = copy.deepcopy(self.fixtures["proposal"])
        rotated["key_id"] = "urn:kf:key:rotated:test-v2"
        rotated["signature"] = "A" * 86
        self.assertEqual(proposal_digest(rotated), proposal_digest(self.fixtures["proposal"]))


if __name__ == "__main__":
    unittest.main()
