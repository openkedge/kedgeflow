// RFCs 0047–0048. Protected exact original parameters; no restore value or
// target credential is agent supplied. Native authority/target verify the proofs.
import { digest, exact, same } from './records.mjs';
export const INVERSE_ACTION = 'kedgeflow.compensation.restore.v1';
export const INVERSE_PROFILE = 'KF-COMPENSATION-LEAF-0.1-draft';
export const INVERSE_EXTENSION = 'io.kedgeflow/compensation-leaf';
export const INVERSE_SCHEMA = {
  "type": "object",
  "additionalProperties": false,
  "required": [
    "resource_id",
    "expected_version",
    "forward_grant_digest",
    "forward_attempt_id",
    "restore_state_digest"
  ],
  "properties": {
    "resource_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "expected_version": {
      "type": "integer",
      "minimum": 1,
      "maximum": 9007199254740991
    },
    "forward_grant_digest": {
      "type": "string",
      "pattern": "^[a-f0-9]{64}$"
    },
    "forward_attempt_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "restore_state_digest": {
      "type": "string",
      "pattern": "^[a-f0-9]{64}$"
    }
  }
};
export function validateInverseDescriptor(d, registration) {
  if (d.action !== INVERSE_ACTION) {
    if (registration !== undefined) throw new Error('inverse registration requires inverse action');
    return;
  }
  exact(registration, ['profile', 'contractDigest', 'parameters']);
  if (registration.profile !== INVERSE_PROFILE || !/^[a-f0-9]{64}$/.test(registration.contractDigest) || d.version !== '1.0' || !same(d.parameter_schema, INVERSE_SCHEMA) || d.parameter_schema_digest !== digest('parameter-schema', INVERSE_SCHEMA) || d.rendering?.parameter_schema_digest !== d.parameter_schema_digest || d.adapter_contract?.fence_parameter !== 'fence') throw new Error('inverse descriptor/contract binding mismatch');
  validateInverseArguments(d, registration.parameters, registration);
}
export function validateInverseArguments(d, args, registration) {
  if (d.action !== INVERSE_ACTION) return;
  exact(args, ['resource_id', 'expected_version', 'forward_grant_digest', 'forward_attempt_id', 'restore_state_digest']);
  const clauses = d.concurrency?.predicate_descriptor?.clauses;
  if (!registration || !same(args, registration.parameters) || !Array.isArray(clauses) || clauses.length !== 1 || clauses[0].kind !== 'version_eq' || args.resource_id !== clauses[0].resource?.id || typeof args.resource_id !== 'string' || args.resource_id.length < 1 || args.resource_id.length > 256 || !Number.isSafeInteger(args.expected_version) || args.expected_version < 1 || String(args.expected_version) !== clauses[0].expected_version || typeof args.forward_attempt_id !== 'string' || args.forward_attempt_id.length < 1 || args.forward_attempt_id.length > 256 || !/^[a-f0-9]{64}$/.test(args.forward_grant_digest) || !/^[a-f0-9]{64}$/.test(args.restore_state_digest)) throw new Error('inverse original parameter binding mismatch');
}
