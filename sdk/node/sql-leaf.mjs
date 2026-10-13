// RFC 0025 named application binding. No target metadata is agent supplied.
import { digest, exact, same } from './records.mjs';
export const SQL_ACTION = 'postgres.reservation.set.v1';
export const SQL_PROFILE = 'KF-POSTGRES-LEAF-0.1-draft';
export const SQL_EXTENSION = 'io.kedgeflow/postgres-leaf';
const label = { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$' };
export const SQL_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['resource_id', 'expected_version', 'reservation'],
  properties: { resource_id: label, expected_version: { type: 'integer', minimum: 1, maximum: 9007199254740990 }, reservation: label }
};
export function validateSqlDescriptor(d) {
  if (d.action !== SQL_ACTION) return;
  if (d.version !== '1.0' || !same(d.parameter_schema, SQL_SCHEMA) || d.parameter_schema_digest !== digest('parameter-schema', SQL_SCHEMA) || d.rendering?.parameter_schema_digest !== d.parameter_schema_digest || d.adapter_contract?.fence_parameter !== 'fence') throw new Error('SQL descriptor binding mismatch');
}
export function validateSqlArguments(d, args) {
  if (d.action !== SQL_ACTION) return;
  exact(args, ['resource_id', 'expected_version', 'reservation']);
  const clauses = d.concurrency?.predicate_descriptor?.clauses;
  const grammar = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;
  if (!Array.isArray(clauses) || clauses.length !== 1 || clauses[0].kind !== 'version_eq' || typeof args.resource_id !== 'string' || !grammar.test(args.resource_id) || args.resource_id !== clauses[0].resource?.id || typeof args.reservation !== 'string' || !grammar.test(args.reservation) || !Number.isSafeInteger(args.expected_version) || args.expected_version < 1 || args.expected_version > 9007199254740990) throw new Error('SQL arguments binding mismatch');
}
