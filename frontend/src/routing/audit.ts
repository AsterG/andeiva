import { ApiError, configurationRequest } from '../firewall/api.js';
import { decimalGeneration, operationID } from './configuration.js';

export type AuditEvent = { sequence: string; at: string; actor_id: string; actor_name?: string; operation_id: string; operation: string; result: string; generation: string; running_revision: string; startup_revision: string };
export type AuditPage = { schema_version: 1; events: AuditEvent[]; next_before: string; truncated: boolean };
const hash = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function auditResponse(value: unknown, before = '0'): AuditPage {

  if (before !== '0' && !decimalGeneration(before)) throw new ApiError('ANDEIVA_INVALID_ARGUMENT');
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  const page = value as Partial<AuditPage>;
  if (page.schema_version !== 1 || !Array.isArray(page.events) || page.events.length > 50 || typeof page.truncated !== 'boolean' || page.next_before !== '0' && !decimalGeneration(page.next_before)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  let previous = before;
  for (const event of page.events) {
    if (!event || !decimalGeneration(event.sequence) || previous !== '0' && BigInt(event.sequence) >= BigInt(previous) || !decimalGeneration(event.generation) || typeof event.at !== 'string' || !Number.isFinite(Date.parse(event.at)) || !operationID(event.actor_id) || !operationID(event.operation_id) || !operationID(event.operation) || !operationID(event.result) || !hash(event.running_revision) || !hash(event.startup_revision) || event.actor_name !== undefined && (typeof event.actor_name !== 'string' || event.actor_name.length > 128 || /[\p{Cc}\p{Cf}]/u.test(event.actor_name))) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    previous = event.sequence;
  }
  if (page.next_before !== '0' && (!page.events.length || page.next_before !== previous)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  return { schema_version: 1, events: page.events.map((event) => ({ sequence: event.sequence, at: event.at, actor_id: event.actor_id, ...(event.actor_name !== undefined ? { actor_name: event.actor_name } : {}), operation_id: event.operation_id, operation: event.operation, result: event.result, generation: event.generation, running_revision: event.running_revision, startup_revision: event.startup_revision })), next_before: page.next_before!, truncated: page.truncated };
}
export async function readAudit(before = '0', signal?: AbortSignal): Promise<AuditPage> {
  if (before !== '0' && !decimalGeneration(before)) throw new ApiError('ANDEIVA_INVALID_ARGUMENT');
  return auditResponse(await configurationRequest(`config/audit?before=${before}&limit=50`, undefined, undefined, signal), before);
}
