import { ApiError } from './api.js';

export type TrafficRecord = {
  sequence: number; observed_at: string; since?: string; revision: string; rule_id: string;
  action: 'allow' | 'deny'; kind: 'baseline' | 'delta'; packets_total: string; bytes_total: string;
  packets_delta?: string; bytes_delta?: string;
};
export type TrafficPage = { stream: string; records: TrafficRecord[]; next_before: number; evicted: number; capacity: 512; sampling: 'on_request'; retention: 'api_process'; truncated: boolean };
const uint64Maximum = 18446744073709551615n;
export function isUint64(value: unknown): value is string {
  return typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= uint64Maximum;
}
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function integer(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0; }
function timestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parts = /^(\d{4})-(\d{2})-(\d{2})T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.\d{1,9})?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value);
  if (!parts) return false;
  const year = Number(parts[1]); const month = Number(parts[2]); const day = Number(parts[3]);
  const days = [31, year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]! && Number.isFinite(Date.parse(value));
}
function validRecord(value: unknown): value is TrafficRecord {
  if (!object(value) || !integer(value.sequence) || value.sequence === 0 || !timestamp(value.observed_at) || typeof value.revision !== 'string' || !/^[a-f0-9]{64}$/.test(value.revision) || typeof value.rule_id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(value.rule_id) || (value.action !== 'allow' && value.action !== 'deny') || !isUint64(value.packets_total) || !isUint64(value.bytes_total)) return false;
  if (value.since !== undefined && (!timestamp(value.since) || Date.parse(value.since) > Date.parse(value.observed_at))) return false;
  if (value.kind === 'baseline') return value.since === undefined && value.packets_delta === undefined && value.bytes_delta === undefined;
  return value.kind === 'delta' && timestamp(value.since) && isUint64(value.packets_delta) && isUint64(value.bytes_delta) && (value.packets_delta !== '0' || value.bytes_delta !== '0') && BigInt(value.packets_delta) <= BigInt(value.packets_total) && BigInt(value.bytes_delta) <= BigInt(value.bytes_total);
}
export function trafficResponse(value: unknown): TrafficPage {
  if (!object(value) || typeof value.stream !== 'string' || !/^[a-f0-9]{32}$/.test(value.stream) || !Array.isArray(value.records) || value.records.length > 50 || !integer(value.next_before) || !integer(value.evicted) || value.capacity !== 512 || value.sampling !== 'on_request' || value.retention !== 'api_process' || typeof value.truncated !== 'boolean') throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  let previous = Number.POSITIVE_INFINITY;
  for (const record of value.records) {
    if (!validRecord(record) || record.sequence >= previous) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    previous = record.sequence;
  }
  if (value.next_before !== 0 && (value.records.length === 0 || value.next_before !== previous)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  return value as TrafficPage;
}
