import { ApiError } from './api.js';
import { canonicalIPv4 } from './model.js';
import type { FirewallState, History, Session } from './model.js';

function object(value: unknown): value is Record<string, unknown> { return !!value && typeof value === 'object' && !Array.isArray(value); }
function text(value: unknown, maximum = 256): value is string { return typeof value === 'string' && value.length > 0 && value.length <= maximum; }
function integer(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0; }
function hash(value: unknown): boolean { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function date(value: unknown): boolean { return typeof value === 'string' && Number.isFinite(Date.parse(value)); }
function ports(value: unknown): boolean { return object(value) && integer(value.from) && integer(value.to) && value.from >= 1 && value.from <= value.to && value.to <= 65535; }
function revision(value: unknown): boolean {
  if (!object(value) || !hash(value.hash) || !object(value.config)) return false;
  const config = value.config;
  if (![2, 4].includes(Number(config.schema_version)) || typeof config.schema_version !== 'number' || config.default_action !== 'deny' || !Array.isArray(config.rules) || config.rules.length > 64) return false;
  const ids = new Set<string>();
  return config.rules.every((rule: unknown) => {
    if (!object(rule) || !text(rule.id, 64) || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(rule.id) || ids.has(rule.id) || !['allow', 'deny'].includes(String(rule.action)) || !object(rule.match)) return false;
    if (config.schema_version === 4 ? typeof rule.enabled !== 'boolean' : rule.enabled !== undefined) return false;
    ids.add(rule.id);
    const match = rule.match;
    return text(match.source, 18) && canonicalIPv4(match.source) === match.source && text(match.destination, 18) && canonicalIPv4(match.destination) === match.destination && ['tcp', 'udp'].includes(String(match.protocol)) && ports(match.source_ports) && ports(match.destination_ports);
  });
}
function invalid(): never { throw new ApiError('ANDEIVA_RESPONSE_INVALID'); }
export function ruleEnabledCapability(value: unknown): boolean {
  return object(value) && value.firewall_rule_enabled === true && Array.isArray(value.firewall_config_schema_versions) && value.firewall_config_schema_versions.includes(4);
}
export function sessionResponse(value: unknown): Session {
  if (!object(value) || !text(value.username, 64) || !['admin', 'viewer'].includes(String(value.role)) || !text(value.csrf) || !date(value.expires_at)) invalid();
  return value as Session;
}
export function firewallResponse(value: unknown): FirewallState {
  if (!object(value) || !object(value.snapshot) || !object(value.effective)) invalid();
  const snapshot = value.snapshot;
  const effective = value.effective;
  if (!integer(snapshot.generation) || !revision(snapshot.running) || !revision(snapshot.startup) || typeof snapshot.recovery_required !== 'boolean') invalid();
  if (snapshot.candidate !== undefined && (!object(snapshot.candidate) || !text(snapshot.candidate.owner, 64) || !hash(snapshot.candidate.base) || !revision(snapshot.candidate.revision))) invalid();
  if (snapshot.pending !== undefined && (!object(snapshot.pending) || !text(snapshot.pending.owner, 64) || !date(snapshot.pending.deadline) || !revision(snapshot.pending.previous))) invalid();
  if (!['verified', 'pending_confirmation', 'recovery_required', 'unavailable'].includes(String(effective.state)) || typeof effective.revision !== 'string' || (effective.revision !== '' && !hash(effective.revision)) || !Array.isArray(effective.rules) || effective.rules.length > 64) invalid();
  if (!effective.rules.every((rule: unknown) => object(rule) && text(rule.id, 64) && integer(rule.packets) && integer(rule.bytes))) invalid();
  return value as FirewallState;
}
export function historyResponse(value: unknown): History {
  if (!object(value) || !Array.isArray(value.revisions) || value.revisions.length > 50 || !Array.isArray(value.audit) || value.audit.length > 50 || !integer(value.next_before)) invalid();
  if (!value.revisions.every((entry: unknown) => object(entry) && integer(entry.sequence) && revision(entry.revision))) invalid();
  if (!value.audit.every((entry: unknown) => object(entry) && integer(entry.sequence) && date(entry.at) && ['actor', 'surface', 'operation', 'result'].every((key) => text(entry[key])) && hash(entry.running_hash))) invalid();
  return value as History;
}
