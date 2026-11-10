import { ApiError } from '../firewall/api.js';
import { canonicalIPv4 } from '../firewall/model.js';
import type { Audit, Operation } from '../firewall/model.js';

export type Zone = 'lan' | 'wan' | 'other';
export type Interface = { name: string; zone: Zone; addresses: string[] };
export type Binding = { interface: string; zone: Zone; local_address: string; sources: string[]; wan_opt_in: boolean };
export type Endpoint = { protocol: 'tcp'; first_port: number; last_port: number };
export type Service = {
  id: 'https' | 'ssh'; owner: 'management'; kind: 'management_https' | 'management_ssh'; enabled: boolean;
  compatible_zones: Zone[]; authentication: 'required'; depends_on: string[] | null; endpoints: Endpoint[]; bindings: Binding[];
  lifecycle: { verify_listeners: true; verify_rules: true; revert_on_failure: true; confirmed_management_changes: true };
};
export type LocalConfig = { schema_version: 1; interfaces: Interface[]; services: Service[] };
export type Config = { schema_version: number; default_action: 'deny'; rules: never[]; local_services?: LocalConfig };
export type Revision = { hash: string; config: Config };
export type Snapshot = { generation: number; running: Revision; startup: Revision; candidate?: { owner: string; base: string; revision: Revision }; pending?: { owner: string; lease: string; deadline: string; previous: Revision }; recovery_required: boolean };
export type Listener = { owner: string; service: string; interface: string; local_address: string; protocol: 'tcp'; port: number };
export type Rule = { id: string; revision: string; owner: string; service: string; management: boolean; interface: string; zone: Zone; family: 'ipv4' | 'ipv6'; local_address: string; source: string; endpoint: Endpoint; action: 'allow'; origin: string };
export type Effective = { hash: string; phase: string; recovery_required: boolean; rules: Rule[]; listeners: Listener[] };
export type Status = { snapshot: Snapshot; effective: Effective };
export type Capabilities = { firewall: boolean; local_services: boolean; endpoint_id: string; recovery_endpoint: boolean; local_interfaces: Interface[] };
export type Transaction = { operation: Operation; key: string; expected_generation: number; config?: Config; target?: string; confirm_for?: number };
export type Request = { transaction: Transaction; recovery_proof?: string; endpoint_proofs?: string[] };
export type Proof = { token: string; expires_at: string };
export type History = { revisions: { sequence: number; revision: Revision }[]; audit: Audit[]; next_before: number };

const hash = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown, max = 128): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;
const integer = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const date = (v: unknown): boolean => typeof v === 'string' && Number.isFinite(Date.parse(v));
const zone = (v: unknown): boolean => v === 'lan' || v === 'wan' || v === 'other';
function invalid(): never { throw new ApiError('ANDEIVA_RESPONSE_INVALID'); }

export function canonicalAddress(raw: string): string | null {
  if (raw.includes('/') || raw.includes('%') || raw.trim() !== raw) return null;
  if (!raw.includes(':')) return canonicalIPv4(raw)?.split('/')[0] ?? null;
  if (!/^[\da-f:]+$/i.test(raw)) return null;
  try { return new URL(`http://[${raw}]/`).hostname.slice(1, -1); } catch { return null; }
}
export function canonicalCIDR(raw: string): string | null {
  const value = raw.trim();
  if (!value.includes(':')) return canonicalIPv4(value);
  const parts = value.split('/');
  const address = canonicalAddress(parts[0] ?? '');
  if (!address || parts.length > 2 || (parts[1] !== undefined && !/^(0|[1-9]\d{0,2})$/.test(parts[1]))) return null;
  const bits = Number(parts[1] ?? 128);
  if (bits > 128) return null;
  const halves = address.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const words = halves.length === 2 ? [...left, ...Array<string>(8 - left.length - right.length).fill('0'), ...right] : left;
  if (words.length !== 8) return null;
  const number = words.reduce((n, word) => (n << 16n) | BigInt(`0x${word}`), 0n);
  const shift = BigInt(128 - bits);
  const network = (number >> shift) << shift;
  const normalized = Array.from({ length: 8 }, (_, i) => ((network >> BigInt((7 - i) * 16)) & 65535n).toString(16)).join(':');
  return `${canonicalAddress(normalized)}/${bits}`;
}
function inventory(value: unknown): value is Interface[] {
  return Array.isArray(value) && value.length <= 2 && new Set(value.map((i: unknown) => object(i) ? i.name : '')).size === value.length && value.every((i: unknown) => object(i) && text(i.name, 15) && zone(i.zone) && Array.isArray(i.addresses) && i.addresses.length > 0 && i.addresses.length <= 4 && i.addresses.every((a: unknown) => typeof a === 'string' && canonicalAddress(a) === a));
}
export function capabilitiesResponse(value: unknown): Capabilities {
  if (!object(value) || typeof value.firewall !== 'boolean' || typeof value.local_services !== 'boolean' || typeof value.recovery_endpoint !== 'boolean' || typeof value.endpoint_id !== 'string' || value.endpoint_id.length > 80 || !(inventory(value.local_interfaces) || (!value.local_services && value.local_interfaces === null))) invalid();
  return { ...(value as Capabilities), local_interfaces: value.local_interfaces === null ? [] : value.local_interfaces as Interface[] };
}
function endpoint(value: unknown): boolean { return object(value) && value.protocol === 'tcp' && integer(value.first_port) && value.first_port >= 1024 && value.first_port <= 65535 && value.last_port === value.first_port; }
function localConfig(value: unknown): value is LocalConfig {
  if (!object(value) || value.schema_version !== 1 || !inventory(value.interfaces) || !Array.isArray(value.services) || value.services.length > 2) return false;
  const ids = new Set<unknown>();
  return value.services.every((s: unknown) => {
    if (!object(s) || (s.id !== 'https' && s.id !== 'ssh') || ids.has(s.id) || s.kind !== `management_${s.id}` || s.owner !== 'management' || typeof s.enabled !== 'boolean' || s.authentication !== 'required' || !Array.isArray(s.compatible_zones) || !s.compatible_zones.every(zone) || (s.depends_on !== null && (!Array.isArray(s.depends_on) || s.depends_on.length > 1 || !s.depends_on.every((id: unknown) => (id === 'https' || id === 'ssh') && id !== s.id))) || !Array.isArray(s.endpoints) || s.endpoints.length !== 1 || !endpoint(s.endpoints[0]) || !Array.isArray(s.bindings) || s.bindings.length > 4 || !object(s.lifecycle) || !['verify_listeners', 'verify_rules', 'revert_on_failure', 'confirmed_management_changes'].every((key) => s.lifecycle && object(s.lifecycle) && s.lifecycle[key] === true)) return false;
    ids.add(s.id);
    return s.bindings.every((b: unknown) => object(b) && text(b.interface, 15) && zone(b.zone) && typeof b.local_address === 'string' && canonicalAddress(b.local_address) === b.local_address && typeof b.wan_opt_in === 'boolean' && Array.isArray(b.sources) && b.sources.length > 0 && b.sources.length <= 16 && b.sources.every((p: unknown) => typeof p === 'string' && canonicalCIDR(p) === p));
  });
}
function revision(v: unknown): v is Revision {
  if (!object(v) || !hash(v.hash) || !object(v.config) || !Array.isArray(v.config.rules) || v.config.rules.length !== 0 || v.config.default_action !== 'deny') return false;
  return v.config.schema_version === 3 ? localConfig(v.config.local_services) : (v.config.schema_version === 1 || v.config.schema_version === 2) && v.config.local_services === undefined;
}
export function effectiveResponse(v: unknown): Effective {
  if (!object(v) || typeof v.hash !== 'string' || (v.hash !== '' && !hash(v.hash)) || !['idle', 'armed', 'pending', 'expired', 'blocked', 'unavailable'].includes(String(v.phase)) || typeof v.recovery_required !== 'boolean' || !Array.isArray(v.rules) || v.rules.length > 128 || !Array.isArray(v.listeners) || v.listeners.length > 8) invalid();
  if (!v.rules.every((r: unknown) => object(r) && ['id', 'owner', 'service', 'interface', 'local_address', 'source', 'origin'].every((k) => text(r[k])) && hash(r.revision) && typeof r.management === 'boolean' && zone(r.zone) && (r.family === 'ipv4' || r.family === 'ipv6') && endpoint(r.endpoint) && r.action === 'allow')) invalid();
  if (!v.listeners.every((l: unknown) => object(l) && ['owner', 'service', 'interface', 'local_address'].every((k) => text(l[k])) && l.protocol === 'tcp' && integer(l.port) && l.port >= 1024 && l.port <= 65535)) invalid();
  return v as Effective;
}
export function effectiveMatchesSnapshot(effective: Effective, snapshot: Snapshot): boolean {
  return !effective.recovery_required && !snapshot.recovery_required && effective.hash === snapshot.running.hash && effective.phase === (snapshot.pending ? 'pending' : 'idle');
}
export function statusResponse(v: unknown): Status {
  if (!object(v) || !object(v.snapshot)) invalid();
  const s = v.snapshot;
  if (!integer(s.generation) || !revision(s.running) || !revision(s.startup) || typeof s.recovery_required !== 'boolean') invalid();
  if (s.candidate !== undefined && (!object(s.candidate) || !text(s.candidate.owner, 64) || !hash(s.candidate.base) || !revision(s.candidate.revision))) invalid();
  if (s.pending !== undefined && (!object(s.pending) || !text(s.pending.owner, 64) || !text(s.pending.lease, 64) || !date(s.pending.deadline) || !revision(s.pending.previous))) invalid();
  const e = effectiveResponse(v.effective);
  if (!e.recovery_required && e.hash !== s.running.hash) return { ...(v as Status), effective: { ...e, phase: 'unavailable', recovery_required: true } };
  return v as Status;
}
export function proofResponse(v: unknown): Proof { if (!object(v) || !hash(v.token) || !date(v.expires_at)) invalid(); return v as Proof; }
export function historyResponse(v: unknown): History {
  if (!object(v) || !Array.isArray(v.revisions) || v.revisions.length > 50 || !Array.isArray(v.audit) || v.audit.length > 50 || !integer(v.next_before)) invalid();
  if (!v.revisions.every((r: unknown) => object(r) && integer(r.sequence) && revision(r.revision))) invalid();
  if (!v.audit.every((a: unknown) => object(a) && integer(a.sequence) && date(a.at) && hash(a.running_hash) && ['actor', 'surface', 'operation', 'result'].every((k) => text(a[k])))) invalid();
  return v as History;
}
export function draftConfig(snapshot: Snapshot, interfaces: Interface[]): Config {
  const c = structuredClone(snapshot.candidate?.revision.config ?? snapshot.running.config);
  return { schema_version: 3, default_action: 'deny', rules: [], local_services: c.local_services ?? { schema_version: 1, interfaces: structuredClone(interfaces), services: [] } };
}
export function newService(id: 'https' | 'ssh'): Service {
  return { id, owner: 'management', kind: `management_${id}`, enabled: false, compatible_zones: ['lan', 'wan', 'other'], authentication: 'required', depends_on: [], endpoints: [{ protocol: 'tcp', first_port: id === 'https' ? 18443 : 18222, last_port: id === 'https' ? 18443 : 18222 }], bindings: [], lifecycle: { verify_listeners: true, verify_rules: true, revert_on_failure: true, confirmed_management_changes: true } };
}
export function usableBindingAddress(address: string): boolean {
  return !address.includes(':') || canonicalCIDR(`${address}/10`) !== 'fe80::/10';
}
export function bindingError(binding: Binding, interfaces: Interface[]): 'interfaceError' | 'sourceError' | 'wanError' | null {
  const nic = interfaces.find((i) => i.name === binding.interface && i.zone === binding.zone && i.addresses.includes(binding.local_address));
  if (!nic || !usableBindingAddress(binding.local_address)) return 'interfaceError';
  if (nic.zone === 'wan' && !binding.wan_opt_in) return 'wanError';
  if (!binding.sources.length || binding.sources.length > 16 || binding.sources.some((s) => canonicalCIDR(s) !== s || s.endsWith('/0') || s.includes(':') !== binding.local_address.includes(':') || s.startsWith('ff') || (!s.includes(':') && Number(s.split('.')[0]) >= 224 && Number(s.split('.')[0]) <= 239)) || new Set(binding.sources).size !== binding.sources.length) return 'sourceError';
  for (let i = 0; i < binding.sources.length; i++) for (let j = 0; j < i; j++) {
    const a = binding.sources[i]!; const b = binding.sources[j]!;
    const bits = Math.min(Number(a.split('/')[1]), Number(b.split('/')[1]));
    if (canonicalCIDR(`${a.split('/')[0]}/${bits}`) === canonicalCIDR(`${b.split('/')[0]}/${bits}`)) return 'sourceError';
  }
  return null;
}
export function serviceError(service: Service, interfaces: Interface[], others: Service[]): 'portError' | 'bindingsError' | 'interfaceError' | 'sourceError' | 'wanError' | 'conflictError' | null {
  if (!endpoint(service.endpoints[0])) return 'portError';
  if (service.bindings.length > 4 || !service.bindings.length) return 'bindingsError';
  const seen = new Set<string>();
  for (const b of service.bindings) {
    const error = bindingError(b, interfaces); if (error) return error;
    const key = `${b.interface}/${b.local_address}`;
    if (seen.has(key)) return 'bindingsError';
    seen.add(key);
    if (service.enabled && others.some((s) => s.id !== service.id && s.enabled && s.endpoints[0]?.first_port === service.endpoints[0]?.first_port && s.bindings.some((other) => other.local_address === b.local_address))) return 'conflictError';
  }
  return null;
}
export function proofTokens(value: string): string[] | null {
  const list = value.trim() ? value.trim().split(/\s+/) : [];
  return list.length <= 8 && list.every(hash) && new Set(list).size === list.length ? list : null;
}
