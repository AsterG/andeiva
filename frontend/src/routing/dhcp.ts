import { ApiError } from '../firewall/api.js';
import { canonicalIPv4 } from '../firewall/model.js';
import type { NetworkPlan } from './configuration.js';

export type DHCPScope = {
  id: string; interface_id: string; subnet: string; router: string;
  pools: { first: string; last: string }[]; excluded: string[];
  reservations: { mac: string; address: string }[]; dns: string[]; ntp: string[]; domain: string;
  lease_seconds: number; renew_seconds: number; rebind_seconds: number;
};
export type DHCPConfig = { schema_version: 1; enabled: boolean; scopes: DHCPScope[] };
const invalid = (): never => { throw new ApiError('ANDEIVA_DHCP_SERVER_INVALID'); };
function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !keys.includes(key)) || keys.some((key) => !(key in record))) return invalid();
  return record;
}
function array(value: unknown, max: number): unknown[] {
  // Go nil slices are valid on the wire; preserve them in the received revision.
  if (value === null) return [];
  if (!Array.isArray(value) || value.length > max) return invalid();
  return value;
}
function ip(value: unknown, requireUnicast = true): number {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(value)) return invalid();
  const bytes = value.split('.').map(Number);
  const number = bytes.reduce((n, byte) => n * 256 + byte, 0);
  if (bytes.some((byte) => byte > 255) || requireUnicast && (bytes[0] === 127 || bytes[0] === 169 && bytes[1] === 254 || bytes[0]! >= 224 && bytes[0]! <= 239 || number === 0 || number === 4294967295)) return invalid();
  return number;
}
const identifier = (value: unknown): value is string => typeof value === 'string' && /^[a-z0-9_-]{1,64}$/.test(value);
const unique = (values: unknown[]) => new Set(values).size === values.length;

/** Validate against selected static LANs, including retained disabled settings. */
export function validateDHCP(value: unknown, network: NetworkPlan): void {
  if (new TextEncoder().encode(JSON.stringify(value)).length > 65536) invalid();
  const config = object(value, ['schema_version', 'enabled', 'scopes']);
  const scopes = array(config.scopes, 32);
  if (config.schema_version !== 1 || typeof config.enabled !== 'boolean' || config.enabled && !scopes.length) invalid();
  const ids = new Set<string>(), bindings = new Set<string>(), subnets: [number, number][] = [];
  let capacity = 0;
  for (const value of scopes) {
    const scope = object(value, ['id', 'interface_id', 'subnet', 'router', 'pools', 'excluded', 'reservations', 'dns', 'ntp', 'domain', 'lease_seconds', 'renew_seconds', 'rebind_seconds']);
    if (!identifier(scope.id) || !identifier(scope.interface_id) || ids.has(scope.id) || bindings.has(scope.interface_id)) invalid();
    ids.add(scope.id as string); bindings.add(scope.interface_id as string);
    if (typeof scope.subnet !== 'string' || canonicalIPv4(scope.subnet) !== scope.subnet) invalid();
    const [address, prefix] = (scope.subnet as string).split('/'), bits = Number(prefix), first = ip(address, false), last = first + 2 ** (32 - bits) - 1;
    if (bits < 1 || bits > 30 || subnets.some(([a, b]) => first <= b && last >= a)) invalid();
    subnets.push([first, last]);
    const host = (value: unknown) => { const n = ip(value); if (n <= first || n >= last) invalid(); return n; };
    const router = host(scope.router);
    const iface = network.interfaces.filter((iface) => iface.id === scope.interface_id);
    if (iface.length !== 1 || iface[0]!.role !== 'lan' || iface[0]!.ipv4.mode !== 'static' || iface[0]!.ipv4.address !== `${scope.router}/${bits}`) invalid();
    const pools = array(scope.pools, 32), excluded = array(scope.excluded, 256), reservations = array(scope.reservations, 256);
    if (!pools.length || !unique(excluded)) invalid();
    excluded.forEach(host);
    const ranges: [number, number][] = [];
    for (const value of pools) {
      const pool = object(value, ['first', 'last']), a = host(pool.first), b = host(pool.last);
      if (a > b || ranges.some(([x, y]) => a <= y && b >= x) || a <= router && router <= b && !excluded.includes(scope.router)) invalid();
      ranges.push([a, b]); capacity += b - a + 1;
      if (capacity > 65536) invalid();
    }
    const macs = new Set<string>(), reserved = new Set<string>();
    for (const value of reservations) {
      const reservation = object(value, ['mac', 'address']);
      if (typeof reservation.mac !== 'string' || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(reservation.mac) || parseInt(reservation.mac.slice(0, 2), 16) % 2 || reservation.mac === '00:00:00:00:00:00' || macs.has(reservation.mac)) invalid();
      host(reservation.address);
      if (reserved.has(reservation.address as string) || excluded.includes(reservation.address) || reservation.address === scope.router) invalid();
      macs.add(reservation.mac as string); reserved.add(reservation.address as string);
    }
    for (const key of ['dns', 'ntp']) { const values = array(scope[key], 4); if (!unique(values)) invalid(); values.forEach((value) => ip(value)); }
    if (typeof scope.domain !== 'string' || scope.domain.length > 253 || scope.domain !== '' && !scope.domain.split('.').every((label) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) invalid();
    const lease = scope.lease_seconds, renew = scope.renew_seconds, rebind = scope.rebind_seconds;
    if (typeof lease !== 'number' || typeof renew !== 'number' || typeof rebind !== 'number' || ![lease, renew, rebind].every(Number.isInteger) || lease < 60 || lease > 604800 || renew < 1 || renew >= rebind || rebind >= lease) invalid();
  }
}

export function editableDHCP(value?: DHCPConfig): DHCPConfig {
  const config: DHCPConfig = structuredClone(value ?? { schema_version: 1, enabled: false, scopes: [] });
  config.scopes = (config.scopes ?? []).map((scope) => ({ ...scope, pools: scope.pools ?? [], excluded: scope.excluded ?? [], reservations: scope.reservations ?? [], dns: scope.dns ?? [], ntp: scope.ntp ?? [] }));
  return config;
}
