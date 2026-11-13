import { canonicalIPv4 } from '../firewall/model.js';
import type { NetworkPlan } from './configuration.js';

export function interfaceAddress(value: string): string | null {
  const input = value.trim();
  if (!/^([0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[1-9]|[12][0-9]|3[0-2])$/.test(input) || canonicalIPv4(input) === null) return null;
  const [address, bits] = input.split('/');
  const octets = address!.split('.').map(Number);
  if (octets[0] === 0 || octets[0] === 127 || octets[0]! >= 224 || address === '255.255.255.255') return null;
  const prefix = Number(bits);
  const host = octets.reduce((acc, part) => ((acc << 8) | part) >>> 0, 0);
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const network = (host & mask) >>> 0;
  if (prefix < 31 && (host === network || host === ((network | ~mask) >>> 0))) return null;
  return input;
}

// Match the canonical networkplan.Config property order and identity ordering.
// The server remains authoritative for inventory binding, conflicts and effects.
export async function networkRevision(plan: NetworkPlan): Promise<{ hash: string; config: NetworkPlan }> {
  const interfaces = plan.interfaces.map((iface) => ({
    id: iface.id, binding: { name: iface.binding.name, hardware_address: iface.binding.hardware_address }, role: iface.role, zone: iface.zone,
    ipv4: { mode: iface.ipv4.mode, ...(iface.ipv4.address ? { address: iface.ipv4.address } : {}), ...(iface.ipv4.gateway ? { gateway: iface.ipv4.gateway } : {}) },
  })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const config: NetworkPlan = {
    schema_version: 1, interfaces, zones: plan.zones.map((zone) => ({ id: zone.id, kind: zone.kind })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    default_route: { interface_id: plan.default_route.interface_id, metric: plan.default_route.metric },
    dns: { mode: plan.dns.mode, ...(plan.dns.interface_id ? { interface_id: plan.dns.interface_id } : {}), servers: [...plan.dns.servers] }, ipv6_forwarding: 'deny',
  };
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(config)));
  return { hash: [...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, '0')).join(''), config };
}
