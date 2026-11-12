export type NetworkAddress = { ip: string; prefix: string | null };
export type NetworkInterface = {
  name: string;
  hardware_address: string;
  mtu: number;
  admin_up: boolean;
  running: boolean;
  kind: 'unknown' | 'loopback' | 'virtual' | 'device-backed';
  addresses: NetworkAddress[];
};
export type NetworkInventory = { schema_version: 1; interfaces: NetworkInterface[] };

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function fields(value: Record<string, unknown>, expected: string[]): boolean {
  return Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}
function ip(value: unknown): value is string {
  if (typeof value !== 'string' || !value.length || value.length > 45) return false;
  if (value.includes(':')) {
    if (!/^[a-fA-F0-9:.]+$/.test(value)) return false;
    try { return new URL(`http://[${value}]/`).hostname.length > 2; } catch { return false; }
  }
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
}
function address(value: unknown): value is NetworkAddress {
  if (!object(value) || !fields(value, ['ip', 'prefix']) || !ip(value.ip)) return false;
  if (value.prefix === null) return true;
  if (typeof value.prefix !== 'string') return false;
  const parts = value.prefix.split('/');
  return parts.length === 2 && parts[0] === value.ip && /^(0|[1-9][0-9]{0,2})$/.test(parts[1] ?? '') && Number(parts[1]) <= (value.ip.includes(':') ? 128 : 32);
}

// Do not infer leases, carrier quality or authorization from an interface sample.
export function networkInventoryResponse(value: unknown): NetworkInventory | null {
  if (!object(value) || !fields(value, ['schema_version', 'interfaces']) || value.schema_version !== 1 || !Array.isArray(value.interfaces) || value.interfaces.length > 256) return null;
  const names = new Set<string>();
  for (const item of value.interfaces) {
    if (!object(item) || !fields(item, ['name', 'hardware_address', 'mtu', 'admin_up', 'running', 'kind', 'addresses']) ||
      typeof item.name !== 'string' || !item.name.length || new TextEncoder().encode(item.name).length > 256 || /[\u0000-\u001f\u007f]/.test(item.name) || names.has(item.name) ||
      typeof item.hardware_address !== 'string' || (item.hardware_address !== '' && !([6, 8, 20].includes(item.hardware_address.split(':').length) && item.hardware_address.split(':').every((part) => /^[0-9a-f]{2}$/.test(part)))) ||
      !Number.isSafeInteger(item.mtu) || (item.mtu as number) < 0 || (item.mtu as number) > 2147483647 ||
      typeof item.admin_up !== 'boolean' || typeof item.running !== 'boolean' ||
      typeof item.kind !== 'string' || !['unknown', 'loopback', 'virtual', 'device-backed'].includes(item.kind) ||
      !Array.isArray(item.addresses) || item.addresses.length > 256 || !item.addresses.every(address)) return null;
    const seen = new Set<string>();
    for (const entry of item.addresses as NetworkAddress[]) {
      const key = `${entry.ip}/${entry.prefix}`;
      if (seen.has(key)) return null;
      seen.add(key);
    }
    names.add(item.name);
  }
  return structuredClone(value) as NetworkInventory;
}
