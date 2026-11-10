export type PortRange = { from: number; to: number };
export type Rule = { id: string; enabled?: boolean; action: 'allow' | 'deny'; match: { source: string; destination: string; protocol: 'tcp' | 'udp'; source_ports: PortRange; destination_ports: PortRange } };
export type Config = { schema_version: number; default_action: 'deny'; rules: Rule[] };
export type Revision = { hash: string; config: Config };
export type Snapshot = {
  generation: number;
  candidate?: { owner: string; base: string; revision: Revision };
  running: Revision;
  startup: Revision;
  pending?: { owner: string; previous: Revision; deadline: string };
  recovery_required: boolean;
};
export type FirewallState = { snapshot: Snapshot; effective: { revision: string; state: 'verified' | 'pending_confirmation' | 'recovery_required' | 'unavailable'; rules: { id: string; packets: number; bytes: number }[] } };
export type Session = { username: string; role: 'admin' | 'viewer'; csrf: string; expires_at: string };
export type Operation = 'stage' | 'validate' | 'commit' | 'confirm' | 'save' | 'rollback';
export type Transaction = { operation: Operation; key: string; expected_generation: number; config?: Config; confirm_for?: number; target?: string };
export type Audit = { sequence: number; at: string; actor: string; surface: string; operation: string; result: string; running_hash: string };
export type History = { revisions: { sequence: number; revision: Revision }[]; audit: Audit[]; next_before: number };

export type RuleDraft = { id: string; enabled?: boolean; action: 'allow' | 'deny'; source: string; destination: string; protocol: 'tcp' | 'udp'; source_ports: string; destination_ports: string };
export type RuleErrors = Partial<Record<keyof RuleDraft, 'idError' | 'duplicateError' | 'cidrError' | 'portsError'>>;
export const emptyRule: RuleDraft = { id: '', action: 'deny', source: '', destination: '', protocol: 'tcp', source_ports: '1-65535', destination_ports: '' };

export function canonicalIPv4(value: string): string | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(value.trim());
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  if (octets.some((part) => part > 255) || match.slice(1, 5).some((part) => part.length > 1 && part.startsWith('0'))) return null;
  const prefix = Number(match[5] ?? 32);
  if (prefix > 32) return null;
  const address = octets.reduce((acc, octet) => ((acc << 8) | octet) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (address & mask) >>> 0;
  return `${[24, 16, 8, 0].map((shift) => (network >>> shift) & 255).join('.')}/${prefix}`;
}

export function parsePorts(value: string): PortRange | null {
  const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(value.trim());
  if (!match) return null;
  const from = Number(match[1]);
  const to = Number(match[2] ?? from);
  return from >= 1 && to <= 65535 && from <= to ? { from, to } : null;
}
export function formatPorts(range: PortRange): string { return range.from === range.to ? String(range.from) : `${range.from}-${range.to}`; }
export function editRule(rule: Rule): RuleDraft { return { id: rule.id, ...(rule.enabled !== undefined ? { enabled: rule.enabled } : {}), action: rule.action, source: rule.match.source, destination: rule.match.destination, protocol: rule.match.protocol, source_ports: formatPorts(rule.match.source_ports), destination_ports: formatPorts(rule.match.destination_ports) }; }
export function validateRule(draft: RuleDraft, rules: Rule[], index: number | null): { errors: RuleErrors; rule?: Rule } {
  const errors: RuleErrors = {};
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(draft.id)) errors.id = 'idError';
  else if (rules.some((rule, position) => rule.id === draft.id && position !== index)) errors.id = 'duplicateError';
  const source = canonicalIPv4(draft.source);
  const destination = canonicalIPv4(draft.destination);
  const sourcePorts = parsePorts(draft.source_ports);
  const destinationPorts = parsePorts(draft.destination_ports);
  if (!source) errors.source = 'cidrError';
  if (!destination) errors.destination = 'cidrError';
  if (!sourcePorts) errors.source_ports = 'portsError';
  if (!destinationPorts) errors.destination_ports = 'portsError';
  if (Object.keys(errors).length || !source || !destination || !sourcePorts || !destinationPorts) return { errors };
  return { errors, rule: { id: draft.id, ...(draft.enabled !== undefined ? { enabled: draft.enabled } : {}), action: draft.action, match: { source, destination, protocol: draft.protocol, source_ports: sourcePorts, destination_ports: destinationPorts } } };
}

export function configWithRules(config: Config, rules: Rule[]): Config {
  if (config.schema_version === 4 || rules.some((rule) => rule.enabled !== undefined)) return { ...config, schema_version: 4, rules: rules.map((rule) => ({ ...rule, enabled: rule.enabled ?? true })) };
  return { ...config, rules };
}

export function draftConfig(snapshot: Snapshot): Config { return structuredClone(snapshot.candidate?.revision.config ?? snapshot.running.config); }
