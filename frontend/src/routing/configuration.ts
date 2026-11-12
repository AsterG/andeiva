import { ApiError, configurationRequest } from '../firewall/api.js';
import type { PortRange } from '../firewall/model.js';
import { canonicalIPv4 } from '../firewall/model.js';
import { interfaceAddress } from './networkPlan.js';

export type NetworkInterfacePlan = {
  id: string; binding: { name: string; hardware_address: string }; role: 'wan' | 'lan' | 'management'; zone: string;
  ipv4: { mode: 'static' | 'dhcp'; address?: string; gateway?: string };
};
export type NetworkPlan = {
  schema_version: 1; interfaces: NetworkInterfacePlan[]; zones: { id: string; kind: NetworkInterfacePlan['role'] }[];
  default_route: { interface_id: string; metric: number };
  dns: { mode: 'none' | 'static' | 'dhcp'; interface_id?: string; servers: string[] }; ipv6_forwarding: 'deny';
};
export type RoutedPath = { from_zone: string; to_zone: string; from_interface: string; to_interface: string };
export type RoutedRule = {
  id: string; enabled: boolean; path: RoutedPath; action: 'allow' | 'deny'; source: string; destination: string;
  protocol: 'tcp' | 'udp'; source_ports: PortRange; destination_ports: PortRange;
};
export type RoutedPolicy = {
  schema_version: 1; lab_only: true; require_identification: false; require_inspection: false;
  network: { hash: string; config: NetworkPlan }; rules: RoutedRule[]; nat: { id: string; path: RoutedPath; source: string }[];
};
export type RoutedConfig = { schema_version: 6; default_action: 'deny'; rules: []; routed: RoutedPolicy };
type WireRoutedConfig = Omit<RoutedConfig, 'routed'> & { routed: Omit<RoutedPolicy, 'rules' | 'nat'> & { rules: RoutedRule[] | null; nat: RoutedPolicy['nat'] | null } };
type Revision = { hash: string; config: WireRoutedConfig | { schema_version: 4; default_action: 'deny'; rules: unknown[] } };
type Composite = { hash: string; config: { schema_version: 7; domains: { firewall: { config_schema: number; revision: string }; local_services: { config_schema: 3; revision: string }; network: { config_schema: 1; revision: string } | null } } };
export type ConfigurationCurrent = {
  global: { lineage_id: string; generation: string; running_revision: string; startup_revision: string }; domain: 'routed';
  domain_generations: { firewall: string; local_services: string; network: string };
  snapshot: {
    generation: string; candidate: { owner: string; base: string; revision: Revision } | null;
    running: Revision; startup: Revision; last_good: Revision;
    pending: { lease?: string; owner: string; previous: Revision; deadline: string } | null; recovery_required: boolean; revoked: string[];
  };
  routed: { schema_version: 7; running: Composite; startup: Composite; last_good: Composite; candidate?: Composite; local_services: unknown; candidate_group?: unknown; confirmation?: { origin_commit_operation_id: string; target_revision: string; confirmation_deadline: string } };
};
export type OperationRequest = { operation: 'stage' | 'validate' | 'commit' | 'confirm' | 'save' | 'rollback'; config?: RoutedConfig; confirm_seconds?: string; target_revision?: string; origin_commit_operation_id?: string };
export type ConfigurationOperation = {
  id: string; namespace_id: string; domain: 'routed'; kind: OperationRequest['operation']; state: 'accepted' | 'pending' | 'final' | 'uncertain';
  expected_generation: string; outcome?: { code: string; error_code?: string; confirmation_deadline?: string };
};
export type OperationResult = { schema_version: 2; operation: ConfigurationOperation; current: ConfigurationCurrent };
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const operationID = (value: unknown): value is string => typeof value === 'string' && /^[a-zA-Z0-9_.-]{1,128}$/.test(value);
export function decimalGeneration(value: unknown): value is string {
  return typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  return value as Record<string, unknown>;
}
const identifier = (value: unknown): value is string => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(value);
function validatePolicy(plan: Record<string, unknown>, routed: Record<string, unknown>) {
  if (!Array.isArray(plan.interfaces) || !Array.isArray(plan.zones)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  const interfaces = new Map<string, Record<string, unknown>>(), zones = new Map<string, string>();
  for (const value of plan.zones) {
    const zone = object(value);
    if (!identifier(zone.id) || typeof zone.kind !== 'string' || !['lan', 'wan', 'management'].includes(zone.kind) || zones.has(zone.id)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    zones.set(zone.id, zone.kind);
  }
  for (const value of plan.interfaces) {
    const iface = object(value), binding = object(iface.binding), ipv4 = object(iface.ipv4);
    if (!identifier(iface.id) || interfaces.has(iface.id) || typeof iface.role !== 'string' || typeof iface.zone !== 'string' || zones.get(iface.zone) !== iface.role || typeof binding.name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/.test(binding.name) || typeof binding.hardware_address !== 'string' || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(binding.hardware_address)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    if (ipv4.mode === 'static') {
      if (typeof ipv4.address !== 'string' || !interfaceAddress(ipv4.address) || ipv4.gateway !== undefined && (typeof ipv4.gateway !== 'string' || !interfaceAddress(`${ipv4.gateway}/32`))) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    } else if (ipv4.mode !== 'dhcp' || iface.role !== 'wan' || ipv4.address !== undefined || ipv4.gateway !== undefined) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    interfaces.set(iface.id, iface);
  }
  const route = object(plan.default_route), dns = object(plan.dns);
  if (typeof route.interface_id !== 'string' || interfaces.get(route.interface_id)?.role !== 'wan' || !Number.isInteger(route.metric) || Number(route.metric) < 1 || Number(route.metric) > 65535 || !['none', 'static', 'dhcp'].includes(typeof dns.mode === 'string' ? dns.mode : '') || !Array.isArray(dns.servers) || dns.servers.length > 4 || !dns.servers.every((server) => typeof server === 'string' && interfaceAddress(`${server}/32`))) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  const validPath = (value: unknown) => {
    const path = object(value), a = typeof path.from_interface === 'string' ? interfaces.get(path.from_interface) : undefined, b = typeof path.to_interface === 'string' ? interfaces.get(path.to_interface) : undefined;
    return a && b && a.id !== b.id && a.role !== 'management' && b.role !== 'management' && a.zone === path.from_zone && b.zone === path.to_zone;
  };
  const ports = (value: unknown) => { const range = object(value); return Number.isInteger(range.from) && Number.isInteger(range.to) && Number(range.from) > 0 && Number(range.to) >= Number(range.from) && Number(range.to) <= 65535; };
  const seen = new Set<string>();
  for (const value of (routed.rules ?? []) as unknown[]) {
    const rule = object(value);
    if (!identifier(rule.id) || seen.has(rule.id) || typeof rule.enabled !== 'boolean' || !['allow', 'deny'].includes(typeof rule.action === 'string' ? rule.action : '') || !['tcp', 'udp'].includes(typeof rule.protocol === 'string' ? rule.protocol : '') || typeof rule.source !== 'string' || canonicalIPv4(rule.source) !== rule.source || typeof rule.destination !== 'string' || canonicalIPv4(rule.destination) !== rule.destination || !ports(rule.source_ports) || !ports(rule.destination_ports) || !validPath(rule.path)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    seen.add(rule.id);
  }
  for (const value of (routed.nat ?? []) as unknown[]) {
    const nat = object(value);
    if (!identifier(nat.id) || seen.has(nat.id) || typeof nat.source !== 'string' || canonicalIPv4(nat.source) !== nat.source || !validPath(nat.path)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    seen.add(nat.id);
  }
}
function revision(value: unknown): Revision {
  const entry = object(value), config = object(entry.config);
  if (!hash(entry.hash) || config.schema_version !== 4 && config.schema_version !== 6 || config.default_action !== 'deny' || !Array.isArray(config.rules) || config.rules.length > 128) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  if (config.schema_version === 6) {
    const routed = object(config.routed), network = object(routed.network), plan = object(network.config);
    if (config.rules.length || routed.schema_version !== 1 || routed.lab_only !== true || routed.require_identification !== false || routed.require_inspection !== false || !hash(network.hash) || plan.schema_version !== 1 || plan.ipv6_forwarding !== 'deny' || !Array.isArray(plan.interfaces) || plan.interfaces.length < 2 || plan.interfaces.length > 32 || !Array.isArray(plan.zones) || plan.zones.length > 32 || !(routed.rules === null || Array.isArray(routed.rules) && routed.rules.length <= 128) || !(routed.nat === null || Array.isArray(routed.nat) && routed.nat.length <= 32)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    validatePolicy(plan, routed);
  }
  return entry as Revision;
}
export function currentResponse(value: unknown): ConfigurationCurrent {
  const data = object(value), current = object(data.current), global = object(current.global), snapshot = object(current.snapshot), routed = object(current.routed), generations = object(current.domain_generations);
  if (data.schema_version !== 2 || current.domain !== 'routed' || routed.schema_version !== 7 || !operationID(global.lineage_id) || !decimalGeneration(global.generation) || !decimalGeneration(snapshot.generation) || !decimalGeneration(generations.local_services) || generations.firewall !== snapshot.generation || generations.network !== generations.firewall || typeof snapshot.recovery_required !== 'boolean') throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  for (const key of ['running', 'startup', 'last_good'] as const) {
    const component = revision(snapshot[key]), composite = object(routed[key]), config = object(composite.config), domains = object(config.domains), firewall = object(domains.firewall), local = object(domains.local_services);
    if (!hash(composite.hash) || config.schema_version !== 7 || firewall.revision !== component.hash || firewall.config_schema !== component.config.schema_version || local.config_schema !== 3 || !hash(local.revision)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    if (component.config.schema_version === 6) {
      const network = object(domains.network);
      if (network.config_schema !== 1 || network.revision !== component.config.routed.network.hash) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    } else if (domains.network !== null) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    if (key !== 'last_good' && global[`${key}_revision`] !== composite.hash) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  }
  if (snapshot.candidate !== null) {
    const candidate = object(snapshot.candidate);
    revision(candidate.revision);
    if (!operationID(candidate.owner) || candidate.base !== object(snapshot.running).hash || !routed.candidate || !routed.candidate_group) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  } else if (routed.candidate || routed.candidate_group) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  if (snapshot.pending !== null) {
    const pending = object(snapshot.pending);
    revision(pending.previous);
    if (!operationID(pending.owner) || !operationID(pending.lease) || typeof pending.deadline !== 'string' || !Number.isFinite(Date.parse(pending.deadline))) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    const confirmation = object(routed.confirmation);
    if (!operationID(confirmation.origin_commit_operation_id) || confirmation.target_revision !== global.running_revision || confirmation.confirmation_deadline !== pending.deadline) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  } else if (routed.confirmation !== undefined) {
    throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  }
  return structuredClone(current) as ConfigurationCurrent;
}
export async function readCurrent(signal?: AbortSignal): Promise<ConfigurationCurrent> {
  return currentResponse(await configurationRequest('config/current', undefined, undefined, signal));
}
export function operationResponse(value: unknown, expectedID?: string): OperationResult {
  const data = object(value), operation = object(data.operation);
  if (data.schema_version !== 2 || !operationID(operation.id) || !operationID(operation.namespace_id) || operation.domain !== 'routed' || !['accepted', 'pending', 'final', 'uncertain'].includes(typeof operation.state === 'string' ? operation.state : '') || !['stage', 'validate', 'commit', 'confirm', 'save', 'rollback'].includes(typeof operation.kind === 'string' ? operation.kind : '') || !decimalGeneration(operation.expected_generation) || (expectedID !== undefined && operation.id !== expectedID)) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  if (operation.outcome !== undefined) {
    const outcome = object(operation.outcome);
    if (!['applied', 'applied_pending_confirmation', 'rejected', 'failed_rolled_back', 'expired_without_effects'].includes(typeof outcome.code === 'string' ? outcome.code : '')) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  }
  if (operation.state === 'final' && !operation.outcome) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  return { schema_version: 2, operation: structuredClone(operation) as ConfigurationOperation, current: currentResponse(data) };
}
export async function admitOperation(current: ConfigurationCurrent, request: OperationRequest, csrf: string): Promise<OperationResult> {
  const namespace = object(await configurationRequest('config/operation-namespaces', { domain: 'routed' }, csrf));
  if (namespace.schema_version !== 2 || !operationID(namespace.namespace_id) || namespace.state !== 'open') throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  const result = operationResponse(await configurationRequest('config/operations/admit', { namespace_id: namespace.namespace_id, expected_generation: current.global.generation, request }, csrf));
  if (result.operation.namespace_id !== namespace.namespace_id || result.operation.kind !== request.operation || result.operation.expected_generation !== current.global.generation || result.operation.state !== 'accepted') throw new ApiError('ANDEIVA_RESPONSE_INVALID');
  return result;
}
export async function executeOperation(id: string, csrf: string): Promise<OperationResult> {
  if (!operationID(id)) throw new ApiError('ANDEIVA_INVALID_ARGUMENT');
  return operationResponse(await configurationRequest(`config/operations/${id}/execute`, {}, csrf), id);
}
export async function queryOperation(id: string): Promise<OperationResult> {
  if (!operationID(id)) throw new ApiError('ANDEIVA_INVALID_ARGUMENT');
  return operationResponse(await configurationRequest(`config/operations/${id}`), id);
}
export async function closeOperationNamespace(id: string, csrf: string): Promise<void> {
  if (!operationID(id)) throw new ApiError('ANDEIVA_INVALID_ARGUMENT');
  const result = object(await configurationRequest(`config/operation-namespaces/${id}/close`, {}, csrf));
  if (result.schema_version !== 2 || result.namespace_id !== id || result.state !== 'closed') throw new ApiError('ANDEIVA_RESPONSE_INVALID');
}
