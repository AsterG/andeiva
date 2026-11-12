import { useId, useState } from 'react';
import { Button, Field, Notice, TextInput } from '../design-system/components.js';
import { FloatingWindow } from '../design-system/FloatingWindow.js';
import { floatingWindowMessages } from '../design-system/floatingWindowMessages.js';
import type { Locale } from '../messages.js';
import type { NetworkInventory } from './inventory.js';
import type { NetworkPlan, RoutedConfig } from './configuration.js';
import { interfaceAddress, networkRevision } from './networkPlan.js';
import { workspaceMessages } from './workspaceMessages.js';

export function NetworkEditor({ locale, inventory, current, onSave, onClose }: { locale: Locale; inventory: NetworkInventory; current: RoutedConfig | null; onSave: (config: RoutedConfig) => void; onClose: () => void }) {
  const copy = workspaceMessages[locale], prefix = useId();
  const previous = current?.routed.network.config;
  const originalWAN = previous?.interfaces.find((iface) => iface.role === 'wan');
  const originalLAN = previous?.interfaces.find((iface) => iface.role === 'lan');
  const interfaces = inventory.interfaces.filter((iface) => iface.name !== 'lo' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/.test(iface.name) && /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(iface.hardware_address));
  const [wan, setWAN] = useState(originalWAN?.binding.name ?? '');
  const [lan, setLAN] = useState(originalLAN?.binding.name ?? '');
  const [wanIP, setWANIP] = useState(originalWAN?.ipv4.address ?? '');
  const [lanIP, setLANIP] = useState(originalLAN?.ipv4.address ?? '');
  const [gateway, setGateway] = useState(originalWAN?.ipv4.gateway ?? '');
  const [metric, setMetric] = useState(String(previous?.default_route.metric ?? 100));
  const [invalid, setInvalid] = useState(false), [busy, setBusy] = useState(false);
  return <FloatingWindow title={copy.editNetwork} description={copy.static} labels={floatingWindowMessages[locale]} onClose={onClose}>
    <p>{copy.editHint}</p>
    {invalid && <Notice title={copy.error} live>{copy.invalid}</Notice>}
    <form onSubmit={(event) => {
      event.preventDefault();
      if (busy) return;
      const observedWAN = interfaces.find((iface) => iface.name === wan), observedLAN = interfaces.find((iface) => iface.name === lan);
      if (!observedWAN || !observedLAN || wan === lan || !interfaceAddress(wanIP) || !interfaceAddress(lanIP) || !interfaceAddress(`${gateway}/32`) || !/^[1-9][0-9]{0,4}$/.test(metric) || Number(metric) > 65535 || previous && (previous.interfaces.length !== 2 || originalWAN?.ipv4.mode !== 'static' || originalLAN?.ipv4.mode !== 'static')) { setInvalid(true); return; }
      const wanID = originalWAN?.id ?? 'wan', lanID = originalLAN?.id ?? 'lan';
      const wanZone = originalWAN?.zone ?? 'wan', lanZone = originalLAN?.zone ?? 'lan';
      const plan: NetworkPlan = { schema_version: 1, ipv6_forwarding: 'deny', interfaces: [
        { id: wanID, binding: { name: observedWAN.name, hardware_address: observedWAN.hardware_address }, role: 'wan', zone: wanZone, ipv4: { mode: 'static', address: wanIP.trim(), gateway: gateway.trim() } },
        { id: lanID, binding: { name: observedLAN.name, hardware_address: observedLAN.hardware_address }, role: 'lan', zone: lanZone, ipv4: { mode: 'static', address: lanIP.trim() } },
      ], zones: [{ id: wanZone, kind: 'wan' }, { id: lanZone, kind: 'lan' }], default_route: { interface_id: wanID, metric: Number(metric) }, dns: previous?.dns ?? { mode: 'none', servers: [] } };
      setBusy(true); setInvalid(false);
      void networkRevision(plan).then((network) => onSave({ schema_version: 6, default_action: 'deny', rules: [], routed: current ? { ...structuredClone(current.routed), network } : { schema_version: 1, lab_only: true, require_identification: false, require_inspection: false, network, rules: [], nat: [] } })).catch(() => { setBusy(false); setInvalid(true); });
    }}>
      <fieldset className="fw-fields" disabled={busy}>
        {([{ label: copy.wan, value: wan, change: setWAN, key: 'wan' }, { label: copy.lan, value: lan, change: setLAN, key: 'lan' }]).map((field) => <Field key={field.key} id={`${prefix}-${field.key}`} label={field.label}><select id={`${prefix}-${field.key}`} className="ds-select" value={field.value} required onChange={(event) => field.change(event.target.value)}><option value="">—</option>{interfaces.map((iface) => <option key={iface.name} value={iface.name}>{iface.name} · {iface.hardware_address}</option>)}</select></Field>)}
        {([{ key: 'wan-ip', label: `${copy.wan} · ${copy.address}`, value: wanIP, change: setWANIP }, { key: 'lan-ip', label: `${copy.lan} · ${copy.address}`, value: lanIP, change: setLANIP }, { key: 'gateway', label: copy.gateway, value: gateway, change: setGateway }, { key: 'metric', label: copy.metric, value: metric, change: setMetric }]).map((field) => <Field key={field.key} id={`${prefix}-${field.key}`} label={field.label}><TextInput id={`${prefix}-${field.key}`} value={field.value} required maxLength={32} onChange={(event) => field.change(event.target.value)} /></Field>)}
      </fieldset>
      <div className="ds-actions"><Button type="submit" disabled={busy}>{copy.localDraft}</Button><Button variant="secondary" disabled={busy} onClick={onClose}>{copy.cancel}</Button></div>
    </form>
  </FloatingWindow>;
}
