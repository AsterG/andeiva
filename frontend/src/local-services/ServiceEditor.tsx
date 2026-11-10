import { useState } from 'react';
import { Button, Field, Notice, Surface, TextInput } from '../design-system/components.js';
import type { LocalMessages } from './messages.js';
import { canonicalCIDR, serviceError, usableBindingAddress } from './model.js';
import type { Binding, Interface, Service } from './model.js';

export function ServiceEditor({ initial, interfaces, services, copy, disabled, save, cancel }: { initial: Service; interfaces: Interface[]; services: Service[]; copy: LocalMessages; disabled: boolean; save: (s: Service) => void; cancel: () => void }) {
  const [service, setService] = useState(() => structuredClone(initial));
  const [sources, setSources] = useState(() => initial.bindings.map((b) => b.sources.join('\n')));
  const [error, setError] = useState<ReturnType<typeof serviceError>>(null);
  function updateBinding(index: number, value: Binding) { setService((s) => ({ ...s, bindings: s.bindings.map((b, i) => i === index ? value : b) })); setError(null); }
  const available = interfaces.filter((i) => i.addresses.some((a) => usableBindingAddress(a)));
  return <Surface title={`${copy.edit}: ${service.id.toUpperCase()}`}>
    <form onSubmit={(event) => {
      event.preventDefault();
      if (disabled) return;
      const normalized = { ...service, bindings: service.bindings.map((b, i) => ({ ...b, sources: (sources[i] ?? '').split(/\n/).map((p) => p.trim()).filter(Boolean).map((p) => canonicalCIDR(p) ?? p) })) };
      const invalid = serviceError(normalized, interfaces, services);
      setError(invalid);
      if (!invalid) save(normalized);
    }}>
      {error && <Notice title={copy.edit} live>{copy[error]}</Notice>}
      <fieldset className="fw-fields" disabled={disabled}><legend>{service.id.toUpperCase()}</legend>
        <label className="ds-checkbox"><input type="checkbox" checked={service.enabled} onChange={(e) => setService({ ...service, enabled: e.target.checked })} />{copy.enabled}</label>
        <Field id="local-port" label={copy.port}><TextInput id="local-port" type="number" min={1024} max={65535} step={1} value={service.endpoints[0]?.first_port ?? ''} onChange={(e) => { const port = Number(e.target.value); setService({ ...service, endpoints: [{ protocol: 'tcp', first_port: port, last_port: port }] }); }} /></Field>
      </fieldset>
      <h3>{copy.bindings}</h3>
      {service.bindings.map((binding, index) => <fieldset className="fw-fields" disabled={disabled} key={index}><legend>{copy.bindings} {index + 1}</legend>
        <Field id={`local-interface-${index}`} label={copy.interface}><select id={`local-interface-${index}`} className="ds-select" value={binding.interface} onChange={(event) => { const nic = available.find((i) => i.name === event.target.value); if (nic) { updateBinding(index, { ...binding, interface: nic.name, zone: nic.zone, local_address: nic.addresses.find((a) => usableBindingAddress(a)) ?? '', sources: [], wan_opt_in: false }); setSources((values) => values.map((v, i) => i === index ? '' : v)); } }}>{available.map((nic) => <option key={nic.name} value={nic.name}>{nic.name} · {nic.zone.toUpperCase()}</option>)}</select></Field>
        <Field id={`local-address-${index}`} label={copy.address}><select id={`local-address-${index}`} className="ds-select" value={binding.local_address} onChange={(event) => updateBinding(index, { ...binding, local_address: event.target.value })}>{available.find((i) => i.name === binding.interface)?.addresses.filter((a) => usableBindingAddress(a)).map((address) => <option key={address}>{address}</option>)}</select></Field>
        <Field id={`local-sources-${index}`} label={copy.sources} hint={copy.sourcesHint}><textarea id={`local-sources-${index}`} className="ds-input" rows={3} maxLength={1024} value={sources[index] ?? ''} aria-describedby={`local-sources-${index}-hint`} onChange={(event) => setSources((values) => values.map((v, i) => i === index ? event.target.value : v))} /></Field>
        {binding.zone === 'wan' && <label className="ds-checkbox"><input type="checkbox" checked={binding.wan_opt_in} onChange={(event) => updateBinding(index, { ...binding, wan_opt_in: event.target.checked })} />{copy.wanOptIn}</label>}
        <Button type="button" variant="secondary" onClick={() => { setService({ ...service, bindings: service.bindings.filter((_, i) => i !== index) }); setSources((values) => values.filter((_, i) => i !== index)); }}>{copy.removeBinding} {index + 1}</Button>
      </fieldset>)}
      <div className="ds-actions"><Button type="button" variant="secondary" disabled={disabled || service.bindings.length >= 4 || !available.length} onClick={() => { const nic = available.find((i) => i.zone === 'lan') ?? available[0]; if (nic) { setService({ ...service, bindings: [...service.bindings, { interface: nic.name, zone: nic.zone, local_address: nic.addresses.find((a) => usableBindingAddress(a)) ?? '', sources: [], wan_opt_in: false }] }); setSources([...sources, '']); } }}>{copy.addBinding}</Button><Button type="submit" disabled={disabled}>{copy.keep}</Button><Button type="button" variant="secondary" onClick={cancel}>{copy.cancel}</Button></div>
    </form>
  </Surface>;
}
