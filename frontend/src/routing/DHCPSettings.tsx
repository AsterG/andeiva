import { useEffect, useId, useState } from 'react';
import { Button, DataTable, Field, Notice, StatusBadge, Surface, TextInput } from '../design-system/components.js';
import { FloatingWindow } from '../design-system/FloatingWindow.js';
import { floatingWindowMessages } from '../design-system/floatingWindowMessages.js';
import { canonicalIPv4 } from '../firewall/model.js';
import type { Locale } from '../messages.js';
import type { RoutedConfig } from './configuration.js';
import { editableDHCP, validateDHCP } from './dhcp.js';
import type { DHCPConfig, DHCPScope } from './dhcp.js';
import { dhcpMessages } from './dhcpMessages.js';

export function DHCPSettings({ locale, current, admin, editable, editing, onEditing, onChange }: { locale: Locale; current: RoutedConfig | null; admin: boolean; editable: boolean; editing: boolean; onEditing: (value: boolean) => void; onChange: (config: RoutedConfig) => void }) {
  const copy = dhcpMessages[locale], prefix = useId();
  const [editor, setEditor] = useState<{ index: number | null } | null>(null);
  useEffect(() => () => onEditing(false), [onEditing]);
  const config = editableDHCP(current?.routed.dhcp_server);
  const lans = current?.routed.network.config.interfaces.filter((iface) => iface.role === 'lan' && iface.ipv4.mode === 'static' && Number(iface.ipv4.address?.split('/')[1]) <= 30) ?? [];
  function change(value: DHCPConfig) {
    if (!current || !editable) return;
    onChange({ ...current, routed: { ...current.routed, schema_version: 2, dhcp_server: value } });
  }
  function close() { setEditor(null); onEditing(false); }
  return <Surface title={copy.title} description={copy.hint}>
    <StatusBadge tone="info">{config.enabled ? copy.configured : copy.disabled}</StatusBadge>
    <p>{copy.retained}</p>
    {!lans.length && <p>{copy.noLAN}</p>}
    {admin && <div className="ds-actions"><label className="fw-enabled-switch"><input type="checkbox" checked={config.enabled} disabled={!editable || editing || !config.scopes.length} onChange={(event) => change({ ...config, enabled: event.target.checked })} />{copy.enabled}</label><Button disabled={!editable || editing || !lans.length || config.scopes.length >= 32} onClick={() => { setEditor({ index: null }); onEditing(true); }}>{copy.addScope}</Button></div>}
    {config.scopes.length ? <DataTable caption={copy.title}><thead><tr><th scope="col">{copy.scope}</th><th scope="col">{copy.binding}</th><th scope="col">{copy.subnet}</th><th scope="col">{copy.pools}</th><th scope="col">{copy.editScope}</th></tr></thead><tbody>{config.scopes.map((scope, index) => <tr key={scope.id}><th scope="row">{scope.id}</th><td>{scope.interface_id}</td><td>{scope.subnet}</td><td>{scope.pools.map((pool) => `${pool.first}–${pool.last}`).join(', ')}</td><td>{admin && <div className="ds-actions"><Button variant="secondary" disabled={!editable || editing} onClick={() => { setEditor({ index }); onEditing(true); }}>{copy.editScope}</Button><Button variant="secondary" disabled={!editable || editing} aria-label={`${copy.remove}: ${scope.id}`} onClick={() => change({ ...config, enabled: config.scopes.length > 1 && config.enabled, scopes: config.scopes.filter((_, i) => i !== index) })}>{copy.remove}</Button></div>}</td></tr>)}</tbody></DataTable> : <p>{copy.empty}</p>}
    {editor && current && <ScopeEditor key={`${prefix}-${editor.index}`} locale={locale} current={current} config={config} index={editor.index} disabled={!editable} onClose={close} onSave={(next) => { change(next); close(); }} />}
  </Surface>;
}

function ScopeEditor({ locale, current, config, index, disabled, onClose, onSave }: { locale: Locale; current: RoutedConfig; config: DHCPConfig; index: number | null; disabled: boolean; onClose: () => void; onSave: (value: DHCPConfig) => void }) {
  const copy = dhcpMessages[locale], prefix = useId();
  const lans = current.routed.network.config.interfaces.filter((iface) => iface.role === 'lan' && iface.ipv4.mode === 'static' && Number(iface.ipv4.address?.split('/')[1]) <= 30);
  const existing = index === null ? undefined : config.scopes[index];
  const [scope, setScope] = useState<DHCPScope>(() => existing ? structuredClone(existing) : { id: '', interface_id: '', subnet: '', router: '', pools: [{ first: '', last: '' }], excluded: [], reservations: [], dns: [], ntp: [], domain: '', lease_seconds: 3600, renew_seconds: 1800, rebind_seconds: 3150 });
  const [lists, setLists] = useState({ excluded: scope.excluded.join(', '), dns: scope.dns.join(', '), ntp: scope.ntp.join(', ') });
  const [invalid, setInvalid] = useState(false);
  const text = (key: 'id' | 'domain', label: string, maxLength: number) => <Field id={`${prefix}-${key}`} label={label}><TextInput id={`${prefix}-${key}`} value={scope[key]} required={key === 'id'} maxLength={maxLength} onChange={(event) => setScope({ ...scope, [key]: event.target.value })} /></Field>;
  return <FloatingWindow title={existing ? copy.editScope : copy.addScope} description={copy.title} labels={floatingWindowMessages[locale]} onClose={onClose}>
    <p>{copy.hint}</p><p className="ds-field-hint">{copy.limits}</p>
    {invalid && <div id={`${prefix}-error`}><Notice title={copy.error} live>{copy.invalid}</Notice></div>}
    <form aria-describedby={invalid ? `${prefix}-error` : undefined} onSubmit={(event) => {
      event.preventDefault(); if (disabled) return;
      const list = (value: string) => value.trim() ? value.split(',').map((item) => item.trim()) : [];
      const nextScope = { ...scope, excluded: list(lists.excluded), dns: list(lists.dns), ntp: list(lists.ntp) };
      const next = { ...config, scopes: index === null ? [...config.scopes, nextScope] : config.scopes.map((old, i) => i === index ? nextScope : old) };
      try { validateDHCP(next, current.routed.network.config); onSave(next); } catch { setInvalid(true); }
    }}>
      <fieldset className="fw-fields" disabled={disabled}>
        {text('id', copy.id, 64)}
        <Field id={`${prefix}-binding`} label={copy.binding}><select id={`${prefix}-binding`} className="ds-select" required value={scope.interface_id} onChange={(event) => { const iface = lans.find((iface) => iface.id === event.target.value); setScope({ ...scope, interface_id: iface?.id ?? '', router: iface?.ipv4.address?.split('/')[0] ?? '', subnet: canonicalIPv4(iface?.ipv4.address ?? '') ?? '' }); }}><option value="">—</option>{lans.map((iface) => <option key={iface.id} value={iface.id}>{iface.binding.name} · {iface.ipv4.address}</option>)}</select></Field>
        <Field id={`${prefix}-subnet`} label={copy.subnet}><TextInput id={`${prefix}-subnet`} value={scope.subnet} readOnly /></Field>
        <Field id={`${prefix}-router`} label={copy.router}><TextInput id={`${prefix}-router`} value={scope.router} readOnly /></Field>
      </fieldset>
      <fieldset disabled={disabled} className="dhcp-collection"><legend>{copy.pools}</legend>{scope.pools.map((pool, i) => <div className="dhcp-entry" key={i}><Field id={`${prefix}-first-${i}`} label={`${copy.first} ${i + 1}`}><TextInput id={`${prefix}-first-${i}`} required maxLength={15} value={pool.first} onChange={(event) => setScope({ ...scope, pools: scope.pools.map((p, j) => j === i ? { ...p, first: event.target.value } : p) })} /></Field><Field id={`${prefix}-last-${i}`} label={`${copy.last} ${i + 1}`}><TextInput id={`${prefix}-last-${i}`} required maxLength={15} value={pool.last} onChange={(event) => setScope({ ...scope, pools: scope.pools.map((p, j) => j === i ? { ...p, last: event.target.value } : p) })} /></Field><Button variant="secondary" disabled={scope.pools.length === 1} aria-label={`${copy.remove}: ${copy.pools} ${i + 1}`} onClick={() => setScope({ ...scope, pools: scope.pools.filter((_, j) => i !== j) })}>{copy.remove}</Button></div>)}<Button variant="secondary" disabled={scope.pools.length >= 32} onClick={() => setScope({ ...scope, pools: [...scope.pools, { first: '', last: '' }] })}>{copy.addPool}</Button></fieldset>
      <fieldset className="fw-fields" disabled={disabled}>{(['excluded', 'dns', 'ntp'] as const).map((key) => <Field key={key} id={`${prefix}-${key}`} label={copy[key]} hint={copy.listHint}><TextInput id={`${prefix}-${key}`} aria-describedby={`${prefix}-${key}-hint`} maxLength={key === 'excluded' ? 4352 : 68} value={lists[key]} onChange={(event) => setLists({ ...lists, [key]: event.target.value })} /></Field>)}{text('domain', copy.domain, 253)}</fieldset>
      <fieldset className="dhcp-collection" disabled={disabled}><legend>{copy.reservations}</legend>{scope.reservations.map((reservation, i) => <div className="dhcp-entry" key={i}>{(['mac', 'address'] as const).map((key) => <Field key={key} id={`${prefix}-${key}-${i}`} label={`${copy[key]} ${i + 1}`}><TextInput id={`${prefix}-${key}-${i}`} required maxLength={key === 'mac' ? 17 : 15} value={reservation[key]} onChange={(event) => setScope({ ...scope, reservations: scope.reservations.map((r, j) => j === i ? { ...r, [key]: event.target.value } : r) })} /></Field>)}<Button variant="secondary" aria-label={`${copy.remove}: ${copy.reservations} ${i + 1}`} onClick={() => setScope({ ...scope, reservations: scope.reservations.filter((_, j) => i !== j) })}>{copy.remove}</Button></div>)}<Button variant="secondary" disabled={scope.reservations.length >= 256} onClick={() => setScope({ ...scope, reservations: [...scope.reservations, { mac: '', address: '' }] })}>{copy.addReservation}</Button></fieldset>
      <p id={`${prefix}-timers`} className="ds-field-hint">{copy.timers}</p><fieldset className="fw-fields" disabled={disabled}>{([{ key: 'lease_seconds', label: copy.lease }, { key: 'renew_seconds', label: copy.renew }, { key: 'rebind_seconds', label: copy.rebind }] as const).map(({ key, label }) => <Field key={key} id={`${prefix}-${key}`} label={label}><TextInput id={`${prefix}-${key}`} type="number" min={key === 'lease_seconds' ? 60 : 1} max={604800} required aria-describedby={`${prefix}-timers`} value={scope[key]} onChange={(event) => setScope({ ...scope, [key]: Number(event.target.value) })} /></Field>)}</fieldset>
      <div className="ds-actions"><Button type="submit" disabled={disabled}>{copy.save}</Button><Button variant="secondary" onClick={onClose}>{copy.cancel}</Button></div>
    </form>
  </FloatingWindow>;
}
