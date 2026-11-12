import { useEffect, useId, useRef, useState } from 'react';
import { Button, DataTable, Dialog, Field, Notice, StatusBadge, Surface, TextInput } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import type { ConsoleView } from '../firewall/consoleMessages.js';
import { consoleMessages } from '../firewall/consoleMessages.js';
import { ApiError, configurationRequest } from '../firewall/api.js';
import type { Rule, Session } from '../firewall/model.js';
import { canonicalIPv4, formatPorts } from '../firewall/model.js';
import { firewallMessages } from '../firewall/messages.js';
import { RuleEditor } from '../firewall/RuleEditor.js';
import { ruleTableMessages } from '../firewall/ruleTableMessages.js';
import { SystemInfoView } from '../firewall/SystemInfoView.js';
import type { ProductInfoState } from '../firewall/productInfo.js';
import { admitOperation, closeOperationNamespace, executeOperation, operationID, queryOperation, readCurrent } from './configuration.js';
import type { ConfigurationCurrent, ConfigurationOperation, OperationRequest, RoutedConfig, RoutedPath } from './configuration.js';
import { NetworkEditor } from './NetworkEditor.js';
import { ConfigurationAudit } from './ConfigurationAudit.js';
import { NetworkInterfaces } from './NetworkInterfaces.js';
import { networkInventoryResponse } from './inventory.js';
import type { NetworkInventory } from './inventory.js';
import { workspaceMessages } from './workspaceMessages.js';

type Effective = { schema_version: 1; generation: string; running_revision: string; observed_revision?: string; phase: string; consistent: boolean };
function effectiveResponse(value: unknown): Effective | null {
  if (!value || typeof value !== 'object') return null;
  const item = value as Partial<Effective>;
  if (item.schema_version !== 1 || typeof item.generation !== 'string' || typeof item.running_revision !== 'string' || typeof item.consistent !== 'boolean' || !['bootstrap', 'armed', 'pending', 'idle', 'expired', 'blocked'].includes(item.phase ?? '')) return null;
  return item as Effective;
}
function simpleRule(rule: RoutedConfig['routed']['rules'][number]): Rule {
  return { id: rule.id, enabled: rule.enabled, action: rule.action, match: { source: rule.source, destination: rule.destination, protocol: rule.protocol, source_ports: rule.source_ports, destination_ports: rule.destination_ports } };
}
const storageKey = (username: string) => `andeiva.configuration.operation.${username}`;
function retainedOperation(username: string): string {
  try { const id = sessionStorage.getItem(storageKey(username)); return operationID(id) ? id : ''; } catch { return ''; }
}

export function RoutingWorkspace({ locale, session, page, product, onProductRefresh, onFailure }: { locale: Locale; session: Session; page: ConsoleView; product: ProductInfoState; onProductRefresh: () => void; onFailure: (error: unknown) => void }) {
  const copy = workspaceMessages[locale], common = firewallMessages[locale], prefix = useId();
  const [current, setCurrent] = useState<ConfigurationCurrent | null>(null), [effective, setEffective] = useState<Effective | null>(null), [inventory, setInventory] = useState<NetworkInventory | null>(null);
  const [draft, setDraft] = useState<RoutedConfig | null>(null), [dirty, setDirty] = useState(false), [draftBase, setDraftBase] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [refresh, setRefresh] = useState(0);
  const [last, setLast] = useState<ConfigurationOperation | null>(null), [uncertainID, setUncertainID] = useState(() => retainedOperation(session.username));
  const [review, setReview] = useState<OperationRequest | null>(null), [seconds, setSeconds] = useState('60');
  const [networkEditor, setNetworkEditor] = useState(false), [editor, setEditor] = useState<{ index: number | null; from: string; to: string } | null>(null);
  const [natEditor, setNATEditor] = useState(false), [search, setSearch] = useState(''), [dragged, setDragged] = useState<number | null>(null), [announcement, setAnnouncement] = useState('');
  const gate = useRef(false), mounted = useRef(true), dirtyRef = useRef(false);
  const keyboardDrag = useRef<{ from: number; to: number } | null>(null);
  const dragContext = useRef<{ rules: RoutedConfig['routed']['rules']; generation: string } | null>(null);
  const admin = session.role === 'admin';
  const editing = !!editor || networkEditor || natEditor;
  const stale = dirty && draftBase !== current?.global.generation;
  const candidateStale = !!current?.snapshot.candidate && (current.snapshot.candidate.base !== current.snapshot.running.hash || current.routed.candidate_group?.base !== current.global.running_revision);
  const writable = admin && !!current && !busy && !current.snapshot.recovery_required && !uncertainID && !stale;
  const editable = writable && !current?.snapshot.pending;
  const verified = !!current && effective?.consistent === true && effective.generation === current.global.generation && effective.running_revision === current.global.running_revision && effective.observed_revision === current.global.running_revision;
  function accept(next: ConfigurationCurrent, reset: boolean) {
    setCurrent(next);
    if (reset) {
      const config = next.snapshot.candidate?.revision.config ?? next.snapshot.running.config;
      // Normalize empty collections only in the editable draft, never in a
      // received revision whose exact bytes are bound to its server hash.
      setDraft(config.schema_version === 6 ? { ...structuredClone(config), routed: { ...structuredClone(config.routed), rules: structuredClone(config.routed.rules ?? []), nat: structuredClone(config.routed.nat ?? []) } } : null);
      setDraftBase(next.global.generation); setDirty(false); dirtyRef.current = false;
    }
  }
  function remember(id: string) {
    setUncertainID(id);
    try { if (id) sessionStorage.setItem(storageKey(session.username), id); else sessionStorage.removeItem(storageKey(session.username)); } catch { /* The displayed durable ID remains available if browser storage is disabled. */ }
  }
  function fail(reason: unknown) {
    const failure = reason instanceof ApiError ? reason : new ApiError('ANDEIVA_RESPONSE_INVALID');
    setError(failure.code); setEffective(null);
    if (failure.status === 401) onFailure(failure);
  }
  function edit(config: RoutedConfig) { setDraft(config); setDirty(true); dirtyRef.current = true; setEditor(null); setNetworkEditor(false); setNATEditor(false); }
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setBusy(true); setError('');
    void (async () => {
      try {
        const next = await readCurrent(controller.signal);
        if (!active) return;
        accept(next, !dirtyRef.current);
        const [observed, links] = await Promise.allSettled([
          configurationRequest('config/effective', undefined, undefined, controller.signal),
          configurationRequest('network/interfaces', undefined, undefined, controller.signal),
        ]);
        if (!active) return;
        setEffective(observed.status === 'fulfilled' ? effectiveResponse(observed.value) : null);
        setInventory(links.status === 'fulfilled' ? networkInventoryResponse(links.value) : null);
        for (const result of [observed, links]) if (result.status === 'rejected' && result.reason instanceof ApiError && result.reason.status === 401) onFailure(result.reason);
      } catch (reason) { if (active) fail(reason); }
      finally { if (active) setBusy(false); }
    })();
    return () => { active = false; controller.abort(); };
  }, [refresh]);
  useEffect(() => {
    if (!dirty && !editing) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty, editing]);
  useEffect(() => {
    if (!current?.snapshot.pending) return;
    const delay = Date.parse(current.snapshot.pending.deadline) - Date.now();
    const timer = window.setTimeout(() => { setEffective(null); setRefresh((value) => value + 1); }, Math.max(0, Math.min(delay + 100, 2147483647)));
    return () => window.clearTimeout(timer);
  }, [current]);
  async function transact(request: OperationRequest) {
    if (!current || !writable || editing || gate.current) return;
    gate.current = true; setBusy(true); setError(''); setReview(null); setEffective(null);
    try {
      const accepted = await admitOperation(current, request, session.csrf);
      if (!mounted.current) return;
      remember(accepted.operation.id); setLast(accepted.operation);
      const result = await executeOperation(accepted.operation.id, session.csrf);
      if (!mounted.current) return;
      setLast(result.operation); accept(result.current, true);
      if (result.operation.state === 'final' || result.operation.state === 'pending') remember('');
      if (result.operation.state === 'final') await closeOperationNamespace(result.operation.namespace_id, session.csrf);
      setRefresh((value) => value + 1);
    } catch (reason) { if (mounted.current) fail(reason); }
    finally { gate.current = false; if (mounted.current) setBusy(false); }
  }
  async function query() {
    if (!uncertainID || gate.current) return;
    gate.current = true; setBusy(true); setError('');
    try {
      const result = await queryOperation(uncertainID);
      if (!mounted.current) return;
      setLast(result.operation); accept(result.current, false);
      if (result.operation.state === 'final' || result.operation.state === 'pending') { remember(''); setRefresh((value) => value + 1); }
      if (result.operation.state === 'final') await closeOperationNamespace(result.operation.namespace_id, session.csrf);
    } catch (reason) { if (mounted.current) fail(reason); }
    finally { gate.current = false; if (mounted.current) setBusy(false); }
  }
  async function resumeAccepted() {
    if (!admin || !uncertainID || last?.id !== uncertainID || last.state !== 'accepted' || editing || gate.current) return;
    gate.current = true; setBusy(true); setError(''); setEffective(null);
    try {
      // Explicitly resume the existing durable request; never admit a second one.
      const result = await executeOperation(uncertainID, session.csrf);
      if (!mounted.current) return;
      setLast(result.operation); accept(result.current, true);
      if (result.operation.state === 'final' || result.operation.state === 'pending') remember('');
      if (result.operation.state === 'final') await closeOperationNamespace(result.operation.namespace_id, session.csrf);
      setRefresh((value) => value + 1);
    } catch (reason) { if (mounted.current) fail(reason); }
    finally { gate.current = false; if (mounted.current) setBusy(false); }
  }
  function move(from: number, to: number) {
    if (!editable || editing || !draft || search.trim() || from === to || from < 0 || to < 0 || from >= draft.routed.rules.length || to >= draft.routed.rules.length) return;
    if (dragContext.current && (dragContext.current.rules !== draft.routed.rules || dragContext.current.generation !== current?.global.generation)) return;
    const rules = [...draft.routed.rules], [rule] = rules.splice(from, 1);
    rules.splice(to, 0, rule!); edit({ ...draft, routed: { ...draft.routed, rules } }); setAnnouncement(`${copy.moved}: ${rule!.id}, ${to + 1}`);
  }
  const paths = draft?.routed.network.config.interfaces.filter((iface) => iface.role !== 'management') ?? [];
  const path = (from: string, to: string): RoutedPath | null => {
    const a = paths.find((iface) => iface.id === from), b = paths.find((iface) => iface.id === to);
    return a && b && a.id !== b.id ? { from_interface: a.id, to_interface: b.id, from_zone: a.zone, to_zone: b.zone } : null;
  };
  const outcomeLabel = last?.outcome?.code === 'applied' || last?.outcome?.code === 'applied_pending_confirmation' ? copy.applied : last?.outcome?.code === 'failed_rolled_back' ? copy.rolledBack : last?.outcome?.code === 'expired_without_effects' ? copy.expired : last?.outcome ? copy.rejected : copy.accepted;
  return <div className="fw-stack" aria-busy={busy}>
    {error && <Notice title={copy.error} live>{copy.errorHint} <code>{error}</code></Notice>}
    {candidateStale && <Notice title={copy.candidate} live>{copy.candidateStale}</Notice>}
    {uncertainID && <Notice title={copy.uncertain} live><code>{uncertainID}</code> <Button variant="secondary" disabled={busy} onClick={() => void query()}>{copy.query}</Button>{admin && last?.id === uncertainID && last.state === 'accepted' && <Button variant="secondary" disabled={busy || editing} onClick={() => void resumeAccepted()}>{copy.resume}</Button>}</Notice>}
    <div className="ds-actions"><Button variant="secondary" disabled={busy || !!editor || networkEditor || natEditor} onClick={() => setRefresh((value) => value + 1)}>{copy.refresh}</Button>{!admin && <StatusBadge tone="info">{copy.readonly}</StatusBadge>}</div>
    {!current ? <Notice title={busy ? copy.checking : copy.error}>{copy.errorHint}</Notice> : <>
      <Surface title={copy.state} className={`console-transaction-bar${dirty || current.snapshot.candidate || current.snapshot.pending ? ' console-transaction-bar--pending' : ''}`}>
        <div className="console-transaction-summary"><StatusBadge tone={current.snapshot.recovery_required ? 'error' : dirty || current.snapshot.pending || current.snapshot.candidate ? 'warning' : 'info'}>{current.snapshot.recovery_required ? copy.recovery : dirty ? copy.localDraft : current.snapshot.pending ? copy.pending : current.snapshot.candidate ? copy.candidate : copy.running}</StatusBadge><span>{current.global.running_revision === current.global.startup_revision ? copy.saved : copy.unsaved}</span>{verified && <StatusBadge tone="success">{common.verified}</StatusBadge>}</div>
        {current.snapshot.pending && <p>{copy.pending} <time dateTime={current.snapshot.pending.deadline}>{new Date(current.snapshot.pending.deadline).toLocaleString(locale)}</time></p>}
        {admin && <div className="console-transaction-actions">
          <Button variant="secondary" disabled={!editable || editing || !dirty || !draft} onClick={() => setReview({ operation: 'stage', config: draft! })}>{copy.stage}</Button>
          <Button variant="secondary" disabled={!editable || candidateStale || editing || dirty || !current.snapshot.candidate} onClick={() => void transact({ operation: 'validate' })}>{copy.validate}</Button>
          <Field id={`${prefix}-confirm-seconds`} label={copy.seconds}><TextInput id={`${prefix}-confirm-seconds`} type="number" min={30} max={120} value={seconds} disabled={busy} onChange={(event) => setSeconds(event.target.value)} /></Field>
          <Button disabled={!editable || candidateStale || editing || dirty || !current.snapshot.candidate || !/^(?:[3-9][0-9]|1[01][0-9]|120)$/.test(seconds)} onClick={() => setReview({ operation: 'commit', confirm_seconds: seconds })}>{copy.commit}</Button>
          {current.routed.confirmation && <Button disabled={!writable || editing || !verified || Date.parse(current.routed.confirmation.confirmation_deadline) <= Date.now()} onClick={() => setReview({ operation: 'confirm', target_revision: current.routed.confirmation!.target_revision, origin_commit_operation_id: current.routed.confirmation!.origin_commit_operation_id })}>{copy.confirm}</Button>}
          <Button variant="secondary" disabled={!editable || editing || !verified || dirty || !!current.snapshot.candidate || current.global.running_revision === current.global.startup_revision} onClick={() => setReview({ operation: 'save' })}>{copy.save}</Button>
          <Button variant="secondary" disabled={!editable || editing || dirty || !!current.snapshot.candidate || current.global.running_revision === current.global.startup_revision} onClick={() => setReview({ operation: 'rollback', target_revision: current.global.startup_revision, confirm_seconds: '60' })}>{copy.rollback}</Button>
          <Button variant="secondary" disabled={!dirty || busy || editing} onClick={() => accept(current, true)}>{copy.discard}</Button>
        </div>}
        {last && <p>{copy.result}: <StatusBadge tone={last.outcome?.code === 'applied' || last.outcome?.code === 'applied_pending_confirmation' ? 'success' : 'info'}>{outcomeLabel}</StatusBadge> <code>{last.id}</code></p>}
        <details><summary>{copy.details}</summary><dl className="fw-review"><dt>{copy.running}</dt><dd><code className="fw-hash">{current.global.running_revision}</code></dd><dt>{copy.startup}</dt><dd><code className="fw-hash">{current.global.startup_revision}</code></dd><dt>{copy.candidate}</dt><dd><code className="fw-hash">{current.routed.candidate?.hash ?? '—'}</code></dd></dl></details>
      </Surface>
      {page === 'audit' ? <ConfigurationAudit locale={locale} admin={admin} onFailure={onFailure} /> : page === 'system' ? <SystemInfoView locale={locale} state={product} refresh={onProductRefresh} /> : page === 'network' ? <>
        <Surface title={copy.network} description={copy.editHint}><div className="ds-actions">{admin && <Button disabled={!editable || editing || !inventory} onClick={() => setNetworkEditor(true)}>{copy.editNetwork}</Button>}</div>{draft && <DataTable caption={copy.network}><thead><tr><th>{copy.name}</th><th>{copy.path}</th><th>{copy.address}</th><th>{copy.gateway}</th></tr></thead><tbody>{draft.routed.network.config.interfaces.map((iface) => <tr key={iface.id}><th scope="row">{iface.binding.name}</th><td>{iface.role.toUpperCase()} · {iface.zone}</td><td>{iface.ipv4.address ?? '—'}</td><td>{iface.ipv4.gateway ?? '—'}</td></tr>)}</tbody></DataTable>}</Surface><NetworkInterfaces locale={locale} />
      </> : page === 'nat' ? <Surface title={copy.nat} description={copy.natHint}>
        {admin && <Button disabled={!editable || editing || !draft || draft.routed.nat.length >= 32} onClick={() => setNATEditor(true)}>{copy.addNAT}</Button>}
        <DataTable caption={copy.nat}><thead><tr><th>{copy.name}</th><th>{copy.source}</th><th>{copy.path}</th><th>{common.actions}</th></tr></thead><tbody>{draft?.routed.nat.map((rule, index) => <tr key={rule.id}><th scope="row">{rule.id}</th><td>{rule.source}</td><td>{rule.path.from_interface} → {rule.path.to_interface}</td><td>{admin && <Button variant="secondary" disabled={!editable || editing} onClick={() => edit({ ...draft, routed: { ...draft.routed, nat: draft.routed.nat.filter((_, position) => position !== index) } })}>{copy.remove}</Button>}</td></tr>)}</tbody></DataTable>
      </Surface> : page === 'rules' ? <Surface title={copy.rules} className="fw-rule-table">
        {!draft && <Notice title={copy.network}>{copy.noNetwork}</Notice>}
        <div className="fw-toolbar"><Field id={`${prefix}-search`} label={copy.search}><TextInput id={`${prefix}-search`} value={search} onChange={(event) => { setSearch(event.target.value); setDragged(null); keyboardDrag.current = null; dragContext.current = null; }} /></Field>{admin && <Button disabled={!editable || editing || !draft || draft.routed.rules.length >= 128} onClick={() => setEditor({ index: null, from: paths.find((iface) => iface.role === 'lan')?.id ?? '', to: paths.find((iface) => iface.role === 'wan')?.id ?? '' })}>{copy.add}</Button>}</div>
        {search.trim() && <p className="ds-field-hint">{copy.filterOrder}</p>}<p className="fw-sr-only" aria-live="polite">{announcement}</p>
        <DataTable caption={copy.rules}><thead><tr><th>{copy.order}</th><th>{copy.name}</th><th>{copy.path}</th><th>{copy.source}</th><th>{copy.destination}</th><th>{copy.protocol}</th><th>{copy.action}</th><th>{common.actions}</th></tr></thead><tbody>{draft?.routed.rules.map((rule, index) => ({ rule, index })).filter(({ rule }) => [rule.id, rule.source, rule.destination, rule.protocol].join(' ').toLowerCase().includes(search.trim().toLowerCase())).map(({ rule, index }) => <tr key={rule.id} onDragOver={(event) => { if (dragged !== null && !search.trim()) { event.preventDefault(); if (event.clientY < 100) window.scrollBy(0, -24); if (event.clientY > window.innerHeight - 100) window.scrollBy(0, 24); } }} onDrop={(event) => { event.preventDefault(); if (dragged !== null) move(dragged, index); setDragged(null); }}>
          <td><div className="fw-rule-order"><button type="button" className="fw-drag-handle" disabled={!editable || editing || !!search.trim()} draggable={editable && !editing && !search.trim()} aria-label={`${copy.reorder}: ${rule.id}`} aria-describedby={`${prefix}-keyboard`} aria-pressed={dragged === index} onDragStart={() => { keyboardDrag.current = null; dragContext.current = { rules: draft!.routed.rules, generation: current.global.generation }; setDragged(index); }} onDragEnd={() => { setDragged(null); dragContext.current = null; }} onBlur={() => { if (keyboardDrag.current) { keyboardDrag.current = null; dragContext.current = null; setDragged(null); } }} onKeyDown={(event) => {
            if (event.key === ' ' && dragged === null) { event.preventDefault(); keyboardDrag.current = { from: index, to: index }; dragContext.current = { rules: draft!.routed.rules, generation: current.global.generation }; setDragged(index); }
            else if (keyboardDrag.current && (event.key === 'ArrowUp' || event.key === 'ArrowDown')) { event.preventDefault(); const to = Math.max(0, Math.min((draft?.routed.rules.length ?? 1) - 1, keyboardDrag.current.to + (event.key === 'ArrowDown' ? 1 : -1))); keyboardDrag.current.to = to; setDragged(to); setAnnouncement(`${copy.order}: ${to + 1}`); }
            else if (event.key === 'Enter' || event.key === 'Escape') { event.preventDefault(); if (event.key === 'Enter' && keyboardDrag.current) move(keyboardDrag.current.from, keyboardDrag.current.to); keyboardDrag.current = null; dragContext.current = null; setDragged(null); }
          }}><svg width="18" height="24" viewBox="0 0 18 24" aria-hidden="true">{[6, 12, 18].flatMap((y) => [6, 12].map((x) => <circle key={`${x}-${y}`} cx={x} cy={y} r="1.5" fill="currentColor" />))}</svg></button><span>{index + 1}</span></div></td>
          <th scope="row">{admin ? <button className="fw-rule-link" type="button" disabled={!editable || editing} onClick={() => setEditor({ index, from: rule.path.from_interface, to: rule.path.to_interface })}>{rule.id}</button> : rule.id}<div><label className="fw-enabled-switch"><input type="checkbox" checked={rule.enabled} disabled={!editable || editing} onChange={(event) => edit({ ...draft!, routed: { ...draft!.routed, rules: draft!.routed.rules.map((existing, position) => position === index ? { ...existing, enabled: event.target.checked } : existing) } })} /> {copy.enabled}</label></div></th><td>{rule.path.from_interface} → {rule.path.to_interface}</td><td>{rule.source}</td><td>{rule.destination}</td><td>{rule.protocol.toUpperCase()} · {formatPorts(rule.destination_ports)}</td><td><StatusBadge tone={rule.action === 'allow' ? 'success' : 'error'}>{common[rule.action]}</StatusBadge></td><td>{admin && <details className="fw-row-menu"><summary aria-label={`${common.actions}: ${rule.id}`}><span aria-hidden="true">•••</span></summary><div className="fw-row-menu-content"><Button variant="secondary" disabled={!editable || editing} onClick={() => setEditor({ index, from: rule.path.from_interface, to: rule.path.to_interface })}>{copy.edit}</Button><Button variant="secondary" disabled={!editable || editing} onClick={() => edit({ ...draft!, routed: { ...draft!.routed, rules: draft!.routed.rules.filter((_, position) => position !== index) } })}>{copy.remove}</Button></div></details>}</td>
        </tr>)}</tbody></DataTable><p id={`${prefix}-keyboard`} className="fw-sr-only">{copy.keyboard}</p>
      </Surface> : page === 'configuration' || page === 'dashboard' ? <Surface title={copy.title}><p>{copy.editHint}</p>{!draft && <p>{copy.noNetwork}</p>}</Surface> : <Notice title={consoleMessages[locale][page]}>{copy.notTelemetry}</Notice>}
    </>}
    {networkEditor && inventory && <NetworkEditor locale={locale} inventory={inventory} current={draft} onSave={edit} onClose={() => setNetworkEditor(false)} />}
    {editor && draft && <RuleEditor key={editor.index ?? 'new'} locale={locale} rules={draft.routed.rules.map(simpleRule)} index={editor.index} copy={common} labels={ruleTableMessages[locale]} supportsEnabled disabled={!editable} extraFields={<>{([{ key: 'from', label: copy.from }, { key: 'to', label: copy.to }] as const).map((field) => <Field key={field.key} id={`${prefix}-${field.key}`} label={field.label}><select id={`${prefix}-${field.key}`} className="ds-select" value={editor[field.key]} onChange={(event) => setEditor({ ...editor, [field.key]: event.target.value })}>{paths.map((iface) => <option key={iface.id} value={iface.id}>{iface.binding.name} · {iface.zone}</option>)}</select></Field>)}</>} onCancel={() => setEditor(null)} onSave={(rule) => {
      const selectedPath = path(editor.from, editor.to);
      if (!selectedPath) { setError('ANDEIVA_NETWORK_INVALID'); return; }
      const routedRule = { id: rule.id, enabled: rule.enabled ?? true, action: rule.action, ...rule.match, path: selectedPath };
      edit({ ...draft, routed: { ...draft.routed, rules: editor.index === null ? [...draft.routed.rules, routedRule] : draft.routed.rules.map((previous, index) => index === editor.index ? routedRule : previous) } });
    }} />}
    {natEditor && draft && <Dialog open title={copy.addNAT} closeLabel={copy.cancel} onClose={() => setNATEditor(false)}><form onSubmit={(event) => {
      event.preventDefault(); const values = new FormData(event.currentTarget), id = String(values.get('name') ?? ''), source = canonicalIPv4(String(values.get('source') ?? '')), selectedPath = path(String(values.get('from') ?? ''), String(values.get('to') ?? ''));
      if (!editable || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(id) || !source || !selectedPath || draft.routed.nat.some((rule) => rule.id === id)) { setError('ANDEIVA_ROUTED_INVALID_POLICY'); return; }
      edit({ ...draft, routed: { ...draft.routed, nat: [...draft.routed.nat, { id, path: selectedPath, source }] } });
    }}><Field id={`${prefix}-nat-name`} label={copy.name}><TextInput id={`${prefix}-nat-name`} name="name" required maxLength={64} /></Field><Field id={`${prefix}-nat-source`} label={copy.sourceNetwork}><TextInput id={`${prefix}-nat-source`} name="source" required maxLength={18} /></Field>{([{ key: 'from', label: copy.from }, { key: 'to', label: copy.to }] as const).map((field) => <Field key={field.key} id={`${prefix}-nat-${field.key}`} label={field.label}><select id={`${prefix}-nat-${field.key}`} className="ds-select" name={field.key}>{paths.map((iface) => <option key={iface.id} value={iface.id}>{iface.binding.name} · {iface.zone}</option>)}</select></Field>)}<Button type="submit" disabled={!editable}>{copy.localDraft}</Button></form></Dialog>}
    <Dialog open={!!review} title={copy.review} closeLabel={copy.cancel} onClose={() => setReview(null)}><p>{copy.reviewHint}</p><p>{review && copy[review.operation]}</p><Button disabled={!writable} onClick={() => { if (review) void transact(review); }}>{copy.proceed}</Button></Dialog>
  </div>;
}
