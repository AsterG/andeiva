import { useEffect, useId, useState } from 'react';
import { Button, DataTable, Field, Notice, Surface, TextInput } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import { ApiError } from '../firewall/api.js';
import { consoleMessages } from '../firewall/consoleMessages.js';
import { firewallMessages } from '../firewall/messages.js';
import { readAudit } from './audit.js';
import type { AuditEvent, AuditPage } from './audit.js';
import { workspaceMessages } from './workspaceMessages.js';

export function ConfigurationAudit({ locale, admin, onFailure }: { locale: Locale; admin: boolean; onFailure: (error: unknown) => void }) {
  const copy = firewallMessages[locale], common = consoleMessages[locale], work = workspaceMessages[locale], prefix = useId();
  const [page, setPage] = useState<AuditPage | null>(null), [before, setBefore] = useState('0'), [refresh, setRefresh] = useState(0), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [actor, setActor] = useState(''), [operation, setOperation] = useState(''), [result, setResult] = useState(''), [revision, setRevision] = useState(''), [since, setSince] = useState(''), [until, setUntil] = useState('');
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  useEffect(() => {
    if (!admin) return;
    let active = true;
    const controller = new AbortController();
    setBusy(true); setError(''); setSelected(null); setPage(null);
    void readAudit(before, controller.signal).then((next) => { if (active) setPage(next); }).catch((reason: unknown) => {
      if (!active) return;
      setError(reason instanceof ApiError ? reason.code : 'ANDEIVA_RESPONSE_INVALID');
      if (reason instanceof ApiError && reason.status === 401) onFailure(reason);
    }).finally(() => { if (active) setBusy(false); });
    return () => { active = false; controller.abort(); };
  }, [admin, before, refresh]);
  if (!admin) return <Notice title={work.readonly}>{copy.deniedError}</Notice>;
  const rows = page?.events.filter((event) => {
    const at = new Date(event.at), start = since ? new Date(`${since}T00:00:00`) : null, end = until ? new Date(`${until}T23:59:59.999`) : null;
    return (!actor || `${event.actor_name ?? ''} ${event.actor_id}`.toLowerCase().includes(actor.toLowerCase())) && (!operation || event.operation === operation) && (!result || event.result === result) && (!revision || event.running_revision.includes(revision.toLowerCase()) || event.startup_revision.includes(revision.toLowerCase())) && (!start || at >= start) && (!end || at <= end);
  }) ?? [];
  return <Surface title={common.audit}>
    <div aria-busy={busy} className="fw-stack">
      {error && <Notice title={copy.error} live><code>{error}</code></Notice>}
      <p>{common.loadedOnly} {work.auditIdentityHint}</p>
      <div className="ds-actions">
        {([{ key: 'actor', label: copy.actor, value: actor, set: setActor, type: 'search' }, { key: 'revision', label: copy.target, value: revision, set: setRevision, type: 'search' }, { key: 'since', label: common.since, value: since, set: setSince, type: 'date' }, { key: 'until', label: common.until, value: until, set: setUntil, type: 'date' }]).map((field) => <Field key={field.key} id={`${prefix}-${field.key}`} label={field.label}><TextInput id={`${prefix}-${field.key}`} type={field.type} maxLength={128} value={field.value} onChange={(event) => field.set(event.target.value)} /></Field>)}
        {([{ key: 'operation', label: copy.operation, value: operation, set: setOperation }, { key: 'result', label: copy.result, value: result, set: setResult }]).map((field) => <Field key={field.key} id={`${prefix}-${field.key}`} label={field.label}><select className="ds-select" id={`${prefix}-${field.key}`} value={field.value} onChange={(event) => field.set(event.target.value)}><option value="">{copy.all}</option>{[...new Set([...(field.value ? [field.value] : []), ...(page?.events.map((event) => event[field.key as 'operation' | 'result']) ?? [])])].map((value) => <option key={value} value={value}>{value}</option>)}</select></Field>)}
      </div>
      {page?.truncated && <Notice title={work.auditBoundedTitle}>{work.auditBounded}</Notice>}
      <DataTable caption={copy.audit}><thead><tr>{[copy.time, copy.actor, copy.operation, copy.result, copy.target, common.detail].map((label) => <th key={label} scope="col">{label}</th>)}</tr></thead><tbody>{rows.map((event) => <tr key={event.sequence}><td><time dateTime={event.at}>{new Date(event.at).toLocaleString(locale)}</time></td><td>{event.actor_name ?? event.actor_id}</td><td>{event.operation}</td><td>{event.result}</td><td>{event.running_revision.slice(0,12)}</td><td><Button variant="secondary" onClick={() => setSelected(event)}>{common.inspect}</Button></td></tr>)}</tbody></DataTable>
      {page && !rows.length && <p>{copy.emptyHistory}</p>}
      <div className="ds-actions"><Button variant="secondary" disabled={busy} onClick={() => { setBefore('0'); setRefresh((value) => value + 1); }}>{copy.newest}</Button><Button variant="secondary" disabled={busy || !page || page.next_before === '0'} onClick={() => setBefore(page!.next_before)}>{copy.older}</Button></div>
      {selected && <details open><summary>{common.detail}</summary><dl>{Object.entries(selected).map(([key,value]) => <div key={key}><dt>{key}</dt><dd><code>{value}</code></dd></div>)}</dl></details>}
    </div>
  </Surface>;
}
