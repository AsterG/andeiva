import { useState } from 'react';
import { Button, DataTable, Field, FilterBar, Surface, TextInput } from '../design-system/components.js';
import type { FirewallMessages } from './messages.js';
import type { History, Operation } from './model.js';
import type { Locale } from '../messages.js';
import { consoleMessages } from './consoleMessages.js';
import { auditCalendarDay } from './auditPresentation.js';

export function HistoryPanel({ history, copy, locale, busy, canRestore, load, restore }: { history: History | null; copy: FirewallMessages; locale: Locale; busy: boolean; canRestore: boolean; load: (before?: number) => void; restore: (hash: string) => void }) {
  const labels = consoleMessages[locale];
  const [query, setQuery] = useState('');
  const [operation, setOperation] = useState('all');
  const [result, setResult] = useState('all');
  const [origin, setOrigin] = useState('all');
  const [since, setSince] = useState('');
  const [until, setUntil] = useState('');
  const [selected, setSelected] = useState<number | null>(null);
  const detail = history?.audit.find((entry) => entry.sequence === selected);
  const operations: Operation[] = ['stage', 'validate', 'commit', 'confirm', 'save', 'rollback'];
  const audit = (history?.audit ?? []).filter((entry) => `${entry.actor} ${entry.running_hash}`.toLowerCase().includes(query.toLowerCase()) && (operation === 'all' || entry.operation === operation) && (result === 'all' || entry.result === result) && (origin === 'all' || entry.surface === origin) && (!since || auditCalendarDay(entry.at) >= since) && (!until || auditCalendarDay(entry.at) <= until));
  return <Surface title={copy.history} description={copy.historyHint}>
    <div className="fw-toolbar"><Button variant="secondary" disabled={busy} onClick={() => load()}>{history ? copy.newest : copy.loadHistory}</Button>{history && <Button variant="secondary" disabled={busy || !history.next_before} onClick={() => load(history.next_before)}>{copy.older}</Button>}</div>
    {history && <>
      <p className="fw-meta">{labels.loadedOnly}</p>
      <FilterBar label={labels.origin}><Field id="audit-origin" label={labels.origin}><select id="audit-origin" className="ds-select" value={origin} onChange={(event) => setOrigin(event.target.value)}><option value="all">{copy.all}</option>{[...new Set([...history.audit.map((entry) => entry.surface), ...(origin === 'all' ? [] : [origin])])].map((value) => <option key={value}>{value}</option>)}</select></Field><Field id="audit-since" label={labels.since}><TextInput id="audit-since" type="date" value={since} onChange={(event) => setSince(event.target.value)} /></Field><Field id="audit-until" label={labels.until}><TextInput id="audit-until" type="date" value={until} onChange={(event) => setUntil(event.target.value)} /></Field></FilterBar>
      <details className="fw-revision-details console-history-revisions"><summary>{copy.revisionHistory}</summary><DataTable caption={copy.revisionHistory}><thead><tr><th scope="col">{copy.sequence}</th><th scope="col">{copy.rules}</th><th scope="col">{copy.actions}</th></tr></thead><tbody>{history.revisions.map(({ sequence, revision }) => <tr key={`${sequence}-${revision.hash}`}><th scope="row">#{sequence}</th><td>{revision.config.rules.length}</td><td><details><summary>{copy.target}</summary><code className="fw-hash">{revision.hash}</code><Button variant="secondary" disabled={!canRestore || busy} onClick={() => restore(revision.hash)} aria-label={`${copy.rollback}: ${revision.hash}`}>{copy.rollback}</Button></details></td></tr>)}{history.revisions.length === 0 && <tr><td colSpan={3}>{copy.emptyHistory}</td></tr>}</tbody></DataTable></details>
      <FilterBar label={copy.filter}><Field id="audit-search" label={copy.search}><TextInput id="audit-search" type="search" maxLength={128} value={query} onChange={(event) => setQuery(event.target.value)} /></Field><Field id="audit-operation" label={copy.operation}><select id="audit-operation" className="ds-select" value={operation} onChange={(event) => setOperation(event.target.value)}><option value="all">{copy.all}</option>{operations.map((value) => <option key={value} value={value}>{copy[value]}</option>)}</select></Field><Field id="audit-result" label={copy.result}><select id="audit-result" className="ds-select" value={result} onChange={(event) => setResult(event.target.value)}><option value="all">{copy.all}</option>{[...new Set([...history.audit.map((entry) => entry.result), ...(result === 'all' ? [] : [result])])].map((value) => <option key={value} value={value}>{value}</option>)}</select></Field></FilterBar>
      <div className="console-audit-layout"><DataTable caption={copy.audit}><thead><tr>{(['sequence', 'time', 'actor', 'surface', 'operation', 'result'] as const).map((key) => <th key={key} scope="col">{copy[key]}</th>)}</tr></thead><tbody>{audit.map((entry) => <tr key={entry.sequence}><th scope="row"><button className="fw-rule-link" aria-label={`${labels.inspect}: ${entry.sequence}`} onClick={() => setSelected(entry.sequence)}>{entry.sequence}</button></th><td><time dateTime={entry.at}>{new Date(entry.at).toLocaleString(locale)}</time></td><td>{entry.actor}</td><td>{entry.surface}</td><td>{operations.includes(entry.operation as Operation) ? copy[entry.operation as Operation] : copy.other}</td><td><code>{entry.result}</code></td></tr>)}{audit.length === 0 && <tr><td colSpan={6}>{copy.emptyHistory}</td></tr>}</tbody></DataTable><aside className="console-audit-detail"><h3>{labels.detail}</h3>{detail ? <dl><dt>{copy.actor}</dt><dd>{detail.actor}</dd><dt>{copy.surface}</dt><dd>{detail.surface}</dd><dt>{copy.operation}</dt><dd>{operations.includes(detail.operation as Operation) ? copy[detail.operation as Operation] : copy.other}</dd><dt>{copy.result}</dt><dd>{detail.result}</dd><dt>{copy.time}</dt><dd><time dateTime={detail.at}>{new Date(detail.at).toLocaleString(locale)}</time></dd><dt>{copy.target}</dt><dd><code className="fw-hash">{detail.running_hash}</code></dd></dl> : <p>{labels.selectEvent}</p>}</aside></div>
    </>}
  </Surface>;
}
