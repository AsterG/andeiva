import { useState } from 'react';
import { Button, DataTable, Field, FilterBar, Surface, TextInput } from '../design-system/components.js';
import type { FirewallMessages } from './messages.js';
import type { History, Operation } from './model.js';

export function HistoryPanel({ history, copy, busy, canRestore, load, restore }: { history: History | null; copy: FirewallMessages; busy: boolean; canRestore: boolean; load: (before?: number) => void; restore: (hash: string) => void }) {
  const [query, setQuery] = useState('');
  const [operation, setOperation] = useState('all');
  const [result, setResult] = useState('all');
  const operations: Operation[] = ['stage', 'validate', 'commit', 'confirm', 'save', 'rollback'];
  const audit = (history?.audit ?? []).filter((entry) => `${entry.actor} ${entry.running_hash}`.toLowerCase().includes(query.toLowerCase()) && (operation === 'all' || entry.operation === operation) && (result === 'all' || entry.result === result));
  return <Surface title={copy.history} description={copy.historyHint}>
    <div className="fw-toolbar"><Button variant="secondary" disabled={busy} onClick={() => load()}>{history ? copy.newest : copy.loadHistory}</Button>{history && <Button variant="secondary" disabled={busy || !history.next_before} onClick={() => load(history.next_before)}>{copy.older}</Button>}</div>
    {history && <>
      <DataTable caption={copy.revisionHistory}><thead><tr><th scope="col">{copy.sequence}</th><th scope="col">{copy.target}</th><th scope="col">{copy.actions}</th></tr></thead><tbody>{history.revisions.map(({ sequence, revision }) => <tr key={`${sequence}-${revision.hash}`}><th scope="row">{sequence}</th><td><code className="fw-hash">{revision.hash}</code></td><td><Button variant="secondary" disabled={!canRestore || busy} onClick={() => restore(revision.hash)} aria-label={`${copy.rollback}: ${revision.hash}`}>{copy.rollback}</Button></td></tr>)}{history.revisions.length === 0 && <tr><td colSpan={3}>{copy.emptyHistory}</td></tr>}</tbody></DataTable>
      <FilterBar label={copy.filter}><Field id="audit-search" label={copy.search}><TextInput id="audit-search" type="search" maxLength={128} value={query} onChange={(event) => setQuery(event.target.value)} /></Field><Field id="audit-operation" label={copy.operation}><select id="audit-operation" className="ds-select" value={operation} onChange={(event) => setOperation(event.target.value)}><option value="all">{copy.all}</option>{operations.map((value) => <option key={value} value={value}>{copy[value]}</option>)}</select></Field><Field id="audit-result" label={copy.result}><select id="audit-result" className="ds-select" value={result} onChange={(event) => setResult(event.target.value)}><option value="all">{copy.all}</option>{[...new Set(history.audit.map((entry) => entry.result))].map((value) => <option key={value} value={value}>{value}</option>)}</select></Field></FilterBar>
      <DataTable caption={copy.audit}><thead><tr>{(['sequence', 'time', 'actor', 'surface', 'operation', 'result'] as const).map((key) => <th key={key} scope="col">{copy[key]}</th>)}</tr></thead><tbody>{audit.map((entry) => <tr key={entry.sequence}><th scope="row">{entry.sequence}</th><td><time dateTime={entry.at}>{entry.at}</time></td><td>{entry.actor}</td><td>{entry.surface}</td><td>{operations.includes(entry.operation as Operation) ? copy[entry.operation as Operation] : copy.other}</td><td><code>{entry.result}</code></td></tr>)}{audit.length === 0 && <tr><td colSpan={6}>{copy.emptyHistory}</td></tr>}</tbody></DataTable>
    </>}
  </Surface>;
}
