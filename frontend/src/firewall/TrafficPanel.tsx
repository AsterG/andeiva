import { useEffect, useRef, useState } from 'react';
import { Button, DataTable, Notice, StatusBadge, Surface } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import { ApiError, request } from './api.js';
import { trafficResponse } from './traffic.js';
import type { TrafficPage } from './traffic.js';
import { trafficMessages } from './trafficMessages.js';

export function TrafficPanel({ locale, busy, onFailure }: { locale: Locale; busy: boolean; onFailure: (error: unknown) => void }) {
  const copy = trafficMessages[locale];
  const [page, setPage] = useState<TrafficPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [changed, setChanged] = useState(false);
  const stream = useRef<string | null>(null);
  const active = useRef(false);
  const lock = useRef(false);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  async function load(older: boolean) {
    if (busy || lock.current || (older && !page?.next_before)) return;
    lock.current = true; setLoading(true);
    try {
      const query = older && page ? `&before=${page.next_before}&stream=${encodeURIComponent(page.stream)}` : '';
      const next = trafficResponse(await request(`firewall/traffic?limit=50${query}`));
      if (!active.current) return;
      const restarted = stream.current !== null && stream.current !== next.stream;
      stream.current = next.stream;
      setChanged(restarted);
      setPage(older && restarted ? null : next);
    } catch (error) {
      if (!active.current) return;
      setPage(null);
      if (error instanceof ApiError && error.code === 'ANDEIVA_TRAFFIC_STREAM_CHANGED') { stream.current = null; setChanged(true); }
      else onFailure(error);
    } finally { lock.current = false; if (active.current) setLoading(false); }
  }
  const formatTime = (value: string) => new Date(value).toLocaleString(locale);
  return <Surface title={copy.title} description={copy.description}>
    <div data-testid="traffic-panel" aria-busy={loading}>
      <p className="fw-meta">{copy.retention}</p>
      <p className="fw-meta">{copy.baselineHint}</p>
      <div className="fw-toolbar"><Button variant="secondary" disabled={busy || loading} onClick={() => void load(false)}>{copy.sample}</Button><Button variant="secondary" disabled={busy || loading || !page?.next_before} onClick={() => void load(true)}>{copy.older}</Button></div>
      {loading && <p role="status">{copy.loading}</p>}
      {changed && <Notice title={copy.changed} live>{copy.changedBody}</Notice>}
      {page?.truncated && <Notice title={copy.truncated}>{copy.truncatedBody}</Notice>}
      {page ? <>
        <p className="fw-meta">{copy.stream}: <code className="fw-hash">{page.stream}</code></p>
        <p className="fw-meta">{copy.evicted}: {page.evicted} · {copy.count}: {page.records.length}</p>
        <DataTable caption={copy.title}><thead><tr>{(['sequence', 'time', 'since', 'revision', 'rule', 'action', 'kind', 'packetsTotal', 'bytesTotal', 'packetsDelta', 'bytesDelta'] as const).map((key) => <th key={key} scope="col">{copy[key]}</th>)}</tr></thead><tbody>{page.records.map((record) => <tr key={record.sequence}>
          <th scope="row">{record.sequence}</th><td><time dateTime={record.observed_at}>{formatTime(record.observed_at)}</time></td><td>{record.since ? <time dateTime={record.since}>{formatTime(record.since)}</time> : copy.noSince}</td><td><code className="fw-hash">{record.revision}</code></td><td>{record.rule_id}</td><td>{copy[record.action]}</td><td><StatusBadge tone={record.kind === 'baseline' ? 'info' : 'success'}>{copy[record.kind]}</StatusBadge></td><td>{record.packets_total}</td><td>{record.bytes_total}</td><td>{record.kind === 'baseline' ? copy.noDelta : record.packets_delta}</td><td>{record.kind === 'baseline' ? copy.noDelta : record.bytes_delta}</td>
        </tr>)}{page.records.length === 0 && <tr><td colSpan={11}>{copy.empty}</td></tr>}</tbody></DataTable>
      </> : <p>{copy.initial}</p>}
    </div>
  </Surface>;
}
