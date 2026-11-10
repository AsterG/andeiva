import { useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Button, DataTable, Field, StatusBadge, TextInput } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import type { FirewallMessages } from './messages.js';
import { formatPorts } from './model.js';
import type { FirewallState, Rule } from './model.js';
import { matchesRuleSearch, ruleChange, sameRuleAtPosition } from './rulePresentation.js';
import { ruleTableMessages } from './ruleTableMessages.js';

type Drag = { from: number; to: number; id: string; pointer?: number; y?: number };

export function RuleTable({ controls, rules, reference, state, locale, copy, editable, reorderable, showCounters, verified, editing, supportsEnabled, onToggle, onMove, onEdit, onRemove }: {
  controls: ReactNode;
  rules: Rule[]; reference: Rule[] | undefined; state: FirewallState; locale: Locale; copy: FirewallMessages; editable: boolean; reorderable: boolean;
  showCounters: boolean; verified: boolean; editing: boolean; supportsEnabled: boolean; onToggle: (index: number, enabled: boolean) => void; onMove: (from: number, to: number) => void; onEdit: (index: number) => void; onRemove: (index: number) => void;
}) {
  const labels = ruleTableMessages[locale];
  const [query, setQuery] = useState('');
  const [action, setAction] = useState('all');
  const [drag, setDrag] = useState<Drag | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const root = useRef<HTMLDivElement>(null);
  const activeDrag = useRef<Drag | null>(null);
  const hintId = useId();
  const filtered = !!query.trim() || action !== 'all';
  const canMove = reorderable && !filtered && !editing && rules.length > 1;
  const visible = rules.map((rule, index) => ({ rule, index })).filter(({ rule }) => matchesRuleSearch(rule, query) && (action === 'all' || rule.action === action));

  function updateDrag(next: Drag | null) { activeDrag.current = next; setDrag(next); }
  function targetAt(y: number): number | undefined {
    const rows = [...(root.current?.querySelectorAll<HTMLElement>('tr[data-rule-position]') ?? [])];
    if (!rows.length) return;
    const nearest = rows.find((row) => y < row.getBoundingClientRect().bottom) ?? rows.at(-1)!;
    return Number(nearest.dataset.rulePosition);
  }
  function announceDrag(next: Drag) { setAnnouncement(`${labels.moving} ${next.id}: ${next.to + 1} / ${rules.length}`); }
  function finish(cancel = false, restoreFocus = true) {
    const current = activeDrag.current;
    updateDrag(null);
    if (!current) return;
    if (!cancel && canMove && rules[current.from]?.id === current.id) {
      onMove(current.from, current.to);
      setAnnouncement(`${labels.placed} ${current.id}: ${current.to + 1} / ${rules.length}`);
    } else setAnnouncement(labels.cancelled);
    if (restoreFocus) requestAnimationFrame(() => {
      const handle = [...(root.current?.querySelectorAll<HTMLButtonElement>('[data-rule-handle]') ?? [])].find((element) => element.dataset.ruleHandle === current.id);
      if (handle && !handle.disabled) { handle.focus(); handle.scrollIntoView({ block: 'nearest', inline: 'nearest' }); }
    });
  }

  // Pointer capture keeps touch dragging reliable outside the handle; scrolling is bounded to the rule list.
  useEffect(() => {
    if (!canMove || drag?.pointer === undefined) return;
    let frame = 0;
    const scroll = () => {
      const current = activeDrag.current;
      const container = root.current?.querySelector<HTMLElement>('.ds-table-scroll');
      if (current?.y !== undefined && container) {
        const rect = container.getBoundingClientRect();
        const delta = current.y < rect.top + 48 ? -12 : current.y > rect.bottom - 48 ? 12 : 0;
        if (delta) {
          container.scrollTop += delta;
          const to = targetAt(current.y);
          if (to !== undefined && to !== current.to) { const next = { ...current, to }; activeDrag.current = next; setDrag(next); }
        }
      }
      frame = requestAnimationFrame(scroll);
    };
    frame = requestAnimationFrame(scroll);
    return () => cancelAnimationFrame(frame);
  }, [canMove, drag?.pointer]);

  return <div ref={root} className="fw-rule-table">
    <div className="fw-rule-filters">
      {controls}
      <Field id="rule-search" label={labels.search}><TextInput id="rule-search" type="search" placeholder={labels.searchHint} value={query} disabled={!!drag} onChange={(event) => setQuery(event.target.value)} /></Field>
      <Field id="rule-action-filter" label={labels.actionFilter}><select id="rule-action-filter" className="ds-select" disabled={!!drag} value={action} onChange={(event) => setAction(event.target.value)}><option value="all">{labels.allActions}</option><option value="allow">{copy.allow}</option><option value="deny">{copy.deny}</option></select></Field>
      <span className="fw-meta">{visible.length} / {rules.length} {labels.ruleCount}</span>
    </div>
    {filtered && <p className="fw-meta">{labels.filtered}</p>}
    <details className="fw-rule-help"><summary>{labels.reorder}</summary><p id={hintId} className="fw-meta">{labels.reorderHint} {copy.rulesHint} {copy.maxRules}</p></details>
    <span className="fw-sr-only" role="status" aria-live="polite" aria-atomic="true">{announcement}</span>
    <DataTable caption={copy.ruleList}>
      <thead><tr><th scope="col">{labels.order}</th><th scope="col">{copy.id}</th><th scope="col">{copy.source}</th><th scope="col">{copy.destination}</th><th scope="col">{labels.service}</th><th scope="col">{copy.action}</th><th scope="col">{labels.execution}</th><th scope="col">{labels.persistence}</th><th scope="col">{labels.counters}</th>{editable && <th scope="col">{copy.actions}</th>}</tr></thead>
      <tbody>{visible.map(({ rule, index }) => {
        const running = sameRuleAtPosition(rule, index, state.snapshot.running.config.rules);
        const saved = sameRuleAtPosition(rule, index, state.snapshot.startup.config.rules);
        const change = reference ? ruleChange(rule, index, reference) : undefined;
        const counter = showCounters ? state.effective.rules.find((entry) => entry.id === rule.id) : undefined;
        return <tr key={rule.id} data-rule-position={index} data-dragging={drag?.from === index || undefined} data-drop-target={drag?.to === index || undefined}>
          <td><div className="fw-rule-order">{editable && <button type="button" className="fw-drag-handle" data-rule-handle={rule.id} disabled={!canMove} aria-label={`${labels.reorder}: ${rule.id}`} aria-describedby={hintId} aria-pressed={drag?.id === rule.id} onKeyDown={(event) => {
            if (!canMove) return;
            if (event.key === 'Escape') { event.preventDefault(); finish(true); return; }
            if (event.key === ' ' || event.key === 'Enter') {
              event.preventDefault();
              if (drag?.id === rule.id) finish();
              else { const next = { from: index, to: index, id: rule.id }; updateDrag(next); announceDrag(next); }
              return;
            }
            if (drag?.id !== rule.id || !['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const to = event.key === 'Home' ? 0 : event.key === 'End' ? rules.length - 1 : Math.max(0, Math.min(rules.length - 1, drag.to + (event.key === 'ArrowUp' ? -1 : 1)));
            const next = { ...drag, to }; updateDrag(next); announceDrag(next);
            root.current?.querySelector(`[data-rule-position="${to}"]`)?.scrollIntoView({ block: 'nearest' });
          }} onBlur={() => { if (activeDrag.current?.pointer === undefined) finish(true, false); }} onPointerDown={(event) => {
            if (!canMove || !event.isPrimary || event.button !== 0) return;
            event.preventDefault(); event.currentTarget.focus(); event.currentTarget.setPointerCapture(event.pointerId);
            const next = { from: index, to: index, id: rule.id, pointer: event.pointerId, y: event.clientY }; updateDrag(next); announceDrag(next);
          }} onPointerMove={(event) => {
            const current = activeDrag.current;
            if (current?.pointer !== event.pointerId) return;
            const to = targetAt(event.clientY);
            if (to !== undefined) updateDrag({ ...current, to, y: event.clientY });
          }} onPointerUp={(event) => { if (activeDrag.current?.pointer === event.pointerId) finish(); }} onPointerCancel={() => finish(true)} onLostPointerCapture={() => { if (activeDrag.current?.pointer !== undefined) finish(true); }}>
            <svg width="18" height="24" viewBox="0 0 18 24" aria-hidden="true">{[6, 12, 18].flatMap((y) => [6, 12].map((x) => <circle key={`${x}-${y}`} cx={x} cy={y} r="1.5" fill="currentColor" />))}</svg>
          </button>}<span>{index + 1}</span></div></td>
          <th scope="row">{editable ? <button type="button" className="fw-rule-link" aria-label={`${copy.edit}: ${rule.id}`} disabled={!reorderable || editing || !!drag} onClick={() => onEdit(index)}>{rule.id}</button> : rule.id}{editable && supportsEnabled ? <label className="fw-enabled-switch"><input type="checkbox" aria-label={`${labels.enabled}: ${rule.id}`} checked={rule.enabled ?? true} disabled={!reorderable || editing || !!drag} onChange={(event) => onToggle(index, event.target.checked)} /><span>{rule.enabled === false ? labels.disabled : labels.enabled}</span></label> : rule.enabled === false && <small>{labels.disabled}</small>}</th>
          <td>{rule.match.source}<small>{copy.source_ports}: {formatPorts(rule.match.source_ports)}</small></td><td>{rule.match.destination}</td>
          <td><strong>{rule.match.protocol.toUpperCase()}</strong><small>{formatPorts(rule.match.destination_ports)}</small></td>
          <td><StatusBadge tone={rule.action === 'allow' ? 'success' : 'error'}>{copy[rule.action]}</StatusBadge></td>
          <td><StatusBadge tone={!verified ? 'warning' : running ? 'success' : 'info'}>{!verified ? labels.unverified : running ? state.snapshot.pending ? copy.pending_confirmation : rule.enabled === false ? labels.disabledRunning : labels.applied : labels.notApplied}</StatusBadge>{change && <small>{labels[change]}</small>}</td>
          <td><StatusBadge tone={saved ? 'success' : 'warning'}>{saved ? labels.saved : labels.unsaved}</StatusBadge></td>
          <td>{rule.enabled === false ? labels.notApplicable : <><span>{copy.packets}: {counter?.packets ?? copy.unknown}</span><small>{copy.bytes}: {counter?.bytes ?? copy.unknown}</small></>}</td>
          {editable && <td><details className="fw-row-menu"><summary aria-label={`${copy.actions}: ${rule.id}`}><span aria-hidden="true">•••</span></summary><div className="fw-row-menu-content">
            <Button variant="secondary" disabled={!reorderable || editing || !!drag} aria-label={`${copy.remove}: ${rule.id}`} onClick={() => onRemove(index)}>{copy.remove}</Button>
            <form onSubmit={(event) => { event.preventDefault(); const to = Number(new FormData(event.currentTarget).get('position')) - 1; if (canMove && Number.isInteger(to) && to >= 0 && to < rules.length) { onMove(index, to); setAnnouncement(`${labels.placed} ${rule.id}: ${to + 1} / ${rules.length}`); const menu = event.currentTarget.closest('details'); menu?.removeAttribute('open'); menu?.querySelector('summary')?.focus(); } }}>
              <Field id={`position-${rule.id}`} label={labels.position}><TextInput id={`position-${rule.id}`} name="position" type="number" min={1} max={rules.length} defaultValue={index + 1} key={index} required disabled={!canMove} /></Field>
              <Button variant="secondary" type="submit" disabled={!canMove}>{labels.move}</Button>
            </form>
          </div></details></td>}
        </tr>;
      })}{!visible.length && <tr><td colSpan={editable ? 10 : 9}>{rules.length ? labels.noMatches : copy.noRules}</td></tr>}</tbody>
    </DataTable>
    {reference && reference.some((rule) => !rules.some((entry) => entry.id === rule.id)) && <p className="fw-meta">{labels.removed}: {reference.filter((rule) => !rules.some((entry) => entry.id === rule.id)).map((rule) => rule.id).join(', ')}</p>}
  </div>;
}
