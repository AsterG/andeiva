import { useEffect, useRef, useState } from 'react';
import { Button, DataTable, Dialog, Field, Notice, StatusBadge, Surface, TextInput } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import { ApiError, request } from './api.js';
import { HistoryPanel } from './HistoryPanel.js';
import { errorMessage, firewallMessages } from './messages.js';
import { draftConfig, formatPorts } from './model.js';
import type { Config, FirewallState, History, Operation, Session, Transaction } from './model.js';
import { RuleEditor } from './RuleEditor.js';
import { firewallResponse, historyResponse, sessionResponse } from './responses.js';

type Review = { operation: Operation; target: string; confirm_for?: number } | { operation: 'remove'; index: number; target: string } | { operation: 'discard'; target: string };
type RuleView = 'draft' | 'candidate' | 'running' | 'startup';

export function FirewallConsole({ locale }: { locale: Locale }) {
  const copy = firewallMessages[locale];
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const lock = useRef(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [success, setSuccess] = useState(false);
  const [state, setState] = useState<FirewallState | null>(null);
  const [fresh, setFresh] = useState(false);
  const [observed, setObserved] = useState('');
  const [draft, setDraft] = useState<Config | null>(null);
  const [baseGeneration, setBaseGeneration] = useState(0);
  const [dirty, setDirty] = useState(false);
  const [view, setView] = useState<RuleView>('draft');
  const [editor, setEditor] = useState<{ index: number | null } | null>(null);
  const [review, setReview] = useState<Review | null>(null);
  const [history, setHistory] = useState<History | null>(null);
  const [historyDenied, setHistoryDenied] = useState(false);
  const [confirmSeconds, setConfirmSeconds] = useState('60');
  const loginForm = useRef<HTMLFormElement>(null);
  const mounted = useRef(true);
  const authVersion = useRef(0);

  function forgetSession() {
    authVersion.current++;
    setSession(null); setState(null); setDraft(null); setHistory(null); setFresh(false); setDirty(false); setEditor(null); setReview(null); setSuccess(false);
  }
  function fail(reason: unknown) {
    const failure = reason instanceof ApiError ? reason : new ApiError('ANDEIVA_RESPONSE_INVALID');
    setError(failure); setFresh(false); setSuccess(false);
    if (failure.status === 401) forgetSession();
  }
  function accept(next: FirewallState, resetDraft: boolean) {
    next = firewallResponse(next);
    // Never render a green verification badge from a mismatched receipt.
    if ((next.effective.state === 'verified' || next.effective.state === 'pending_confirmation') && (next.effective.revision !== next.snapshot.running.hash || (next.effective.state === 'pending_confirmation' && !next.snapshot.pending))) next = { ...next, effective: { ...next.effective, state: 'unavailable' } };
    setState(next); setFresh(true); setObserved(new Date().toISOString());
    setView((previous) => previous === 'candidate' && !next.snapshot.candidate ? 'running' : previous);
    if (resetDraft) { setDraft(draftConfig(next.snapshot)); setBaseGeneration(next.snapshot.generation); setDirty(false); setEditor(null); }
  }
  async function refresh(resetDraft = !dirty) {
    if (lock.current) return;
    lock.current = true; setBusy(true); setError(null); setSuccess(false); setFresh(false);
    const version = authVersion.current;
    try { const next = await request<FirewallState>('firewall'); if (version === authVersion.current) accept(next, resetDraft); }
    catch (reason) { fail(reason); }
    finally { lock.current = false; setBusy(false); }
  }
  useEffect(() => {
    mounted.current = true;
    let active = true;
    void (async () => {
      const version = authVersion.current;
      try {
        const identity = sessionResponse(await request('auth/session'));
        if (!active) return;
        setSession(identity); setView(identity.role === 'admin' ? 'draft' : 'running');
        const next = await request<FirewallState>('firewall');
        if (active && version === authVersion.current) accept(next, true);
      } catch (reason) { if (active && !(reason instanceof ApiError && reason.status === 401)) fail(reason); }
      finally { if (active) setLoading(false); }
    })();
    return () => { active = false; mounted.current = false; };
  }, []);
  useEffect(() => {
    if (!session) return;
    const delay = Date.parse(session.expires_at) - Date.now();
    const timer = window.setTimeout(() => { forgetSession(); setError(new ApiError('ANDEIVA_SESSION_EXPIRED', 401)); }, Math.max(0, Math.min(delay, 2_147_483_647)));
    return () => window.clearTimeout(timer);
  }, [session]);
  useEffect(() => {
    if (!state?.snapshot.pending) return;
    const timer = window.setTimeout(() => setFresh(false), Math.max(0, Date.parse(state.snapshot.pending.deadline) - Date.now()));
    return () => window.clearTimeout(timer);
  }, [state]);
  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  async function login(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (lock.current) return;
    const values = new FormData(event.currentTarget);
    const username = String(values.get('username') ?? '').trim();
    const credential = String(values.get('credential') ?? '');
    lock.current = true; setBusy(true); setError(null);
    const version = authVersion.current;
    try {
      const identity = sessionResponse(await request('auth/login', { username, credential }));
      loginForm.current?.reset();
      setSession(identity); setView(identity.role === 'admin' ? 'draft' : 'running'); setHistoryDenied(false);
      const next = await request<FirewallState>('firewall');
      if (version === authVersion.current) accept(next, true);
    } catch (reason) { loginForm.current?.reset(); fail(reason); }
    finally { lock.current = false; if (mounted.current) setBusy(false); }
  }
  async function logout() {
    if (!session || lock.current) return;
    lock.current = true; setBusy(true); setError(null);
    try { await request('auth/logout', {}, session.csrf); forgetSession(); }
    catch (reason) { fail(reason); }
    finally { lock.current = false; setBusy(false); }
  }
  async function transact(operation: Operation, options: { target?: string; confirm_for?: number } = {}) {
    if (!session || !state || !fresh || lock.current || session.role !== 'admin') return;
    lock.current = true; setBusy(true); setError(null); setSuccess(false); setReview(null);
    const transaction: Transaction = { operation, key: crypto.randomUUID(), expected_generation: state.snapshot.generation, ...options };
    if (operation === 'stage' && draft) transaction.config = { ...draft, schema_version: 2 };
    setFresh(false);
    const version = authVersion.current;
    try {
      await request<FirewallState>('firewall/transactions', transaction, session.csrf);
      const next = await request<FirewallState>('firewall');
      if (version === authVersion.current) { accept(next, true); setHistory(null); setSuccess(true); }
    } catch (reason) { fail(reason); }
    finally { lock.current = false; setBusy(false); }
  }
  async function loadHistory(before?: number) {
    if (lock.current || session?.role !== 'admin') return;
    lock.current = true; setBusy(true); setError(null);
    const version = authVersion.current;
    try { const next = historyResponse(await request(`firewall/history?limit=50${before ? `&before=${before}` : ''}`)); if (version === authVersion.current) setHistory(next); }
    catch (reason) { if (reason instanceof ApiError && reason.status === 403) { setHistoryDenied(true); setHistory(null); } fail(reason); }
    finally { lock.current = false; setBusy(false); }
  }

  const snapshot = state?.snapshot;
  const admin = session?.role === 'admin';
  const ownsCandidate = !snapshot?.candidate || snapshot.candidate.owner === session?.username;
  const healthy = fresh && !!state && !snapshot?.recovery_required && (state.effective.state === 'verified' || state.effective.state === 'pending_confirmation');
  const writable = admin && healthy && !busy && !snapshot?.pending && ownsCandidate;
  const staleDraft = dirty && baseGeneration !== snapshot?.generation;
  const canEdit = writable && !staleDraft && view === 'draft';
  const selectedRevision = snapshot && view !== 'draft' ? view === 'candidate' ? snapshot.candidate?.revision : snapshot[view] : undefined;
  const config = view === 'draft' ? draft : selectedRevision?.config;
  const selectedHash = view === 'draft' && !dirty ? snapshot?.candidate?.revision.hash ?? snapshot?.running.hash : selectedRevision?.hash;
  const showCounters = healthy && selectedHash === state?.effective.revision;
  const secondsValid = /^\d+$/.test(confirmSeconds) && Number(confirmSeconds) >= 30 && Number(confirmSeconds) <= 120;
  const date = (value: string) => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString(locale) : copy.unknown;
  function move(index: number, delta: number) {
    if (!canEdit || !draft) return;
    const rules = [...draft.rules];
    const moved = rules.splice(index, 1)[0];
    if (moved) rules.splice(index + delta, 0, moved);
    setDraft({ ...draft, rules }); setDirty(true); setEditor(null);
  }

  return <div className="fw-stack" aria-busy={loading || busy}>
    {error && <Notice title={copy.error} live>{errorMessage(error.code, copy, error.status)}</Notice>}
    {loading ? <Notice title={copy.loading}>{copy.https}</Notice> : !session ? <Surface title={copy.login} description={copy.https} className="fw-login"><form ref={loginForm} onSubmit={(event) => void login(event)}>
      <Field id="login-username" label={copy.username}><TextInput id="login-username" name="username" autoComplete="username" maxLength={64} required disabled={busy} /></Field>
      <Field id="login-credential" label={copy.credential} hint={copy.credentialHint}><TextInput id="login-credential" name="credential" type="password" autoComplete="off" maxLength={256} required disabled={busy} aria-describedby="login-credential-hint" /></Field>
      <Button type="submit" disabled={busy}>{busy ? copy.loading : copy.login}</Button>
    </form></Surface> : <>
      <div className="fw-state"><div><strong>{copy.identity}: {session.username}</strong><p className="fw-meta">{admin ? copy.admin : copy.viewer} · {copy.expires}: {date(session.expires_at)}</p></div><div className="fw-toolbar"><Button variant="secondary" disabled={busy} onClick={() => void refresh()}>{copy.retry}</Button><Button variant="secondary" disabled={busy} onClick={() => void logout()}>{copy.logout}</Button></div></div>
      {(!healthy || !state) && <Notice title={copy.disconnected}>{copy.disconnectedBody}</Notice>}
      {success && <Notice title={copy.success} live>{copy.successBody}</Notice>}
      {state && snapshot && <>
        <Surface title={copy.revisions} description={`${copy.generation}: ${snapshot.generation}`}>
          <dl className="fw-revisions">{(['candidate', 'running', 'startup'] as const).map((key) => <div key={key}><dt>{copy[key]}</dt><dd><code className="fw-hash">{key === 'candidate' ? snapshot.candidate?.revision.hash ?? copy.none : snapshot[key].hash}</code>{key === 'candidate' && snapshot.candidate && <p className="fw-meta">{copy.owner}: {snapshot.candidate.owner}</p>}</dd></div>)}</dl>
          <div className="fw-toolbar ds-actions"><strong>{copy.effective}</strong><StatusBadge tone={healthy ? state.effective.state === 'verified' ? 'success' : 'warning' : 'error'}>{fresh ? copy[state.effective.state] : copy.unknown}</StatusBadge></div>
          <p className="fw-meta">{copy.observed}: <time dateTime={observed}>{date(observed)}</time></p><p className="fw-meta">{copy.effectiveRevision}: <code className="fw-hash">{fresh ? state.effective.revision || copy.unknown : copy.unknown}</code></p>
          {snapshot.pending && <><Notice title={copy.pendingTitle}>{copy.pendingBody}</Notice><p>{copy.deadline}: <time dateTime={snapshot.pending.deadline}>{date(snapshot.pending.deadline)}</time></p>{admin && <Button disabled={!healthy || busy || snapshot.pending.owner !== session.username} onClick={() => setReview({ operation: 'confirm', target: snapshot.running.hash })}>{copy.confirm}</Button>}</>}
        </Surface>
        <Surface title={copy.rules} description={copy.rulesHint}>
          <div className="fw-toolbar"><Field id="rule-view" label={copy.revisions}><select id="rule-view" className="ds-select" value={view} onChange={(event) => { setView(event.target.value as RuleView); setEditor(null); }}>{admin && <option value="draft">{copy.draft}</option>}<option value="candidate" disabled={!snapshot.candidate}>{copy.candidate}</option><option value="running">{copy.running}</option><option value="startup">{copy.startup}</option></select></Field>{admin && <Button disabled={!canEdit || !draft || draft.rules.length >= 64} onClick={() => setEditor({ index: null })}>{copy.add}</Button>}</div>
          {view === 'draft' && <><p className="fw-meta">{copy.draftHint} {copy.maxRules}</p><StatusBadge tone={dirty ? 'warning' : 'info'}>{dirty ? copy.dirty : copy.clean}</StatusBadge>{staleDraft && <Notice title={copy.dirty}>{copy.staleDraft}</Notice>}{!ownsCandidate && <Notice title={copy.owner}>{copy.candidateBusy}</Notice>}</>}
          <DataTable caption={copy.ruleList}><thead><tr>{(['priority', 'id', 'action', 'protocol', 'source', 'source_ports', 'destination', 'destination_ports', 'packets', 'bytes'] as const).map((key) => <th key={key} scope="col">{copy[key]}</th>)}{admin && view === 'draft' && <th scope="col">{copy.actions}</th>}</tr></thead><tbody>{(config?.rules ?? []).map((rule, index) => {
            const counter = showCounters ? state.effective.rules.find((entry) => entry.id === rule.id) : undefined;
            return <tr key={rule.id}><td>{index + 1}</td><th scope="row">{rule.id}</th><td><StatusBadge tone={rule.action === 'allow' ? 'info' : 'warning'}>{copy[rule.action]}</StatusBadge></td><td>{rule.match?.protocol.toUpperCase() ?? copy.unknown}</td><td>{rule.match?.source ?? copy.unknown}</td><td>{rule.match ? formatPorts(rule.match.source_ports) : copy.unknown}</td><td>{rule.match?.destination ?? copy.unknown}</td><td>{rule.match ? formatPorts(rule.match.destination_ports) : copy.unknown}</td><td>{counter?.packets ?? copy.unknown}</td><td>{counter?.bytes ?? copy.unknown}</td>{admin && view === 'draft' && <td><div className="fw-rule-actions"><Button variant="secondary" disabled={!canEdit || !rule.match} aria-label={`${copy.edit}: ${rule.id}`} onClick={() => setEditor({ index })}>{copy.edit}</Button><Button variant="secondary" disabled={!canEdit} aria-label={`${copy.up}: ${rule.id}`} onClick={() => move(index, -1)} {...(index === 0 ? { disabled: true } : {})}>{copy.up}</Button><Button variant="secondary" disabled={!canEdit || index === (config?.rules.length ?? 0) - 1} aria-label={`${copy.down}: ${rule.id}`} onClick={() => move(index, 1)}>{copy.down}</Button><Button variant="secondary" disabled={!canEdit} aria-label={`${copy.remove}: ${rule.id}`} onClick={() => setReview({ operation: 'remove', index, target: rule.id })}>{copy.remove}</Button></div></td>}</tr>;
          })}{!config?.rules.length && <tr><td colSpan={admin && view === 'draft' ? 11 : 10}>{copy.noRules}</td></tr>}</tbody></DataTable>
          {admin && <><p className="fw-meta">{copy.transactionHint}</p><div className="ds-actions"><Button disabled={!writable || staleDraft || !dirty || !!editor} onClick={() => void transact('stage')}>{copy.stage}</Button><Button variant="secondary" disabled={busy || !dirty || !fresh} onClick={() => setReview({ operation: 'discard', target: snapshot.candidate?.revision.hash ?? snapshot.running.hash })}>{copy.discard}</Button><Button variant="secondary" disabled={!writable || !snapshot.candidate || dirty || !!editor} onClick={() => void transact('validate')}>{copy.validate}</Button><Button variant="secondary" disabled={!writable || !snapshot.candidate || dirty || !!editor} onClick={() => setReview({ operation: 'commit', target: snapshot.candidate!.revision.hash })}>{copy.commit}</Button></div><div className="ds-actions"><Field id="confirm-seconds" label={copy.confirmSeconds}><TextInput id="confirm-seconds" type="number" min={30} max={120} step={1} value={confirmSeconds} onChange={(event) => setConfirmSeconds(event.target.value)} aria-invalid={!secondsValid} /></Field><Button disabled={!writable || !snapshot.candidate || dirty || !!editor || !secondsValid} onClick={() => setReview({ operation: 'commit', target: snapshot.candidate!.revision.hash, confirm_for: Number(confirmSeconds) * 1_000_000_000 })}>{copy.commitConfirmed}</Button><Button variant="secondary" disabled={!writable || dirty || !!editor || snapshot.running.hash === snapshot.startup.hash} onClick={() => setReview({ operation: 'save', target: snapshot.running.hash })}>{copy.save}</Button></div></>}
        </Surface>
        {editor && draft && <RuleEditor key={editor.index ?? 'new'} rules={draft.rules} index={editor.index} copy={copy} disabled={!canEdit} onCancel={() => setEditor(null)} onSave={(rule) => { setDraft({ ...draft, rules: editor.index === null ? [...draft.rules, rule] : draft.rules.map((previous, index) => index === editor.index ? rule : previous) }); setDirty(true); setEditor(null); }} />}
        {admin && !historyDenied && <HistoryPanel history={history} copy={copy} busy={busy} canRestore={writable && !dirty && !editor} load={(before) => void loadHistory(before)} restore={(target) => setReview({ operation: 'rollback', target })} />}
      </>}
    </>}
    <Dialog open={!!review} title={copy.review} closeLabel={copy.cancel} onClose={() => setReview(null)}>{review && <><p>{review.operation === 'remove' ? copy.removeWarning : review.operation === 'discard' ? copy.discardWarning : review.operation === 'save' ? copy.saveWarning : copy.commitWarning}</p><dl className="fw-review"><dt>{copy.operation}</dt><dd>{review.operation === 'discard' ? copy.discard : review.operation === 'commit' && review.confirm_for ? copy.commitConfirmed : copy[review.operation]}</dd><dt>{copy.target}</dt><dd><code className="fw-hash">{review.target}</code></dd></dl><Button disabled={busy || !fresh} onClick={() => {
      if (review.operation === 'remove' && draft && canEdit) { setDraft({ ...draft, rules: draft.rules.filter((_, index) => index !== review.index) }); setDirty(true); setEditor(null); setReview(null); }
      else if (review.operation === 'discard' && snapshot) { setDraft(draftConfig(snapshot)); setBaseGeneration(snapshot.generation); setDirty(false); setEditor(null); setReview(null); }
      else if (review.operation !== 'remove' && review.operation !== 'discard') void transact(review.operation, { ...(review.operation === 'confirm' || review.operation === 'rollback' ? { target: review.target } : {}), ...(review.confirm_for ? { confirm_for: review.confirm_for } : {}) });
    }}>{copy.proceed}</Button></>}</Dialog>
    <Notice title={copy.scope}>{copy.limitation}</Notice>
  </div>;
}
