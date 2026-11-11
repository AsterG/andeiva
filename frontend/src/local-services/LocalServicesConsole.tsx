import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Button, DataTable, Dialog, Field, FilterBar, Notice, StatusBadge, Surface, TextInput } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import { ApiError, request } from '../firewall/api.js';
import { errorMessage, firewallMessages } from '../firewall/messages.js';
import type { Operation, Session } from '../firewall/model.js';
import { sessionResponse } from '../firewall/responses.js';
import { HistoryPanel } from '../firewall/HistoryPanel.js';
import { localMessages } from './messages.js';
import { capabilitiesResponse, draftConfig, effectiveMatchesSnapshot, effectiveResponse, historyResponse, newService, proofResponse, proofTokens, statusResponse } from './model.js';
import type { Capabilities, Config, Effective, History, Proof, Request, Service, Status } from './model.js';
import { HeaderAccount } from '../design-system/HeaderAccount.js';
import { ServiceEditor } from './ServiceEditor.js';

export function LocalServicesConsole({ locale, view, renderFrame }: { locale: Locale; view: 'services' | 'effective'; renderFrame: (content: ReactNode, authenticated: boolean, account: ReactNode) => ReactNode }) {
  const copy = localMessages[locale]; const common = firewallMessages[locale];
  const [session, setSession] = useState<Session | null>(null);
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [state, setState] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false);
  const [fresh, setFresh] = useState(false); const [error, setError] = useState<ApiError | null>(null);
  const [draft, setDraft] = useState<Config | null>(null); const [dirty, setDirty] = useState(false);
  const [base, setBase] = useState(0); const [revisionView, setRevisionView] = useState<'draft' | 'candidate' | 'running' | 'startup'>('draft');
  const [editor, setEditor] = useState<Service | null>(null); const [history, setHistory] = useState<History | null>(null);
  const [review, setReview] = useState<{ operation: Operation; target: string } | null>(null);
  const [seconds, setSeconds] = useState('60'); const [tokens, setTokens] = useState(''); const [proof, setProof] = useState<Proof | null>(null);
  const [filtered, setFiltered] = useState<Effective | null>(null);
  const [filters, setFilters] = useState({ service: '', interface: '', protocol: '', port: '', source: '' });
  const lock = useRef(false); const version = useRef(0); const mounted = useRef(true); const loginForm = useRef<HTMLFormElement>(null);
  const snapshot = state?.snapshot; const admin = session?.role === 'admin';
  const healthy = fresh && !!state && effectiveMatchesSnapshot(state.effective, state.snapshot);
  const owns = !snapshot?.candidate || snapshot.candidate.owner === session?.username;
  const canWrite = admin && healthy && caps?.recovery_endpoint && !busy && !snapshot?.pending && owns;
  const staleDraft = dirty && base !== snapshot?.generation;
  const canEdit = !!canWrite && !staleDraft && revisionView === 'draft' && !!caps?.local_interfaces.length;
  const durationValid = /^(?:[3-9]\d|1[01]\d|120)$/.test(seconds);
  const parsedTokens = proofTokens(tokens);
  const bindingsNeeded = snapshot?.running.config.local_services?.services.filter((s) => s.enabled).reduce((sum, s) => sum + s.bindings.length, 0) ?? 0;
  function forget() { version.current++; setSession(null); setState(null); setCaps(null); setDraft(null); setFresh(false); setDirty(false); setEditor(null); setReview(null); setProof(null); setTokens(''); setHistory(null); setFiltered(null); }
  function fail(reason: unknown) { const e = reason instanceof ApiError ? reason : new ApiError('ANDEIVA_RESPONSE_INVALID'); setError(e); setFresh(false); setProof(null); setTokens(''); if (e.status === 401) forget(); }
  function accept(value: unknown, capabilities: Capabilities, reset: boolean) {
    const next = statusResponse(value); setState(next); setFresh(true); setFiltered(null); setProof(null); setTokens('');
    if (reset) { setDraft(draftConfig(next.snapshot, capabilities.local_interfaces)); setDirty(false); setBase(next.snapshot.generation); setEditor(null); }
  }
  async function load(identity: Session, reset = true) {
    if (Date.parse(identity.expires_at) <= Date.now()) throw new ApiError('ANDEIVA_SESSION_EXPIRED', 401);
    const epoch = version.current;
    const capabilities = capabilitiesResponse(await request('capabilities'));
    if (epoch !== version.current || !mounted.current) return;
    setCaps(capabilities); setSession(identity);
    if (identity.role !== 'admin' || !capabilities.recovery_endpoint) setRevisionView('running');
    if (capabilities.local_services) { const next = await request('local-services'); if (epoch === version.current && mounted.current) accept(next, capabilities, reset); }
  }
  useEffect(() => {
    mounted.current = true; let active = true;
    void (async () => { try { const identity = sessionResponse(await request('auth/session')); if (active) await load(identity); } catch (reason) { if (active && !(reason instanceof ApiError && reason.status === 401)) fail(reason); } finally { if (active) setLoading(false); } })();
    return () => { active = false; mounted.current = false; version.current++; };
  }, []);
  useEffect(() => { if (!session) return; const timer = window.setTimeout(() => { forget(); setError(new ApiError('ANDEIVA_SESSION_EXPIRED', 401)); }, Math.max(0, Math.min(Date.parse(session.expires_at) - Date.now(), 2_147_483_647))); return () => window.clearTimeout(timer); }, [session]);
  useEffect(() => { if (!snapshot?.pending) return; const timer = window.setTimeout(() => { setFresh(false); setProof(null); setTokens(''); }, Math.max(0, Date.parse(snapshot.pending.deadline) - Date.now())); return () => window.clearTimeout(timer); }, [snapshot?.pending]);
  useEffect(() => { if (!proof) return; const timer = window.setTimeout(() => setProof(null), Math.max(0, Date.parse(proof.expires_at) - Date.now())); return () => window.clearTimeout(timer); }, [proof]);
  useEffect(() => { if (!dirty) return; const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; }; window.addEventListener('beforeunload', warn); return () => window.removeEventListener('beforeunload', warn); }, [dirty]);
  async function task(work: () => Promise<void>) { if (lock.current) return; lock.current = true; const epoch = version.current; setBusy(true); setError(null); try { await work(); } catch (reason) { if (mounted.current && epoch === version.current) fail(reason); } finally { lock.current = false; if (mounted.current) setBusy(false); } }
  async function login(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault(); const data = new FormData(event.currentTarget);
    const credentials = { username: String(data.get('username') ?? '').trim(), credential: String(data.get('credential') ?? '') };
    await task(async () => { try { const identity = sessionResponse(await request('auth/login', credentials)); await load(identity); } finally { loginForm.current?.reset(); } });
  }
  async function transact(operation: Operation, target: string) {
    if (!session || !snapshot || !caps || !healthy || !admin || !caps.recovery_endpoint) return;
    if ((operation === 'commit' || operation === 'rollback') && !durationValid) return;
    if (operation === 'confirm' && (!parsedTokens || parsedTokens.length !== bindingsNeeded)) return;
    const epoch = version.current;
    await task(async () => {
      setReview(null);
      const transaction: Request['transaction'] = { operation, key: crypto.randomUUID(), expected_generation: snapshot.generation };
      if (operation === 'stage' && draft) transaction.config = draft;
      if (operation === 'commit' || operation === 'rollback') transaction.confirm_for = Number(seconds) * 1_000_000_000;
      if (operation === 'confirm' || operation === 'rollback') transaction.target = target;
      const body: Request = { transaction };
      if (['commit', 'rollback', 'confirm', 'save'].includes(operation)) {
        const lease = operation === 'confirm' ? snapshot.pending?.lease : transaction.key;
        const p = proofResponse(await request('local-services/proof', { generation: snapshot.generation, target, lease }, session.csrf));
        if (Date.parse(p.expires_at) <= Date.now()) throw new ApiError('ANDEIVA_CONFIG_CONFIRMATION_EXPIRED');
        if (epoch !== version.current || !mounted.current) return; body.recovery_proof = p.token;
      }
      if (operation === 'confirm') body.endpoint_proofs = parsedTokens ?? [];
      setFresh(false); setTokens(''); setProof(null);
      const next = await request('local-services/transactions', body, session.csrf);
      if (epoch === version.current && mounted.current) { accept(next, caps, true); setHistory(null); }
    });
  }
  async function issueProof() {
    if (!session || !snapshot?.pending || !healthy || !admin || caps?.recovery_endpoint || snapshot.pending.owner !== session.username) return;
    const epoch = version.current; await task(async () => { const p = proofResponse(await request('local-services/proof', { generation: snapshot.generation, target: snapshot.running.hash, lease: snapshot.pending!.lease }, session.csrf)); if (Date.parse(p.expires_at) <= Date.now()) throw new ApiError('ANDEIVA_CONFIG_CONFIRMATION_EXPIRED'); if (mounted.current && epoch === version.current) setProof(p); });
  }
  const selected = snapshot && (revisionView === 'candidate' ? snapshot.candidate?.revision.config : revisionView === 'draft' ? draft : snapshot[revisionView].config);
  const services = selected?.local_services?.services ?? [];
  const effective = filtered ?? state?.effective;
  const authenticated = !loading && !!session && Date.parse(session.expires_at) > Date.now();
  const content = <div className="fw-stack" aria-busy={busy || loading}>
    {error && <Notice title={common.error} live>{errorMessage(error.code, common, error.status)}</Notice>}
    {loading ? <Notice title={common.loading}>{common.https}</Notice> : !authenticated ? <Surface title={common.login} description={common.https} className="fw-login"><form ref={loginForm} onSubmit={(e) => void login(e)}><Field id="local-username" label={common.username}><TextInput id="local-username" name="username" required maxLength={64} autoComplete="username" disabled={busy} /></Field><Field id="local-credential" label={common.credential} hint={common.credentialHint}><TextInput id="local-credential" name="credential" type="password" required maxLength={256} autoComplete="off" disabled={busy} /></Field><Button type="submit" disabled={busy}>{common.login}</Button></form></Surface> : <>
      <div className="fw-status-tools"><Button variant="secondary" disabled={busy} onClick={() => void task(async () => { setFresh(false); await load(session, !dirty); })}>{common.retry}</Button></div>
      {!caps?.local_services ? <Notice title={copy.title}>{copy.unavailable}</Notice> : <>
        <Notice title={caps.recovery_endpoint ? copy.recovery : copy.managed}>{caps.recovery_endpoint ? copy.recoveryHint : copy.managedHint}</Notice>
        {!healthy && <Notice title={common.disconnected}>{copy.stale}</Notice>}
        {state && snapshot && <>
          <Surface title={common.revisions} description={`${copy.generation}: ${snapshot.generation}`}><dl className="fw-revisions">{(['candidate', 'running', 'startup'] as const).map((key) => <div key={key}><dt>{common[key]}</dt><dd><code className="fw-hash">{key === 'candidate' ? snapshot.candidate?.revision.hash ?? common.none : snapshot[key].hash}</code></dd></div>)}</dl><p><StatusBadge tone={healthy ? snapshot.pending ? 'warning' : 'success' : 'error'}>{healthy ? snapshot.pending ? common.pending_confirmation : common.verified : common.unavailable}</StatusBadge></p>{snapshot.pending && <><Notice title={common.pendingTitle}>{copy.confirmWarning}</Notice><p>{common.deadline}: <time dateTime={snapshot.pending.deadline}>{snapshot.pending.deadline}</time></p></>}</Surface>
          {view === 'services' ? <>
            <Surface title={copy.declared}><div className="fw-toolbar"><Field id="local-view" label={common.revisions}><select id="local-view" className="ds-select" value={revisionView} onChange={(e) => { setRevisionView(e.target.value as typeof revisionView); setEditor(null); }}>{admin && caps.recovery_endpoint && <option value="draft">{common.draft}</option>}<option value="candidate" disabled={!snapshot.candidate}>{common.candidate}</option><option value="running">{common.running}</option><option value="startup">{common.startup}</option></select></Field></div>
              {revisionView === 'draft' && <><StatusBadge tone={dirty ? 'warning' : 'info'}>{dirty ? common.dirty : common.clean}</StatusBadge>{staleDraft && <Notice title={common.dirty}>{common.staleDraft}</Notice>}{!owns && <Notice title={common.owner}>{common.candidateBusy}</Notice>}</>}
              {!selected?.local_services && <Notice title={copy.declared}>{copy.legacy}</Notice>}
              <DataTable caption={copy.declared}><thead><tr>{[copy.service, copy.state, copy.port, copy.bindings, copy.sources].map((label) => <th scope="col" key={label}>{label}</th>)}{admin && revisionView === 'draft' && <th scope="col">{common.actions}</th>}</tr></thead><tbody>{services.map((s) => <tr key={s.id}><th scope="row">{s.id.toUpperCase()}</th><td>{s.enabled ? copy.enabled : copy.disabled}</td><td>{s.endpoints[0]?.first_port}</td><td>{s.bindings.map((b) => <div key={`${b.interface}/${b.local_address}`}>{b.interface} · {b.local_address}</div>)}</td><td>{s.bindings.map((b) => <div key={`${b.interface}/${b.local_address}`}>{b.sources.join(', ')}</div>)}</td>{admin && revisionView === 'draft' && <td><Button variant="secondary" disabled={!canEdit} onClick={() => setEditor(s)}>{copy.edit}: {s.id.toUpperCase()}</Button></td>}</tr>)}{services.length === 0 && <tr><td colSpan={6}>{copy.noServices}</td></tr>}</tbody></DataTable>
              {admin && caps.recovery_endpoint && <><div className="ds-actions">{(['https', 'ssh'] as const).filter((id) => !services.some((s) => s.id === id)).map((id) => <Button key={id} variant="secondary" disabled={!canEdit} onClick={() => setEditor(newService(id))}>{copy.edit}: {id.toUpperCase()}</Button>)}</div>{!caps.local_interfaces.length && <Notice title={copy.title}>{copy.missingInventory}</Notice>}<div className="ds-actions"><Button disabled={!canWrite || staleDraft || !dirty || !!editor} onClick={() => void transact('stage', '')}>{common.stage}</Button><Button variant="secondary" disabled={busy || !dirty || !fresh} onClick={() => { setDraft(draftConfig(snapshot, caps.local_interfaces)); setDirty(false); setEditor(null); setBase(snapshot.generation); }}>{common.discard}</Button><Button variant="secondary" disabled={!canWrite || !snapshot.candidate || dirty || !!editor} onClick={() => void transact('validate', '')}>{common.validate}</Button></div><div className="ds-actions"><Field id="local-confirm-seconds" label={common.confirmSeconds}><TextInput id="local-confirm-seconds" type="number" min={30} max={120} value={seconds} aria-invalid={!durationValid} onChange={(e) => setSeconds(e.target.value)} /></Field><Button disabled={!canWrite || !snapshot.candidate || dirty || !!editor || !durationValid} onClick={() => setReview({ operation: 'commit', target: snapshot.candidate!.revision.hash })}>{common.commitConfirmed}</Button><Button variant="secondary" disabled={!canWrite || dirty || !!editor || snapshot.running.hash === snapshot.startup.hash} onClick={() => setReview({ operation: 'save', target: snapshot.running.hash })}>{common.save}</Button></div></>}
            </Surface>
            {editor && draft?.local_services && <ServiceEditor initial={editor} interfaces={caps.local_interfaces} services={draft.local_services.services} copy={copy} disabled={!canEdit} cancel={() => setEditor(null)} save={(s) => { const local = draft.local_services!; setDraft({ ...draft, local_services: { ...local, services: [...local.services.filter((previous) => previous.id !== s.id), s] } }); setDirty(true); setEditor(null); }} />}
          </> : <Surface title={copy.effective} description={copy.readOnly}><FilterBar label={copy.filter}>{(['service', 'interface', 'protocol', 'port', 'source'] as const).map((key) => <Field key={key} id={`effective-${key}`} label={copy[key]}><TextInput id={`effective-${key}`} value={filters[key]} maxLength={128} onChange={(e) => setFilters({ ...filters, [key]: e.target.value })} /></Field>)}<Button disabled={busy} onClick={() => void task(async () => { const query = new URLSearchParams(Object.entries(filters).filter(([, value]) => value !== '')); const epoch = version.current; const next = effectiveResponse(await request(`effective-policies?${query}`)); if (mounted.current && epoch === version.current) { if (effectiveMatchesSnapshot(next, snapshot)) setFiltered(next); else { setFiltered(null); setFresh(false); setProof(null); setTokens(''); } } })}>{copy.filterApply}</Button></FilterBar>
            {healthy && effective && effectiveMatchesSnapshot(effective, snapshot) ? <><DataTable caption={copy.effective}><thead><tr>{[copy.service, copy.owner, copy.interface, copy.protocol, copy.port, copy.address, copy.source, copy.action].map((label) => <th scope="col" key={label}>{label}</th>)}</tr></thead><tbody>{effective?.rules.map((r) => <tr key={r.id}><th scope="row">{r.service}</th><td>{r.owner}</td><td>{r.interface}</td><td>{r.endpoint.protocol.toUpperCase()}</td><td>{r.endpoint.first_port}</td><td>{r.local_address}</td><td>{r.source}</td><td>{copy.allow}</td></tr>)}{!effective?.rules.length && <tr><td colSpan={8}>{copy.noRules}</td></tr>}</tbody></DataTable>
            <DataTable caption={copy.applied}><thead><tr>{[copy.service, copy.interface, copy.address, copy.port].map((label) => <th key={label} scope="col">{label}</th>)}</tr></thead><tbody>{effective?.listeners.map((l) => <tr key={`${l.service}/${l.interface}/${l.local_address}`}><th scope="row">{l.service}</th><td>{l.interface}</td><td>{l.local_address}</td><td>{l.port}</td></tr>)}{!effective?.listeners.length && <tr><td colSpan={4}>{copy.noBindings}</td></tr>}</tbody></DataTable></> : <Notice title={common.unavailable}>{copy.stale}</Notice>}
          </Surface>}
          {admin && snapshot.pending && snapshot.pending.owner === session.username && <Surface title={copy.proofTitle} description={copy.proofHint}><p>{copy.proofNeeded}</p><dl className="fw-review"><dt>{copy.target}</dt><dd><code className="fw-hash">{snapshot.running.hash}</code></dd><dt>{copy.lease}</dt><dd><code>{snapshot.pending.lease}</code></dd><dt>{copy.generation}</dt><dd>{snapshot.generation}</dd></dl>{caps.recovery_endpoint ? <><Field id="endpoint-proofs" label={copy.proofInput} {...(parsedTokens === null ? { error: copy.proofError } : {})}><textarea id="endpoint-proofs" className="ds-input" rows={3} maxLength={520} autoComplete="off" spellCheck={false} value={tokens} onChange={(e) => setTokens(e.target.value)} /></Field><div className="ds-actions"><Button disabled={!healthy || busy || parsedTokens === null || parsedTokens.length !== bindingsNeeded} onClick={() => setReview({ operation: 'confirm', target: snapshot.running.hash })}>{common.confirm}</Button></div></> : <><Button disabled={!healthy || busy} onClick={() => void issueProof()}>{copy.issueProof}</Button>{proof && <><Field id="issued-proof" label={copy.proofResult}><TextInput id="issued-proof" readOnly autoComplete="off" value={proof.token} /></Field><p>{copy.proofExpiry}: <time dateTime={proof.expires_at}>{proof.expires_at}</time></p><Button variant="secondary" onClick={() => setProof(null)}>{copy.clearProof}</Button></>}</>}</Surface>}
          {admin && <HistoryPanel history={history} copy={common} busy={busy} canRestore={!!canWrite && !dirty && !editor && durationValid} load={(before) => void task(async () => { const epoch = version.current; const next = historyResponse(await request(`local-services/history?limit=50${before ? `&before=${before}` : ''}`)); if (mounted.current && epoch === version.current) setHistory(next); })} restore={(target) => setReview({ operation: 'rollback', target })} />}
        </>}
      </>}
    </>}
    <Dialog open={authenticated && !!review} title={common.review} closeLabel={common.cancel} onClose={() => setReview(null)}>{authenticated && review && <><p>{review.operation === 'save' ? common.saveWarning : copy.confirmWarning}</p><dl className="fw-review"><dt>{common.operation}</dt><dd>{common[review.operation]}</dd><dt>{copy.target}</dt><dd><code className="fw-hash">{review.target}</code></dd></dl><Button disabled={!healthy || busy} onClick={() => void transact(review.operation, review.target)}>{common.proceed}</Button></>}</Dialog>
  </div>;
  return renderFrame(content, authenticated, authenticated && session ? <HeaderAccount locale={locale} username={session.username} role={session.role} expiresAt={session.expires_at} busy={busy} logout={() => void task(async () => { await request('auth/logout', {}, session.csrf); forget(); })} /> : null);
}
