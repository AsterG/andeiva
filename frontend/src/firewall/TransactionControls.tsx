import { Button, Field, Notice, StatusBadge, Surface, TextInput } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import { consoleMessages } from './consoleMessages.js';
import { firewallMessages } from './messages.js';
import { ruleTableMessages } from './ruleTableMessages.js';
import type { FirewallState, Operation, Session } from './model.js';

type Props = {
  state: FirewallState; session: Session; locale: Locale; healthy: boolean; fresh: boolean; busy: boolean;
  writable: boolean; dirty: boolean; staleDraft: boolean; editing: boolean; observed: string;
  confirmSeconds: string; setConfirmSeconds: (value: string) => void;
  execute: (operation: 'stage' | 'validate') => void;
  review: (operation: Operation, confirmed?: number) => void; discard: () => void;
};
export function TransactionControls({ state, session, locale, healthy, fresh, busy, writable, dirty, staleDraft, editing, observed, confirmSeconds, setConfirmSeconds, execute, review, discard }: Props) {
  const copy = firewallMessages[locale];
  const labels = ruleTableMessages[locale];
  const consoleCopy = consoleMessages[locale];
  const snapshot = state.snapshot;
  const admin = session.role === 'admin';
  const changed = dirty || !!snapshot.pending || (!!snapshot.candidate && snapshot.candidate.revision.hash !== snapshot.running.hash) || snapshot.running.hash !== snapshot.startup.hash;
  const secondsValid = /^\d+$/.test(confirmSeconds) && Number(confirmSeconds) >= 30 && Number(confirmSeconds) <= 120;
  const mayApply = writable && !!snapshot.candidate && !dirty && !editing;
  const date = (value: string) => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString(locale) : copy.unknown;
  return <Surface title={consoleCopy.actionBar} className={`console-transaction-bar${changed ? ' console-transaction-bar--pending' : ''}`}>
    <div className="console-transaction-summary"><strong>{dirty ? copy.dirty : snapshot.pending ? copy.pendingTitle : snapshot.candidate && snapshot.candidate.revision.hash !== snapshot.running.hash ? labels.candidateChanged : snapshot.running.hash !== snapshot.startup.hash ? labels.unsavedRevision : labels.savedRevision}</strong><div className="fw-overview-status"><StatusBadge tone={healthy ? state.effective.state === 'verified' ? 'success' : 'warning' : 'error'}>{fresh ? copy[state.effective.state] : copy.unknown}</StatusBadge>{(dirty || snapshot.pending || (snapshot.candidate && snapshot.candidate.revision.hash !== snapshot.running.hash)) && <StatusBadge tone={snapshot.running.hash === snapshot.startup.hash ? 'success' : 'warning'}>{snapshot.running.hash === snapshot.startup.hash ? labels.savedRevision : labels.unsavedRevision}</StatusBadge>}</div></div>
    {admin && <div className="console-transaction-actions">
      <Button variant={dirty ? 'primary' : 'secondary'} disabled={!writable || staleDraft || !dirty || editing} onClick={() => execute('stage')}>{copy.stage}</Button>
      <Button variant="secondary" disabled={!mayApply} onClick={() => execute('validate')}>{copy.validate}</Button>

      <Button variant={mayApply ? 'primary' : 'secondary'} disabled={!mayApply || !secondsValid} onClick={() => review('commit', Number(confirmSeconds) * 1_000_000_000)}>{copy.commitConfirmed}</Button>
      {snapshot.pending && <Button disabled={!healthy || busy || snapshot.pending.owner !== session.username} onClick={() => review('confirm')}>{copy.confirm}</Button>}
      <Button variant={!dirty && !snapshot.candidate && snapshot.running.hash !== snapshot.startup.hash ? 'primary' : 'secondary'} disabled={!writable || dirty || editing || snapshot.running.hash === snapshot.startup.hash} onClick={() => review('save')}>{copy.save}</Button>
      <details className="console-other-actions"><summary>{copy.actions}</summary><div><Field id="confirm-seconds" label={copy.confirmSeconds}><TextInput id="confirm-seconds" type="number" min={30} max={120} step={1} value={confirmSeconds} onChange={(event) => setConfirmSeconds(event.target.value)} aria-invalid={!secondsValid} /></Field><Button variant="secondary" disabled={!mayApply} onClick={() => review('commit')}>{copy.commit}</Button><Button variant="secondary" disabled={busy || !dirty || !fresh} onClick={discard}>{copy.discard}</Button><details className="fw-revision-details"><summary>{labels.details}</summary><dl className="fw-revisions">{(['candidate', 'running', 'startup'] as const).map((key) => <div key={key}><dt>{copy[key]}</dt><dd><code className="fw-hash">{key === 'candidate' ? snapshot.candidate?.revision.hash ?? copy.none : snapshot[key].hash}</code>{key === 'candidate' && snapshot.candidate && <p className="fw-meta">{copy.owner}: {snapshot.candidate.owner}</p>}</dd></div>)}</dl><p className="fw-meta">{consoleCopy.stateHint}</p><p className="fw-meta">{copy.observed}: <time dateTime={observed}>{date(observed)}</time></p><p className="fw-meta">{copy.effectiveRevision}: <code className="fw-hash">{fresh ? state.effective.revision || copy.unknown : copy.unknown}</code></p></details></div></details>
    </div>}
    {snapshot.pending && <div className="console-confirmation"><Notice title={copy.pendingTitle}>{copy.pendingBody}</Notice><p>{copy.deadline}: <time dateTime={snapshot.pending.deadline}>{date(snapshot.pending.deadline)}</time></p></div>}

  </Surface>;
}
