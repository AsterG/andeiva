import { useEffect, useId, useRef, useState } from 'react';
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';

export type Tone = 'success' | 'warning' | 'error' | 'info';

export function Button({ variant = 'primary', className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' }) {
  return <button type="button" {...props} className={`ds-button ds-button--${variant} ${className}`} />;
}

export function Surface({ title, description, children, className = '' }: { title: string; description?: string; children: ReactNode; className?: string }) {
  const id = useId();
  return <section className={`ds-surface ${className}`} aria-labelledby={id}><div className="ds-section-heading"><h2 id={id}>{title}</h2>{description && <p>{description}</p>}</div>{children}</section>;
}

export function Field({ label, hint, error, id, children }: { label: string; hint?: string; error?: string; id: string; children: ReactNode }) {
  return <div className="ds-field"><label htmlFor={id}>{label}</label>{children}{hint && <p id={`${id}-hint`} className="ds-field-hint">{hint}</p>}{error && <p id={`${id}-error`} className="ds-field-error">{error}</p>}</div>;
}

export function TextInput(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`ds-input ${props.className ?? ''}`} />;
}

const toneSymbols: Record<Tone, string> = { success: '✓', warning: '!', error: '×', info: 'i' };

export function StatusBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`ds-badge ds-badge--${tone}`}><span aria-hidden="true" className="ds-badge-symbol">{toneSymbols[tone]}</span>{children}</span>;
}

export function Notice({ title, children, live = false }: { title: string; children: ReactNode; live?: boolean }) {
  return <div className="ds-notice" role={live ? 'status' : undefined}><span className="ds-notice-icon" aria-hidden="true">i</span><div><strong>{title}</strong><p>{children}</p></div></div>;
}

export function FilterBar({ children, label }: { children: ReactNode; label: string }) {
  return <div className="ds-filter-bar" role="search" aria-label={label}>{children}</div>;
}

export function DataTable({ caption, children }: { caption: string; children: ReactNode }) {
  return <div className="ds-table-scroll" role="region" aria-label={caption} tabIndex={0}><table className="ds-table"><caption>{caption}</caption>{children}</table></div>;
}

export function Navigation({ label, items }: { label: string; items: { id: string; label: string; active: boolean; icon: ReactNode; onSelect: () => void }[] }) {
  return <nav aria-label={label} className="ds-navigation">{items.map((item) => <button key={item.id} type="button" data-testid={`nav-${item.id}`} className="ds-nav-item" aria-current={item.active ? 'page' : undefined} onClick={item.onSelect}><span aria-hidden="true">{item.icon}</span>{item.label}</button>)}</nav>;
}

export function Dialog({ open, onClose, title, closeLabel, children }: { open: boolean; onClose: () => void; title: string; closeLabel: string; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = ref.current;
    if (open && dialog && !dialog.open) dialog.showModal();
    if (!open && dialog?.open) dialog.close();
  }, [open]);
  return <dialog ref={ref} className="ds-dialog" aria-labelledby={titleId} onClose={onClose} onKeyDown={(event) => {
    if (event.key !== 'Tab') return;
    const candidates = ref.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]');
    const controls = [...(candidates ?? [])].filter((element) => element.tabIndex >= 0 && element.getClientRects().length > 0 && !element.closest('[inert]'));
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  }}><div className="ds-dialog-content"><h2 id={titleId}>{title}</h2>{children}<div className="ds-actions"><Button variant="secondary" onClick={() => ref.current?.close()} data-testid="close-dialog">{closeLabel}</Button></div></div></dialog>;
}

export function HelpTip({ label, text }: { label: string; text: string }) {
  const id = useId();
  const [dismissed, setDismissed] = useState(false);
  useEffect(() => {
    const dismiss = (event: KeyboardEvent) => { if (event.key === 'Escape') setDismissed(true); };
    document.addEventListener('keydown', dismiss);
    return () => document.removeEventListener('keydown', dismiss);
  }, []);
  return <span className="ds-help" data-dismissed={dismissed} onMouseEnter={() => setDismissed(false)} onFocus={() => setDismissed(false)}><button type="button" className="ds-help-trigger" aria-label={label} aria-describedby={id}>?</button><span role="tooltip" id={id} className="ds-tooltip">{text}</span></span>;
}

export function Legend({ labels }: { labels: string[] }) {
  return <ul className="ds-legend">{labels.map((label, index) => <li key={label}><span className={`ds-legend-mark ds-legend-mark--${index + 1}`} aria-hidden="true" />{label}</li>)}</ul>;
}
