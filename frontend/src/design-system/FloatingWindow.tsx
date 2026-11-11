import { useId, useLayoutEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Button } from './components.js';
import { placeFloatingWindow } from './floatingWindowGeometry.js';
import type { WindowPosition, WindowViewport } from './floatingWindowGeometry.js';
import type { FloatingWindowMessages } from './floatingWindowMessages.js';

type Movement = { origin: WindowPosition; pointer?: number; x?: number; y?: number };

// Desktop stays modeless so the underlying table remains available for reference.
// Small screens use the native modal focus boundary while the window fills the viewport.
export function FloatingWindow({ title, description, labels, visible = true, className = '', initialFocusSelector, onClose, children }: {
  title: string; description?: string; labels: FloatingWindowMessages; visible?: boolean; className?: string;
  initialFocusSelector?: string; onClose: () => void; children: ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const header = useRef<HTMLElement>(null);
  const position = useRef<WindowPosition | null>(null);
  const movement = useRef<Movement | null>(null);
  const onCloseRef = useRef(onClose);
  const labelsRef = useRef(labels);
  const [located, setLocated] = useState(false);
  const [compact, setCompact] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 48rem)').matches);
  const [moving, setMoving] = useState(false);
  const [announcement, setAnnouncement] = useState('');
  const titleId = useId(); const descriptionId = useId(); const hintId = useId();
  useLayoutEffect(() => { onCloseRef.current = onClose; }, [onClose]);
  useLayoutEffect(() => { labelsRef.current = labels; }, [labels]);

  function viewport(): WindowViewport {
    const view = window.visualViewport;
    return { left: view?.offsetLeft ?? 0, top: view?.offsetTop ?? 0, width: view?.width ?? window.innerWidth, height: view?.height ?? window.innerHeight };
  }
  function put(next: WindowPosition | null) {
    const panel = dialog.current;
    if (!panel) return;
    const view = viewport();
    const small = window.matchMedia('(max-width: 48rem)').matches;
    const inset = small ? 0 : Number.parseFloat(getComputedStyle(header.current!).paddingLeft);
    const bounded = placeFloatingWindow(next, panel.getBoundingClientRect(), view, inset);
    position.current = bounded;
    panel.style.left = `${bounded.left}px`; panel.style.top = `${bounded.top}px`;
  }
  function clearMovement() {
    const current = movement.current;
    movement.current = null; setMoving(false);
    if (current?.pointer !== undefined && header.current?.hasPointerCapture(current.pointer)) header.current.releasePointerCapture(current.pointer);
    return current;
  }
  function finishMove(cancel = false) {
    const current = clearMovement();
    if (!current) return;
    if (cancel) put(current.origin);
    setAnnouncement(cancel ? labelsRef.current.cancelled : labelsRef.current.placed);
  }
  useLayoutEffect(() => {
    const panel = dialog.current;
    if (!panel || !visible) return;
    const opener = document.activeElement;
    let small = window.matchMedia('(max-width: 48rem)').matches;
    if (small) panel.showModal(); else panel.show();
    const measure = () => {
      const current = document.activeElement;
      const nextSmall = window.matchMedia('(max-width: 48rem)').matches;
      if (nextSmall !== small) {
        clearMovement(); position.current = null;
        panel.close();
        if (nextSmall) panel.showModal(); else panel.show();
        if (current instanceof HTMLElement && panel.contains(current)) {
          const target = nextSmall && current.closest('.ds-floating-window-actions') ? panel.querySelector<HTMLElement>(initialFocusSelector ?? 'button') : current;
          target?.focus();
        }
        small = nextSmall;
      }
      setCompact(small);
      const view = viewport();
      const inset = small ? 0 : Number.parseFloat(getComputedStyle(header.current!).paddingLeft);
      panel.style.maxWidth = `${Math.max(0, view.width - inset * 2)}px`;
      panel.style.maxHeight = `${Math.max(0, view.height - inset * 2)}px`;
      if (small) { panel.style.width = `${view.width}px`; panel.style.height = `${view.height}px`; }
      else { panel.style.removeProperty('width'); panel.style.removeProperty('height'); }
      put(position.current); panel.style.visibility = 'visible'; setLocated(true);
    };
    measure();
    if (initialFocusSelector) panel.querySelector<HTMLElement>(initialFocusSelector)?.focus();
    const resize = () => { finishMove(); measure(); };
    const observer = new ResizeObserver(measure); observer.observe(panel);
    window.addEventListener('resize', resize);
    window.visualViewport?.addEventListener('resize', resize);
    window.visualViewport?.addEventListener('scroll', resize);
    return () => {
      observer.disconnect(); window.removeEventListener('resize', resize);
      window.visualViewport?.removeEventListener('resize', resize); window.visualViewport?.removeEventListener('scroll', resize);
      clearMovement();
      if (panel.open) panel.close();
      requestAnimationFrame(() => { if (opener instanceof HTMLElement && opener.isConnected && opener.getClientRects().length) opener.focus(); });
    };
  }, [visible, initialFocusSelector]);

  return <dialog ref={dialog} className={`ds-floating-window ${className}`} aria-modal={compact} aria-labelledby={titleId} aria-describedby={description ? descriptionId : undefined} data-moving={moving || undefined} style={{ visibility: located ? 'visible' : 'hidden' }} onClose={() => { if (!dialog.current?.open && visible) onCloseRef.current(); }} onCancel={(event) => { event.preventDefault(); if (movement.current) finishMove(true); else onCloseRef.current(); }} onKeyDown={(event) => {
    if (compact && event.key === 'Tab') {
      const controls = [...(dialog.current?.querySelectorAll<HTMLElement>('button, input, select, textarea, a[href], [tabindex]') ?? [])].filter((element) => element.tabIndex >= 0 && !element.matches(':disabled') && element.getClientRects().length > 0);
      const first = controls[0]; const last = controls.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
    if (event.key !== 'Escape') return;
    event.preventDefault(); event.stopPropagation();
    if (movement.current) finishMove(true); else onCloseRef.current();
  }}>
    <header ref={header} className="ds-floating-titlebar" onPointerDown={(event) => {
      if (compact || !event.isPrimary || event.button !== 0 || (event.target instanceof Element && event.target.closest('button'))) return;
      event.preventDefault(); finishMove();
      event.currentTarget.setPointerCapture(event.pointerId);
      movement.current = { origin: position.current!, pointer: event.pointerId, x: event.clientX, y: event.clientY }; setMoving(true); setAnnouncement(labels.moving);
    }} onPointerMove={(event) => {
      const current = movement.current;
      if (current?.pointer !== event.pointerId) return;
      put({ left: current.origin.left + event.clientX - current.x!, top: current.origin.top + event.clientY - current.y! });
    }} onPointerUp={(event) => { if (movement.current?.pointer === event.pointerId) finishMove(); }} onPointerCancel={() => finishMove(true)} onLostPointerCapture={() => { if (movement.current?.pointer !== undefined) finishMove(true); }}>
      <div className="ds-floating-title"><h2 id={titleId}>{title}</h2>{description && <p id={descriptionId}>{description}</p>}</div>
      <div className="ds-floating-window-actions"><Button variant="secondary" hidden={compact} aria-label={labels.move} title={labels.move} aria-pressed={moving && movement.current?.pointer === undefined} aria-describedby={hintId} onClick={() => {
        if (movement.current) finishMove(); else { movement.current = { origin: position.current! }; setMoving(true); setAnnouncement(labels.moving); }
      }} onBlur={() => { if (movement.current?.pointer === undefined) finishMove(); }} onKeyDown={(event) => {
        if (!movement.current || movement.current.pointer !== undefined) return;
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); finishMove(); return; }
        if (event.key === 'Home') { event.preventDefault(); put(null); return; }
        if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return;
        event.preventDefault(); const step = event.shiftKey ? 1 : 10; const current = position.current!;
        put({ left: current.left + (event.key === 'ArrowLeft' ? -step : event.key === 'ArrowRight' ? step : 0), top: current.top + (event.key === 'ArrowUp' ? -step : event.key === 'ArrowDown' ? step : 0) });
      }}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><path d="M12 3v18M3 12h18M8 7l4-4 4 4M7 8l-4 4 4 4m10-8 4 4-4 4m-9 1 4 4 4-4" /></svg></Button><Button variant="secondary" hidden={compact} aria-label={labels.center} title={labels.center} onClick={() => { finishMove(); put(null); }}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M8 12h8M12 8v8" /></svg></Button><Button variant="secondary" aria-label={labels.close} title={labels.close} onClick={onClose}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg></Button></div>
    </header>
    <p className="fw-sr-only" id={hintId}>{labels.moveHint}</p><span className="fw-sr-only" role="status" aria-live="polite">{announcement}</span>
    <div className="ds-floating-content">{children}</div>
  </dialog>;
}
