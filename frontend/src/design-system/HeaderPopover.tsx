import { useId, useLayoutEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';

// Native auto popovers remain modeless and share the browser's light-dismiss
// behavior without putting form controls inside a menu role.
export function HeaderPopover({ name, label, icon, children, className = '', initialFocus }: {
  name: string; label: string; icon: ReactNode; children: ReactNode; className?: string; initialFocus?: string;
}) {
  const id = useId(); const triggerId = useId();
  const trigger = useRef<HTMLButtonElement>(null); const panel = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  useLayoutEffect(() => {
    const element = panel.current;
    if (!element) return;
    const place = () => {
      if (!element.matches(':popover-open') || !trigger.current) return;
      const anchor = trigger.current.getBoundingClientRect();
      const inset = Number.parseFloat(getComputedStyle(element).paddingLeft);
      const viewport = window.visualViewport;
      const left = viewport?.offsetLeft ?? 0; const top = viewport?.offsetTop ?? 0;
      const availableWidth = viewport?.width ?? window.innerWidth; const availableHeight = viewport?.height ?? window.innerHeight;
      element.style.maxWidth = `${Math.max(0, availableWidth - inset * 2)}px`;
      const width = element.getBoundingClientRect().width;
      const height = Math.min(element.scrollHeight + element.offsetHeight - element.clientHeight, Math.max(0, availableHeight - inset * 2));
      const y = Math.max(top + inset, Math.min(anchor.bottom + inset / 2, top + availableHeight - inset - height));
      element.style.left = `${Math.max(left + inset, Math.min(anchor.right - width, left + availableWidth - width - inset))}px`;
      element.style.top = `${y}px`;
      element.style.maxHeight = `${Math.max(0, top + availableHeight - y - inset)}px`;
    };
    const before = (event: Event) => { if ((event as ToggleEvent).newState === 'open') element.style.visibility = 'hidden'; };
    const toggle = (event: Event) => {
      const shown = (event as ToggleEvent).newState === 'open';
      setOpen(shown);
      if (shown) {
        place(); element.style.visibility = 'visible';
        (initialFocus ? element.querySelector<HTMLElement>(initialFocus) : element)?.focus({ preventScroll: true });
      }
    };
    element.addEventListener('beforetoggle', before); element.addEventListener('toggle', toggle);
    window.addEventListener('resize', place); window.addEventListener('scroll', place, true);
    window.visualViewport?.addEventListener('resize', place); window.visualViewport?.addEventListener('scroll', place);
    return () => {
      element.removeEventListener('beforetoggle', before); element.removeEventListener('toggle', toggle);
      window.removeEventListener('resize', place); window.removeEventListener('scroll', place, true);
      window.visualViewport?.removeEventListener('resize', place); window.visualViewport?.removeEventListener('scroll', place);
      if (element.matches(':popover-open')) element.hidePopover();
    };
  }, [initialFocus]);
  return <div className={`ds-header-menu ${className}`}>
    <button ref={trigger} id={triggerId} data-testid={`${name}-trigger`} type="button" className="ds-header-trigger" popoverTarget={id} aria-label={label} aria-haspopup="dialog" aria-controls={id} aria-expanded={open}>{icon}</button>
    <div ref={panel} id={id} data-testid={`${name}-panel`} popover="auto" className="ds-header-popover" role="dialog" aria-modal="false" aria-labelledby={triggerId} tabIndex={-1} onKeyDown={(event) => {
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); panel.current?.hidePopover(); trigger.current?.focus(); }
    }}>{children}</div>
  </div>;
}
