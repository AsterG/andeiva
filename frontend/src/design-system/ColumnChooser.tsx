import { useEffect, useLayoutEffect, useRef, useState } from 'react';

export function ColumnChooser({ label, columns, onChange }: { label: string; columns: { id: string; label: string; visible: boolean }[]; onChange: (id: string, visible: boolean) => void }) {
  const details = useRef<HTMLDetailsElement>(null);
  const popup = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ left: 0, top: 0 });
  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const anchor = details.current?.querySelector('summary')?.getBoundingClientRect();
      const panel = popup.current;
      if (!anchor || !panel) return;
      const inset = Number.parseFloat(getComputedStyle(panel).paddingLeft);
      const width = panel.offsetWidth;
      const height = panel.offsetHeight;
      const below = window.innerHeight - anchor.bottom - inset;
      const top = below >= height ? anchor.bottom : anchor.top - height;
      setPosition({ left: Math.max(inset, Math.min(anchor.right - width, window.innerWidth - width - inset)), top: Math.max(inset, Math.min(top, window.innerHeight - height - inset)) });
    };
    place();
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => { window.removeEventListener('resize', place); window.removeEventListener('scroll', place, true); };
  }, [open, columns]);
  useEffect(() => {
    if (!open) return;
    const dismiss = (event: PointerEvent) => { if (event.target instanceof Node && !details.current?.contains(event.target)) details.current?.removeAttribute('open'); };
    document.addEventListener('pointerdown', dismiss);
    return () => document.removeEventListener('pointerdown', dismiss);
  }, [open]);
  return <details ref={details} className="ds-column-chooser" onToggle={(event) => setOpen(event.currentTarget.open)} onKeyDown={(event) => { if (event.key === 'Escape') { event.stopPropagation(); details.current?.removeAttribute('open'); details.current?.querySelector('summary')?.focus(); } }}><summary>{label}</summary><div ref={popup} style={position}>{columns.map((column) => <label key={column.id}><input type="checkbox" aria-label={`${label}: ${column.label}`} checked={column.visible} onChange={(event) => onChange(column.id, event.target.checked)} />{column.label}</label>)}</div></details>;
}
