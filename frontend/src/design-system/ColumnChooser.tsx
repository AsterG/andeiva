import { useRef } from 'react';

export function ColumnChooser({ label, columns, onChange }: { label: string; columns: { id: string; label: string; visible: boolean }[]; onChange: (id: string, visible: boolean) => void }) {
  const details = useRef<HTMLDetailsElement>(null);
  return <details ref={details} className="ds-column-chooser" onKeyDown={(event) => { if (event.key === 'Escape') { event.stopPropagation(); details.current?.removeAttribute('open'); details.current?.querySelector('summary')?.focus(); } }}><summary>{label}</summary><div>{columns.map((column) => <label key={column.id}><input type="checkbox" aria-label={`${label}: ${column.label}`} checked={column.visible} onChange={(event) => onChange(column.id, event.target.checked)} />{column.label}</label>)}</div></details>;
}
