import { useEffect, useRef, useState } from 'react';
import { messages, parseLocale } from './messages.js';
import type { Locale, Messages } from './messages.js';
import { applyTheme, parseTheme, readTheme, saveTheme } from './preferences.js';
import { Button, DataTable, Dialog, Field, FilterBar, HelpTip, Legend, Navigation, Notice, StatusBadge, Surface, TextInput } from './design-system/components.js';
import type { Tone } from './design-system/components.js';

function GridIcon() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></svg>;
}
function LayersIcon() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="m12 3 10 5-10 5L2 8 12 3Z" /><path d="m2 12 10 5 10-5M2 16l10 5 10-5" /></svg>;
}

function ComponentLibrary({ copy }: { copy: Messages }) {
  const [name, setName] = useState('ANDEIVA');
  const [notes, setNotes] = useState('');
  const [notifications, setNotifications] = useState(true);
  const [applied, setApplied] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const [query, setQuery] = useState('');
  const [tone, setTone] = useState('all');
  const [selected, setSelected] = useState<string[]>([]);
  const [dialog, setDialog] = useState(false);
  const rows: { id: string; name: string; category: string; tone: Tone }[] = [
    { id: 'appearance', name: copy.rowOne, category: copy.catOne, tone: 'success' },
    { id: 'content', name: copy.rowTwo, category: copy.catTwo, tone: 'warning' },
    { id: 'validation', name: copy.rowThree, category: copy.catThree, tone: 'error' },
    { id: 'reference', name: copy.rowFour, category: copy.catFour, tone: 'info' },
  ];
  const visible = rows.filter((row) => row.name.toLocaleLowerCase().includes(query.toLocaleLowerCase()) && (tone === 'all' || row.tone === tone));
  return <div className="component-grid">
    <Surface title={copy.forms} description={copy.formDescription}>
      <form className="preview-form" onSubmit={(event) => {
        event.preventDefault();
        const missing = name.trim().length === 0;
        setInvalid(missing);
        setApplied(!missing && notifications);
        if (missing) document.getElementById('preview-name')?.focus();
      }} noValidate>
        <Field id="preview-name" label={copy.name} hint={copy.nameHint} {...(invalid ? { error: copy.nameError } : {})}>
          <TextInput id="preview-name" data-testid="preview-name" value={name} placeholder={copy.namePlaceholder} maxLength={80} required aria-invalid={invalid} aria-describedby={`preview-name-hint${invalid ? ' preview-name-error' : ''}`} onChange={(event) => { setName(event.target.value); setInvalid(false); setApplied(false); }} />
        </Field>
        <Field id="preview-notes" label={copy.notes}>
          <textarea id="preview-notes" data-testid="preview-notes" className="ds-textarea" value={notes} onChange={(event) => { setNotes(event.target.value); setApplied(false); }} maxLength={500} placeholder={copy.notesPlaceholder} />
        </Field>
        <label className="ds-checkbox"><input data-testid="preview-notifications" type="checkbox" checked={notifications} onChange={(event) => setNotifications(event.target.checked)} />{copy.notifications}</label>
        <div className="ds-actions"><Button type="submit" data-testid="apply-preview">{copy.apply}</Button><Button variant="secondary" onClick={() => { setName('ANDEIVA'); setNotes(''); setNotifications(true); setInvalid(false); setApplied(false); }}>{copy.reset}</Button></div>
        {applied && <Notice title={copy.applied} live>{copy.appliedBody}</Notice>}
      </form>
    </Surface>
    <Surface title={copy.indicators} description={copy.indicatorDescription}>
      <div className="status-list">{(['success', 'warning', 'error', 'info'] as const).map((value) => <StatusBadge key={value} tone={value}>{copy[value]}</StatusBadge>)}</div>
      <div className="component-note"><Notice title={copy.scope}>{copy.limitation}</Notice></div>
      <div className="legend-example"><h3>{copy.legendTitle}</h3><p>{copy.legendDescription}</p><Legend labels={[copy.seriesOne, copy.seriesTwo, copy.seriesThree, copy.seriesFour]} /></div>
    </Surface>
    <Surface title={copy.tableTitle} description={copy.tableDescription} className="wide-surface">
      <FilterBar label={copy.filterLabel}>
        <Field id="filter-search" label={copy.search}><TextInput id="filter-search" data-testid="filter-search" type="search" value={query} placeholder={copy.searchPlaceholder} onChange={(event) => setQuery(event.target.value)} /></Field>
        <Field id="status-filter" label={copy.state}><select id="status-filter" data-testid="status-filter" className="ds-select" value={tone} onChange={(event) => setTone(event.target.value)}><option value="all">{copy.allStates}</option>{(['success', 'warning', 'error', 'info'] as const).map((value) => <option key={value} value={value}>{copy[value]}</option>)}</select></Field>
        <Button variant="secondary" onClick={() => { setQuery(''); setTone('all'); }}>{copy.reset}</Button>
      </FilterBar>
      <DataTable caption={copy.tableCaption}>
        <thead><tr><th scope="col">{copy.selected}</th><th scope="col">{copy.entry}</th><th scope="col">{copy.category}</th><th scope="col">{copy.state}</th></tr></thead>
        <tbody>{visible.map((row) => <tr key={row.id} data-selected={selected.includes(row.id)}><td><label className="ds-checkbox table-checkbox"><input type="checkbox" checked={selected.includes(row.id)} onChange={(event) => setSelected((previous) => event.target.checked ? [...previous, row.id] : previous.filter((id) => id !== row.id))} aria-label={`${copy.selectRow}: ${row.name}`} /></label></td><th scope="row">{row.name}</th><td>{row.category}</td><td><StatusBadge tone={row.tone}>{copy[row.tone]}</StatusBadge></td></tr>)}{visible.length === 0 && <tr><td colSpan={4} className="empty-state">{copy.noEntries}</td></tr>}</tbody>
      </DataTable>
    </Surface>
    <Surface title={copy.overlays} description={copy.overlayDescription} className="wide-surface">
      <div className="overlay-controls"><Button data-testid="open-dialog" onClick={() => setDialog(true)}>{copy.openDialog}</Button><HelpTip label={copy.helpLabel} text={copy.helpText} /><details className="ds-disclosure"><summary>{copy.details}<span aria-hidden="true">⌄</span></summary><div className="ds-disclosure-panel">{copy.detailsBody}</div></details></div>
      <Dialog open={dialog} onClose={() => setDialog(false)} title={copy.dialogTitle} closeLabel={copy.close}><p>{copy.dialogBody}</p><Notice title={copy.scope}>{copy.limitation}</Notice></Dialog>
    </Surface>
  </div>;
}

export function App({ initialLocale = 'en' }: { initialLocale?: Locale }) {
  const [locale, setLocale] = useState<Locale>(initialLocale);
  const [theme, setTheme] = useState(readTheme);
  const [view, setView] = useState<'overview' | 'components'>('overview');
  const [about, setAbout] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const previousView = useRef(view);
  const copy = messages[locale];
  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  useEffect(() => { applyTheme(theme); }, [theme]);
  useEffect(() => {
    if (previousView.current !== view) heading.current?.focus();
    previousView.current = view;
  }, [view]);

  return <div className="app" data-theme={theme} lang={locale}>
    <a className="skip-link" href="#main-content">{copy.skip}</a>
    <aside className="sidebar">
      <div className="brand-panel" data-testid="brand-surface"><img className="brand-image" src="/andeiva-logo.png" alt="ANDEIVA Security Gateway" width={1100} height={550} /></div>
      <p className="workspace-label">{copy.workspace}</p>
      <Navigation label={copy.navigation} items={[
        { id: 'overview', label: copy.overview, icon: <GridIcon />, active: view === 'overview', onSelect: () => setView('overview') },
        { id: 'components', label: copy.components, icon: <LayersIcon />, active: view === 'components', onSelect: () => setView('components') },
      ]} />
      <div className="sidebar-note"><span className="sidebar-rule" /><p>{copy.version}</p><span>{copy.local}</span></div>
    </aside>
    <div className="workspace">
      <header className="header"><div className="header-title"><span className="header-marker" aria-hidden="true" /><p>{copy.phase}</p></div><div className="preferences">
        <Field id="language" label={copy.language}><select id="language" className="ds-select" value={locale} onChange={(event) => setLocale(parseLocale(event.target.value))}><option value="en" lang="en">English</option><option value="es" lang="es">Español</option><option value="pt" lang="pt">Português</option></select></Field>
        <Field id="theme" label={copy.theme}><select id="theme" className="ds-select" value={theme} onChange={(event) => { const selected = parseTheme(event.target.value); applyTheme(selected); setTheme(selected); saveTheme(selected); }}><option value="light">{copy.light}</option><option value="dark">{copy.dark}</option></select></Field>
      </div></header>
      <main id="main-content" className="content" tabIndex={-1}>
        <div className="page-heading"><div><p className="eyebrow">{view === 'overview' ? copy.overview : copy.workspace}</p><h1 ref={heading} tabIndex={-1}>{view === 'overview' ? copy.title : copy.libraryTitle}</h1><p className="page-description">{view === 'overview' ? copy.description : copy.libraryDescription}</p></div><StatusBadge tone="info">{copy.local}</StatusBadge></div>
        {view === 'overview' ? <>
          <section className="welcome" aria-labelledby="welcome-title"><div className="welcome-copy"><span className="accent-rule" /><h2 id="welcome-title">{copy.introduction}</h2><p>{copy.introBody}</p><div className="ds-actions"><Button onClick={() => setView('components')}>{copy.explore}<span aria-hidden="true">→</span></Button><Button variant="secondary" onClick={() => setAbout(true)}>{copy.about}</Button></div></div><div className="theme-preview" aria-label={copy.currentTheme}><span className="theme-preview-label">{copy.currentTheme}</span><div className="theme-preview-window" aria-hidden="true"><div className="theme-preview-top"><i /><i /><i /></div><div className="theme-preview-layout"><span /><div><i /><i /><i /></div></div></div><strong>{theme === 'light' ? copy.light : copy.dark}</strong><p>{copy.themeHint}</p></div></section>
          <div className="overview-grid"><Surface title={copy.themeTitle}><p className="card-copy">{copy.themeBody}</p></Surface><Surface title={copy.accessTitle}><p className="card-copy">{copy.accessBody}</p></Surface><Surface title={copy.modulesTitle}><p className="card-copy">{copy.modulesBody}</p></Surface></div>
          <Notice title={copy.scope}>{copy.limitation}</Notice>
          <Dialog open={about} onClose={() => setAbout(false)} title={copy.about} closeLabel={copy.close}><p>{copy.detailsBody}</p><p>{copy.limitation}</p></Dialog>
        </> : <ComponentLibrary copy={copy} />}
        <footer className="footer">{copy.footer}</footer>
      </main>
    </div>
  </div>;
}
