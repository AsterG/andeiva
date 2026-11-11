import { useEffect, useState } from 'react';
import { AccessLayout } from '../design-system/AccessLayout.js';
import { Field, Navigation } from '../design-system/components.js';
import { messages, parseLocale } from '../messages.js';
import type { Locale } from '../messages.js';
import { applyTheme, parseTheme, readTheme, saveTheme } from '../preferences.js';
import { LocalServicesConsole } from './LocalServicesConsole.js';
import { localMessages } from './messages.js';

export function LocalServicesPage({ initialLocale = 'en' }: { initialLocale?: Locale }) {
  const [locale, setLocale] = useState(initialLocale);
  const [theme, setTheme] = useState(readTheme);
  const [view, setView] = useState<'services' | 'effective'>('services');
  const common = messages[locale];
  const copy = localMessages[locale];
  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  useEffect(() => { applyTheme(theme); }, [theme]);
  const icon = <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Z" /></svg>;
  const preferences = <>
      <Field id="language" label={common.language}><select id="language" className="ds-select" value={locale} onChange={(event) => setLocale(parseLocale(event.target.value))}><option value="en" lang="en">English</option><option value="es" lang="es">Español</option><option value="pt" lang="pt">Português</option></select></Field>
      <Field id="theme" label={common.theme}><select id="theme" className="ds-select" value={theme} onChange={(event) => { const selected = parseTheme(event.target.value); applyTheme(selected); setTheme(selected); saveTheme(selected); }}><option value="light">{common.light}</option><option value="dark">{common.dark}</option></select></Field>
    </>;
  return <LocalServicesConsole locale={locale} view={view} renderFrame={(content, authenticated) => !authenticated ? <AccessLayout locale={locale} theme={theme} preferences={preferences}>{content}</AccessLayout> : <div className="app" data-theme={theme} lang={locale}>
    <a className="skip-link" href="#main-content">{common.skip}</a>
    <aside className="sidebar"><div className="brand-panel" data-testid="brand-surface"><img className="brand-image" src="/andeiva-logo.png" alt="ANDEIVA Security Gateway" width={1100} height={550} /></div>
      <p className="workspace-label">{copy.system}</p><Navigation label={copy.system} items={[{ id: 'local-services', label: copy.title, active: view === 'services', onSelect: () => { setView('services'); document.getElementById('main-content')?.focus(); }, icon }]} />
      <p className="workspace-label">{copy.firewall}</p><Navigation label={copy.firewall} items={[{ id: 'effective-policies', label: copy.effective, active: view === 'effective', onSelect: () => { setView('effective'); document.getElementById('main-content')?.focus(); }, icon }]} />
      <div className="sidebar-note"><span className="sidebar-rule" /><p>{copy.scope}</p></div></aside>
    <div className="workspace"><header className="header"><div className="header-title"><span className="header-marker" aria-hidden="true" /><p>{copy.system}</p></div><div className="preferences">{preferences}</div></header><main id="main-content" className="content" tabIndex={-1}><div className="page-heading"><div><p className="eyebrow">ANDEIVA Security Gateway</p><h1>{view === 'services' ? copy.title : copy.effective}</h1><p className="page-description">{copy.subtitle}</p></div></div>{content}</main></div>
  </div>} />;
}
