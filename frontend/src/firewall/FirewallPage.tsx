import { useEffect, useState } from 'react';
import { Field, Navigation } from '../design-system/components.js';
import { messages, parseLocale } from '../messages.js';
import type { Locale } from '../messages.js';
import { applyTheme, parseTheme, readTheme, saveTheme } from '../preferences.js';
import { FirewallConsole } from './FirewallConsole.js';
import { firewallMessages } from './messages.js';

export function FirewallPage({ initialLocale = 'en' }: { initialLocale?: Locale }) {
  const [locale, setLocale] = useState(initialLocale);
  const [theme, setTheme] = useState(readTheme);
  const common = messages[locale];
  const copy = firewallMessages[locale];
  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  useEffect(() => { applyTheme(theme); }, [theme]);
  return <div className="app fw-app" data-theme={theme} lang={locale}>
    <a className="skip-link" href="#main-content">{common.skip}</a>
    <aside className="sidebar"><div className="brand-panel" data-testid="brand-surface"><img className="brand-image" src="/andeiva-logo.png" alt="ANDEIVA Security Gateway" width={1100} height={550} /></div><p className="workspace-label">{copy.navigation}</p><Navigation label={copy.navigation} items={[{ id: 'firewall', label: copy.title, active: true, onSelect: () => document.getElementById('main-content')?.focus(), icon: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Z" /></svg> }]} /><div className="sidebar-note"><span className="sidebar-rule" /><p>{copy.scope}</p></div></aside>
    <div className="workspace"><header className="header"><div className="header-title"><span className="header-marker" aria-hidden="true" /><p>{copy.navigation}</p></div><div className="preferences"><Field id="language" label={common.language}><select id="language" className="ds-select" value={locale} onChange={(event) => setLocale(parseLocale(event.target.value))}><option value="en" lang="en">English</option><option value="es" lang="es">Español</option><option value="pt" lang="pt">Português</option></select></Field><Field id="theme" label={common.theme}><select id="theme" className="ds-select" value={theme} onChange={(event) => { const selected = parseTheme(event.target.value); applyTheme(selected); setTheme(selected); saveTheme(selected); }}><option value="light">{common.light}</option><option value="dark">{common.dark}</option></select></Field></div></header><main id="main-content" className="content" tabIndex={-1}><div className="page-heading"><div><p className="eyebrow">ANDEIVA Security Gateway</p><h1>{copy.title}</h1><p className="page-description">{copy.subtitle}</p></div></div><FirewallConsole locale={locale} /></main></div>
  </div>;
}
