import { useEffect, useRef, useState } from 'react';
import { AccessLayout } from '../design-system/AccessLayout.js';
import { Field } from '../design-system/components.js';
import { messages, parseLocale } from '../messages.js';
import type { Locale } from '../messages.js';
import { applyTheme, parseTheme, readTheme, saveTheme } from '../preferences.js';
import { FirewallConsole } from './FirewallConsole.js';
import { consoleMessages, consoleViews, readConsoleView } from './consoleMessages.js';
import { ConsoleIcon } from './ConsoleIcon.js';
import { productVersionLabel } from './SystemInfoView.js';
import { systemMessages } from './systemMessages.js';

export function FirewallPage({ initialLocale = 'en' }: { initialLocale?: Locale }) {
  const [locale, setLocale] = useState(initialLocale);
  const [theme, setTheme] = useState(readTheme);
  const [view, setView] = useState(() => readConsoleView(typeof window === 'undefined' ? '' : window.location.hash));
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [localServices, setLocalServices] = useState(false);
  const [mobile, setMobile] = useState(() => typeof window !== 'undefined' && window.matchMedia('(max-width: 48rem)').matches);
  const menu = useRef<HTMLButtonElement>(null);
  const common = messages[locale];
  const copy = consoleMessages[locale];
  const descriptions = { dashboard: copy.overview, rules: copy.rulesIntro, audit: copy.auditIntro, configuration: copy.configurationIntro, traffic: copy.trafficIntro, system: copy.systemIntro };
  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  useEffect(() => { applyTheme(theme); }, [theme]);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 48rem)');
    const resize = () => { setMobile(media.matches); setMobileOpen(false); };
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape' && media.matches && mobileOpen && !document.querySelector('dialog[open]')) { setMobileOpen(false); menu.current?.focus(); } };
    media.addEventListener('change', resize);
    window.addEventListener('keydown', escape);
    return () => { media.removeEventListener('change', resize); window.removeEventListener('keydown', escape); };
  }, [mobileOpen]);
  useEffect(() => {
    const change = () => { if (!window.location.hash || consoleViews.some((item) => window.location.hash === `#${item}`)) setView(readConsoleView(window.location.hash)); setMobileOpen(false); };
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  const preferences = <><Field id="language" label={common.language}><select id="language" className="ds-select" value={locale} onChange={(event) => setLocale(parseLocale(event.target.value))}><option value="en" lang="en">English</option><option value="es" lang="es">Español</option><option value="pt" lang="pt">Português</option></select></Field><Field id="theme" label={common.theme}><select id="theme" className="ds-select" value={theme} onChange={(event) => { const selected = parseTheme(event.target.value); applyTheme(selected); setTheme(selected); saveTheme(selected); }}><option value="light">{common.light}</option><option value="dark">{common.dark}</option></select></Field></>;
  return <FirewallConsole locale={locale} page={view} onLocalServices={setLocalServices} renderFrame={(content, authenticated, product) => !authenticated ? <AccessLayout locale={locale} theme={theme} preferences={preferences}>{content}</AccessLayout> : <div className={`fw-app console-app${collapsed ? ' console-collapsed' : ''}${mobileOpen ? ' console-menu-open' : ''}`} data-theme={theme} lang={locale}>
    <a className="skip-link" href="#main-content">{common.skip}</a>
    <header className="console-header"><button className="console-menu-button" ref={menu} aria-label={(mobile ? !mobileOpen : collapsed) ? copy.expand : copy.collapse} aria-expanded={mobile ? mobileOpen : !collapsed} aria-controls="console-navigation" onClick={() => mobile ? setMobileOpen(!mobileOpen) : setCollapsed(!collapsed)}><ConsoleIcon name="menu" /></button><div className="console-brand" data-testid="brand-surface"><img src="/andeiva-logo.png" alt="ANDEIVA Security Gateway" width={1100} height={550} /></div><span className="console-product">{copy.navigation}</span><div className="console-preferences">{preferences}</div></header>
    <aside className="console-sidebar" id="console-navigation"><p className="console-group">ANDEIVA</p><nav aria-label={copy.navigation}>{consoleViews.map((item) => <a key={item} href={`#${item}`} aria-label={copy[item]} title={copy[item]} aria-current={view === item ? 'page' : undefined} onClick={() => { setMobileOpen(false); requestAnimationFrame(() => document.getElementById('main-content')?.focus()); }}><ConsoleIcon name={item} /><span>{copy[item]}</span></a>)}{localServices && <a href="/local-services"><ConsoleIcon name="configuration" /><span>{copy.localServices}</span></a>}</nav><div className="console-version" aria-label={systemMessages[locale].footer}><span>{systemMessages[locale].footer}</span><strong>{productVersionLabel(product, locale)}</strong></div></aside>
    <main id="main-content" className="console-content" tabIndex={-1}><div className="console-page-heading"><p>{copy.navigation} / {copy[view]}</p><h1>{copy[view]}</h1><p>{descriptions[view]}</p></div>{content}</main>
  </div>} />;
}
