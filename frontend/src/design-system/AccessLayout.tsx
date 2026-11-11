import type { ReactNode } from 'react';
import type { Locale } from '../messages.js';
import { messages } from '../messages.js';
import type { Theme } from '../preferences.js';

// This frame never receives administrative navigation or configuration details.
export function AccessLayout({ locale, theme, preferences, children }: { locale: Locale; theme: Theme; preferences: ReactNode; children: ReactNode }) {
  return <div className="access-app" data-theme={theme} lang={locale}>
    <a className="skip-link" href="#main-content">{messages[locale].skip}</a>
    <header className="access-header"><div className="access-brand" data-testid="brand-surface"><img src="/andeiva-logo.png" alt="ANDEIVA Security Gateway" width={1100} height={550} /></div><div className="access-preferences header-actions">{preferences}</div></header>
    <main id="main-content" className="access-content" tabIndex={-1}><div className="access-panel"><h1>ANDEIVA Security Gateway</h1>{children}</div></main>
  </div>;
}
