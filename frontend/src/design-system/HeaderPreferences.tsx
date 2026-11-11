import { messages, parseLocale } from '../messages.js';
import type { Locale } from '../messages.js';
import { parseTheme } from '../preferences.js';
import type { Theme } from '../preferences.js';
import { Field } from './components.js';
import { HeaderPopover } from './HeaderPopover.js';
import { headerMessages } from './headerMessages.js';

export function HeaderPreferences({ locale, theme, onLocale, onTheme }: { locale: Locale; theme: Theme; onLocale: (locale: Locale) => void; onTheme: (theme: Theme) => void }) {
  const copy = messages[locale]; const header = headerMessages[locale];
  return <HeaderPopover name="preferences" label={header.preferences} className="ds-header-preferences" initialFocus="select" icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><path d="m9 3-.6 2.4-2.1 1.2L4 6l-2 3.5 1.7 1.8v2.4L2 15.5 4 19l2.3-.6 2.1 1.2L9 22h4l.6-2.4 2.1-1.2L18 19l2-3.5-1.7-1.8v-2.4L20 9l-2-3-2.3.6-2.1-1.2L13 3Z" /><circle cx="11" cy="12.5" r="3.2" /></svg>}>
    <h2>{header.preferences}</h2>
    <Field id="language" label={copy.language}><select id="language" className="ds-select" value={locale} onChange={(event) => onLocale(parseLocale(event.target.value))}><option value="en" lang="en">English</option><option value="es" lang="es">Español</option><option value="pt" lang="pt">Português</option></select></Field>
    <Field id="theme" label={copy.theme}><select id="theme" className="ds-select" value={theme} onChange={(event) => onTheme(parseTheme(event.target.value))}><option value="light">{copy.light}</option><option value="dark">{copy.dark}</option></select></Field>
  </HeaderPopover>;
}
