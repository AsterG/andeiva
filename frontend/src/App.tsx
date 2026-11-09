import { useEffect, useState } from 'react';
import { messages, parseLocale } from './messages.js';
import type { Locale } from './messages.js';
import { parseTheme, readTheme, saveTheme } from './preferences.js';

export function App({ initialLocale = 'en' }: { initialLocale?: Locale }) {
  const [locale, setLocale] = useState<Locale>(initialLocale);
  const [theme, setTheme] = useState(readTheme);
  const copy = messages[locale];

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  return (
    <div className="app" data-theme={theme} lang={locale}>
      <header className="header">
        <p className="brand">ANDEIVA <span>Security Gateway</span></p>
        <div className="preferences">
          <label htmlFor="language">{copy.language}
            <select id="language" value={locale} onChange={(event) => setLocale(parseLocale(event.target.value))}>
              <option value="en" lang="en">English</option>
              <option value="es" lang="es">Español</option>
              <option value="pt" lang="pt">Português</option>
            </select>
          </label>
          <label htmlFor="theme">{copy.theme}
            <select id="theme" value={theme} onChange={(event) => {
              const selected = parseTheme(event.target.value);
              setTheme(selected);
              saveTheme(selected);
            }}>
              <option value="light">{copy.light}</option>
              <option value="dark">{copy.dark}</option>
            </select>
          </label>
        </div>
      </header>
      <main className="content">
        <section className="intro" aria-labelledby="page-title">
          <p className="eyebrow">{copy.phase}</p>
          <h1 id="page-title">{copy.title}</h1>
          <p>{copy.description}</p>
          <p className="notice">{copy.limitation}</p>
        </section>
      </main>
    </div>
  );
}
