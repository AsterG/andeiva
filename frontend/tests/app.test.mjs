import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { App } from '../.test-build/App.js';
import { messages, parseLocale } from '../.test-build/messages.js';
import { parseTheme, readTheme, saveTheme, themeKey } from '../.test-build/preferences.js';

test('approved logo is preserved byte-for-byte and has an accessible product name', () => {
  const logo = readFileSync(new URL('../public/andeiva-logo.png', import.meta.url));
  assert.equal(createHash('sha256').update(logo).digest('hex'),
    '1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81');
  const html = renderToStaticMarkup(createElement(App));
  const image = html.match(/<img\b[^>]*alt="ANDEIVA Security Gateway"[^>]*>/)?.[0];
  assert.ok(image, 'logo needs the product name as its accessible text');
  assert.ok(image.includes('src="/andeiva-logo.png"'));
});

test('first render is English and light without browser preferences', () => {
  const html = renderToStaticMarkup(createElement(App));
  assert.match(html, /data-theme="light"/);
  assert.match(html, /lang="en"/);
  assert.ok(html.includes(messages.en.limitation));
  assert.match(html, /<main/);
  assert.match(html, /for="language"/);
  assert.match(html, /for="theme"/);
});

for (const locale of ['en', 'es', 'pt']) {
  test(`renders complete ${locale} text with an explicit development limitation`, () => {
    const html = renderToStaticMarkup(createElement(App, { initialLocale: locale }));
    for (const value of Object.values(messages[locale])) {
      assert.ok(html.includes(value), `missing text: ${value}`);
    }
    assert.match(html, new RegExp(`lang="${locale}"`));
    assert.equal(Object.keys(messages[locale]).length, Object.keys(messages.en).length);
  });
}

test('invalid preference values fall back to English and light', () => {
  for (const value of ['', 'system', 'de', '<script>', 'DARK']) {
    assert.equal(parseLocale(value), 'en');
    assert.equal(parseTheme(value), 'light');
  }
  assert.equal(parseTheme(null), 'light');
  assert.equal(parseTheme('dark'), 'dark');
});

test('dark mode requires an explicit saved selection', () => {
  const values = new Map();
  const storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
  };
  assert.equal(readTheme(storage), 'light');
  saveTheme('dark', storage);
  assert.equal(values.get(themeKey), 'dark');
  assert.equal(readTheme(storage), 'dark');
  saveTheme('light', storage);
  assert.equal(readTheme(storage), 'light');
});

test('unavailable browser storage does not prevent rendering or theme selection', () => {
  const storage = {
    getItem: () => { throw new Error('storage unavailable'); },
    setItem: () => { throw new Error('storage unavailable'); },
  };
  assert.equal(readTheme(storage), 'light');
  assert.doesNotThrow(() => saveTheme('dark', storage));
});
