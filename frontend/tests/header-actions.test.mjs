import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { HeaderAccount } from '../.test-build/design-system/HeaderAccount.js';
import { HeaderPreferences } from '../.test-build/design-system/HeaderPreferences.js';
import { headerMessages } from '../.test-build/design-system/headerMessages.js';
import { FirewallPage } from '../.test-build/firewall/FirewallPage.js';

for (const locale of ['en', 'es', 'pt']) test(`header ${locale} popovers retain semantic labels without menu roles`, () => {
  const copy = headerMessages[locale];
  assert.deepEqual(Object.keys(copy).sort(), Object.keys(headerMessages.en).sort());
  const preferences = renderToStaticMarkup(createElement(HeaderPreferences, { locale, theme: 'light', onLocale() {}, onTheme() {} }));
  assert.match(preferences, /popover="auto"/);
  assert.match(preferences, /aria-haspopup="dialog"/);
  assert.match(preferences, /data-testid="preferences-trigger"/);
  assert.equal((preferences.match(/<select /g) ?? []).length, 2);
  assert.doesNotMatch(preferences, /role="menu|option value="system"/);
  const account = renderToStaticMarkup(createElement(HeaderAccount, { locale, username: 'operator-a', role: 'viewer', expiresAt: '2026-11-11T18:00:00Z', busy: false, logout() {} }));
  assert.ok(account.includes(copy.account));
  assert.ok(account.includes(copy.viewer));
  assert.ok(account.includes(copy.logout));
  assert.match(account, /datetime="2026-11-11T18:00:00Z"/i);
  assert.doesNotMatch(account, /role="menu|csrf|credential|Bearer/);
});

test('anonymous bootstrap has preferences but no account or administrative frame', () => {
  const html = renderToStaticMarkup(createElement(FirewallPage));
  assert.match(html, /data-testid="preferences-trigger"/);
  assert.doesNotMatch(html, /data-testid="account-trigger"|data-testid="account-panel"|<aside|<nav/);
});
