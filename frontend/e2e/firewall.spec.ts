import { selectLocale, selectTheme, signOut } from './headerHelpers.js';
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import type { Config, FirewallState, History, Session, Transaction } from '../src/firewall/model.js';
import { firewallMessages } from '../src/firewall/messages.js';
import { consoleMessages } from '../src/firewall/consoleMessages.js';
import { systemMessages } from '../src/firewall/systemMessages.js';
import { floatingWindowMessages } from '../src/design-system/floatingWindowMessages.js';

// Explicit transport fixtures only. These tests do not prove authentication or packet enforcement.
const now = new Date('2026-11-09T12:00:00Z');
const initialConfig: Config = { schema_version: 2, default_action: 'deny', rules: [] };
const initialHash = '1'.repeat(64);
async function fixture(page: Page, role: Session['role'] = 'admin', authenticated = false) {
  await page.clock.install({ time: now });
  await page.clock.setFixedTime(now);
  const session: Session = { username: 'lab-admin', role, csrf: 'fixture-csrf-not-a-real-token', expires_at: '2026-11-09T13:00:00Z' };
  let loggedIn = authenticated;
  let disconnected = false;
  let conflict = false;
  let status: FirewallState = { snapshot: { generation: 1, running: { hash: initialHash, config: structuredClone(initialConfig) }, startup: { hash: initialHash, config: structuredClone(initialConfig) }, recovery_required: false }, effective: { revision: initialHash, state: 'verified', rules: [] } };
  const transactions: Transaction[] = [];
  const history: History = { revisions: [{ sequence: 1, revision: structuredClone(status.snapshot.running) }], audit: [
    { sequence: 2, at: now.toISOString(), actor: 'lab-admin', surface: 'web', operation: 'commit', result: 'ok', running_hash: initialHash },
    { sequence: 1, at: now.toISOString(), actor: 'lab-viewer', surface: 'cli', operation: 'stage', result: 'ANDEIVA_CONFIG_DENIED', running_hash: initialHash },
  ], next_before: 0 };
  await page.route('**/api/v1/**', async (route) => {
    const req = route.request();
    expect(req.headers()['x-andeiva-client']).toBe('web');
    expect(req.headers()['authorization']).toBeUndefined();
    const path = new URL(req.url()).pathname;
    if (disconnected) return route.abort('failed');
    if (path.endsWith('/auth/login')) {
      expect(req.postDataJSON()).toEqual({ username: 'lab-admin', credential: 'test-only-fixture' });
      loggedIn = true;
      return route.fulfill({ json: session });
    }
    if (!loggedIn) return route.fulfill({ status: 401, json: { code: 'ANDEIVA_AUTH_REQUIRED', request_id: 'fixture' } });
    if (path.endsWith('/system/info')) return route.fulfill({ json: { product: 'ANDEIVA Security Gateway', version: '0.1.0~alpha16', channel: 'experimental', update_status: 'unavailable' } });
    if (path.endsWith('/capabilities')) return route.fulfill({ json: { firewall_rule_enabled: true, firewall_config_schema_versions: [2, 4] } });
    if (path.endsWith('/auth/session')) return route.fulfill({ json: session });
    if (path.endsWith('/auth/logout')) { expect(req.headers()['x-csrf-token']).toBe(session.csrf); loggedIn = false; return route.fulfill({ json: { ok: true } }); }
    if (path.endsWith('/history')) {
      if (role !== 'admin') return route.fulfill({ status: 403, json: { code: 'ANDEIVA_CONFIG_DENIED' } });
      return route.fulfill({ json: history });
    }
    if (path.endsWith('/transactions')) {
      expect(req.headers()['x-csrf-token']).toBe(session.csrf);
      const transaction: Transaction = req.postDataJSON();
      expect(transaction.key).toMatch(/^[\da-f]{8}-[\da-f-]{27}$/);
      expect(transaction.expected_generation).toBe(status.snapshot.generation);
      transactions.push(transaction);
      if (conflict) { status.snapshot.generation++; return route.fulfill({ status: 409, json: { code: 'ANDEIVA_CONFIG_CONFLICT' } }); }
      const snapshot = status.snapshot;
      if (transaction.operation === 'stage') snapshot.candidate = { owner: session.username, base: snapshot.running.hash, revision: { hash: String(snapshot.generation + 1).repeat(64), config: transaction.config! } };
      if (transaction.operation === 'commit') {
        const previous = structuredClone(snapshot.running);
        snapshot.running = snapshot.candidate!.revision;
        delete snapshot.candidate;
        if (transaction.confirm_for) snapshot.pending = { owner: session.username, previous, deadline: new Date(now.getTime() + transaction.confirm_for / 1_000_000).toISOString() };
      }
      if (transaction.operation === 'confirm') { expect(transaction.target).toBe(snapshot.running.hash); delete snapshot.pending; }
      if (transaction.operation === 'save') snapshot.startup = structuredClone(snapshot.running);
      if (transaction.operation === 'rollback') { expect(transaction.target).toBe(initialHash); snapshot.running = structuredClone(history.revisions[0]!.revision); }
      snapshot.generation++;
      status = { snapshot, effective: { revision: snapshot.running.hash, state: snapshot.pending ? 'pending_confirmation' : 'verified', rules: snapshot.running.config.rules.filter((rule) => rule.enabled !== false).map((rule) => ({ id: rule.id, packets: 7, bytes: 256 })) } };
      return route.fulfill({ json: status });
    }
    return route.fulfill({ json: status });
  });
  return { transactions, history, disconnect: () => { disconnected = true; }, conflict: () => { conflict = true; }, state: () => status };
}

async function expectAccessOnly(page: Page) {
  await expect(page.locator('aside, nav, .console-page-heading, .page-heading, .console-menu-button, [data-testid=account-trigger], [data-testid=account-panel], .fw-transaction-controls')).toHaveCount(0);
  await expect(page.getByRole('table')).toHaveCount(0);
  await expect(page.getByRole('dialog')).toHaveCount(0);
}

test('anonymous direct routes never mount administrative navigation, including during session lookup', async ({ page }) => {
  await fixture(page);
  await page.addInitScript(() => {
    const state = window as Window & { administrativeMounts: number };
    state.administrativeMounts = 0;
    new MutationObserver((records) => {
      for (const record of records) for (const node of record.addedNodes) if (node instanceof Element && (node.matches('aside, nav, .console-page-heading, [data-testid=account-trigger]') || node.querySelector('aside, nav, .console-page-heading, [data-testid=account-trigger]'))) state.administrativeMounts++;
    }).observe(document, { childList: true, subtree: true });
  });
  for (const path of ['/', '/#dashboard', '/firewall#audit', '/firewall#configuration', '/firewall#traffic', '/local-services']) {
    let release!: () => void;
    const held = new Promise<void>((done) => { release = done; });
    await page.route('**/auth/session', async (route) => { await held; await route.fulfill({ status: 401, json: { code: 'ANDEIVA_AUTH_REQUIRED' } }); });
    const destination = new URL(path, 'http://127.0.0.1:4173');
    destination.searchParams.set('access-check', path);
    await page.goto(destination.href);
    await expect(page.locator('[aria-busy="true"]')).toBeVisible();
    await expectAccessOnly(page);
    release();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await expectAccessOnly(page);
    expect(await page.evaluate(() => (window as Window & { administrativeMounts: number }).administrativeMounts)).toBe(0);
    await page.unroute('**/auth/session');
  }
});

test('rejected login, logout, history navigation and server revocation preserve the access boundary', async ({ page }) => {
  await fixture(page);
  await page.route('**/auth/login', (route) => route.fulfill({ status: 401, json: { code: 'ANDEIVA_AUTH_DENIED' } }));
  await page.goto('/firewall');
  await page.getByLabel('Username', { exact: true }).fill('lab-admin');
  await page.getByLabel('Provisioned access credential', { exact: true }).fill('test-only-fixture');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('status')).toBeVisible();
  await expect(page.getByLabel('Username', { exact: true })).toHaveValue('');
  await expectAccessOnly(page);
  await page.unroute('**/auth/login');
  await page.getByLabel('Username', { exact: true }).fill('lab-admin');
  await page.getByLabel('Provisioned access credential', { exact: true }).fill('test-only-fixture');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('#console-navigation')).toHaveCount(1);
  await signOut(page);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await page.evaluate(() => { location.hash = 'configuration'; });
  await page.goBack();
  await expectAccessOnly(page);
  await login(page);
  await page.route('**/api/v1/firewall', (route) => route.fulfill({ status: 401, json: { code: 'ANDEIVA_AUTH_REQUIRED' } }));
  await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expectAccessOnly(page);
});

test('an already expired session response cannot mount protected content', async ({ page }) => {
  await fixture(page, 'admin', true);
  await page.route('**/auth/session', (route) => route.fulfill({ json: { username: 'expired', role: 'admin', csrf: 'fixture-only', expires_at: now.toISOString() } }));
  for (const path of ['/firewall#configuration', '/local-services']) {
    await page.goto(path);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await expectAccessOnly(page);
  }
});
async function login(page: Page) {
  await page.goto('/firewall');
  await page.getByLabel('Username', { exact: true }).fill('lab-admin');
  await page.getByLabel('Provisioned access credential', { exact: true }).fill('test-only-fixture');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('.ds-badge').filter({ hasText: 'Verified at last refresh' })).toBeVisible();
}
async function fillRule(page: Page, id = 'allow-web', protocol = 'tcp') {
  await page.getByRole('button', { name: 'Add rule', exact: true }).click();
  await page.getByLabel('Rule ID', { exact: true }).fill(id);
  await page.getByLabel('Source IPv4 / CIDR', { exact: true }).fill('10.42.0.7/24');
  await page.getByLabel('Destination IPv4 / CIDR', { exact: true }).fill('10.43.0.2');
  await page.getByLabel('Destination ports', { exact: true }).fill('443-445');
  await page.getByLabel('Protocol', { exact: true }).selectOption(protocol);
  await page.getByLabel('Action', { exact: true }).selectOption('allow');
}
async function addRule(page: Page, id = 'allow-web', protocol = 'tcp') {
  await fillRule(page, id, protocol);
  await page.getByRole('button', { name: 'Keep in local draft', exact: true }).click();
}
async function proceed(page: Page, name: string) {
  if (name === 'Commit now') await page.locator('.console-other-actions > summary').click();
  await page.getByRole('button', { name, exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Proceed', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await expect(page.getByText('Request completed', { exact: true })).toBeVisible();
}

test('firewall session, CRUD, ordering, confirmed commit, save and historical rollback', async ({ page }) => {
  const mock = await fixture(page);
  await login(page);
  await addRule(page);
  await addRule(page, 'allow-dns', 'udp');
  const handle = page.getByRole('button', { name: 'Reorder: allow-dns', exact: true });
  await handle.focus(); await handle.press('Space'); await handle.press('ArrowUp'); await handle.press('Enter');
  await expect(page.getByRole('table').locator('tbody th .fw-rule-link')).toHaveText(['allow-dns', 'allow-web']);
  await page.getByRole('button', { name: 'Edit: allow-web', exact: true }).click();
  await page.getByLabel('Destination ports', { exact: true }).fill('8443');
  await page.getByRole('button', { name: 'Keep in local draft', exact: true }).click();
  await page.getByRole('button', { name: 'Stage candidate', exact: true }).click();
  await expect(page.getByText('Request completed', { exact: true })).toBeVisible();
  expect(mock.transactions[0]?.config?.rules.map((rule) => rule.id)).toEqual(['allow-dns', 'allow-web']);
  expect(mock.transactions[0]?.config?.rules[0]?.match.source).toBe('10.42.0.0/24');
  expect(mock.transactions[0]?.config?.rules[1]?.match.destination_ports).toEqual({ from: 8443, to: 8443 });
  await page.getByRole('button', { name: 'Validate candidate', exact: true }).click();
  await expect(page.getByText('Request completed', { exact: true })).toBeVisible();
  await proceed(page, 'Commit with confirmation');
  expect(mock.transactions.at(-1)?.confirm_for).toBe(60_000_000_000);
  await expect(page.locator('.ds-badge').filter({ hasText: 'Awaiting confirmation' }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add rule', exact: true })).toBeDisabled();
  await proceed(page, 'Confirm running revision');
  await proceed(page, 'Save running to startup');
  expect(mock.state().snapshot.running.hash).toBe(mock.state().snapshot.startup.hash);
  await page.evaluate(() => { window.location.hash = 'audit'; });
  await page.getByRole('button', { name: 'Load history', exact: true }).click();
  await page.getByLabel('Actor or revision', { exact: true }).fill('LAB-VIEWER');
  const audit = page.getByRole('table', { name: 'Transaction audit', exact: true });
  await expect(audit.locator('tbody tr')).toHaveCount(1);
  await expect(audit).toContainText('lab-viewer');
  await page.locator('.console-history-revisions > summary').click();
  await page.locator('.console-history-revisions tbody summary').click();
  await page.getByRole('button', { name: `Restore revision: ${initialHash}`, exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Proceed', exact: true }).click();
  await page.evaluate(() => { window.location.hash = 'rules'; });
  await expect(page.getByText('No rules. Default deny applies.', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => ({ local: JSON.stringify(localStorage), session: JSON.stringify(sessionStorage) }))).toEqual({ local: '{}', session: '{}' });
  await signOut(page);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
});

test('firewall validation focuses invalid fields and prevents transport writes', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await page.getByRole('button', { name: 'Add rule', exact: true }).click();
  await page.getByRole('button', { name: 'Keep in local draft', exact: true }).click();
  await expect(page.getByLabel('Rule ID', { exact: true })).toBeFocused();
  await expect(page.getByLabel('Rule ID', { exact: true })).toHaveAttribute('aria-invalid', 'true');
  await page.getByLabel('Rule ID', { exact: true }).fill('valid');
  await page.getByLabel('Source IPv4 / CIDR', { exact: true }).fill('256.1.1.1');
  await page.getByLabel('Destination IPv4 / CIDR', { exact: true }).fill('::1');
  await page.getByLabel('Destination ports', { exact: true }).fill('90-80');
  await page.getByRole('button', { name: 'Keep in local draft', exact: true }).click();
  await expect(page.getByLabel('Source IPv4 / CIDR', { exact: true })).toBeFocused();
  expect(mock.transactions).toEqual([]);
});

test('editor associates localized CIDR and port hints with labels and validation errors', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  for (const locale of ['en', 'es', 'pt'] as const) {
    const copy = firewallMessages[locale];
    await selectLocale(page, locale);
    await page.getByRole('button', { name: copy.add, exact: true }).click();
    const id = page.getByLabel(copy.id, { exact: true });
    await expect(id).toBeFocused(); await id.fill('accessible');
    for (const key of ['source', 'destination', 'source_ports', 'destination_ports'] as const) {
      const control = page.getByLabel(copy[key], { exact: true });
      const hint = key.includes('ports') ? copy.portsHint : copy.cidrHint;
      await expect(control).toHaveAccessibleDescription(hint);
      await control.fill(key.includes('ports') ? '0' : '999.1.1.1');
    }
    await page.getByRole('button', { name: copy.applyRule, exact: true }).click();
    await expect(page.getByLabel(copy.source, { exact: true })).toBeFocused();
    for (const key of ['source', 'destination', 'source_ports', 'destination_ports'] as const) {
      const control = page.getByLabel(copy[key], { exact: true });
      const hint = key.includes('ports') ? copy.portsHint : copy.cidrHint;
      const error = key.includes('ports') ? copy.portsError : copy.cidrError;
      await expect(control).toHaveAccessibleDescription(`${hint} ${error}`);
      expect(await control.evaluate((element) => (element.getAttribute('aria-describedby') ?? '').split(/\s+/).every((id) => !!id && document.querySelectorAll(`[id="${CSS.escape(id)}"]`).length === 1))).toBe(true);
      await control.fill(key.includes('ports') ? '443' : '10.42.0.0/24');
      await expect(control).toHaveAccessibleDescription(hint);
      await expect(control).toHaveAttribute('aria-invalid', 'false');
    }
    await page.getByLabel(copy.source, { exact: true }).focus(); await page.keyboard.press('Tab');
    await expect(page.getByLabel(copy.destination, { exact: true })).toBeFocused();
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    await page.getByRole('button', { name: copy.cancel, exact: true }).last().click();
  }
  expect(mock.transactions).toEqual([]);
});

test('active drag locks column visibility and other table mutations until explicit drop or cancel', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  const rules = ['first', 'second', 'third'].map((id) => ({ id, action: 'allow' as const, match: { source: '10.42.0.0/24', destination: '10.43.0.2/32', protocol: 'tcp' as const, source_ports: { from: 1, to: 65535 }, destination_ports: { from: 443, to: 443 } } }));
  mock.state().snapshot.running.config.rules = rules;
  mock.state().snapshot.startup.config.rules = structuredClone(rules);
  await page.goto('/firewall');
  const summary = page.locator('.ds-column-chooser summary');
  const column = page.getByRole('checkbox', { name: 'Columns: Service', exact: true, includeHidden: true });
  await summary.click(); await column.uncheck();
  await summary.click();
  const handle = page.getByRole('button', { name: 'Reorder: third', exact: true });
  await handle.scrollIntoViewIfNeeded(); const from = await handle.boundingBox();
  const target = await page.getByRole('button', { name: 'Reorder: first', exact: true }).boundingBox();
  if (!from || !target) throw Error('Drag geometry unavailable');
  await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2); await page.mouse.down();
  await expect(handle).toHaveAttribute('aria-pressed', 'true');
  // Reproduce the original cancellation from a queued second input source.
  await column.evaluate((element: HTMLInputElement) => element.click());
  await expect(handle).toHaveAttribute('aria-pressed', 'true'); await expect(column).not.toBeChecked();
  await expect(summary).toHaveAttribute('aria-disabled', 'true');
  await expect(column).toBeDisabled();
  await expect(page.getByLabel('Search rules', { exact: true })).toBeDisabled();
  await expect(page.getByLabel('Filter by action', { exact: true })).toBeDisabled();
  await expect(page.locator('#rule-view')).toBeDisabled();
  await page.mouse.move(from.x + from.width / 2, target.y + target.height / 2, { steps: 6 }); await page.mouse.up();
  await expect(page.locator('.fw-rule-link')).toHaveText(['third', 'first', 'second']);
  await expect(summary).not.toHaveAttribute('aria-disabled', 'true');
  await handle.focus(); await handle.press('Space'); await handle.press('End');
  await expect(column).toBeDisabled(); await handle.press('Escape');
  await expect(handle).toBeFocused();
  await expect(page.locator('.fw-rule-link')).toHaveText(['third', 'first', 'second']);
  await page.getByLabel('Search rules', { exact: true }).fill('first'); await expect(page.getByRole('button', { name: 'Reorder: first', exact: true })).toBeDisabled();
  await page.getByLabel('Search rules', { exact: true }).clear();
  expect(mock.state().snapshot.running.config.rules.map((rule) => rule.id)).toEqual(['first', 'second', 'third']);
  expect(mock.transactions).toEqual([]);
});

test('firewall viewer cannot edit or load privileged history', async ({ page }) => {
  await fixture(page, 'viewer', true);
  await page.goto('/firewall');
  await expect(page.locator('.ds-badge').filter({ hasText: 'Verified at last refresh' })).toBeVisible();
  for (const name of ['Add rule', 'Stage candidate', 'Commit now', 'Save running to startup', 'Load history']) await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
});

test('firewall removal stays local and session expiry removes sensitive views', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await addRule(page);
  await page.getByLabel('Actions: allow-web', { exact: true }).click();
  await page.getByRole('button', { name: 'Remove: allow-web', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Proceed', exact: true }).click();
  await page.evaluate(() => { window.location.hash = 'rules'; });
  await expect(page.getByText('No rules. Default deny applies.', { exact: true })).toBeVisible();
  expect(mock.transactions).toEqual([]);
  await page.clock.fastForward(3_601_000);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expectAccessOnly(page);
  await expect(page.getByRole('table')).toHaveCount(0);
});

test('firewall disconnect and conflicting generation never claim success', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await addRule(page);
  mock.conflict();
  await page.getByRole('button', { name: 'Stage candidate', exact: true }).click();
  await expect(page.getByText('Configuration changed or belongs to another administrator. Refresh and review before submitting again.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Stage candidate', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
  await expect(page.getByText('This draft is based on an older generation. Discard it and review the current candidate before staging.', { exact: true })).toBeVisible();
  mock.disconnect();
  await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
  await expect(page.getByText('Effective state unknown', { exact: true })).toBeVisible();
  await expect(page.locator('.ds-badge').filter({ hasText: 'Verified at last refresh' })).toHaveCount(0);
});

test('firewall confirmation deadline invalidates the observed effective state', async ({ page }) => {
  await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await addRule(page);
  await page.getByRole('button', { name: 'Stage candidate', exact: true }).click();
  await proceed(page, 'Commit with confirmation');
  await page.clock.fastForward(61_000);
  await expect(page.getByRole('button', { name: 'Confirm running revision', exact: true })).toBeDisabled();
  await expect(page.getByText('Effective state unknown', { exact: true })).toBeVisible();
});

test('firewall rejects malformed responses and mismatched effective revisions', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  mock.state().effective.revision = 'f'.repeat(64);
  await page.goto('/firewall');
  await expect(page.getByText('Effective state unknown', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add rule', exact: true })).toBeDisabled();
  mock.state().snapshot.running.config.schema_version = 999;
  await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
  await expect(page.getByText('The request could not be completed. Refresh status before trying again.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add rule', exact: true })).toBeDisabled();
});

for (const theme of ['light', 'dark'] as const) {
  test(`firewall ${theme}: visual baseline login and rule editor`, async ({ page }) => {
    const mock = await fixture(page);
    await page.goto('/firewall');
    await selectTheme(page, theme);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    for (const locale of ['es', 'pt', 'en'] as const) {
      await selectLocale(page, locale);
      await expect(page.getByRole('heading', { name: firewallMessages[locale].login, exact: true })).toBeVisible();
      await expectAccessOnly(page);
    }
    await expectAccessOnly(page);
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    await expect(page).toHaveScreenshot(`firewall-${theme}-login.png`, { fullPage: true });
    const rules = ['lab-web', 'lab-dns', 'lab-maintenance'].map((id, index) => ({ id, enabled: index !== 2, action: index === 1 ? 'deny' as const : 'allow' as const, match: { source: '10.42.0.0/24', destination: '10.43.0.2/32', protocol: index === 1 ? 'udp' as const : 'tcp' as const, source_ports: { from: 1, to: 65535 }, destination_ports: { from: index === 1 ? 53 : 443, to: index === 1 ? 53 : 443 } } }));
    mock.state().snapshot.running.config = { schema_version: 4, default_action: 'deny', rules };
    mock.state().snapshot.startup = { hash: 'b'.repeat(64), config: { schema_version: 4, default_action: 'deny', rules: [rules[0]!] } };
    mock.state().effective.rules = rules.filter((rule) => rule.enabled).map((rule) => ({ id: rule.id, packets: 7, bytes: 256 }));
    await login(page);
    await expect(page).toHaveScreenshot(`firewall-${theme}-rules.png`, { fullPage: true });
    await fillRule(page);
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect(page).toHaveScreenshot(`firewall-${theme}-editor.png`);
    await page.getByRole('button', { name: 'Close editor', exact: true }).click();
    for (const locale of ['es', 'pt', 'en'] as const) {
      await selectLocale(page, locale);
      const copy = firewallMessages[locale];
      await page.getByRole('button', { name: copy.add, exact: true }).click();
      await expect(page.getByRole('dialog', { name: copy.editor, exact: true })).toBeVisible();
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      await page.getByRole('button', { name: copy.cancel, exact: true }).last().click();
    }
  });
}


test('rule reorder cancellation, filtering and explicit position preserve local-only edits', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await addRule(page, 'first'); await addRule(page, 'second'); await addRule(page, 'third');
  const table = page.getByRole('table', { name: 'Ordered rules', exact: true });
  const handle = page.getByRole('button', { name: 'Reorder: first', exact: true });
  await handle.focus(); await handle.press('Space'); await handle.press('End'); await handle.press('Escape');
  await expect(table.locator('tbody th .fw-rule-link')).toHaveText(['first', 'second', 'third']);
  await page.getByLabel('Search rules', { exact: true }).fill('first');
  await expect(handle).toBeDisabled();
  await expect(table.locator('tbody tr')).toHaveCount(1);
  await page.getByLabel('Search rules', { exact: true }).clear();
  await page.getByLabel('Actions: third', { exact: true }).click();
  const menu = table.locator('details[open]');
  await menu.getByLabel('Move to position', { exact: true }).fill('1');
  await menu.getByRole('button', { name: 'Move', exact: true }).click();
  await expect(table.locator('tbody th .fw-rule-link')).toHaveText(['third', 'first', 'second']);
  expect(mock.transactions).toEqual([]);
});

for (const input of ['mouse', 'touch'] as const) {
  test('rule reorder using real ' + input + ' pointer input', async ({ page }) => {
    const mock = await fixture(page, 'admin', true);
    await page.goto('/firewall');
    await addRule(page, 'first'); await addRule(page, 'second'); await addRule(page, 'third');
    const handle = page.getByRole('button', { name: 'Reorder: third', exact: true });
    await handle.scrollIntoViewIfNeeded();
    const from = await handle.boundingBox();
    const target = await page.getByRole('button', { name: 'Reorder: first', exact: true }).boundingBox();
    if (!from || !target) throw new Error('Drag geometry unavailable');
    const x = from.x + from.width / 2; const start = from.y + from.height / 2; const end = target.y + target.height / 2;
    if (input === 'mouse') {
      await page.mouse.move(x, start); await page.mouse.down(); await page.mouse.move(x, end, { steps: 8 }); await page.mouse.up();
    } else {
      const client = await page.context().newCDPSession(page);
      await client.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x, y: start }] });
      await client.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x, y: end }] });
      await client.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
      await client.detach();
    }
    await expect(page.getByRole('table', { name: 'Ordered rules', exact: true }).locator('tbody th .fw-rule-link')).toHaveText(['third', 'first', 'second']);
    expect(mock.transactions).toEqual([]);
  });
}

test('disabled rule lifecycle uses v4, effective counters absent, Startup order and state tracked', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await fillRule(page, 'dormant');
  await page.getByRole('checkbox', { name: 'Enabled', exact: true }).uncheck();
  await page.getByRole('button', { name: 'Keep in local draft', exact: true }).click();
  await addRule(page, 'active');
  await page.getByRole('button', { name: 'Stage candidate', exact: true }).click();
  await expect(page.getByText('Request completed', { exact: true })).toBeVisible();
  expect(mock.transactions[0]?.config?.schema_version).toBe(4);
  expect(mock.transactions[0]?.config?.rules.map((rule) => rule.enabled)).toEqual([false, true]);
  await proceed(page, 'Commit now');
  const table = page.getByRole('table', { name: 'Ordered rules', exact: true });
  const dormant = table.locator('tbody tr').filter({ has: page.getByRole('button', { name: 'Edit: dormant', exact: true }) });
  await expect(dormant).toContainText('Disabled in Running');
  await expect(dormant).toContainText('Not applicable');
  await expect(dormant).toContainText('Not saved');
  await proceed(page, 'Save running to startup');
  await expect(dormant).toContainText('Matches Startup');
  await page.getByRole('checkbox', { name: 'Enabled: dormant', exact: true }).check();
  await expect(dormant).toContainText('Not applied');
  await expect(dormant).toContainText('Not saved');
  expect(mock.state().snapshot.running.config.rules[0]?.enabled).toBe(false);
  await page.getByRole('button', { name: 'Reorder: active', exact: true }).focus();
  await page.keyboard.press('Space'); await page.keyboard.press('Home'); await page.keyboard.press('Enter');
  await expect(table.locator('tbody tr').filter({ hasText: 'Not saved' })).toHaveCount(2);
});

test('legacy runtime never exposes disabling or sends enabled', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.route('**/api/v1/capabilities', (route) => route.fulfill({ json: { firewall_rule_enabled: false, firewall_config_schema_versions: [2] } }));
  await page.goto('/firewall'); await fillRule(page, 'legacy');
  await expect(page.getByRole('checkbox', { name: 'Enabled', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Keep in local draft', exact: true }).click();
  await page.getByRole('button', { name: 'Stage candidate', exact: true }).click();
  await expect(page.getByText('Request completed', { exact: true })).toBeVisible();
  expect(mock.transactions[0]?.config?.schema_version).toBe(2);
  expect(mock.transactions[0]?.config?.rules[0]).not.toHaveProperty('enabled');
});


test('rule handle autoscrolls a bounded policy and restores keyboard focus on cancellation', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  const rules = Array.from({ length: 20 }, (_, index) => ({ id: 'rule-' + String(index + 1).padStart(2, '0'), action: 'allow' as const, match: { source: '10.42.0.0/24', destination: '10.43.0.2/32', protocol: 'tcp' as const, source_ports: { from: 1, to: 65535 }, destination_ports: { from: 443, to: 443 } } }));
  mock.state().snapshot.running.config.rules = rules;
  mock.state().snapshot.startup.config.rules = structuredClone(rules);
  await page.goto('/firewall');
  const handle = page.getByRole('button', { name: 'Reorder: rule-01', exact: true });
  await page.locator('.ds-column-chooser summary').click();
  await page.getByRole('checkbox', { name: 'Columns: Service', exact: true }).uncheck();
  await page.locator('.ds-column-chooser summary').click();
  const region = page.getByRole('region', { name: 'Ordered rules', exact: true });
  await handle.focus(); await handle.press('Space'); await handle.press('End'); await handle.press('Escape');
  await page.clock.runFor(100);
  await expect(handle).toBeFocused(); await expect(handle).toBeInViewport();
  await region.evaluate((element) => element.scrollIntoView({ block: 'start' }));
  await region.evaluate((element) => { element.scrollTop = 0; });
  const from = await handle.boundingBox(); const bounds = await region.boundingBox();
  if (!from || !bounds) throw new Error('Drag geometry unavailable');
  const x = from.x + from.width / 2;
  await page.mouse.move(x, from.y + from.height / 2); await page.mouse.down();
  await page.mouse.move(x, bounds.y + bounds.height - 8, { steps: 5 });
  await page.clock.runFor(500);
  expect(await region.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
  const viewport = page.viewportSize()!;
  await page.setViewportSize({ ...viewport, height: viewport.height - 30 });
  await expect(handle).toHaveAttribute('aria-pressed', 'true');
  await page.mouse.up(); await page.clock.runFor(100);
  const ids = await page.getByRole('table', { name: 'Ordered rules', exact: true }).locator('tbody th .fw-rule-link').allTextContents();
  expect(ids.indexOf('rule-01')).toBeGreaterThan(0);
  expect(new Set(ids).size).toBe(20);
  expect(mock.transactions).toEqual([]);
});


test('late pointer release cannot reorder a refreshed snapshot', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  const rules = ['first', 'second', 'third'].map((id) => ({ id, action: 'allow' as const, match: { source: '10.42.0.0/24', destination: '10.43.0.2/32', protocol: 'tcp' as const, source_ports: { from: 1, to: 65535 }, destination_ports: { from: 443, to: 443 } } }));
  mock.state().snapshot.running.config.rules = rules;
  mock.state().snapshot.startup.config.rules = structuredClone(rules);
  await page.goto('/firewall');
  const handle = page.getByRole('button', { name: 'Reorder: first', exact: true });
  await handle.scrollIntoViewIfNeeded();
  const from = await handle.boundingBox(); const to = await page.getByRole('button', { name: 'Reorder: third', exact: true }).boundingBox();
  if (!from || !to) throw new Error('Drag geometry unavailable');
  await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2); await page.mouse.down();
  await page.mouse.move(to.x + to.width / 2, to.y + to.height / 2, { steps: 5 });
  await expect(handle).toHaveAttribute('aria-pressed', 'true');
  mock.state().snapshot.generation++;
  mock.state().snapshot.running.config.rules = [rules[0]!, rules[2]!, rules[1]!];
  await page.getByRole('button', { name: 'Refresh status', exact: true }).evaluate((button) => button.click());
  await expect(page.getByRole('table', { name: 'Ordered rules', exact: true }).locator('tbody th .fw-rule-link')).toHaveText(['first', 'third', 'second']);
  await expect(handle).toHaveAttribute('aria-pressed', 'false');
  await page.mouse.up();
  await expect(page.getByRole('table', { name: 'Ordered rules', exact: true }).locator('tbody th .fw-rule-link')).toHaveText(['first', 'third', 'second']);
  await expect(page.getByRole('button', { name: 'Stage candidate', exact: true })).toBeDisabled();
  expect(mock.transactions).toEqual([]);
});

for (const theme of ['light', 'dark'] as const) {
  test(`console V3 ${theme}: view navigation and visual baseline`, async ({ page }) => {
    const mock = await fixture(page, 'admin', true);
    const sample = ['web', 'dns', 'maintenance'].map((id, index) => ({ id, enabled: index !== 2, action: index === 1 ? 'deny' as const : 'allow' as const, match: { source: '10.42.0.0/24', destination: '10.43.0.2/32', protocol: index === 1 ? 'udp' as const : 'tcp' as const, source_ports: { from: 1, to: 65535 }, destination_ports: { from: index === 1 ? 53 : 443, to: index === 1 ? 53 : 443 } } }));
    mock.state().snapshot.running.config = { schema_version: 4, default_action: 'deny', rules: sample };
    mock.state().snapshot.startup = { hash: 'b'.repeat(64), config: { schema_version: 4, default_action: 'deny', rules: [sample[0]!] } };
    mock.state().effective.rules = sample.filter((rule) => rule.enabled).map((rule) => ({ id: rule.id, packets: 7, bytes: 256 }));
    await page.goto('/firewall#dashboard');
    await selectTheme(page, theme);
    await expect(page.locator('.console-kpis')).toContainText('14');
    await expect(page.locator('.console-geo')).toContainText('No geographic traffic observations');
    for (const view of ['dashboard', 'configuration', 'audit'] as const) {
      await page.evaluate((next) => { window.location.hash = next; }, view);
      await expect(page.getByRole('heading', { name: consoleMessages.en[view], level: 1, exact: true })).toBeVisible();
      if (view === 'audit') {
        await page.getByRole('button', { name: 'Load history', exact: true }).click();
        await page.getByRole('button', { name: 'Inspect event: 2', exact: true }).click();
        await expect(page.locator('.console-audit-detail')).toContainText('lab-admin');
      }
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
      await page.evaluate(() => window.scrollTo(0, 0));
      await expect(page).toHaveScreenshot(`console-${theme}-${view}.png`, { fullPage: true });
      for (const locale of ['es', 'pt', 'en'] as const) {
        await selectLocale(page, locale);
        await expect(page.getByRole('heading', { name: consoleMessages[locale][view], level: 1, exact: true })).toBeVisible();
      }
    }
    expect(mock.transactions).toEqual([]);
  });
}

test('console hash navigation preserves draft and does not stage until explicitly requested', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await addRule(page, 'preserved-draft');
  await page.evaluate(() => { window.location.hash = 'configuration'; });
  await expect(page.getByRole('heading', { name: 'Configuration', level: 1, exact: true })).toBeVisible();
  await page.evaluate(() => { window.location.hash = 'rules'; });
  await expect(page.getByRole('table', { name: 'Ordered rules', exact: true })).toContainText('preserved-draft');
  expect(mock.transactions).toEqual([]);
  await page.getByRole('button', { name: 'Stage candidate', exact: true }).click();
  expect(mock.transactions).toHaveLength(1);
  expect(mock.transactions[0]?.config?.rules[0]?.id).toBe('preserved-draft');
});

test('console navigation expansion describes mobile visibility and supports Escape and resize', async ({ page }) => {
  await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/firewall');
  const toggle = page.locator('.console-menu-button');
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('.console-sidebar')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(toggle).toBeFocused();
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await toggle.click();
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
});

test('root opens the authenticated console and internal anchors preserve views and editor input', async ({ page }) => {
  const mock = await fixture(page);
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.getByText('Development foundation', { exact: true })).toHaveCount(0);
  await page.getByLabel('Username', { exact: true }).fill('lab-admin');
  await page.getByLabel('Provisioned access credential', { exact: true }).fill('test-only-fixture');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await fillRule(page, 'unsubmitted-editor');
  await page.evaluate(() => { window.location.hash = 'dashboard'; });
  await expect(page.getByRole('heading', { name: 'Dashboard', level: 1, exact: true })).toBeVisible();
  await expect(page.locator('.fw-editor-notice')).toContainText(firewallMessages.en.editorOpen);
  for (const locale of ['es', 'pt', 'en'] as const) {
    await selectLocale(page, locale);
    await expect(page.locator('.fw-editor-notice')).toContainText(firewallMessages[locale].editorOpen);
    await expect(page.getByRole('link', { name: firewallMessages[locale].returnToRules, exact: true })).toHaveAttribute('href', '#rules');
  }
  await expect(page.getByRole('button', { name: 'Refresh status', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Stage candidate', exact: true })).toBeDisabled();
  await expect(page.locator('.fw-rule-editor')).not.toBeVisible();
  await page.locator('.skip-link').focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Dashboard', level: 1, exact: true })).toBeVisible();
  await page.getByRole('link', { name: firewallMessages.en.returnToRules, exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'Rule editor', exact: true })).toBeVisible();
  await expect(page.getByLabel('Rule ID', { exact: true })).toBeFocused();
  await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue('unsubmitted-editor');
  await expect(page.getByLabel('Destination ports', { exact: true })).toHaveValue('443-445');
  expect(mock.transactions).toEqual([]);
});

test('audit pagination retains visible selected filters when the loaded page no longer has matches', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall#audit');
  await page.getByRole('button', { name: 'Load history', exact: true }).click();
  await page.getByRole('combobox', { name: 'Origin', exact: true }).selectOption('cli');
  await expect(page.getByRole('table', { name: 'Transaction audit', exact: true })).toContainText('lab-viewer');
  mock.history.audit.splice(1, 1);
  await page.getByRole('button', { name: 'Newest page', exact: true }).click();
  await expect(page.getByRole('combobox', { name: 'Origin', exact: true })).toHaveValue('cli');
  await expect(page.getByRole('combobox', { name: 'Origin', exact: true }).locator('option:checked')).toHaveText('cli');
  await page.getByRole('combobox', { name: 'Origin', exact: true }).selectOption('all');
  await expect(page.getByRole('table', { name: 'Transaction audit', exact: true })).toContainText('lab-admin');
});

test('rule column choices affect presentation only and retain global persistence status', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  mock.state().snapshot.startup.hash = 'b'.repeat(64);
  await page.goto('/firewall');
  await addRule(page, 'column-rule');
  const table = page.getByRole('table', { name: 'Ordered rules', exact: true });
  await page.locator('.ds-column-chooser > summary').click();
  const chooser = page.locator('.ds-column-chooser');
  const bounds = await chooser.locator(':scope > div').boundingBox();
  const viewport = page.viewportSize();
  expect(bounds).not.toBeNull(); expect(viewport).not.toBeNull();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.y).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport!.width);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(viewport!.height);
  for (const label of ['Source IPv4 / CIDR', 'Destination IPv4 / CIDR', 'Service', 'Execution', 'At next boot', 'Observed counters']) {
    await chooser.getByRole('checkbox', { name: `Columns: ${label}`, exact: true }).uncheck();
    await expect(table.getByRole('columnheader', { name: label, exact: true })).toHaveCount(0);
  }
  await expect(table.getByRole('columnheader', { name: 'Rule ID', exact: true })).toBeVisible();
  await expect(table.getByRole('columnheader', { name: 'Action', exact: true })).toBeVisible();
  await expect(page.locator('.console-transaction-summary')).toContainText('Running revision has unsaved changes');
  await chooser.getByRole('checkbox', { name: 'Columns: At next boot', exact: true }).check();
  await expect(table.getByRole('columnheader', { name: 'At next boot', exact: true })).toBeVisible();
  expect(mock.transactions).toEqual([]);
});

test('console Back and Forward restore hashless Rules without losing a local draft', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await addRule(page, 'history-preserved');
  await page.evaluate(() => { window.location.hash = 'dashboard'; });
  await expect(page.getByRole('heading', { name: 'Dashboard', level: 1, exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Rules', level: 1, exact: true })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Ordered rules', exact: true })).toContainText('history-preserved');
  await page.goForward();
  await expect(page.getByRole('heading', { name: 'Dashboard', level: 1, exact: true })).toBeVisible();
  expect(mock.transactions).toEqual([]);
});

for (const theme of ['light', 'dark'] as const) test(`rule editor ${theme}: identity field spans the layout independently of generated IDs`, async ({ page }, info) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await selectTheme(page, theme);
  await fillRule(page, 'layout-regression');
  const identity = page.getByLabel('Rule ID', { exact: true });
  const layout = await identity.evaluate((control) => {
    const grid = control.closest('.fw-fields')!;
    const item = [...grid.children].find((child) => child.contains(control))!;
    const style = getComputedStyle(item);
    const bounds = item.getBoundingClientRect();
    const gridBounds = grid.getBoundingClientRect();
    return { start: style.gridColumnStart, end: style.gridColumnEnd, left: bounds.left, width: bounds.width, gridLeft: gridBounds.left, gridWidth: gridBounds.width };
  });
  await info.attach(`identity-layout-${theme}-${info.project.name}`, { body: JSON.stringify(layout), contentType: 'application/json' });
  expect(layout.start).toBe('1');
  expect(layout.end).toBe('-1');
  expect(Math.abs(layout.left - layout.gridLeft)).toBeLessThanOrEqual(1);
  expect(Math.abs(layout.width - layout.gridWidth)).toBeLessThanOrEqual(1);
  await expect(page.locator('.fw-rule-editor .fw-field--full-width')).toHaveCount(1);
  await expect(identity).toHaveValue('layout-regression');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
  expect(mock.transactions).toEqual([]);
});

for (const theme of ['light', 'dark'] as const) test(`floating rule editor ${theme}: wide centered window keeps the rule list available`, async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall');
  await selectTheme(page, theme);
  await fillRule(page, 'floating-draft');
  const editor = page.locator('.fw-rule-editor');
  expect(await editor.evaluate((element) => getComputedStyle(element).position)).toBe('fixed');
  await expect(page.getByRole('dialog', { name: 'Rule editor', exact: true })).toBeVisible();
  const bounds = await editor.boundingBox();
  const viewport = page.viewportSize()!;
  expect(bounds).not.toBeNull();
  expect(bounds!.width).toBeGreaterThanOrEqual(Math.min(800, viewport.width - 32));
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.y).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width + 1);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(viewport.height + 1);
  const compact = viewport.width <= 768;
  await expect(editor).toHaveAttribute('aria-modal', String(compact));
  expect(await editor.evaluate((element) => element.matches(':modal'))).toBe(compact);
  if (!compact) {
    expect(Math.abs(bounds!.x - (viewport.width - bounds!.width) / 2)).toBeLessThanOrEqual(1);
    await expect(page.getByRole('table', { name: 'Ordered rules', exact: true })).toBeVisible();
  }
  expect(mock.transactions).toEqual([]);
});

for (const input of ['mouse', 'touch'] as const) test(`floating window moves with real ${input} input and keeps edits local`, async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/firewall');
  await fillRule(page, 'movable-local-rule');
  const editor = page.locator('.fw-rule-editor'); const title = editor.locator('.ds-floating-title');
  const before = await editor.boundingBox(); const start = await title.boundingBox();
  if (!before || !start) throw Error('Window geometry unavailable');
  const x = start.x + 30; const y = start.y + start.height / 2;
  if (input === 'mouse') {
    await page.mouse.move(x, y); await page.mouse.down(); await page.mouse.move(x - 100, y + 35, { steps: 7 }); await page.mouse.up();
  } else {
    const client = await page.context().newCDPSession(page);
    await client.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x, y }] });
    await client.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x: x - 100, y: y + 35 }] });
    await client.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] }); await client.detach();
  }
  const after = await editor.boundingBox();
  expect(after!.x).toBeCloseTo(before.x - 100, 0);
  expect(after!.y).toBeCloseTo(before.y + 35, 0);
  await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue('movable-local-rule');
  await expect(page.getByRole('button', { name: 'Stage candidate', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Refresh status', exact: true })).toBeDisabled();
  await expect(page.locator('#rule-view')).toBeDisabled();
  await expect(page.getByRole('table', { name: 'Ordered rules', exact: true })).toBeVisible();
  expect(mock.state().snapshot.running.config.rules).toEqual([]);
  expect(mock.transactions).toEqual([]);
});

test('floating keyboard movement distinguishes move cancellation from closing and restores focus', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 1440, height: 1000 }); await page.goto('/firewall');
  await addRule(page, 'previous-local-rule');
  await fillRule(page, 'keyboard-local-rule');
  const editor = page.locator('.fw-rule-editor'); const move = page.getByRole('button', { name: 'Move window', exact: true });
  const before = await editor.boundingBox();
  await page.locator('.console-other-actions > summary').evaluate((element) => element.click());
  await expect(page.getByRole('button', { name: 'Discard local edits', exact: true })).toBeDisabled();
  await page.locator('.console-other-actions > summary').evaluate((element) => element.click());
  await move.click(); await expect(move).toHaveAttribute('aria-pressed', 'true');
  await move.press('ArrowLeft'); await move.press('Shift+ArrowDown');
  const moved = await editor.boundingBox();
  expect(moved!.x).toBeCloseTo(before!.x - 10, 0); expect(moved!.y).toBeCloseTo(before!.y + 1, 0);
  await move.press('Escape'); await expect(editor).toBeVisible();
  const restored = await editor.boundingBox();
  expect(restored!.x).toBeCloseTo(before!.x, 0); expect(restored!.y).toBeCloseTo(before!.y, 0);
  await move.click(); await move.press('ArrowRight'); await move.press('Enter');
  expect((await editor.boundingBox())!.x).toBeCloseTo(before!.x + 10, 0);
  await move.click(); await move.press('Home'); await move.press('Enter');
  expect((await editor.boundingBox())!.x).toBeCloseTo(before!.x, 0);
  await move.press('Escape'); await expect(editor).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Add rule', exact: true })).toBeFocused();
  expect(mock.transactions).toEqual([]);
});

test('floating window remains reachable on resize and mobile focus stays in the fitted editor', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 1440, height: 1000 }); await page.goto('/firewall');
  await fillRule(page, 'responsive-local-rule');
  const editor = page.locator('.fw-rule-editor'); const title = editor.locator('.ds-floating-title');
  const start = await title.boundingBox(); if (!start) throw Error('Window geometry unavailable');
  await page.mouse.move(start.x + 30, start.y + 10); await page.mouse.down();
  await page.mouse.move(-500, 2000, { steps: 6 }); await page.mouse.up();
  expect((await editor.boundingBox())!.x).toBeGreaterThanOrEqual(0);
  await page.getByRole('button', { name: 'Move window', exact: true }).click();
  await page.getByRole('button', { name: 'Move window', exact: true }).press('ArrowRight');
  await page.setViewportSize({ width: 390, height: 680 });
  await expect(editor).toHaveAttribute('aria-modal', 'true');
  expect(await editor.evaluate((element) => element.matches(':modal'))).toBe(true);
  expect(await editor.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  const fitted = await editor.boundingBox();
  expect(fitted!.x).toBe(0); expect(fitted!.y).toBe(0); expect(fitted!.width).toBeCloseTo(390, 0); expect(fitted!.height).toBeCloseTo(680, 0);
  await expect(page.getByRole('button', { name: 'Move window', exact: true })).toHaveCount(0);
  await page.getByLabel('Rule ID', { exact: true }).focus(); await page.keyboard.press('Tab');
  expect(await editor.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  const close = page.getByRole('button', { name: 'Close editor', exact: true });
  const cancel = editor.getByRole('button', { name: 'Cancel', exact: true });
  await expect(close).toBeInViewport();
  await close.focus(); await close.press('Shift+Tab'); await expect(cancel).toBeFocused();
  await cancel.press('Tab'); await expect(close).toBeFocused();
  await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue('responsive-local-rule');
  await page.setViewportSize({ width: 1280, height: 800 });
  await expect(editor).toHaveAttribute('aria-modal', 'false');
  expect(await editor.evaluate((element) => element.matches(':modal'))).toBe(false);
  await expect(page.getByRole('button', { name: 'Move window', exact: true })).toBeVisible();
  await title.locator('..').evaluate((element) => element.addEventListener('gotpointercapture', (event) => { (element as HTMLElement).dataset.testPointer = String((event as PointerEvent).pointerId); }, { once: true }));
  const activeStart = await title.boundingBox(); if (!activeStart) throw Error('Window geometry unavailable');
  await page.mouse.move(activeStart.x + 25, activeStart.y + 10); await page.mouse.down();
  await page.mouse.move(activeStart.x + 40, activeStart.y + 20, { steps: 3 });
  await expect(editor).toHaveAttribute('data-moving', 'true');
  const header = title.locator('..');
  await expect(header).toHaveAttribute('data-test-pointer', /^\d+$/);
  await page.setViewportSize({ width: 390, height: 680 });
  await expect(editor).toHaveAttribute('aria-modal', 'true');
  expect(await header.evaluate((element) => element.hasPointerCapture(Number((element as HTMLElement).dataset.testPointer)))).toBe(false);
  await page.setViewportSize({ width: 1280, height: 800 }); await page.mouse.up();
  await expect(editor).toHaveAttribute('aria-modal', 'false');
  await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue('responsive-local-rule');
  expect(mock.transactions).toEqual([]);
});

test('floating editor closes on logout or expiry without publishing its unsaved rule', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 1440, height: 1000 }); await page.goto('/firewall');
  await fillRule(page, 'logout-local-rule');
  await signOut(page);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.locator('.ds-floating-window')).toHaveCount(0);
  await login(page); await fillRule(page, 'expiry-local-rule');
  await page.clock.fastForward(3_601_000);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.locator('.ds-floating-window')).toHaveCount(0);
  expect(mock.state().snapshot.running.config.rules).toEqual([]);
  expect(mock.transactions).toEqual([]);
});

test('floating controls and validation stay localized in EN ES PT', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 1440, height: 1000 }); await page.goto('/firewall');
  for (const locale of ['en', 'es', 'pt'] as const) {
    await selectLocale(page, locale);
    const copy = firewallMessages[locale]; const windowCopy = floatingWindowMessages[locale];
    await page.getByRole('button', { name: copy.add, exact: true }).click();
    const editor = page.getByRole('dialog', { name: copy.editor, exact: true });
    await expect(editor).toBeVisible();
    await expect(page.getByRole('button', { name: windowCopy.move, exact: true })).toHaveAccessibleDescription(windowCopy.moveHint);
    await page.getByRole('button', { name: copy.applyRule, exact: true }).click();
    await expect(page.getByLabel(copy.id, { exact: true })).toBeFocused();
    await expect(page.getByLabel(copy.id, { exact: true })).toHaveAttribute('aria-invalid', 'true');
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    await page.getByRole('button', { name: windowCopy.close, exact: true }).click();
  }
  expect(mock.transactions).toEqual([]);
});


test('system information is queried only after login and clears on logout', async ({ page }) => {
  const mock = await fixture(page);
  const requests: string[] = [];
  page.on('request', (request) => { if (request.url().endsWith('/system/info')) requests.push(request.method()); });
  await page.goto('/firewall#system');
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expectAccessOnly(page);
  expect(requests).toEqual([]);
  await page.getByLabel('Username', { exact: true }).fill('lab-admin');
  await page.getByLabel('Provisioned access credential', { exact: true }).fill('test-only-fixture');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('.console-system-info').getByText('0.1.0~alpha16', { exact: true })).toBeVisible();
  await expect(page.locator('.console-transaction-bar')).toHaveCount(0);
  expect(requests).toEqual(['GET']);
  await page.getByRole('button', { name: 'Refresh information', exact: true }).click();
  await expect.poll(() => requests.length).toBe(2);
  await expect(page.locator('.console-system-info').getByText('0.1.0~alpha16', { exact: true })).toBeVisible();
  await signOut(page);
  await expectAccessOnly(page);
  await expect(page.getByText('0.1.0~alpha16', { exact: true })).toHaveCount(0);
  expect(mock.transactions).toEqual([]);
});

test('system metadata failure and development fallback do not invalidate healthy configuration', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.route('**/system/info', (route) => route.fulfill({ json: { product: 'ANDEIVA Security Gateway', version: 'not-a-version', channel: 'experimental', update_status: 'unavailable', kernel: 'private-fixture' } }));
  await page.goto('/firewall#system');
  await expect(page.getByText('Product information unavailable', { exact: true })).toBeVisible();
  await expect(page.getByText('private-fixture')).toHaveCount(0);
  await page.evaluate(() => { location.hash = 'rules'; });
  await expect(page.getByRole('button', { name: 'Add rule', exact: true })).toBeEnabled();
  await page.evaluate(() => { location.hash = 'system'; });
  await page.unroute('**/system/info');
  await page.route('**/system/info', (route) => route.fulfill({ json: { product: 'ANDEIVA Security Gateway', channel: 'development', update_status: 'unavailable' } }));
  await page.getByRole('button', { name: 'Refresh information', exact: true }).click();
  await expect(page.getByText('No packaged version', { exact: true })).toBeVisible();
  await expect(page.locator('.console-system-info').getByText('Development build', { exact: false })).toBeVisible();
  await expect(page.locator('.console-system-info').getByText('0.1.0~alpha16', { exact: true })).toHaveCount(0);
  for (const failure of ['unavailable', 'connection'] as const) {
    await page.unroute('**/system/info');
    await page.route('**/system/info', (route) => failure === 'connection' ? route.abort('failed') : route.fulfill({ status: 503, json: { code: 'ANDEIVA_UNAVAILABLE' } }));
    await page.getByRole('button', { name: 'Refresh information', exact: true }).click();
    await expect(page.getByText('Product information unavailable', { exact: true })).toBeVisible();
    await page.evaluate(() => { location.hash = 'rules'; });
    await expect(page.getByRole('button', { name: 'Add rule', exact: true })).toBeEnabled();
    await page.evaluate(() => { location.hash = 'system'; });
  }
  expect(mock.transactions).toEqual([]);
});

test('system information remains readable when configuration is unavailable', async ({ page }) => {
  const mock = await fixture(page, 'viewer', true);
  await page.route('**/api/v1/firewall', (route) => route.fulfill({ status: 503, json: { code: 'ANDEIVA_CONFIG_UNAVAILABLE' } }));
  await page.goto('/firewall#system');
  await expect(page.locator('.console-system-info').getByText('0.1.0~alpha16', { exact: true })).toBeVisible();
  await expect(page.locator('.console-transaction-bar')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Refresh information', exact: true })).toBeEnabled();
  expect(mock.transactions).toEqual([]);
});

test('system unauthorized response clears the session and delayed metadata cannot restore it', async ({ page }) => {
  await fixture(page, 'admin', true);
  await page.goto('/firewall#system');
  await expect(page.locator('.console-system-info').getByText('0.1.0~alpha16', { exact: true })).toBeVisible();
  await page.route('**/system/info', (route) => route.fulfill({ status: 401, json: { code: 'ANDEIVA_AUTH_REQUIRED' } }));
  await page.getByRole('button', { name: 'Refresh information', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expectAccessOnly(page);
  await page.unroute('**/system/info');
  let release!: () => void;
  const held = new Promise<void>((done) => { release = done; });
  await page.route('**/system/info', async (route) => { await held; await route.fulfill({ json: { product: 'ANDEIVA Security Gateway', version: '0.1.0~alpha999', channel: 'experimental', update_status: 'unavailable' } }); });
  await page.getByLabel('Username', { exact: true }).fill('lab-admin');
  await page.getByLabel('Provisioned access credential', { exact: true }).fill('test-only-fixture');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('.console-system-info').getByText('Reading product information…', { exact: true })).toBeVisible();
  await signOut(page);
  release();
  await expectAccessOnly(page);
  await expect(page.getByText('0.1.0~alpha999', { exact: true })).toHaveCount(0);
});

test('system loading and expiry expose no stale identity', async ({ page }) => {
  await fixture(page, 'viewer', true);
  let release!: () => void;
  const held = new Promise<void>((done) => { release = done; });
  await page.route('**/system/info', async (route) => { await held; await route.fulfill({ json: { product: 'ANDEIVA Security Gateway', version: '0.1.0~alpha999', channel: 'experimental', update_status: 'unavailable' } }); });
  await page.goto('/firewall#system');
  await expect(page.getByRole('button', { name: 'Refresh information', exact: true })).toBeDisabled();
  await page.clock.setFixedTime(new Date('2026-11-09T13:00:01Z'));
  await page.clock.fastForward(60 * 60 * 1000);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  release();
  await expectAccessOnly(page);
  await expect(page.getByText('0.1.0~alpha999', { exact: true })).toHaveCount(0);
});

for (const theme of ['light', 'dark'] as const) {
  test('system ' + theme + ' visual baseline, translations and authorized viewer', async ({ page }) => {
    const mock = await fixture(page, 'viewer', true);
    await page.goto('/firewall#system');
    await selectTheme(page, theme);
    await expect(page.locator('.console-system-info').getByText('0.1.0~alpha16', { exact: true })).toBeVisible();
    for (const locale of ['es', 'pt', 'en'] as const) {
      await selectLocale(page, locale);
      await expect(page.getByRole('heading', { name: consoleMessages[locale].system, exact: true, level: 1 })).toBeVisible();
      await expect(page.getByRole('heading', { name: systemMessages[locale].about, exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: systemMessages[locale].refresh, exact: true })).toBeEnabled();
      await expect(page.getByText(/Laboratory scope|Alcance de laboratorio|Escopo do laboratório|Isolated laboratory|Laboratorio aislado|Laboratório isolado/)).toHaveCount(0);
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    }
    const refresh = page.getByRole('button', { name: 'Refresh information', exact: true });
    const response = page.waitForResponse((value) => value.url().endsWith('/system/info') && value.request().method() === 'GET');
    await refresh.focus();
    await page.keyboard.press('Enter');
    await response;
    await expect(refresh).toBeEnabled();
    await expect(page.locator('.console-system-info').getByText('0.1.0~alpha16', { exact: true })).toBeVisible();
    await refresh.focus();
    await page.evaluate(() => window.scrollTo(0, 0));
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    await expect(page).toHaveScreenshot('system-' + theme + '.png', { fullPage: true });
    if (page.viewportSize()!.width > 768) {
      await expect(page.locator('.console-version')).toBeVisible();
      await page.getByRole('button', { name: 'Collapse navigation', exact: true }).click();
      await expect(page.locator('.console-version')).toBeHidden();
    }
    expect(mock.transactions).toEqual([]);
  });
}


test('System navigation preserves the floating draft and an unauthorized metadata response closes it', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/firewall');
  await expect(page.locator('.console-version strong')).toHaveText('0.1.0~alpha16');
  await fillRule(page, 'system-roundtrip-local');
  const editor = page.locator('.fw-rule-editor');
  await expect(editor).toBeVisible();
  await page.evaluate(() => { location.hash = 'system'; });
  await expect(editor).toBeHidden();
  await expect(page.locator('.fw-editor-notice')).toContainText(firewallMessages.en.editorOpen);
  await expect(page.getByRole('button', { name: 'Refresh status', exact: true })).toHaveCount(0);
  await expect(page.locator('.console-transaction-bar')).toHaveCount(0);
  await expect(page.locator('.console-system-info')).toBeVisible();
  await page.getByRole('link', { name: firewallMessages.en.returnToRules, exact: true }).click();
  await expect(editor).toBeVisible();
  await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue('system-roundtrip-local');
  await expect(page.getByLabel('Rule ID', { exact: true })).toBeFocused();
  await expect(page.getByLabel('Destination ports', { exact: true })).toHaveValue('443-445');
  await page.evaluate(() => { location.hash = 'system'; });
  await expect(page.locator('.console-system-info')).toBeVisible();
  await page.route('**/system/info', (route) => route.fulfill({ status: 401, json: { code: 'ANDEIVA_AUTH_REQUIRED' } }));
  await page.getByRole('button', { name: 'Refresh information', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.locator('.ds-floating-window')).toHaveCount(0);
  await expectAccessOnly(page);
  expect(mock.state().snapshot.running.config.rules).toEqual([]);
  expect(mock.transactions).toEqual([]);
});


test('header anonymous preferences remain separate from account and configuration', async ({ page }) => {
  const mock = await fixture(page);
  const writes: string[] = [];
  page.on('request', (request) => { if (request.method() !== 'GET') writes.push(request.url()); });
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/firewall');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.getByTestId('account-trigger')).toHaveCount(0);
  await expect(page.getByTestId('account-panel')).toHaveCount(0);
  const trigger = page.getByTestId('preferences-trigger');
  await expect(page.locator('#language')).toBeHidden();
  await trigger.focus(); await trigger.press('Enter');
  const preferences = page.getByTestId('preferences-panel');
  await expect(preferences).toBeVisible();
  await expect(page.locator('#language')).toBeFocused();
  await expect(page.getByRole('menu')).toHaveCount(0);
  await page.locator('#language').selectOption('es');
  await expect(preferences).toHaveAccessibleName('Preferencias');
  await page.locator('#theme').selectOption('dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await preferences.press('Escape');
  await expect(preferences).toBeHidden(); await expect(trigger).toBeFocused();
  await expectAccessOnly(page);
  await page.emulateMedia({ colorScheme: 'light' }); await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.getByTestId('account-trigger')).toHaveCount(0);
  expect(writes).toEqual([]); expect(mock.transactions).toEqual([]);
});

test('header account is in the top bar, dismisses accessibly and logout clears protected content', async ({ page }) => {
  const mock = await fixture(page, 'viewer', true);
  await page.goto('/firewall#system');
  const trigger = page.getByTestId('account-trigger'); const panel = page.getByTestId('account-panel');
  await expect(page.locator('header').getByTestId('account-trigger')).toBeVisible();
  await expect(page.locator('main').getByTestId('account-trigger')).toHaveCount(0);
  await expect(page.locator('.fw-state')).toHaveCount(0);
  await page.locator('.skip-link').focus();
  expect(await page.locator('.skip-link').evaluate((element) => { const box = element.getBoundingClientRect(); return element.contains(document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2)); })).toBe(true);
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeHidden();
  await trigger.focus(); await trigger.press('Enter'); await expect(panel).toBeVisible();
  await expect(panel).toHaveAccessibleName('Account: lab-admin');
  await expect(panel.getByText('Read only', { exact: true })).toBeVisible();
  await expect(panel.locator('time')).toHaveAttribute('datetime', '2026-11-09T13:00:00Z');
  await expect(panel).toBeFocused(); await page.keyboard.press('Tab');
  await expect(panel.getByRole('button', { name: 'Sign out', exact: true })).toBeFocused();
  await panel.press('Escape'); await expect(panel).toBeHidden(); await expect(trigger).toBeFocused();
  await trigger.click(); await expect(panel).toBeVisible();
  await page.mouse.click(4, page.viewportSize()!.height - 4);
  await expect(panel).toBeHidden();
  await trigger.click(); await page.getByTestId('preferences-trigger').click();
  await expect(panel).toBeHidden(); await expect(page.getByTestId('preferences-panel')).toBeVisible();
  await page.getByTestId('preferences-panel').press('Escape');
  await signOut(page);
  await expectAccessOnly(page); await expect(panel).toHaveCount(0);
  await expect(page.getByText('lab-admin', { exact: true })).toHaveCount(0);
  expect(mock.transactions).toEqual([]);
});

test('header account and preferences clear on expiry and leave local rule drafts untouched', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 1440, height: 1000 }); await page.goto('/firewall');
  await fillRule(page, 'header-local-draft');
  await selectLocale(page, 'es');
  await expect(page.getByLabel(firewallMessages.es.id, { exact: true })).toHaveValue('header-local-draft');
  await expect(page.getByLabel(firewallMessages.es.destination_ports, { exact: true })).toHaveValue('443-445');
  await selectLocale(page, 'en');
  await page.getByTestId('account-trigger').click();
  await expect(page.getByTestId('account-panel')).toBeVisible();
  expect(await page.getByTestId('account-panel').evaluate((element) => element.matches(':popover-open'))).toBe(true);
  await page.clock.fastForward(3_601_000);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expectAccessOnly(page);
  await expect(page.locator('.ds-floating-window')).toHaveCount(0);
  await expect(page.getByTestId('account-panel')).toHaveCount(0);
  expect(mock.transactions).toEqual([]); expect(mock.state().snapshot.running.config.rules).toEqual([]);
});

for (const theme of ['light', 'dark'] as const) test('header ' + theme + ' preferences and account visual baseline', async ({ page }) => {
  const mock = await fixture(page, 'admin', true);
  await page.goto('/firewall#system');
  await expect(page.locator('.console-system-info').getByText('0.1.0~alpha16', { exact: true })).toBeVisible();
  await selectTheme(page, theme);
  for (const locale of ['es', 'pt', 'en'] as const) {
    await selectLocale(page, locale);
    const names = { en: ['Preferences', 'Account', 'Role', 'Sign out'], es: ['Preferencias', 'Cuenta', 'Rol', 'Cerrar sesión'], pt: ['Preferências', 'Conta', 'Função', 'Sair'] }[locale];
    await expect(page.getByTestId('preferences-trigger')).toHaveAccessibleName(names[0]!);
    await expect(page.getByTestId('account-trigger')).toHaveAccessibleName(names[1]! + ': lab-admin');
    await page.getByTestId('account-trigger').click();
    const panel = page.getByTestId('account-panel');
    await expect(panel.getByText(names[2]!, { exact: true })).toBeVisible();
    await expect(panel.getByRole('button', { name: names[3]!, exact: true })).toBeEnabled();
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    await panel.press('Escape');
  }
  await page.getByTestId('preferences-trigger').click();
  const preferences = page.getByTestId('preferences-panel');
  await expect(preferences).toBeVisible();
  const bounds = await preferences.boundingBox(); const viewport = page.viewportSize()!;
  expect(bounds!.x).toBeGreaterThanOrEqual(0); expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width);
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  await expect(page).toHaveScreenshot('header-' + theme + '-preferences.png');
  await preferences.press('Escape'); await page.getByTestId('account-trigger').click();
  await expect(page.getByTestId('account-panel')).toBeVisible();
  await expect(page).toHaveScreenshot('header-' + theme + '-account.png');
  expect(mock.transactions).toEqual([]);
});


test('header popovers fit a zoomed visual viewport and a short mobile resize', async ({ page }) => {
  await fixture(page, 'admin', true);
  await page.setViewportSize({ width: 390, height: 844 }); await page.goto('/firewall#system');
  await page.getByTestId('preferences-trigger').click();
  const panel = page.getByTestId('preferences-panel'); await expect(panel).toBeVisible();
  const client = await page.context().newCDPSession(page);
  await client.send('Emulation.setPageScaleFactor', { pageScaleFactor: 2 });
  await expect.poll(() => page.evaluate(() => visualViewport!.width)).toBeLessThan(250);
  const fit = async () => page.evaluate(() => {
    const viewport = visualViewport!; const panel = document.querySelector<HTMLElement>('.ds-header-popover:popover-open')!; const bounds = panel.getBoundingClientRect();
    return bounds.left >= viewport.offsetLeft && bounds.right <= viewport.offsetLeft + viewport.width + 1 && bounds.top >= viewport.offsetTop && bounds.bottom <= viewport.offsetTop + viewport.height + 1;
  });
  await expect.poll(fit).toBe(true);
  await client.send('Emulation.setPageScaleFactor', { pageScaleFactor: 1 });
  await page.setViewportSize({ width: 320, height: 260 });
  await expect.poll(fit).toBe(true);
  await panel.press('Escape'); await page.getByTestId('account-trigger').click();
  const account = page.getByTestId('account-panel'); await expect(account).toBeVisible();
  await expect.poll(fit).toBe(true);
  const logout = account.getByRole('button', { name: 'Sign out', exact: true });
  await logout.scrollIntoViewIfNeeded(); await expect(logout).toBeInViewport();
  await account.press('Escape'); await expect(page.getByTestId('account-trigger')).toBeFocused();
  await client.detach();
});
