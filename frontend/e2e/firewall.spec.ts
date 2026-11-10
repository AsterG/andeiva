import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import type { Config, FirewallState, History, Session, Transaction } from '../src/firewall/model.js';
import { consoleMessages } from '../src/firewall/consoleMessages.js';

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
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
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
    await page.locator('#theme').selectOption(theme);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
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
    await expect(page).toHaveScreenshot(`firewall-${theme}-editor.png`, { fullPage: true });
    for (const [locale, title] of [['es', 'Reglas'], ['pt', 'Regras'], ['en', 'Rules']]) {
      await page.locator('#language').selectOption(locale!);
      await expect(page.getByRole('heading', { name: title!, exact: true, level: 1 })).toBeVisible();
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
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
    await page.locator('#theme').selectOption(theme);
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
        await page.locator('#language').selectOption(locale);
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
  await page.locator('.skip-link').focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Dashboard', level: 1, exact: true })).toBeVisible();
  await page.evaluate(() => { window.location.hash = 'rules'; });
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
