import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import type { Config, FirewallState, History, Session, Transaction } from '../src/firewall/model.js';

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
      status = { snapshot, effective: { revision: snapshot.running.hash, state: snapshot.pending ? 'pending_confirmation' : 'verified', rules: snapshot.running.config.rules.map((rule) => ({ id: rule.id, packets: 7, bytes: 256 })) } };
      return route.fulfill({ json: status });
    }
    return route.fulfill({ json: status });
  });
  return { transactions, disconnect: () => { disconnected = true; }, conflict: () => { conflict = true; }, state: () => status };
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
  await page.getByRole('button', { name: 'Move up: allow-dns', exact: true }).click();
  await expect(page.getByRole('table').locator('tbody th')).toHaveText(['allow-dns', 'allow-web']);
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
  await expect(page.locator('.ds-badge').filter({ hasText: 'Awaiting confirmation' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add rule', exact: true })).toBeDisabled();
  await proceed(page, 'Confirm running revision');
  await proceed(page, 'Save running to startup');
  expect(mock.state().snapshot.running.hash).toBe(mock.state().snapshot.startup.hash);
  await page.getByRole('button', { name: 'Load history', exact: true }).click();
  await page.getByLabel('Actor or revision', { exact: true }).fill('LAB-VIEWER');
  const audit = page.getByRole('table', { name: 'Transaction audit', exact: true });
  await expect(audit.locator('tbody tr')).toHaveCount(1);
  await expect(audit).toContainText('lab-viewer');
  await page.getByRole('button', { name: `Restore revision: ${initialHash}`, exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Proceed', exact: true }).click();
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
  await page.getByRole('button', { name: 'Remove: allow-web', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Proceed', exact: true }).click();
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
    await fixture(page);
    await page.goto('/firewall');
    await page.locator('#theme').selectOption(theme);
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await expect(page).toHaveScreenshot(`firewall-${theme}-login.png`, { fullPage: true });
    await login(page);
    await fillRule(page);
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect(page).toHaveScreenshot(`firewall-${theme}-editor.png`, { fullPage: true });
    for (const [locale, title] of [['es', 'Administración del firewall'], ['pt', 'Administração do firewall'], ['en', 'Firewall administration']]) {
      await page.locator('#language').selectOption(locale!);
      await expect(page.getByRole('heading', { name: title!, exact: true })).toBeVisible();
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    }
  });
}
