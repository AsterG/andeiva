import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import type { Capabilities, Config, Request, Status } from '../src/local-services/model.js';

// Transport fixtures exercise the UI contract, not kernel filtering or real login.
const instant = new Date('2026-11-10T15:00:00Z');
const inventory: Capabilities['local_interfaces'] = [{ name: 'src0', zone: 'lan', addresses: ['198.18.1.1', 'fd42:616e:6465:1::1'] }, { name: 'dst0', zone: 'wan', addresses: ['198.18.2.1'] }];
const hash = '1'.repeat(64);
const initial: Config = { schema_version: 3, default_action: 'deny', rules: [], local_services: { schema_version: 1, interfaces: inventory, services: [] } };
async function fixture(page: Page, options: { viewer?: boolean; unavailable?: boolean; managed?: boolean } = {}) {
  await page.clock.install({ time: instant }); await page.clock.setFixedTime(instant);
  const session = { username: 'lab-admin', role: options.viewer ? 'viewer' : 'admin', csrf: 'fixture-not-a-real-secret', expires_at: '2026-11-10T16:00:00Z' };
  const caps: Capabilities = { firewall: false, local_services: !options.unavailable, endpoint_id: options.managed ? `binding-${'c'.repeat(64)}` : 'recovery', recovery_endpoint: !options.managed, local_interfaces: inventory };
  const revision = { hash, config: structuredClone(initial) };
  const state: Status = { snapshot: { generation: 1, running: revision, startup: structuredClone(revision), recovery_required: false }, effective: { hash, phase: 'idle', recovery_required: false, rules: [], listeners: [] } };
  let authenticated = false; const operations: Request[] = []; const queries: string[] = []; let proofRequests = 0;
  if (options.managed) { state.snapshot.pending = { owner: session.username, lease: 'lease-fixture', deadline: '2026-11-10T15:02:00Z', previous: structuredClone(revision) }; state.effective.phase = 'pending'; }
  await page.route('**/api/v1/**', async (route) => {
    const req = route.request(); const url = new URL(req.url()); const path = url.pathname;
    expect(req.headers()['x-andeiva-client']).toBe('web');
    if (path.endsWith('/auth/login')) { authenticated = true; return route.fulfill({ json: session }); }
    if (!authenticated) return route.fulfill({ status: 401, json: { code: 'ANDEIVA_AUTH_DENIED' } });
    if (path.endsWith('/auth/session')) return route.fulfill({ json: session });
    if (path.endsWith('/auth/logout')) { authenticated = false; return route.fulfill({ json: {} }); }
    if (path.endsWith('/capabilities')) return route.fulfill({ json: caps });
    if (path.endsWith('/proof')) { proofRequests++; expect(req.headers()['x-csrf-token']).toBe(session.csrf); expect(req.postDataJSON().generation).toBe(state.snapshot.generation); return route.fulfill({ json: { token: 'b'.repeat(64), expires_at: new Date(instant.getTime() + 20_000).toISOString() } }); }
    if (path.endsWith('/history')) return route.fulfill({ json: { revisions: [{ sequence: 1, revision }], audit: [], next_before: 0 } });
    if (path.endsWith('/effective-policies')) { queries.push(url.search); return route.fulfill({ json: state.effective }); }
    if (path.endsWith('/transactions')) {
      const body = req.postDataJSON() as Request; operations.push(body); const tx = body.transaction; const s = state.snapshot;
      expect(req.headers()['x-csrf-token']).toBe(session.csrf); expect(tx.expected_generation).toBe(s.generation);
      if (tx.operation === 'stage') s.candidate = { owner: session.username, base: s.running.hash, revision: { hash: String(s.generation + 1).repeat(64), config: tx.config! } };
      if (['commit', 'rollback', 'confirm', 'save'].includes(tx.operation)) expect(body.recovery_proof).toBe('b'.repeat(64));
      if (tx.operation === 'commit') { expect(tx.confirm_for).toBe(60_000_000_000); const previous = structuredClone(s.running); s.running = s.candidate!.revision; delete s.candidate; s.pending = { owner: session.username, lease: tx.key, deadline: '2026-11-10T15:01:00Z', previous }; }
      if (tx.operation === 'confirm') { expect(tx.target).toBe(s.running.hash); delete s.pending; }
      if (tx.operation === 'save') s.startup = structuredClone(s.running);
      s.generation++; state.effective.hash = s.running.hash; state.effective.phase = s.pending ? 'pending' : 'idle';
      return route.fulfill({ json: state });
    }
    return route.fulfill({ json: state });
  });
  return { operations, state, queries, proofRequests: () => proofRequests };
}
async function login(page: Page) {
  await page.goto('/local-services');
  await page.getByLabel('Username', { exact: true }).fill('lab-admin');
  await page.getByLabel('Provisioned access credential', { exact: true }).fill('fixture-only');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
}
async function editHTTPS(page: Page) {
  await page.getByRole('button', { name: 'Edit service: HTTPS', exact: true }).click();
  await page.getByLabel('Enabled', { exact: true }).check();
  await page.getByRole('button', { name: 'Add binding', exact: true }).click();
  await page.getByLabel('Authorized source networks', { exact: true }).fill('198.18.1.2/32');
}
async function proceed(page: Page, label: string) { await page.getByRole('button', { name: label, exact: true }).click(); await page.getByRole('dialog').getByRole('button', { name: 'Proceed', exact: true }).click(); await expect(page.getByRole('dialog')).not.toBeVisible(); }

test('local service edit, stage, confirmation proofs and Save use shared typed requests', async ({ page }) => {
  const mock = await fixture(page); await login(page); await editHTTPS(page);
  await page.getByRole('button', { name: 'Keep service in draft', exact: true }).click();
  await page.getByRole('button', { name: 'Stage candidate', exact: true }).click();
  await page.getByRole('button', { name: 'Validate candidate', exact: true }).click();
  await proceed(page, 'Commit with confirmation');
  await expect(page.getByRole('button', { name: 'Confirm running revision', exact: true })).toBeDisabled();
  await page.getByLabel('Endpoint proofs', { exact: true }).fill('a'.repeat(64));
  await proceed(page, 'Confirm running revision'); await proceed(page, 'Save running to startup');
  expect(mock.operations.map((r) => r.transaction.operation)).toEqual(['stage', 'validate', 'commit', 'confirm', 'save']);
  expect(mock.operations[0]!.transaction.config!.local_services!.services[0]!.bindings[0]!.wan_opt_in).toBe(false);
  expect(mock.operations[3]!.endpoint_proofs).toEqual(['a'.repeat(64)]);
  expect(mock.proofRequests()).toBe(3);
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain('a'.repeat(64));
  await page.getByRole('button', { name: 'Effective Policies', exact: true }).click();
  await page.getByLabel('Service', { exact: true }).fill('https');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  expect(mock.queries).toEqual(['?service=https']);
});
test('WAN and CIDR errors require explicit operator correction', async ({ page }) => {
  await fixture(page); await login(page); await editHTTPS(page);
  await page.getByLabel('Interface', { exact: true }).selectOption('dst0');
  await page.getByLabel('Authorized source networks', { exact: true }).fill('198.18.2.2/32');
  await page.getByRole('button', { name: 'Keep service in draft', exact: true }).click();
  await expect(page.getByText('WAN management requires explicit approval for this binding.', { exact: true })).toBeVisible();
  await page.getByLabel('Explicitly allow management on this WAN binding', { exact: true }).check();
  await page.getByLabel('Authorized source networks', { exact: true }).fill('0.0.0.0/0');
  await page.getByRole('button', { name: 'Keep service in draft', exact: true }).click();
  await expect(page.getByText('Provide distinct, non-overlapping canonical CIDRs in the correct address family; /0 is prohibited.', { exact: true })).toBeVisible();
});
test('viewer and unavailable runtime do not expose write actions', async ({ page }) => {
  await fixture(page, { viewer: true }); await login(page);
  await expect(page.getByRole('button', { name: 'Stage candidate', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Edit service: HTTPS', exact: true })).toHaveCount(0);
});
test('missing capability is displayed honestly', async ({ page }) => {
  await fixture(page, { unavailable: true }); await login(page);
  await expect(page.getByText('Local Services is not available on this endpoint.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Stage candidate', exact: true })).toHaveCount(0);
});
for (const failure of ['unavailable', 'revision', 'blocked', 'pending'] as const) test(`effective policy ${failure} response invalidates the observed state`, async ({ page }) => {
  const mock = await fixture(page); await login(page);
  await expect(page.getByText('Verified at last refresh')).toBeVisible();
  await page.route('**/api/v1/effective-policies?*', (route) => route.fulfill({ json: {
    ...mock.state.effective,
    hash: failure === 'revision' ? '9'.repeat(64) : hash,
    phase: failure === 'revision' ? 'idle' : failure,
    recovery_required: failure === 'unavailable',
  } }));
  await page.getByRole('button', { name: 'Effective Policies', exact: true }).click();
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect(page.getByText('Verified at last refresh')).toHaveCount(0);
  await expect(page.getByText('No generated rules match the filters.', { exact: true })).toHaveCount(0);
  await expect(page.getByText('No managed listeners are enabled.', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('table')).toHaveCount(0);
  await page.getByRole('button', { name: 'Local Services', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Edit service: HTTPS', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
  await expect(page.getByText('Verified at last refresh')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Edit service: HTTPS', exact: true })).toBeEnabled();
});
test('managed endpoint only issues a temporary proof for a pending activation', async ({ page }) => {
  const mock = await fixture(page, { managed: true }); await login(page);
  await page.getByRole('button', { name: 'Create endpoint proof', exact: true }).click();
  await expect(page.getByLabel('Temporary endpoint proof', { exact: true })).toHaveValue('b'.repeat(64));
  expect(mock.proofRequests()).toBe(1); expect(mock.operations).toEqual([]);
  await page.clock.fastForward(21_000);
  await expect(page.getByLabel('Temporary endpoint proof', { exact: true })).toHaveCount(0);
});
test('verified timeout restoration permits a new draft and candidate', async ({ page }) => {
  const mock = await fixture(page); mock.state.effective.phase = 'expired';
  await login(page);
  await expect(page.getByText('Verified at last refresh')).toBeVisible();
  await page.getByRole('button', { name: 'Effective Policies', exact: true }).click();
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect(page.getByText('Verified at last refresh')).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(2);
  await page.getByRole('button', { name: 'Local Services', exact: true }).click();
  await editHTTPS(page);
  await page.getByRole('button', { name: 'Keep service in draft', exact: true }).click();
  await page.getByRole('button', { name: 'Stage candidate', exact: true }).click();
  await expect.poll(() => mock.operations.map((r) => r.transaction.operation)).toEqual(['stage']);
  await expect(page.getByRole('button', { name: 'Validate candidate', exact: true })).toBeEnabled();
});
test('late endpoint proof cannot restore sensitive state after session expiry', async ({ page }) => {
  await fixture(page, { managed: true }); await login(page);
  let release: (() => void) | undefined;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  let requested = false;
  await page.route('**/api/v1/local-services/proof', async (route) => {
    requested = true;
    await pending;
    await route.fulfill({ json: { token: 'e'.repeat(64), expires_at: '2026-11-10T16:01:00Z' } });
  });
  await page.getByRole('button', { name: 'Create endpoint proof', exact: true }).click();
  await expect.poll(() => requested).toBe(true);
  await page.clock.fastForward(3_600_001);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  release!();
  await expect(page.getByLabel('Temporary endpoint proof', { exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain('e'.repeat(64));
});
for (const theme of ['light', 'dark']) test(`local services ${theme}: visual baseline and accessibility`, async ({ page }, info) => {
  await fixture(page); await page.emulateMedia({ colorScheme: 'dark' }); await login(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  if (theme === 'dark') await page.getByLabel('Appearance', { exact: true }).selectOption('dark');
  await editHTTPS(page);
  await expect(page.locator('.app')).toHaveAttribute('data-theme', theme);
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  expect(result.violations).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const capture = await page.screenshot({ fullPage: true });
  await info.attach(`local-services-${theme}-${info.project.name}-fixture`, { body: capture, contentType: 'image/png' });
  await expect(page).toHaveScreenshot(`local-services-${theme}-editor.png`, { fullPage: true });
  await page.getByLabel('Language', { exact: true }).selectOption('es');
  await expect(page.getByRole('heading', { name: 'Servicios locales', exact: true })).toBeVisible();
  await page.getByLabel('Idioma', { exact: true }).selectOption('pt');
  await expect(page.getByRole('heading', { name: 'Serviços locais', exact: true })).toBeVisible();
});
