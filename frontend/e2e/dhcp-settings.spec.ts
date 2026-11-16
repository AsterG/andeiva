import { readFile } from 'node:fs/promises';
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { selectLocale, selectTheme, signOut } from './headerHelpers.js';
import { dhcpMessages } from '../src/routing/dhcpMessages.js';
import { workspaceMessages } from '../src/routing/workspaceMessages.js';
import type { Locale } from '../src/messages.js';
import type { RoutedConfig } from '../src/routing/configuration.js';

// Explicit render fixtures; these do not exercise DHCP runtime or grant leases.
const fixtures = JSON.parse(await readFile(new URL('../tests/fixtures/routed-current-v2.json', import.meta.url), 'utf8'));
async function setup(page: Page, role = 'admin') {
  const current = structuredClone(fixtures.routed);
  const staged: RoutedConfig[] = [];
  await page.clock.install({ time: new Date('2026-11-12T12:00:00Z') });
  await page.route('**/api/**', async (route) => {
    const request = route.request(), path = new URL(request.url()).pathname;
    if (path === '/api/v1/auth/session') return route.fulfill({ json: { username: 'fixture-admin', role, csrf: 'fixture-csrf', expires_at: '2026-11-12T13:00:00Z' } });
    if (path === '/api/v1/capabilities') return route.fulfill({ json: { configuration_operations_v2: true, network_inventory_v2: true } });
    if (path === '/api/v1/system/info') return route.fulfill({ json: { product: 'ANDEIVA Security Gateway', version: '0.1.0~alpha999', channel: 'experimental', update_status: 'unavailable' } });
    if (path === '/api/v2/config/current') return route.fulfill({ json: current });
    if (path === '/api/v2/config/effective') return route.fulfill({ status: 503, json: { code: 'ANDEIVA_CONFIG_RECOVERY_REQUIRED' } });
    if (path === '/api/v2/network/interfaces') return route.fulfill({ json: { schema_version: 1, interfaces: [] } });
    if (path === '/api/v2/config/operation-namespaces') { expect(request.headers()['x-csrf-token']).toBe('fixture-csrf'); return route.fulfill({ json: { schema_version: 2, namespace_id: 'dhcp-fixture', state: 'open' } }); }
    if (path === '/api/v2/config/operations/admit') {
      expect(request.headers()['x-csrf-token']).toBe('fixture-csrf');
      const body = request.postDataJSON(); expect(body.request.operation).toBe('stage');
      staged.push(body.request.config);
      return route.fulfill({ status: 422, json: { code: 'ANDEIVA_DHCP_SERVER_INVALID' } });
    }
    return route.fulfill({ status: 404, json: { code: 'ANDEIVA_NOT_FOUND' } });
  });
  return staged;
}

for (const locale of ['en', 'es', 'pt'] as Locale[]) test(`LAN DHCP draft and server rejection in ${locale}`, async ({ page }, info) => {
  const staged = await setup(page), copy = dhcpMessages[locale], workspace = workspaceMessages[locale];
  await page.goto('/firewall#network'); await selectLocale(page, locale);
  await expect(page.getByText(copy.hint, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: copy.addScope, exact: true }).click();
  const editor = page.getByRole('dialog', { name: copy.addScope, exact: true });
  await editor.getByLabel(copy.id, { exact: true }).fill('clients');
  await expect(editor.getByLabel(copy.binding, { exact: true }).locator('option')).toHaveCount(2);
  await editor.getByLabel(copy.binding, { exact: true }).selectOption('lan');
  await editor.getByLabel(`${copy.first} 1`, { exact: true }).fill('198.18.0.10');
  await editor.getByLabel(`${copy.last} 1`, { exact: true }).fill('198.18.0.30');
  await editor.getByLabel(copy.excluded, { exact: true }).fill('198.18.0.15');
  await editor.getByLabel(copy.dns, { exact: true }).fill('198.18.0.1');
  await editor.getByLabel(copy.ntp, { exact: true }).fill('198.18.0.2');
  await editor.getByLabel(copy.domain, { exact: true }).fill('lab.example');
  await editor.getByRole('button', { name: copy.addReservation, exact: true }).click();
  await editor.getByLabel(`${copy.mac} 1`, { exact: true }).fill('02:00:00:00:00:ab');
  await editor.getByLabel(`${copy.address} 1`, { exact: true }).fill('198.18.0.40');
  await editor.getByLabel(copy.renew, { exact: true }).fill('3500');
  await editor.getByRole('button', { name: copy.save, exact: true }).click();
  await expect(editor.getByText(copy.invalid, { exact: true })).toBeVisible();
  await editor.getByLabel(copy.renew, { exact: true }).fill('1800');
  await editor.getByRole('button', { name: copy.save, exact: true }).click();
  await expect(editor).toHaveCount(0);
  for (const theme of ['light', 'dark'] as const) {
    await selectTheme(page, theme);
    await page.getByRole('button', { name: copy.editScope, exact: true }).click();
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: info.outputPath(`dhcp-editor-${locale}-${theme}.png`) });
    const reopened = page.getByRole('dialog', { name: copy.editScope, exact: true });
    await reopened.getByRole('button', { name: copy.save, exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath(`dhcp-editor-details-${locale}-${theme}.png`) });
    await reopened.getByRole('button', { name: copy.cancel, exact: true }).click();
  }
  await page.getByLabel(copy.enabled, { exact: true }).check();
  await page.getByLabel(copy.enabled, { exact: true }).uncheck();
  await expect(page.getByRole('row').filter({ hasText: 'clients' })).toBeVisible();
  await page.getByLabel(copy.enabled, { exact: true }).check();
  for (const theme of ['light', 'dark'] as const) { await selectTheme(page, theme); await page.evaluate(() => window.scrollTo(0, 0)); await page.screenshot({ path: info.outputPath(`dhcp-list-${locale}-${theme}.png`), fullPage: true }); }
  await page.getByRole('button', { name: workspace.stage, exact: true }).click();
  await page.getByRole('dialog', { name: workspace.review }).getByRole('button', { name: workspace.proceed }).click();
  await expect(page.getByText('ANDEIVA_DHCP_SERVER_INVALID', { exact: true })).toBeVisible();
  expect(staged).toHaveLength(1);
  expect(staged[0]!.routed.schema_version).toBe(2);
  expect(staged[0]!.routed.dhcp_server).toMatchObject({ enabled: true, scopes: [{ id: 'clients', router: '198.18.0.1', subnet: '198.18.0.0/24', renew_seconds: 1800, rebind_seconds: 3150, excluded: ['198.18.0.15'], dns: ['198.18.0.1'], ntp: ['198.18.0.2'], reservations: [{ mac: '02:00:00:00:00:ab', address: '198.18.0.40' }] }] });
  expect(staged[0]!.routed.network).toEqual(fixtures.routed.current.snapshot.running.config.routed.network);
  expect(staged[0]!.routed.rules).toEqual(fixtures.routed.current.snapshot.running.config.routed.rules);
});

test('viewer cannot edit DHCP or stage and sees no fabricated lease telemetry', async ({ page }) => {
  await setup(page, 'viewer'); await page.goto('/firewall#network');
  await expect(page.getByText(dhcpMessages.en.hint, { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: dhcpMessages.en.addScope, exact: true })).toHaveCount(0);
  await expect(page.getByLabel(dhcpMessages.en.enabled, { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: workspaceMessages.en.stage, exact: true })).toHaveCount(0);
});

test('DHCP editing blocks refresh and resets; navigation retains only saved local edits', async ({ page }, info) => {
  const staged = await setup(page), copy = dhcpMessages.en, workspace = workspaceMessages.en;
  let response = structuredClone(fixtures.routed), reads = 0;
  const policy = response.current.snapshot.running.config.routed;
  policy.schema_version = 2;
  policy.dhcp_server = { schema_version: 1, enabled: false, scopes: [{ id: 'alpha', interface_id: 'lan', subnet: '198.18.0.0/24', router: '198.18.0.1', pools: [{ first: '198.18.0.10', last: '198.18.0.30' }], excluded: [], reservations: [], dns: [], ntp: [], domain: 'original.example', lease_seconds: 3600, renew_seconds: 1800, rebind_seconds: 3150 }] };
  await page.route('**/api/v2/config/current', (route) => { reads++; return route.fulfill({ json: response }); });
  await page.route('**/api/v1/auth/logout', (route) => route.fulfill({ json: { ok: true } }));
  await page.goto('/firewall#network');
  await page.getByRole('button', { name: copy.editScope, exact: true }).click();
  const editor = page.getByRole('dialog', { name: copy.editScope, exact: true });
  await editor.getByLabel(copy.domain, { exact: true }).fill('obsolete.example');
  for (const name of [workspace.refresh, workspace.stage, workspace.validate, workspace.commit, workspace.save, workspace.rollback, workspace.discard, workspace.editNetwork, copy.addScope]) await expect(page.getByRole('button', { name, exact: true })).toBeDisabled();
  await expect(page.getByLabel(copy.enabled, { exact: true })).toBeDisabled();
  response = structuredClone(response);
  response.current.global.generation = '12'; response.current.snapshot.generation = '12';
  response.current.domain_generations.firewall = '12'; response.current.domain_generations.network = '12';
  response.current.snapshot.running.config.routed.dhcp_server.scopes[0].domain = 'external.example';
  expect(reads).toBe(1); expect(staged).toHaveLength(0);
  await editor.getByLabel(copy.domain, { exact: true }).press('Escape');
  await expect(editor).toHaveCount(0);
  await page.getByRole('button', { name: workspace.refresh, exact: true }).click();
  await expect.poll(() => reads).toBe(2);
  await expect(page.getByRole('button', { name: copy.editScope, exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: workspace.stage, exact: true })).toBeDisabled();
  await page.getByRole('button', { name: copy.editScope, exact: true }).click();
  await expect(editor.getByLabel(copy.domain, { exact: true })).toHaveValue('external.example');
  await editor.getByLabel(copy.domain, { exact: true }).fill('retained.example');
  await editor.getByRole('button', { name: copy.save, exact: true }).click();
  await page.getByRole('button', { name: copy.editScope, exact: true }).click();
  await editor.getByLabel(copy.domain, { exact: true }).fill('unsaved.example');
  await page.evaluate(() => { window.location.hash = 'rules'; });
  await expect(editor).toHaveCount(0);
  await page.evaluate(() => { window.location.hash = 'network'; });
  await page.getByRole('button', { name: copy.editScope, exact: true }).click();
  await expect(editor.getByLabel(copy.domain, { exact: true })).toHaveValue('retained.example');
  await editor.getByLabel(copy.domain, { exact: true }).press('Escape');
  await page.getByRole('button', { name: workspace.discard, exact: true }).click();
  await page.getByRole('button', { name: copy.editScope, exact: true }).click();
  await expect(editor.getByLabel(copy.domain, { exact: true })).toHaveValue('external.example');
  // Compact windows are native modal: close before accessing account controls.
  if (info.project.name !== 'desktop') await editor.getByLabel(copy.domain, { exact: true }).press('Escape');
  await signOut(page);
  await expect(editor).toHaveCount(0);
  await expect(page.getByRole('button', { name: copy.addScope, exact: true })).toHaveCount(0);
  expect(staged).toHaveLength(0);
});
