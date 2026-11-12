import { readFile } from 'node:fs/promises';
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { selectLocale, selectTheme, signOut } from './headerHelpers.js';
import { workspaceMessages } from '../src/routing/workspaceMessages.js';
import { firewallMessages } from '../src/firewall/messages.js';
import { consoleMessages } from '../src/firewall/consoleMessages.js';
import type { Locale } from '../src/messages.js';

// These render fixtures test browser behavior, not authentication or packet enforcement.
const fixtures = JSON.parse(await readFile(new URL('../tests/fixtures/routed-current-v2.json', import.meta.url), 'utf8'));
async function setup(page: Page, role = 'admin') {
  const current = structuredClone(fixtures.routed);
  const calls: { path: string; method: string; body: unknown }[] = [];
  let loggedIn = true;
  await page.clock.install({ time: new Date('2026-11-12T12:00:00Z') });
  await page.route('**/api/**', async (route) => {
    const req = route.request(), path = new URL(req.url()).pathname;
    const body = req.postData() ? req.postDataJSON() : null;
    calls.push({ path, method: req.method(), body });
    if (!loggedIn) return route.fulfill({ status: 401, json: { code: 'ANDEIVA_AUTH_REQUIRED' } });
    if (req.method() === 'POST') expect(req.headers()['x-csrf-token']).toBe('routing-fixture-csrf');
    if (path === '/api/v1/auth/session') return route.fulfill({ json: { username: 'fixture-admin', role, csrf: 'routing-fixture-csrf', expires_at: '2026-11-12T13:00:00Z' } });
    if (path === '/api/v1/auth/logout') { loggedIn = false; return route.fulfill({ json: { ok: true } }); }
    if (path === '/api/v1/capabilities') return route.fulfill({ json: { configuration_operations_v2: true, network_inventory_v2: true } });
    if (path === '/api/v1/system/info') return route.fulfill({ json: { product: 'ANDEIVA Security Gateway', version: '0.1.0~alpha999', channel: 'experimental', update_status: 'unavailable' } });
    if (path === '/api/v2/config/current') return route.fulfill({ json: current });
    if (path === '/api/v2/config/effective') return route.fulfill({ json: { schema_version: 1, generation: current.current.global.generation, running_revision: current.current.global.running_revision, observed_revision: current.current.global.running_revision, phase: 'idle', consistent: true } });
    if (path === '/api/v2/network/interfaces') return route.fulfill({ json: { schema_version: 1, interfaces: current.current.snapshot.running.config.routed.network.config.interfaces.map((iface: { binding: { name: string; hardware_address: string }; ipv4: { address: string } }) => ({ name: iface.binding.name, hardware_address: iface.binding.hardware_address, mtu: 1500, admin_up: true, running: true, kind: 'virtual', addresses: [{ ip: iface.ipv4.address.split('/')[0], prefix: iface.ipv4.address }] })) } });
    if (path === '/api/v2/config/operation-namespaces') return route.fulfill({ status: 201, json: { schema_version: 2, namespace_id: 'v2.ns.1.browser', state: 'open', admit_until: '2026-11-12T13:00:00Z' } });
    if (path === '/api/v2/config/operations/admit') {
      expect(body.expected_generation).toBe('18446744073709551615');
      return route.fulfill({ status: 201, json: { ...current, operation: { id: 'v2.op.1.browser', namespace_id: body.namespace_id, domain: 'routed', kind: body.request.operation, state: 'accepted', expected_generation: body.expected_generation } } });
    }
    if (path === '/api/v2/config/operations/v2.op.1.browser/execute') return route.fulfill({ status: 503, json: { code: 'ANDEIVA_CONFIG_RECOVERY_REQUIRED' } });
    if (path === '/api/v2/config/operations/v2.op.1.browser') return route.fulfill({ json: { ...current, operation: { id: 'v2.op.1.browser', namespace_id: 'v2.ns.1.browser', domain: 'routed', kind: 'stage', state: 'uncertain', expected_generation: '18446744073709551615' } } });
    return route.fulfill({ status: 404, json: { code: 'ANDEIVA_NOT_FOUND' } });
  });
  return calls;
}

test('routed mode never loads legacy firewall state; logout removes all administrative navigation', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/firewall#network');
  await expect(page.getByRole('button', { name: workspaceMessages.en.editNetwork, exact: true })).toBeVisible();
  if (!await page.locator('#console-navigation').isVisible()) await page.locator('[aria-controls="console-navigation"]').click();
  await expect(page.getByRole('link', { name: consoleMessages.en.nat, exact: true })).toBeVisible();
  expect(calls.some((call) => call.path.startsWith('/api/v1/firewall'))).toBe(false);
  await signOut(page);
  await expect(page.locator('#console-navigation')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
});

test('routed editor stages an explicit path and retains an uncertain durable operation without retry', async ({ page }) => {
  const calls = await setup(page);
  await page.goto('/firewall#rules');
  await page.getByRole('button', { name: workspaceMessages.en.add, exact: true }).click();
  const editor = page.getByRole('dialog', { name: firewallMessages.en.editor, exact: true });
  await editor.getByLabel(workspaceMessages.en.from, { exact: true }).selectOption('lan');
  await editor.getByLabel(workspaceMessages.en.to, { exact: true }).selectOption('wan');
  await editor.getByLabel(firewallMessages.en.id, { exact: true }).fill('browser-only-fixture');
  await editor.getByLabel(firewallMessages.en.source, { exact: true }).fill('198.18.0.2/32');
  await editor.getByLabel(firewallMessages.en.destination, { exact: true }).fill('198.19.0.2/32');
  await editor.getByLabel(firewallMessages.en.destination_ports, { exact: true }).fill('443');
  await editor.getByRole('button', { name: firewallMessages.en.applyRule, exact: true }).click();
  await expect(page.getByRole('row').filter({ hasText: 'browser-only-fixture' })).toBeVisible();
  await page.getByRole('button', { name: workspaceMessages.en.stage, exact: true }).click();
  await page.getByRole('dialog', { name: workspaceMessages.en.review }).getByRole('button', { name: workspaceMessages.en.proceed }).click();
  await expect(page.getByText(workspaceMessages.en.uncertain, { exact: true })).toBeVisible();
  const admit = calls.find((call) => call.path.endsWith('/admit'))!.body as { request: { config: { routed: { rules: { path: { from_interface: string; to_interface: string } }[] } } } };
  expect(admit.request.config.routed.rules.at(-1)!.path).toMatchObject({ from_interface: 'lan', to_interface: 'wan' });
  await page.getByRole('button', { name: workspaceMessages.en.query, exact: true }).click();
  expect(calls.filter((call) => call.path.endsWith('/execute'))).toHaveLength(1);
  await page.reload();
  await expect(page.getByRole('button', { name: workspaceMessages.en.query, exact: true })).toBeVisible();
  expect(calls.filter((call) => call.path.endsWith('/execute'))).toHaveLength(1);
});

test('routed rule order supports keyboard movement and blocks reordering under a search', async ({ page }) => {
  await setup(page);
  await page.goto('/firewall#rules');
  const handles = page.getByRole('button', { name: /^Reorder rule:/ });
  await expect(handles).toHaveCount(2);
  const first = await handles.nth(0).getAttribute('aria-label');
  await handles.nth(0).focus();
  await page.keyboard.press('Space');
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Escape');
  await expect(handles.nth(0)).toHaveAttribute('aria-label', first!);
  await expect(page.getByRole('button', { name: workspaceMessages.en.stage, exact: true })).toBeDisabled();
  await handles.nth(0).focus();
  await page.keyboard.press('Space');
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(handles.nth(1)).toHaveAttribute('aria-label', first!);
  await page.getByLabel(workspaceMessages.en.search, { exact: true }).fill('tcp');
  for (const handle of await handles.all()) await expect(handle).toBeDisabled();
});

test('accepted request resumes only on explicit action and closes its terminal namespace', async ({ page }) => {
  const calls = await setup(page);
  await page.addInitScript(() => sessionStorage.setItem('andeiva.configuration.operation.fixture-admin', 'v2.op.1.browser'));
  let executions = 0, closures = 0;
  const operation = { id: 'v2.op.1.browser', namespace_id: 'v2.ns.1.browser', domain: 'routed', kind: 'save', state: 'accepted', expected_generation: '18446744073709551615' };
  await page.route('**/api/v2/config/operations/v2.op.1.browser', (route) => route.fulfill({ json: { ...fixtures.routed, operation } }));
  await page.route('**/api/v2/config/operations/v2.op.1.browser/execute', (route) => {
    executions++;
    return route.fulfill({ json: { ...fixtures.routed, operation: { ...operation, state: 'final', outcome: { code: 'applied' } } } });
  });
  await page.route('**/api/v2/config/operation-namespaces/v2.ns.1.browser/close', (route) => {
    closures++;
    return route.fulfill({ json: { schema_version: 2, namespace_id: 'v2.ns.1.browser', state: 'closed' } });
  });
  await page.goto('/firewall#rules');
  await expect(page.getByRole('button', { name: workspaceMessages.en.resume, exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: workspaceMessages.en.query, exact: true }).click();
  await expect(page.getByRole('button', { name: workspaceMessages.en.resume, exact: true })).toBeVisible();
  expect(executions).toBe(0);
  await page.getByRole('button', { name: workspaceMessages.en.resume, exact: true }).click();
  await expect(page.getByText(workspaceMessages.en.uncertain, { exact: true })).toHaveCount(0);
  await expect.poll(() => closures).toBe(1);
  expect(executions).toBe(1);
  expect(calls.some((call) => call.path.endsWith('/admit'))).toBe(false);
});

test('routed audit uses protected records with combined filters in both themes', async ({ page }, testInfo) => {
  const calls = await setup(page);
  const event = { sequence: '10', at: '2026-11-12T12:00:00Z', actor_id: 'subject-a', actor_name: 'alice', operation_id: 'operation-a', operation: 'save', result: 'applied', generation: '18446744073709551615', running_revision: 'a'.repeat(64), startup_revision: 'b'.repeat(64) };
  await page.route('**/api/v2/config/audit?**', (route) => route.fulfill({ json: { schema_version: 1, events: [event], next_before: '0', truncated: false } }));
  await page.goto('/firewall#audit');
  await expect(page.getByRole('cell', { name: 'alice', exact: true })).toBeVisible();
  await page.getByLabel('Actor', { exact: true }).fill('alice');
  await page.getByRole('combobox', { name: 'Operation', exact: true }).selectOption('save');
  await page.getByRole('button', { name: 'Inspect event', exact: true }).click();
  await expect(page.getByText('operation-a', { exact: true })).toBeVisible();
  for (const theme of ['light', 'dark'] as const) {
    await selectTheme(page, theme);
    expect((await new AxeBuilder({ page }).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()).violations).toEqual([]);
    await page.screenshot({ path: testInfo.outputPath(`audit-${theme}.png`), fullPage: true });
  }
  expect(calls.some((call) => call.path.startsWith('/api/v1/firewall'))).toBe(false);
  expect(calls.some((call) => call.path.endsWith('/admit'))).toBe(false);
});

test('preserved historical Candidate remains visible but cannot validate or apply', async ({ page }) => {
  const calls = await setup(page), restored = structuredClone(fixtures.pre), old = fixtures.routed.current;
  restored.current.snapshot.candidate = { owner: 'subject', base: old.snapshot.running.hash, revision: structuredClone(old.snapshot.running) };
  restored.current.routed.local_services.candidate = { owner: 'subject', base: old.routed.local_services.running.hash, revision: structuredClone(old.routed.local_services.running) };
  restored.current.routed.candidate = structuredClone(old.routed.running);
  restored.current.routed.candidate_group = { stage_operation_id: 'stage-original', owner: 'subject', base: old.routed.running.hash, domains: ['firewall', 'local_services'] };
  await page.route('**/api/v2/config/current', (route) => route.fulfill({ json: restored }));
  await page.goto('/firewall#rules');
  await expect(page.getByText(workspaceMessages.en.candidateStale, { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: workspaceMessages.en.validate, exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: workspaceMessages.en.commit, exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'tcp-test', exact: true })).toBeVisible();
  expect(calls.some((call) => call.path.endsWith('/admit') || call.path.endsWith('/execute'))).toBe(false);
});

test('viewer cannot open network, rule or NAT editors', async ({ page }) => {
  await setup(page, 'viewer');
  for (const view of ['network', 'rules', 'nat']) {
    await page.goto(`/firewall#${view}`);
    await expect(page.locator('.ds-badge').filter({ hasText: workspaceMessages.en.readonly })).toBeVisible();
    for (const name of [workspaceMessages.en.editNetwork, workspaceMessages.en.add, workspaceMessages.en.addNAT]) await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
  }
});

for (const locale of ['en', 'es', 'pt'] as Locale[]) for (const theme of ['light', 'dark']) {
  test(`routed rendered ${locale} ${theme} has accessible network and rules`, async ({ page }, testInfo) => {
    await setup(page);
    await page.goto('/firewall#network');
    await selectLocale(page, locale); await selectTheme(page, theme);
    await expect(page.getByRole('button', { name: workspaceMessages[locale].editNetwork, exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`network-${locale}-${theme}.png`), fullPage: true });
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
    expect(results.violations).toEqual([]);
    if (!await page.locator('#console-navigation').isVisible()) await page.locator('[aria-controls="console-navigation"]').click();
    await page.getByRole('link', { name: consoleMessages[locale].rules, exact: true }).click();
    await expect(page.getByRole('button', { name: workspaceMessages[locale].add, exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`rules-${locale}-${theme}.png`), fullPage: true });
  });
}
