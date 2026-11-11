import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { trafficMessages } from '../src/firewall/trafficMessages.js';

// These explicit transport fixtures exercise UI behavior, not real traffic enforcement.
const hash = 'a'.repeat(64);
const baseline = { sequence: 3, observed_at: '2026-11-10T12:00:00Z', revision: hash, rule_id: 'baseline-rule', action: 'allow', kind: 'baseline', packets_total: '18446744073709551615', bytes_total: '0' };
const delta = { ...baseline, sequence: 2, rule_id: 'delta-rule', action: 'deny', kind: 'delta', since: '2026-11-10T11:59:00Z', packets_total: '9007199254740993', bytes_total: '256', packets_delta: '2', bytes_delta: '128' };
async function setup(page: Page, role = 'admin') {
  let stream = 'a'.repeat(32); let denied = false; let unavailable = false; let truncated = false;
  const calls: URL[] = [];
  const revision = { hash, config: { schema_version: 2, default_action: 'deny', rules: [] } };
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    expect(route.request().headers()['x-andeiva-client']).toBe('web');
    if (url.pathname.endsWith('/auth/session')) return route.fulfill({ json: { username: 'test-admin', role, csrf: 'fixture', expires_at: new Date(Date.now() + 3_600_000).toISOString() } });
    if (url.pathname.endsWith('/auth/logout')) return route.fulfill({ json: { logged_out: true } });
    if (url.pathname.endsWith('/traffic')) {
      calls.push(url);
      if (denied) return route.fulfill({ status: 403, json: { code: 'ANDEIVA_CONFIG_DENIED' } });
      if (url.searchParams.has('before') && url.searchParams.get('stream') !== stream) return route.fulfill({ status: 409, json: { code: 'ANDEIVA_TRAFFIC_STREAM_CHANGED' } });
      const older = url.searchParams.has('before');
      return route.fulfill({ json: { stream, records: truncated && older ? [] : older ? [{ ...baseline, sequence: 1, rule_id: 'older-rule' }] : [baseline, delta], next_before: older ? 0 : 2, evicted: 4, capacity: 512, sampling: 'on_request', retention: 'api_process', truncated: older && truncated } });
    }
    if (unavailable) return route.abort('failed');
    return route.fulfill({ json: { snapshot: { generation: 1, running: revision, startup: revision, recovery_required: false }, effective: { revision: hash, state: 'verified', rules: [] } } });
  });
  await page.goto('/firewall#traffic');
  // A replacement transport fixture must start a new document, not retain a prior role through hash navigation.
  await page.reload();
  return { calls, restart: () => { stream = 'b'.repeat(32); }, deny: () => { denied = true; }, disconnect: () => { unavailable = true; }, evict: () => { truncated = true; } };
}

for (const theme of ['light', 'dark'] as const) {
  test(`traffic ${theme}: precise baseline/delta counters and localized accessible semantics`, async ({ page }) => {
    const mock = await setup(page);
    await page.locator('#theme').selectOption(theme);
    await expect(page.getByTestId('traffic-panel')).toBeVisible();
    expect(mock.calls).toHaveLength(0);
    for (const locale of ['en', 'es', 'pt'] as const) {
      await page.locator('#language').selectOption(locale);
      const copy = trafficMessages[locale];
      await page.getByRole('button', { name: copy.sample, exact: true }).click();
      const table = page.getByRole('table', { name: copy.title, exact: true });
      await expect(table).toContainText('18446744073709551615');
      await expect(table).toContainText('9007199254740993');
      await expect(table.getByRole('row').filter({ hasText: 'baseline-rule' })).toContainText(copy.noDelta);
      await expect(table.getByRole('row').filter({ hasText: 'delta-rule' })).toContainText(copy.deny);
      await expect(page.getByText(copy.retention, { exact: true })).toBeVisible();
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    }
    expect(mock.calls).toHaveLength(3);
  });
}
test('traffic older pages bind the stream; restart clears stale records and truncation is explicit', async ({ page }) => {
  const mock = await setup(page);
  await page.getByRole('button', { name: trafficMessages.en.sample }).click();
  await expect(page.getByRole('table', { name: trafficMessages.en.title })).toBeVisible();
  await page.getByRole('button', { name: trafficMessages.en.older }).click();
  await expect(page.getByRole('table', { name: trafficMessages.en.title })).toContainText('older-rule');
  expect(mock.calls[1]?.searchParams.get('before')).toBe('2');
  expect(mock.calls[1]?.searchParams.get('stream')).toBe('a'.repeat(32));
  await page.getByRole('button', { name: trafficMessages.en.sample }).click();
  await expect(page.getByRole('button', { name: trafficMessages.en.older })).toBeEnabled();
  mock.restart();
  await page.getByRole('button', { name: trafficMessages.en.older }).click();
  await expect(page.getByText(trafficMessages.en.changed, { exact: true })).toBeVisible();
  await expect(page.getByRole('table', { name: trafficMessages.en.title })).toHaveCount(0);
  await page.getByRole('button', { name: trafficMessages.en.sample }).click();
  await expect(page.getByText('b'.repeat(32), { exact: true })).toBeVisible();
  mock.evict();
  await page.getByRole('button', { name: trafficMessages.en.older }).click();
  await expect(page.getByText(trafficMessages.en.truncated, { exact: true })).toBeVisible();
  await expect(page.getByText(trafficMessages.en.empty, { exact: true })).toBeVisible();
});
test('traffic hides viewer controls, clears on denied reads, stale status and logout', async ({ page }) => {
  let mock = await setup(page, 'viewer');
  await expect(page.getByRole('button', { name: 'Refresh status', exact: true })).toBeVisible();
  await expect(page.getByTestId('traffic-panel')).toHaveCount(0);
  expect(mock.calls).toHaveLength(0);
  await page.unrouteAll(); mock = await setup(page);
  mock.deny();
  await page.getByRole('button', { name: trafficMessages.en.sample }).click();
  await expect(page.getByText('Your role does not permit this action.', { exact: true })).toBeVisible();
  await expect(page.getByTestId('traffic-panel')).toHaveCount(0);
  await page.unrouteAll(); mock = await setup(page);
  await page.getByRole('button', { name: trafficMessages.en.sample }).click();
  await expect(page.getByRole('table', { name: trafficMessages.en.title })).toBeVisible();
  mock.disconnect();
  await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
  await expect(page.getByTestId('traffic-panel')).toHaveCount(0);
  await page.unrouteAll(); await setup(page);
  await page.getByRole('button', { name: trafficMessages.en.sample }).click();
  await expect(page.getByRole('table', { name: trafficMessages.en.title })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByTestId('traffic-panel')).toHaveCount(0);
});
