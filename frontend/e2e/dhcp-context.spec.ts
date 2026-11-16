import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { expect, test } from '@playwright/test';

// Compile only the test host; no hidden test hooks or routes enter the product.
let javascript = '', css = '';
test.beforeAll(async () => {
  const result = await build({ configFile: false, logLevel: 'silent', define: { 'process.env.NODE_ENV': JSON.stringify('production') }, build: { write: false, minify: false, lib: { entry: fileURLToPath(new URL('./fixtures/dhcp-context.tsx', import.meta.url)), formats: ['iife'], name: 'DHCPContextFixture' } } });
  const bundle = Array.isArray(result) ? result[0] : result;
  if (!bundle || !('output' in bundle)) throw new Error('fixture bundle missing');
  for (const item of bundle.output) {
    if (item.type === 'chunk') javascript += item.code;
    else if (item.fileName.endsWith('.css')) css += String(item.source);
  }
});

for (const kind of ['reordered-response', 'snapshot', 'generation', 'draft-reset', 'network', 'readonly', 'blocked', 'logout']) test(`DHCP editor invalidates on ${kind} without saving old scope`, async ({ page }) => {
  page.on('pageerror', (error) => { throw error; });
  await page.route('**/dhcp-context-fixture', (route) => route.fulfill({ contentType: 'text/html', body: '<!doctype html><html lang="en"><head><title>Explicit DHCP context fixture</title><link rel="stylesheet" href="/dhcp-context-fixture.css"></head><body><div id="root"></div><script src="/dhcp-context-fixture.js"></script></body></html>' }));
  await page.route('**/dhcp-context-fixture.js', (route) => route.fulfill({ contentType: 'text/javascript', body: javascript }));
  await page.route('**/dhcp-context-fixture.css', (route) => route.fulfill({ contentType: 'text/css', body: css }));
  await page.goto('/dhcp-context-fixture');
  await expect(page.getByTestId('writes')).toHaveText('0');
  await page.getByRole('row').filter({ hasText: 'alpha' }).getByRole('button', { name: 'Edit scope', exact: true }).click();
  const editor = page.getByRole('dialog', { name: 'Edit scope', exact: true });
  await editor.getByLabel('Domain (optional)', { exact: true }).fill('obsolete.example');
  await page.evaluate((detail) => window.dispatchEvent(new CustomEvent('fixture-context-update', { detail })), kind);
  await expect(editor).toHaveCount(0);
  await expect(page.getByTestId('editing')).toHaveText('false');
  await expect(page.getByTestId('writes')).toHaveText('0');
  await expect(page.getByTestId('draft')).not.toContainText('obsolete.example');
  if (kind === 'reordered-response') {
    const scopes = JSON.parse((await page.getByTestId('draft').textContent())!).scopes;
    expect(scopes.map((scope: { id: string }) => scope.id)).toEqual(['beta', 'alpha']);
    expect(scopes[1].domain).toBe('external.example');
    await page.getByRole('row').filter({ hasText: 'alpha' }).getByRole('button', { name: 'Edit scope', exact: true }).click();
    await expect(editor.getByLabel('Domain (optional)', { exact: true })).toHaveValue('external.example');
  }
});
