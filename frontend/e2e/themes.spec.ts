import { selectLocale, selectTheme } from './headerHelpers.js';
import { createHash } from 'node:crypto';
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import type { Locator, Page } from '@playwright/test';

const preferenceKey = 'andeiva.preview.theme';
const approvedLogo = '1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81';

test.describe('Turkish browser locale', () => {
  test.use({ locale: 'tr-TR' });

  for (const theme of ['light', 'dark'] as const) {
    test(`${theme}: search casing follows the supported interface languages`, async ({ page }) => {
      await page.goto('/?view=design-system');
      expect(await page.evaluate(() => ({
        language: navigator.language,
        locale: new Intl.NumberFormat().resolvedOptions().locale,
        defaultLower: 'I'.toLocaleLowerCase(),
        invariantLower: 'I'.toLowerCase(),
      }))).toEqual({ language: 'tr-TR', locale: 'tr-TR', defaultLower: 'ı', invariantLower: 'i' });
      await selectTheme(page, theme);
      await page.getByTestId('nav-components').click();
      const examples = [
        { locale: 'en', interfaceQuery: 'interface', interfaceName: 'Interface preferences', validationName: 'Form validation', rowsWithI: ['Interface preferences', 'Documentation draft', 'Form validation', 'Component guidance'] },
        { locale: 'es', interfaceQuery: 'interfaz', interfaceName: 'Preferencias de la interfaz', validationName: 'Validación del formulario', rowsWithI: ['Preferencias de la interfaz', 'Borrador de documentación', 'Validación del formulario'] },
        { locale: 'pt', interfaceQuery: 'interface', interfaceName: 'Preferências da interface', validationName: 'Validação do formulário', rowsWithI: ['Preferências da interface', 'Validação do formulário', 'Guia de componentes'] },
      ];
      for (const example of examples) {
        await selectLocale(page, example.locale);
        await expect(page.locator('html')).toHaveAttribute('lang', example.locale);
        for (const [query, expected] of [
          [example.interfaceQuery, [example.interfaceName]],
          [example.interfaceQuery.toUpperCase(), [example.interfaceName]],
          ['valid', [example.validationName]],
          ['VALID', [example.validationName]],
          ['i', example.rowsWithI],
          ['I', example.rowsWithI],
        ] as [string, string[]][]) {
          await page.getByTestId('filter-search').fill(query);
          await expect(page.getByRole('table').locator('tbody th[scope="row"]')).toHaveText(expected);
        }
      }
    });
  }
});

async function expectNoPageOverflow(page: Page) {
  const size = await page.evaluate(() => ({
    content: document.documentElement.scrollWidth,
    viewport: document.documentElement.clientWidth,
  }));
  expect(size.content).toBeLessThanOrEqual(size.viewport + 1);
}

async function expectAccessible(page: Page) {
  const result = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  expect(result.violations).toEqual([]);
}

async function expectVisibleFocus(target: Locator) {
  await expect(target).toBeFocused();
  await expect(target).toBeVisible();
  await expect(target).toBeInViewport();
  const outline = await target.evaluate((element) => {
    const css = getComputedStyle(element);
    return { width: parseFloat(css.outlineWidth), style: css.outlineStyle, color: css.outlineColor };
  });
  expect(outline.width).toBeGreaterThan(0);
  expect(outline.style).not.toBe('none');
  expect(outline.style).not.toBe('hidden');
  expect(outline.color).not.toBe('rgba(0, 0, 0, 0)');
}

test('light stays default when the operating system prefers dark', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/?view=design-system');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('#theme')).toHaveValue('light');
  await page.emulateMedia({ colorScheme: 'light' });
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(page.locator('#theme')).toHaveValue('light');
  expect(await page.evaluate((key) => localStorage.getItem(key), preferenceKey)).toBeNull();
});

test('manual theme preference persists without following the operating system', async ({ page }) => {
  await page.goto('/?view=design-system');
  await selectTheme(page, 'dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate((key) => localStorage.getItem(key), preferenceKey)).toBe('dark');
  await page.reload();
  await expect(page.locator('#theme')).toHaveValue('dark');
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await selectTheme(page, 'light');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
});

test('invalid or unavailable storage falls back safely to light', async ({ page }) => {
  await page.addInitScript((key) => localStorage.setItem(key, 'system'), preferenceKey);
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/?view=design-system');
  await expect(page.locator('#theme')).toHaveValue('light');
  await page.addInitScript(() => {
    Object.defineProperty(Storage.prototype, 'getItem', { value: () => { throw new Error('storage unavailable'); } });
    Object.defineProperty(Storage.prototype, 'setItem', { value: () => { throw new Error('storage unavailable'); } });
  });
  await page.reload();
  await expect(page.locator('#theme')).toHaveValue('light');
  await selectTheme(page, 'dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});

test('stored theme is applied before the React bundle can execute', async ({ page }) => {
  await page.addInitScript((key) => localStorage.setItem(key, 'dark'), preferenceKey);
  let releaseBundle: () => void = () => {};
  const bundleGate = new Promise<void>((resolve) => { releaseBundle = resolve; });
  await page.route('**/assets/*.js', async (route) => {
    await bundleGate;
    await route.continue();
  });
  try {
    await page.goto('/?view=design-system', { waitUntil: 'commit' });
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('#root')).toBeEmpty();
    await expect.poll(async () => page.evaluate(() => {
      const rootStyle = getComputedStyle(document.documentElement);
      const token = rootStyle.getPropertyValue('--color-background').trim();
      const swatch = document.createElement('span');
      swatch.style.backgroundColor = token;
      const actual = getComputedStyle(document.body).backgroundColor;
      const canvas = rootStyle.backgroundColor;
      return Boolean(token) && (actual === swatch.style.backgroundColor ||
        (actual === 'rgba(0, 0, 0, 0)' && canvas === swatch.style.backgroundColor));
    })).toBe(true);
  } finally {
    releaseBundle();
  }
  await expect(page.locator('#theme')).toHaveValue('dark');
});

for (const theme of ['light', 'dark'] as const) {
  test(`${theme}: skip link and view navigation show focus on their content targets`, async ({ page }) => {
    await page.addInitScript(({ key, value }) => localStorage.setItem(key, value), { key: preferenceKey, value: theme });
    await page.goto('/?view=design-system');
    await expect(page.locator('#theme')).toHaveValue(theme);
    await page.keyboard.press('Tab');
    const skip = page.getByRole('link', { name: 'Skip to content', exact: true });
    await expectVisibleFocus(skip);
    await page.keyboard.press('Enter');
    await expectVisibleFocus(page.getByRole('main'));
    for (const [navigation, title] of [['nav-components', 'Component library'], ['nav-overview', 'A consistent foundation.']]) {
      await page.getByTestId(navigation).focus();
      await page.keyboard.press('Enter');
      await expectVisibleFocus(page.getByRole('heading', { level: 1, name: title, exact: true }));
    }
  });

  test(`${theme}: filters, local form feedback, menu and tooltip work`, async ({ page }) => {
    await page.goto('/?view=design-system');
    await selectTheme(page, theme);
    await page.getByTestId('nav-components').click();
    const table = page.getByRole('table');
    await expect(table.locator('tbody tr')).toHaveCount(4);
    await page.getByTestId('filter-search').fill('Documentation');
    await expect(table.locator('tbody tr')).toHaveCount(1);
    await expect(table).toContainText('Documentation draft');
    await page.getByTestId('filter-search').fill('does-not-match-any-example');
    await expect(table).toContainText('No entries match these filters.');
    await page.getByTestId('filter-search').clear();
    await page.getByTestId('status-filter').selectOption('warning');
    await expect(table.locator('tbody tr')).toHaveCount(1);
    await page.getByTestId('status-filter').selectOption('all');
    await expect(table.locator('tbody tr')).toHaveCount(4);

    await page.getByTestId('preview-name').fill('');
    await page.getByTestId('apply-preview').click();
    await expect(page.getByTestId('preview-name')).toHaveAttribute('aria-invalid', 'true');
    await page.getByTestId('preview-name').fill('Theme validation');
    await page.getByTestId('preview-notes').fill('Local interface example only.');
    await page.getByTestId('preview-notifications').check();
    await page.getByTestId('apply-preview').click();
    await expect(page.getByRole('status')).toContainText('Preview updated');

    const menu = page.locator('summary');
    await menu.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('details')).toHaveAttribute('open', '');
    await expect(page.locator('.ds-disclosure-panel')).toBeVisible();
    const menuBounds = await page.locator('.ds-disclosure-panel').boundingBox();
    expect(menuBounds).not.toBeNull();
    expect(menuBounds!.x).toBeGreaterThanOrEqual(0);
    expect(menuBounds!.x + menuBounds!.width).toBeLessThanOrEqual(page.viewportSize()!.width);
    await menu.press('Enter');
    await expect(page.locator('.ds-disclosure-panel')).not.toBeVisible();

    const help = page.getByRole('button', { name: 'About shared components', exact: true });
    await page.getByTestId('filter-search').focus();
    await help.hover();
    await expect(page.getByRole('tooltip')).toBeVisible();
    await page.getByRole('tooltip').hover();
    await expect(page.getByRole('tooltip')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('tooltip')).not.toBeVisible();
    await help.focus();
    await expect(page.getByRole('tooltip')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('tooltip')).not.toBeVisible();
    await expectNoPageOverflow(page);
    await expectAccessible(page);
  });

  test(`${theme}: 320px reflow and 200 percent text remain usable`, async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 900 });
    await page.goto('/?view=design-system');
    await selectTheme(page, theme);
    await expectNoPageOverflow(page);
    await page.getByTestId('nav-components').click();
    await expectNoPageOverflow(page);
    await page.locator('summary').click();
    const menuBounds = await page.locator('.ds-disclosure-panel').boundingBox();
    expect(menuBounds).not.toBeNull();
    expect(menuBounds!.x).toBeGreaterThanOrEqual(0);
    expect(menuBounds!.x + menuBounds!.width).toBeLessThanOrEqual(320);
    await page.locator('summary').click();
    await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    await expectNoPageOverflow(page);
    await expect(page.getByTestId('filter-search')).toBeVisible();
    await expect(page.getByTestId('open-dialog')).toBeVisible();
    await page.getByTestId('open-dialog').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.getByTestId('close-dialog').scrollIntoViewIfNeeded();
    await expect(page.getByTestId('close-dialog')).toBeInViewport();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).not.toBeVisible();
  });

  test(`${theme}: logo, responsive layout, semantics and both views`, async ({ page, request }) => {
    await page.goto('/?view=design-system');
    await selectTheme(page, theme);
    const image = page.getByRole('img', { name: 'ANDEIVA Security Gateway', exact: true });
    await expect(image).toBeVisible();
    const logo = await request.get('/andeiva-logo.png');
    expect(createHash('sha256').update(await logo.body()).digest('hex')).toBe(approvedLogo);
    const rendered = await image.evaluate((element) => {
      const img = element as HTMLImageElement;
      const css = getComputedStyle(img);
      const box = img.getBoundingClientRect();
      return { filter: css.filter, transform: css.transform, fit: css.objectFit, ratio: box.width / box.height, naturalRatio: img.naturalWidth / img.naturalHeight };
    });
    expect(rendered.filter).toBe('none');
    expect(rendered.transform).toBe('none');
    expect(rendered.fit).toBe('contain');
    expect(rendered.ratio).toBeCloseTo(rendered.naturalRatio, 2);
    await expectNoPageOverflow(page);
    await expectAccessible(page);
    await page.getByTestId('nav-components').click();
    await expect(page.getByRole('table')).toBeVisible();
    await expectNoPageOverflow(page);
    await expectAccessible(page);
    await page.getByTestId('open-dialog').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expectAccessible(page);
  });

  test(`${theme}: keyboard, dialog focus and localized content`, async ({ page }) => {
    await page.goto('/?view=design-system');
    await selectTheme(page, theme);
    await page.getByTestId('nav-components').focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('table')).toBeVisible();
    for (const locale of ['en', 'es', 'pt']) {
      await selectLocale(page, locale);
      await expect(page.locator('html')).toHaveAttribute('lang', locale);
      await expect(page.getByRole('heading', { name: locale === 'en' ? 'Component library' : 'Biblioteca de componentes', exact: true })).toBeVisible();
      await expect(page.locator('#theme option[value="dark"]')).toHaveText(locale === 'en' ? 'Dark' : locale === 'es' ? 'Oscuro' : 'Escuro');
      await expect(page.getByTestId('open-dialog')).toHaveAccessibleName(/\S/);
      await expect(page.getByTestId('filter-search')).toHaveAccessibleName(/\S/);
      await expectNoPageOverflow(page);
      await expectAccessible(page);
    }
    const trigger = page.getByTestId('open-dialog');
    await trigger.focus();
    await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAccessibleName(/\S/);
    for (let index = 0; index < 8; index++) {
      await page.keyboard.press('Tab');
      expect(await dialog.evaluate((element) => element.contains(document.activeElement))).toBe(true);
    }
    await page.keyboard.press('Escape');
    await expect(dialog).not.toBeVisible();
    await expect(trigger).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(dialog).toBeVisible();
    await page.getByTestId('close-dialog').focus();
    await page.keyboard.press('Enter');
    await expect(dialog).not.toBeVisible();
    await expect(trigger).toBeFocused();
  });

  test(`${theme}: visual baseline`, async ({ page }) => {
    await page.goto('/?view=design-system');
    await selectTheme(page, theme);
    await page.getByRole('img', { name: 'ANDEIVA Security Gateway', exact: true }).evaluate(async (element) => { await (element as HTMLImageElement).decode(); });
    await expect(page).toHaveScreenshot(`${theme}-overview.png`, { fullPage: true });
    await page.getByTestId('nav-components').click();
    await expect(page).toHaveScreenshot(`${theme}-components.png`, { fullPage: true });
    await page.getByTestId('open-dialog').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page).toHaveScreenshot(`${theme}-dialog.png`);
  });
}
