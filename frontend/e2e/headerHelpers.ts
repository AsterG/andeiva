import { expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import { headerMessages } from '../src/design-system/headerMessages.js';
import type { Locale } from '../src/messages.js';

async function selectPreference(page: Page, id: 'language' | 'theme', value: string) {
  const control = page.locator(`#${id}`);
  const hidden = !await control.isVisible();
  if (hidden) {
    await page.getByTestId('preferences-trigger').click();
    await expect(page.getByTestId('preferences-panel')).toBeVisible();
  }
  await control.selectOption(value);
  if (hidden) {
    await page.getByTestId('preferences-panel').press('Escape');
    await expect(page.getByTestId('preferences-panel')).toBeHidden();
  }
}

export async function selectLocale(page: Page, value: string) { await selectPreference(page, 'language', value); }
export async function selectTheme(page: Page, value: string) { await selectPreference(page, 'theme', value); }
export async function signOut(page: Page, locale: Locale = 'en') {
  await page.getByTestId('account-trigger').click();
  await expect(page.getByTestId('account-panel')).toBeVisible();
  await page.getByTestId('account-panel').getByRole('button', { name: headerMessages[locale].logout, exact: true }).click();
}
