export type Theme = 'light' | 'dark';
export const themeKey = 'andeiva.preview.theme';

export function parseTheme(value: string | null): Theme {
  return value === 'dark' ? 'dark' : 'light';
}

export function readTheme(storage?: Pick<Storage, 'getItem'>): Theme {
  try {
    return parseTheme((storage ?? window.localStorage).getItem(themeKey));
  } catch {
    return 'light';
  }
}

export function saveTheme(theme: Theme, storage?: Pick<Storage, 'setItem'>): void {
  try {
    (storage ?? window.localStorage).setItem(themeKey, theme);
  } catch {
    // The selection still applies to this page when browser storage is unavailable.
  }
}
