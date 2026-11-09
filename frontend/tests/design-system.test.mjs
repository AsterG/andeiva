import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { checkDesignSystem, contrast, readThemes, unauthorizedColors, undeclaredTokenReferences } from '../scripts/check-design-system.mjs';

test('semantic themes satisfy the source color policy and declared contrast pairs', () => {
  assert.deepEqual(checkDesignSystem().errors, []);
});

test('color gate rejects unauthorized literals while accepting token consumers', () => {
  for (const source of ['.panel { background: #fff; }', '.label { color: white; }', '.label { color: hotpink; }', '.panel { background: tomato; }', '.panel { border-color: rgb(1 2 3); }', '<svg fill="#000000"/>']) {
    assert.ok(unauthorizedColors(source).length > 0, source);
  }
  assert.deepEqual(unauthorizedColors('.panel { color: var(--color-text); background: transparent; }'), []);
  assert.deepEqual(unauthorizedColors('.panel { color: var(--color-brand-blue); border-color: var(--color-brand-border); }'), []);
  assert.deepEqual(unauthorizedColors('<div style={{backgroundColor: "var(--color-surface)"}} />'), []);
  for (const property of ['backgroundColor', 'borderColor', 'borderTopColor', 'outlineColor', 'boxShadow', 'accentColor']) {
    assert.ok(unauthorizedColors(`<div style={{${property}: 'tomato'}} />`).length > 0, property);
  }
  assert.ok(unauthorizedColors('.panel { color: var(--color-brand-blue, blue); }').length > 0);
  assert.equal(contrast('#ffffff', '#000000'), 21);
  assert.equal(contrast('#ffffff', '#ffffff'), 1);
});

test('token gate rejects undeclared references in CSS, aliases and inline styles', () => {
  const css = readFileSync(new URL('../src/design-system/tokens.css', import.meta.url), 'utf8');
  const declarations = new Set(Object.keys(readThemes(css).light));
  assert.deepEqual(undeclaredTokenReferences('.panel { color: var(--color-brand-blue); gap: var(--space-4); font: var(--font-body); box-shadow: var(--shadow-sm); }', declarations), []);
  assert.deepEqual(undeclaredTokenReferences('<div style={{backgroundColor: "var(--color-surface)"}} />', declarations), []);
  const invalid = `.panel { color: var(--color-tetx); gap: var(--space-99, var(--space-4)); }
    :root { --new-alias: var(--missing-target); }
    <div style={{borderColor: "var(--brand-blue)"}} />`;
  assert.deepEqual(undeclaredTokenReferences(invalid, declarations), ['--color-tetx', '--space-99', '--missing-target', '--brand-blue']);
  assert.deepEqual(undeclaredTokenReferences('/* var(--retired-token) */ .panel { color: var( --color-text ); }', declarations), []);
});

test('theme bootstrap handles saved, invalid and unavailable storage before application code', () => {
  const script = readFileSync(new URL('../public/theme-init.js', import.meta.url), 'utf8');
  for (const [stored, expected] of [[null, 'light'], ['dark', 'dark'], ['light', 'light'], ['system', 'light'], ['DARK', 'light']]) {
    const root = { dataset: {}, style: {}, setAttribute(name, value) { this[name] = value; } };
    const storage = { getItem: () => stored };
    runInNewContext(script, { document: { documentElement: root }, localStorage: storage, window: { localStorage: storage } });
    assert.equal(root.dataset.theme ?? root['data-theme'], expected);
  }
  const root = { dataset: {}, style: {}, setAttribute(name, value) { this[name] = value; } };
  const storage = { getItem: () => { throw new Error('unavailable'); } };
  runInNewContext(script, { document: { documentElement: root }, localStorage: storage, window: { localStorage: storage } });
  assert.equal(root.dataset.theme ?? root['data-theme'], 'light');
});
