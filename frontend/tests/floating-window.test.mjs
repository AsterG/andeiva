import assert from 'node:assert/strict';
import test from 'node:test';
import { placeFloatingWindow } from '../.test-build/design-system/floatingWindowGeometry.js';
import { floatingWindowMessages } from '../.test-build/design-system/floatingWindowMessages.js';

test('floating placement centers initially and clamps every edge within its viewport', () => {
  const size = { width: 1000, height: 540 };
  const viewport = { left: 0, top: 0, width: 1440, height: 900 };
  assert.deepEqual(placeFloatingWindow(null, size, viewport, 16), { left: 220, top: 180 });
  assert.deepEqual(placeFloatingWindow({ left: -2000, top: -1000 }, size, viewport, 16), { left: 16, top: 16 });
  assert.deepEqual(placeFloatingWindow({ left: 2000, top: 1000 }, size, viewport, 16), { left: 424, top: 344 });
});

test('floating placement respects an offset visual viewport and a fitted full-screen window', () => {
  const viewport = { left: 30, top: 40, width: 800, height: 600 };
  assert.deepEqual(placeFloatingWindow(null, { width: 700, height: 500 }, viewport, 16), { left: 80, top: 90 });
  assert.deepEqual(placeFloatingWindow({ left: -10, top: 999 }, { width: 800, height: 600 }, viewport, 0), { left: 30, top: 40 });
});

test('window movement and close controls have complete EN/ES/PT instructions', () => {
  for (const locale of ['en', 'es', 'pt']) {
    assert.deepEqual(Object.keys(floatingWindowMessages[locale]).sort(), Object.keys(floatingWindowMessages.en).sort());
    assert.ok(Object.values(floatingWindowMessages[locale]).every((value) => typeof value === 'string' && value.trim()));
  }
});
