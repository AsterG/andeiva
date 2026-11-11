import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { productInfoResponse } from '../.test-build/firewall/productInfo.js';
import { productVersionLabel, SystemInfoView } from '../.test-build/firewall/SystemInfoView.js';
import { systemMessages } from '../.test-build/firewall/systemMessages.js';

const development = { product: 'ANDEIVA Security Gateway', channel: 'development', update_status: 'unavailable' };
const experimental = { ...development, version: '0.1.0~alpha16', channel: 'experimental' };

test('product identity accepts only the authenticated public version contract', () => {
  for (const info of [development, experimental, { ...experimental, version: '0.1.0~alpha' + '9'.repeat(64 - '0.1.0~alpha'.length) }]) assert.deepEqual(productInfoResponse(info), info);
  for (const info of [null, [], {}, { ...development, version: null }, { ...development, version: '' }, { ...experimental, version: '0.1.0~alpha1\n' }, { ...experimental, version: '0.1.0~alpha01' }, { ...experimental, version: '0.1.0~alpha0' }, { ...experimental, version: '0.1.0~alpha' + '9'.repeat(65 - '0.1.0~alpha'.length) }, { ...experimental, channel: 'stable' }, { ...experimental, channel: 'development' }, { ...development, update_status: 'up-to-date' }, { ...experimental, product: 'other' }, { ...experimental, kernel: 'private' }, { ...experimental, Version: experimental.version }]) assert.throws(() => productInfoResponse(info), { code: 'ANDEIVA_RESPONSE_INVALID' });
});

test('system copy covers EN ES PT and distinguishes missing version from verified identity', () => {
  for (const locale of ['en', 'es', 'pt']) {
    assert.deepEqual(Object.keys(systemMessages[locale]).sort(), Object.keys(systemMessages.en).sort());
    assert.ok(Object.values(systemMessages[locale]).every((value) => value.trim().length > 0));
    assert.equal(productVersionLabel({ state: 'ready', info: experimental }, locale), experimental.version);
    assert.equal(productVersionLabel({ state: 'ready', info: development }, locale), systemMessages[locale].development);
    const html = renderToStaticMarkup(createElement(SystemInfoView, { locale, state: { state: 'ready', info: experimental }, refresh() {} }));
    assert.match(html, /0\.1\.0~alpha16/);
    assert.ok(html.includes(systemMessages[locale].updateHint));
    assert.doesNotMatch(html, /kernel|go1\.|source_revision|linux|<input/i);
    assert.doesNotMatch(renderToStaticMarkup(createElement(SystemInfoView, { locale, state: { state: 'unavailable' }, refresh() {} })), /0\.1\.0~alpha16/);
  }
});
