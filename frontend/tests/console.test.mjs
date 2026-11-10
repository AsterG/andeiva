import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { consoleMessages, consoleViews, readConsoleView } from '../.test-build/firewall/consoleMessages.js';
import { ConsoleDashboard } from '../.test-build/firewall/ConsoleDashboard.js';
import { ConfigurationView } from '../.test-build/firewall/ConfigurationView.js';
import { TransactionControls } from '../.test-build/firewall/TransactionControls.js';
import { auditCalendarDay } from '../.test-build/firewall/auditPresentation.js';

const rule = { id: 'sample-rule', action: 'deny', enabled: false, match: { source: '10.42.0.0/24', destination: '10.43.0.2/32', protocol: 'tcp', source_ports: { from: 1, to: 65535 }, destination_ports: { from: 443, to: 443 } } };
const revision = { hash: 'a'.repeat(64), config: { schema_version: 4, default_action: 'deny', rules: [rule] } };
const state = { snapshot: { generation: 1, running: revision, startup: revision, recovery_required: false }, effective: { state: 'verified', revision: revision.hash, rules: [] } };
test('console hash navigation is an explicit allowlist and defaults to rules', () => {
  for (const view of consoleViews) assert.equal(readConsoleView(`#${view}`), view);
  for (const value of ['', '#main-content', '#https://example.invalid', '#constructor']) assert.equal(readConsoleView(value), 'rules');
});
test('console copy covers the same keys in EN ES PT', () => {
  for (const locale of ['en', 'es', 'pt']) {
    assert.deepEqual(Object.keys(consoleMessages[locale]).sort(), Object.keys(consoleMessages.en).sort());
    assert.ok(Object.values(consoleMessages[locale]).every((value) => value.trim().length > 0));
  }
});
test('dashboard shows unavailable telemetry and never presents stale counters as observed totals', () => {
  const html = renderToStaticMarkup(createElement(ConsoleDashboard, { state: { ...state, effective: { ...state.effective, rules: [{ id: rule.id, packets: 954321, bytes: 784321 }] } }, verified: false, locale: 'en' }));
  assert.match(html, /Unavailable/);
  assert.match(html, /No geographic traffic observations/);
  assert.doesNotMatch(html, /954,321|954321|784321|784,321|DEMO|Fictional/);
});
test('configuration comparison includes enablement differences with equal positions', () => {
  const html = renderToStaticMarkup(createElement(ConfigurationView, { snapshot: { ...state.snapshot, startup: { ...revision, hash: 'b'.repeat(64), config: { ...revision.config, rules: [{ ...rule, enabled: true }] } } }, locale: 'en' }));
  assert.match(html, /Different/);
  assert.match(html, /Disabled rules/);
  assert.match(html, /Enabled rules/);
});
test('dashboard sums safe individual counters with exact integer arithmetic', () => {
  const html = renderToStaticMarkup(createElement(ConsoleDashboard, { state: { ...state, effective: { ...state.effective, rules: [{ id: 'a', packets: Number.MAX_SAFE_INTEGER, bytes: Number.MAX_SAFE_INTEGER }, { id: 'b', packets: 2, bytes: 2 }] } }, verified: true, locale: 'en' }));
  assert.match(html, /9,007,199,254,740,993/);
  assert.doesNotMatch(html, /9,007,199,254,740,992/);
});
test('equal candidate and Running do not announce a pending change', () => {
  const html = renderToStaticMarkup(createElement(TransactionControls, { state: { ...state, snapshot: { ...state.snapshot, candidate: { owner: 'a', base: revision.hash, revision } } }, session: { username: 'a', role: 'viewer' }, locale: 'en', healthy: true, fresh: true, dirty: false, observed: '2026-11-10T12:00:00Z', confirmSeconds: '60' }));
  assert.doesNotMatch(html, /console-transaction-bar--pending|Candidate differs/);
});
test('audit date boundaries use the same local calendar day as displayed timestamps', () => {
  assert.equal(auditCalendarDay('2026-11-11T00:30:00Z', 'America/Argentina/Buenos_Aires'), '2026-11-10');
  assert.equal(auditCalendarDay('2026-11-11T00:30:00Z', 'UTC'), '2026-11-11');
});
