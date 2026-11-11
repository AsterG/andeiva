import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { LocalServicesPage } from '../.test-build/local-services/LocalServicesPage.js';
import { localMessages } from '../.test-build/local-services/messages.js';
import { bindingError, canonicalAddress, canonicalCIDR, capabilitiesResponse, draftConfig, effectiveMatchesSnapshot, newService, proofResponse, proofTokens, serviceError, statusResponse, usableBindingAddress } from '../.test-build/local-services/model.js';

const interfaces = [{ name: 'src0', zone: 'lan', addresses: ['198.18.1.1', 'fd42:616e:6465:1::1'] }, { name: 'dst0', zone: 'wan', addresses: ['198.18.2.1'] }];
function config() { return { schema_version: 3, default_action: 'deny', rules: [], local_services: { schema_version: 1, interfaces: structuredClone(interfaces), services: [] } }; }
function state() { const revision = { hash: 'a'.repeat(64), config: config() }; return { snapshot: { generation: 1, running: revision, startup: structuredClone(revision), recovery_required: false }, effective: { hash: revision.hash, phase: 'idle', recovery_required: false, rules: [], listeners: [] } }; }
function binding() { return { interface: 'src0', zone: 'lan', local_address: '198.18.1.1', sources: ['198.18.1.2/32'], wan_opt_in: false }; }

test('local inventory and revision validation reject invented capability and optimistic receipts', () => {
  assert.equal(capabilitiesResponse({ firewall: false, local_services: true, endpoint_id: 'recovery', recovery_endpoint: true, local_interfaces: interfaces }).local_interfaces.length, 2);
  assert.throws(() => capabilitiesResponse({ local_services: true }));
  assert.deepEqual(capabilitiesResponse({ firewall: true, local_services: false, endpoint_id: '', recovery_endpoint: false, local_interfaces: null }).local_interfaces, []);
  assert.equal(statusResponse(state()).effective.recovery_required, false);
  const mismatched = state(); mismatched.effective.hash = 'b'.repeat(64);
  assert.equal(statusResponse(mismatched).effective.recovery_required, true);
  const malformed = state(); malformed.snapshot.running.config.local_services.services = [{}];
  assert.throws(() => statusResponse(malformed));
  const forwarded = state(); forwarded.snapshot.running.config.rules = [{ id: 'unexpected' }];
  assert.throws(() => statusResponse(forwarded));
});
test('IPv4 and IPv6 sources are canonicalized without DNS or network calls', () => {
  assert.equal(canonicalCIDR('198.18.1.2/24'), '198.18.1.0/24');
  assert.equal(canonicalCIDR('fd42:616e:6465:1:0:0:0:2/64'), 'fd42:616e:6465:1::/64');
  assert.equal(canonicalCIDR('2001:DB8::1'), '2001:db8::1/128');
  for (const value of ['example.org', 'fe80::1%eth0', '::1/129', '2001:::1', '1.2.3.999', 'http://host']) assert.equal(canonicalCIDR(value), null, value);
  assert.equal(canonicalAddress('2001:0db8:0:0:0:0:0:1'), '2001:db8::1');
  for (const address of ['fe80::1', 'fe90::1', 'febf::1']) assert.equal(usableBindingAddress(address), false);
  assert.equal(usableBindingAddress('fd42::1'), true);
});
test('service editor requires explicit sources, WAN intent and non-overlapping listeners', () => {
  const service = newService('https'); service.enabled = true;
  assert.equal(serviceError(service, interfaces, []), 'bindingsError');
  service.bindings = [binding()];
  assert.equal(serviceError(service, interfaces, []), null);
  const ssh = newService('ssh'); ssh.enabled = true; ssh.bindings = [binding()]; ssh.endpoints = structuredClone(service.endpoints);
  assert.equal(serviceError(ssh, interfaces, [service]), 'conflictError');
  for (const sources of [[], ['0.0.0.0/0'], ['198.18.1.0/24', '198.18.1.2/32'], ['fd42::/64'], ['224.0.0.0/4']]) assert.equal(bindingError({ ...binding(), sources }, interfaces), 'sourceError');
  assert.equal(bindingError({ ...binding(), interface: 'dst0', zone: 'wan', local_address: '198.18.2.1', sources: ['198.18.2.2/32'] }, interfaces), 'wanError');
  assert.equal(bindingError({ ...binding(), interface: 'ens33' }, interfaces), 'interfaceError');
  assert.equal(bindingError({ ...binding(), local_address: 'fd42:616e:6465:1::1', sources: ['fd42::/16', 'fd42:616e::/32'] }, interfaces), 'sourceError');
});
test('legacy draft migration requires trusted inventory and does not share mutable state', () => {
  const s = state().snapshot; s.running.config = { schema_version: 2, default_action: 'deny', rules: [] };
  const draft = draftConfig(s, interfaces);
  assert.equal(draft.schema_version, 3); assert.deepEqual(draft.local_services.interfaces, interfaces);
  draft.local_services.interfaces[0].name = 'changed';
  assert.equal(interfaces[0].name, 'src0'); assert.equal(s.running.config.local_services, undefined);
});
test('server-validated service dependencies survive reads and draft edits', () => {
  const s = state(); const https = newService('https'); const ssh = newService('ssh');
  https.bindings = [binding()]; ssh.bindings = [binding()]; https.depends_on = ['ssh'];
  s.snapshot.running.config.local_services.services = [https, ssh];
  const parsed = statusResponse(s);
  assert.deepEqual(draftConfig(parsed.snapshot, interfaces).local_services.services[0].depends_on, ['ssh']);
  https.depends_on = ['unavailable'];
  assert.throws(() => statusResponse(s));
});
test('proof parsing rejects booleans, duplicates, oversized sets and invalid expiry', () => {
  const token = 'a'.repeat(64);
  assert.deepEqual(proofTokens(token), [token]); assert.deepEqual(proofTokens(''), []);
  for (const value of ['true', `${token}\n${token}`, Array.from({ length: 9 }, (_, i) => String(i).repeat(64)).join('\n')]) assert.equal(proofTokens(value), null);
  assert.throws(() => proofResponse({ token: true, expires_at: '2026-11-10' }));
  assert.throws(() => proofResponse({ token, expires_at: 'never' }));
});
test('expired guardian is healthy only after the exact Running revision is restored', () => {
  const s = state(); s.effective.phase = 'expired';
  assert.equal(effectiveMatchesSnapshot(s.effective, s.snapshot), true);
  assert.equal(effectiveMatchesSnapshot({ ...s.effective, hash: 'b'.repeat(64) }, s.snapshot), false);
  assert.equal(effectiveMatchesSnapshot({ ...s.effective, recovery_required: true }, s.snapshot), false);
  assert.equal(effectiveMatchesSnapshot(s.effective, { ...s.snapshot, recovery_required: true }), false);
  assert.equal(effectiveMatchesSnapshot(s.effective, { ...s.snapshot, pending: { owner: 'admin', lease: 'lease', deadline: '2026-11-10T15:00:00Z', previous: s.snapshot.running } }), false);
  assert.equal(effectiveMatchesSnapshot({ ...s.effective, phase: 'blocked' }, s.snapshot), false);
});
for (const locale of ['en', 'es', 'pt']) test(`Local Services preserves branding, Light default and complete ${locale} copy`, () => {
  const html = renderToStaticMarkup(createElement(LocalServicesPage, { initialLocale: locale }));
  assert.match(html, /data-theme="light"/); assert.match(html, /src="\/andeiva-logo.png"/);
  assert.match(html, /alt="ANDEIVA Security Gateway"/); assert.match(html, new RegExp(`lang="${locale}"`));
  assert.ok(html.includes('ANDEIVA Security Gateway'));
  assert.doesNotMatch(html, /<aside|<nav|class="page-heading"/);
  assert.deepEqual(Object.keys(localMessages[locale]).sort(), Object.keys(localMessages.en).sort());
  assert.ok(Object.values(localMessages[locale]).every((value) => typeof value === 'string' && value.trim().length > 0));
});
