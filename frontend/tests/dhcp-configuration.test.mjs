import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { currentResponse } from '../.test-build/routing/configuration.js';
import { editableDHCP, validateDHCP } from '../.test-build/routing/dhcp.js';
import { dhcpMessages } from '../.test-build/routing/dhcpMessages.js';

const fixtures = JSON.parse(await readFile(new URL('./fixtures/routed-current-v2.json', import.meta.url), 'utf8'));
const network = { interfaces: [{ id: 'lan', role: 'lan', ipv4: { mode: 'static', address: '198.18.0.1/24' } }] };
const valid = () => ({ schema_version: 1, enabled: true, scopes: [{ id: 'clients', interface_id: 'lan', subnet: '198.18.0.0/24', router: '198.18.0.1', pools: [{ first: '198.18.0.10', last: '198.18.0.30' }], excluded: ['198.18.0.15'], reservations: [{ mac: '02:00:00:00:00:ab', address: '198.18.0.40' }], dns: ['198.18.0.1'], ntp: [], domain: 'lab.example', lease_seconds: 3600, renew_seconds: 1800, rebind_seconds: 3150 }] });

test('DHCP rejects topology, ranges, identities, coercions and unbounded settings even when disabled', () => {
  validateDHCP(valid(), network);
  for (const mutate of [
    c => { c.enabled = 'false'; }, c => { c.schema_version = 2; }, c => { c.extra = true; },
    c => { c.scopes = []; }, c => { c.scopes[0].interface_id = 'wan'; },
    c => { c.scopes[0].router = '198.18.0.2'; }, c => { c.scopes[0].subnet = '198.18.0.1/24'; },
    c => { c.scopes[0].pools[0].first = '198.18.0.0'; }, c => { c.scopes[0].pools[0].last = '198.18.0.255'; },
    c => { c.scopes[0].pools[0].first = '198.18.1.10'; }, c => { c.scopes[0].pools[0].first = '198.18.0.31'; },
    c => { c.scopes[0].pools.push({ first: '198.18.0.20', last: '198.18.0.40' }); },
    c => { c.scopes[0].pools[0].first = '198.18.0.1'; },
    c => { c.scopes[0].excluded.push('198.18.0.15'); },
    c => { c.scopes[0].reservations[0].mac = '01:00:00:00:00:ab'; },
    c => { c.scopes[0].reservations[0].mac = '00:00:00:00:00:00'; },
    c => { c.scopes[0].reservations[0].mac = '02:00:00:00:00:AB'; },
    c => { c.scopes[0].reservations[0].address = '198.18.0.15'; },
    c => { c.scopes[0].reservations[0].address = '198.18.0.1'; },
    c => { c.scopes[0].dns = ['127.0.0.1']; }, c => { c.scopes[0].dns = ['169.254.1.1']; },
    c => { c.scopes[0].ntp = ['224.0.0.1']; }, c => { c.scopes[0].dns = ['198.018.0.1']; },
    c => { c.scopes[0].dns = Array(5).fill('198.18.0.1'); },
    c => { c.scopes[0].domain = '-bad.example'; }, c => { c.scopes[0].domain = 'Upper.example'; },
    c => { c.scopes[0].lease_seconds = '3600'; }, c => { c.scopes[0].lease_seconds = 604801; },
    c => { c.scopes[0].renew_seconds = 0; }, c => { c.scopes[0].renew_seconds = 3150; },
    c => { c.scopes[0].rebind_seconds = 3600; }, c => { c.scopes.push(structuredClone(c.scopes[0])); },
    c => { c.scopes[0].pools = Array(33).fill(c.scopes[0].pools[0]); },
  ]) {
    const c = valid(); mutate(c); assert.throws(() => validateDHCP(c, network));
    if (c.scopes?.length && typeof c.enabled === 'boolean') { c.enabled = false; assert.throws(() => validateDHCP(c, network)); }
  }
  for (const iface of [{ id: 'lan', role: 'wan', ipv4: { mode: 'static', address: '198.18.0.1/24' } }, { id: 'lan', role: 'lan', ipv4: { mode: 'dhcp' } }]) assert.throws(() => validateDHCP(valid(), { interfaces: [iface] }));
});

test('disabled DHCP preserves settings and wire nil arrays normalize only in independent editable copy', () => {
  const c = valid(); c.enabled = false; c.scopes[0].ntp = null;
  validateDHCP(c, network);
  const copy = editableDHCP(c);
  assert.equal(copy.enabled, false); assert.deepEqual(copy.scopes[0].ntp, []);
  copy.scopes[0].id = 'changed'; assert.equal(c.scopes[0].id, 'clients'); assert.equal(c.scopes[0].ntp, null);
  validateDHCP({ schema_version: 1, enabled: false, scopes: null }, network);
});

test('DHCP bounds the total pool capacity and rejects overlapping selected LAN subnets', () => {
  const c = valid();
  c.scopes[0].subnet = '10.0.0.0/8'; c.scopes[0].router = '10.0.0.1';
  c.scopes[0].excluded = []; c.scopes[0].reservations = [];
  c.scopes[0].pools = [{ first: '10.1.0.1', last: '10.2.0.1' }];
  const plan = { interfaces: [{ id: 'lan', role: 'lan', ipv4: { mode: 'static', address: '10.0.0.1/8' } }] };
  assert.throws(() => validateDHCP(c, plan));
  c.scopes[0].pools[0].last = '10.2.0.0'; validateDHCP(c, plan);
  c.scopes[0].subnet = '0.0.0.0/1'; plan.interfaces[0].ipv4.address = '10.0.0.1/1';
  validateDHCP(c, plan);
  const second = { ...valid().scopes[0], id: 'second', interface_id: 'lan-two' };
  const overlap = valid(); overlap.scopes.push(second);
  assert.throws(() => validateDHCP(overlap, { interfaces: [...network.interfaces, { ...network.interfaces[0], id: 'lan-two' }] }));
});

test('policy v1 roundtrip remains byte-identical; v2 requires and validates DHCP without changing received bytes', () => {
  assert.equal(JSON.stringify(currentResponse(fixtures.routed)), JSON.stringify(fixtures.routed.current));
  const value = structuredClone(fixtures.routed);
  const policy = value.current.snapshot.running.config.routed;
  const c = valid(); c.enabled = false;
  policy.schema_version = 2; policy.dhcp_server = c;
  assert.deepEqual(currentResponse(value).snapshot.running.config.routed.dhcp_server, c);
  delete policy.dhcp_server; assert.throws(() => currentResponse(value));
  policy.dhcp_server = null; assert.throws(() => currentResponse(value));
  policy.schema_version = 1; policy.dhcp_server = c; assert.throws(() => currentResponse(value));
  policy.schema_version = 2; policy.dhcp_server = { ...c, enabled: true, scopes: [] }; assert.throws(() => currentResponse(value));
});

test('DHCP copy keys are complete in EN ES PT', () => {
  for (const locale of ['es', 'pt']) assert.deepEqual(Object.keys(dhcpMessages[locale]).sort(), Object.keys(dhcpMessages.en).sort());
});
