import assert from 'node:assert/strict';
import test from 'node:test';
import { networkInventoryResponse } from '../.test-build/routing/inventory.js';
import { routingMessages } from '../.test-build/routing/messages.js';

const sample = () => ({ schema_version: 1, interfaces: [{ name: 'lan0', hardware_address: '02:00:00:00:00:01', mtu: 1500, admin_up: true, running: false, kind: 'virtual', addresses: [{ ip: '192.0.2.1', prefix: '192.0.2.1/24' }, { ip: '2001:db8::1', prefix: '2001:db8::1/64' }] }] });

test('interface observations preserve host addresses without inferring link or DHCP success', () => {
  const input = sample();
  const actual = networkInventoryResponse(input);
  assert.deepEqual(actual, input);
  input.interfaces[0].addresses[0].ip = '192.0.2.99';
  assert.equal(actual.interfaces[0].addresses[0].ip, '192.0.2.1');
  assert.equal(actual.interfaces[0].running, false);
  assert.equal(Object.hasOwn(actual.interfaces[0], 'dhcp_lease'), false);
});

test('inventory rejects unknown/private fields, duplicates, malformed addresses and resource bounds', () => {
  for (const change of [
    (v) => { v.namespace = 123; },
    (v) => { v.interfaces[0].index = 7; },
    (v) => { v.interfaces[0].os_version = 'private'; },
    (v) => { v.interfaces.push(structuredClone(v.interfaces[0])); },
    (v) => { v.interfaces[0].name = 'control\nsequence'; },
    (v) => { v.interfaces[0].mtu = '1500'; },
    (v) => { v.interfaces[0].kind = {}; },
    (v) => { v.interfaces[0].addresses[0].prefix = '192.0.2.0/24'; },
    (v) => { v.interfaces[0].addresses[0].ip = '192.000.2.1'; },
    (v) => { v.interfaces[0].addresses[1].ip = ':::::'; },
    (v) => { v.interfaces[0].addresses[1].prefix = '2001:db8::1/129'; },
    (v) => { v.interfaces[0].addresses.push(structuredClone(v.interfaces[0].addresses[0])); },
    (v) => { v.interfaces[0].addresses = Array.from({ length: 257 }, () => ({ ip: '192.0.2.1', prefix: null })); },
    (v) => { v.interfaces = Array.from({ length: 257 }, (_, n) => ({ ...v.interfaces[0], name: `link${n}` })); },
  ]) {
    const value = sample(); change(value);
    assert.equal(networkInventoryResponse(value), null);
  }
});

test('loopback and non-Ethernet addresses remain observations, not configurable-binding claims', () => {
  const input = sample();
  input.interfaces[0].hardware_address = '';
  input.interfaces[0].kind = 'loopback';
  assert.notEqual(networkInventoryResponse(input), null);
  input.interfaces[0].hardware_address = '02:00:00:00:00:01:02:03';
  input.interfaces[0].kind = 'device-backed';
  assert.notEqual(networkInventoryResponse(input), null);
});

test('network interface messages cover English, Spanish and Portuguese consistently', () => {
  const keys = Object.keys(routingMessages.en).sort();
  for (const language of ['en', 'es', 'pt']) {
    assert.deepEqual(Object.keys(routingMessages[language]).sort(), keys);
    assert(Object.values(routingMessages[language]).every((text) => typeof text === 'string' && text.length));
  }
});
