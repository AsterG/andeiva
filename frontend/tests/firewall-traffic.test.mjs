import assert from 'node:assert/strict';
import test from 'node:test';
import { isUint64, trafficResponse } from '../.test-build/firewall/traffic.js';
import { trafficMessages } from '../.test-build/firewall/trafficMessages.js';

const baseline = { sequence: 2, observed_at: '2026-11-10T12:00:00.123456789Z', revision: 'a'.repeat(64), rule_id: 'tcp-rule', action: 'allow', kind: 'baseline', packets_total: '18446744073709551615', bytes_total: '0' };
const delta = { ...baseline, sequence: 1, kind: 'delta', since: '2026-11-10T11:59:00Z', packets_total: '9007199254740993', bytes_total: '256', packets_delta: '2', bytes_delta: '128' };
const page = () => ({ stream: 'a'.repeat(32), records: [structuredClone(baseline), structuredClone(delta)], next_before: 1, evicted: 3, capacity: 512, sampling: 'on_request', retention: 'api_process', truncated: false });

test('traffic counters retain every uint64 digit without Number conversion', () => {
  for (const value of ['0', '9007199254740993', '18446744073709551615']) assert(isUint64(value));
  for (const value of ['-1', '01', '1e3', '18446744073709551616', '', '1.0', 12, null]) assert.equal(isUint64(value), false);
  const result = trafficResponse(page());
  assert.equal(result.records[0].packets_total, '18446744073709551615');
  assert.equal(result.records[1].packets_total, '9007199254740993');
  assert.equal(result.records[0].packets_delta, undefined);
});

test('traffic rejects false baseline deltas, malformed timestamps, unknown actions and invalid bounds', () => {
  const mutations = [
    (v) => { v.records[0].packets_delta = '0'; },
    (v) => { delete v.records[1].bytes_delta; },
    (v) => { v.records[1].bytes_delta = '300'; },
    (v) => { v.records[0].observed_at = '2026-02-30T00:00:00Z'; },
    (v) => { v.records[0].observed_at = 'tomorrow'; },
    (v) => { v.records[1].since = '2027-11-10T00:00:00Z'; },
    (v) => { v.records[0].action = 'permit'; },
    (v) => { v.records[0].action = ['allow']; },
    (v) => { v.records[0].since = '2026-11-10T11:59:00Z'; },
    (v) => { delete v.records[1].since; },
    (v) => { v.records[1].packets_delta = '0'; v.records[1].bytes_delta = '0'; },
    (v) => { v.stream = 'unknown'; },
    (v) => { v.next_before = 4; },
    (v) => { v.records = []; },
    (v) => { v.records[1].sequence = 2; },
    (v) => { v.records[0].packets_total = 42; },
    (v) => { v.capacity = 513; },
    (v) => { v.sampling = 'automatic'; },
    (v) => { v.retention = 'persistent'; },
    (v) => { delete v.truncated; },
    (v) => { v.next_before = -1; },
    (v) => { v.evicted = Number.MAX_SAFE_INTEGER + 1; },
    (v) => { v.records = null; },
    (v) => { v.records = Array.from({ length: 51 }, (_, index) => ({ ...baseline, sequence: 100 - index })); },
  ];
  for (const mutate of mutations) { const value = page(); mutate(value); assert.throws(() => trafficResponse(value), /ANDEIVA_RESPONSE_INVALID/); }
});

test('traffic accepts empty retained pages and complete EN/ES/PT copy', () => {
  assert.deepEqual(trafficResponse({ ...page(), records: [], next_before: 0, truncated: true }).records, []);
  for (const locale of ['es', 'pt']) assert.deepEqual(Object.keys(trafficMessages[locale]).sort(), Object.keys(trafficMessages.en).sort());
  for (const copy of Object.values(trafficMessages)) for (const text of Object.values(copy)) assert.equal(typeof text, 'string');
});
