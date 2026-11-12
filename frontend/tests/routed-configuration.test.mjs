import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { currentResponse, decimalGeneration, operationResponse } from '../.test-build/routing/configuration.js';
import { interfaceAddress, networkRevision } from '../.test-build/routing/networkPlan.js';
import { workspaceMessages } from '../.test-build/routing/workspaceMessages.js';

// Synthetic Go-generated wire documents; never imported by the application.
const fixtures = JSON.parse(await readFile(new URL('./fixtures/routed-current-v2.json', import.meta.url), 'utf8'));

test('routed browser contract preserves uint64 generations and separate composite identities', () => {
  for (const fixture of Object.values(fixtures)) {
    const current = currentResponse(fixture);
    assert.equal(current.global.generation, '18446744073709551615');
    assert.notEqual(current.global.running_revision, current.snapshot.running.hash);
    current.snapshot.running.hash = '0'.repeat(64);
    assert.notEqual(fixture.current.snapshot.running.hash, current.snapshot.running.hash);
  }
  for (const invalid of [0, 1, '0', '01', '18446744073709551616', '-1', '1e2', null]) assert.equal(decimalGeneration(invalid), false);
  assert.equal(decimalGeneration('18446744073709551615'), true);
});

test('routed browser refuses mismatched components, missing confirmation and generation confusion', () => {
  for (const mutate of [
    (v) => { v.current.global.running_revision = v.current.snapshot.running.hash; },
    (v) => { v.current.routed.startup.config.domains.network.revision = '0'.repeat(64); },
    (v) => { v.current.domain_generations.network = '3'; },
    (v) => { v.current.global.generation = 18446744073709551615; },
    (v) => { v.current.snapshot.pending = { lease: 'lease', owner: 'subject', previous: v.current.snapshot.running, deadline: '2030-01-01T00:00:00Z' }; },
    (v) => { v.current.routed.confirmation = { origin_commit_operation_id: 'commit', target_revision: v.current.global.running_revision, confirmation_deadline: '2030-01-01T00:00:00Z' }; },
    (v) => { v.current.routed.candidate = v.current.routed.running; },
    (v) => { v.current.snapshot.running.config.routed.network.hash = '0'.repeat(64); },
    (v) => { v.current.snapshot.running.config.routed.network.config.dns.mode = ['none']; },
    (v) => { v.current.snapshot.running.config.routed.rules[0].protocol = ['tcp']; },
    (v) => { v.current.snapshot.running.config.routed.rules[0].action = ['allow']; },
  ]) {
    const value = structuredClone(fixtures.routed);
    mutate(value);
    assert.throws(() => currentResponse(value));
  }
});

test('browser network revision matches canonical Go bytes and preserves host bits', async () => {
  const network = fixtures.routed.current.snapshot.running.config.routed.network;
  assert.deepEqual(await networkRevision(network.config), network);
  assert.equal(interfaceAddress('192.168.18.10/24'), '192.168.18.10/24');
  assert.equal(interfaceAddress('192.168.18.0/24'), null);
  assert.equal(interfaceAddress('192.168.18.255/24'), null);
  assert.equal(interfaceAddress('192.168.18.10/0'), null);
  assert.equal(interfaceAddress('127.0.0.1/8'), null);
  assert.equal(interfaceAddress('224.0.0.1/24'), null);
  assert.equal(interfaceAddress('192.168.018.10/24'), null);
  assert.equal(interfaceAddress('198.18.0.0/31'), '198.18.0.0/31');
});

test('routed operation replies correlate the durable ID and reject invented outcomes', () => {
  const reply = { ...structuredClone(fixtures.routed), operation: { id: 'v2.op.1.fixture', namespace_id: 'v2.ns.1.fixture', domain: 'routed', kind: 'commit', state: 'final', expected_generation: '18446744073709551615', outcome: { code: 'applied_pending_confirmation' } } };
  assert.equal(operationResponse(reply, 'v2.op.1.fixture').operation.id, 'v2.op.1.fixture');
  assert.throws(() => operationResponse(reply, 'v2.op.2.other'));
  reply.operation.outcome.code = 'probably-applied';
  assert.throws(() => operationResponse(reply));
  delete reply.operation.outcome;
  assert.throws(() => operationResponse(reply));
});

test('routed administrative copy has complete EN ES PT keys', () => {
  const keys = Object.keys(workspaceMessages.en).sort();
  for (const locale of ['es', 'pt']) assert.deepEqual(Object.keys(workspaceMessages[locale]).sort(), keys);
});

test('verified no-effect finality remains consultable without accepting mismatched reasons', () => {
  for (const [code, reason] of [['profile_changed_without_effects', 'ANDEIVA_RESERVE_PROFILE_CHANGED'], ['confirmation_resolved_without_effects', 'ANDEIVA_CONFIRMATION_RESOLVED']]) {
    const reply = { ...structuredClone(fixtures.routed), operation: { id: 'v2.op.1.fixture', namespace_id: 'v2.ns.1.fixture', domain: 'routed', kind: 'stage', state: 'final', expected_generation: '18446744073709551615', outcome: { code, error_code: reason } } };
    assert.equal(operationResponse(reply).operation.outcome.code, code);
    reply.operation.outcome.error_code = 'ANDEIVA_UNRELATED';
    assert.throws(() => operationResponse(reply));
    reply.operation.outcome.error_code = reason;
    reply.operation.state = 'pending';
    assert.throws(() => operationResponse(reply));
  }
});
