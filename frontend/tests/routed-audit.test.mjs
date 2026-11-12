import assert from 'node:assert/strict';
import test from 'node:test';
import { auditResponse } from '../.test-build/routing/audit.js';

const event = { sequence: '18446744073709551615', at: '2026-11-12T12:00:00Z', actor_id: 'subject-a', actor_name: 'alice', operation_id: 'operation-a', operation: 'save', result: 'applied', generation: '18446744073709551615', running_revision: 'a'.repeat(64), startup_revision: 'b'.repeat(64) };
test('audit response preserves exact sequences and rejects malformed or unordered pages', () => {
  const page = { schema_version: 1, events: [event], next_before: '0', truncated: false };
  assert.equal(auditResponse(page).events[0].sequence, event.sequence);
  const extra = structuredClone(page); extra.events[0].unmodeled_private_field = 'not-a-public-field';
  assert.equal('unmodeled_private_field' in auditResponse(extra).events[0], false);
  for (const change of [
    (p) => { p.events = null; },
    (p) => { p.events.push({ ...p.events[0] }); },
    (p) => { p.events[0].sequence = 18446744073709551615; },
    (p) => { p.next_before = '1'; },
    (p) => { p.events[0].actor_name = '\u001b[2J'; },
    (p) => { p.events[0].at = 'invalid'; },
    (p) => { p.events[0].startup_revision = '../../file'; },
  ]) {
    const value = structuredClone(page); change(value);
    assert.throws(() => auditResponse(value));
  }
});
