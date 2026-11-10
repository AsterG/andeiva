import assert from 'node:assert/strict';
import test from 'node:test';
import { sameRuleAtPosition, moveRule, matchesRuleSearch } from '../.test-build/firewall/rulePresentation.js';
import { configWithRules } from '../.test-build/firewall/model.js';
import { ruleEnabledCapability, firewallResponse } from '../.test-build/firewall/responses.js';

const rule = (id) => ({ id, action: 'allow', match: { source: '10.1.0.0/24', destination: '10.2.0.1/32', protocol: 'tcp', source_ports: { from: 1, to: 65535 }, destination_ports: { from: 443, to: 443 } } });
test('Startup comparison includes position, match, verdict and enablement', () => {
  const rules = [rule('one'), rule('two')];
  assert(sameRuleAtPosition(structuredClone(rules[0]), 0, rules));
  assert(!sameRuleAtPosition(rules[0], 1, rules));
  assert(!sameRuleAtPosition({ ...rules[0], enabled: false }, 0, rules));
  assert(sameRuleAtPosition({ ...rules[0], enabled: true }, 0, rules));
  assert(!sameRuleAtPosition({ ...rules[0], action: 'deny' }, 0, rules));
  const changed = structuredClone(rules[0]); changed.match.destination_ports.to = 444;
  assert(!sameRuleAtPosition(changed, 0, rules));
});
test('reordering is immutable, bounded and retains all rules', () => {
  const rules = [rule('one'), rule('two'), rule('three')];
  assert.deepEqual(moveRule(rules, 0, 2).map((r) => r.id), ['two', 'three', 'one']);
  assert.deepEqual(moveRule(rules, 2, 0).map((r) => r.id), ['three', 'one', 'two']);
  assert.deepEqual(rules.map((r) => r.id), ['one', 'two', 'three']);
  for (const [a, b] of [[-1, 0], [0, 3], [1, 1], [0.5, 1], [NaN, 1]]) assert.equal(moveRule(rules, a, b), rules);
});
test('legacy configurations retain absent enabled; migration explicitly fills all v4 rules', () => {
  const config = { schema_version: 2, default_action: 'deny', rules: [rule('one'), rule('two')] };
  assert.equal(configWithRules(config, [...config.rules]).schema_version, 2);
  assert.equal('enabled' in configWithRules(config, config.rules).rules[0], false);
  const next = configWithRules(config, [{ ...config.rules[0], enabled: false }, config.rules[1]]);
  assert.equal(next.schema_version, 4);
  assert.deepEqual(next.rules.map((r) => r.enabled), [false, true]);
  assert.equal(config.schema_version, 2);
});
test('disabled rules require explicit runtime capability and strict versioned response', () => {
  for (const value of [{}, { firewall_rule_enabled: true }, { firewall_rule_enabled: true, firewall_config_schema_versions: [2] }, { firewall_rule_enabled: 'true', firewall_config_schema_versions: [4] }]) assert.equal(ruleEnabledCapability(value), false);
  assert(ruleEnabledCapability({ firewall_rule_enabled: true, firewall_config_schema_versions: [2, 4] }));
  const revision = { hash: 'a'.repeat(64), config: { schema_version: 4, default_action: 'deny', rules: [{ ...rule('one'), enabled: false }] } };
  const state = { snapshot: { generation: 1, running: revision, startup: revision, recovery_required: false }, effective: { revision: revision.hash, state: 'verified', rules: [] } };
  assert.equal(firewallResponse(state).snapshot.running.config.rules[0].enabled, false);
  delete revision.config.rules[0].enabled;
  assert.throws(() => firewallResponse(state));
  revision.config.schema_version = 2;
  assert.doesNotThrow(() => firewallResponse(state));
  revision.config.rules[0].enabled = true;
  assert.throws(() => firewallResponse(state));
});
test('rule search is predictable for IDs, CIDRs, protocols and ports', () => {
  const value = rule('INPUT');
  for (const query of ['input', ' TCP ', '10.1.', '443']) assert(matchesRuleSearch(value, query));
  assert(!matchesRuleSearch(value, 'udp'));
});
