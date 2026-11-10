import type { Rule } from './model.js';

// Position is part of policy semantics: moving a matching rule can change the verdict.
export function sameRuleAtPosition(rule: Rule, index: number, rules: Rule[]): boolean {
  const other = rules[index];
  return !!other && rule.id === other.id && (rule.enabled ?? true) === (other.enabled ?? true) && rule.action === other.action &&
    rule.match.source === other.match.source && rule.match.destination === other.match.destination &&
    rule.match.protocol === other.match.protocol &&
    rule.match.source_ports.from === other.match.source_ports.from && rule.match.source_ports.to === other.match.source_ports.to &&
    rule.match.destination_ports.from === other.match.destination_ports.from && rule.match.destination_ports.to === other.match.destination_ports.to;
}

export function moveRule(rules: Rule[], from: number, to: number): Rule[] {
  if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < 0 || from >= rules.length || to >= rules.length || from === to) return rules;
  const next = [...rules];
  const [rule] = next.splice(from, 1);
  next.splice(to, 0, rule!);
  return next;
}

export function ruleChange(rule: Rule, index: number, reference: Rule[]): 'new' | 'modified' | 'moved' | undefined {
  const previous = reference.findIndex((entry) => entry.id === rule.id);
  if (previous < 0) return 'new';
  if (!sameRuleAtPosition(rule, previous, reference)) return 'modified';
  return previous !== index ? 'moved' : undefined;
}

export function matchesRuleSearch(rule: Rule, query: string): boolean {
  return [rule.id, rule.match.source, rule.match.destination, rule.match.protocol,
    `${rule.match.source_ports.from}-${rule.match.source_ports.to}`, `${rule.match.destination_ports.from}-${rule.match.destination_ports.to}`]
    .join(' ').toLowerCase().includes(query.trim().toLowerCase());
}
