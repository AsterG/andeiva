import { Button } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import type { Rule } from '../firewall/model.js';
import { RuleTable } from '../firewall/RuleTable.js';
import { firewallMessages } from '../firewall/messages.js';
import type { ConfigurationCurrent, RetainedConfig } from './configuration.js';
import { workspaceMessages } from './workspaceMessages.js';

export function RetainedRules({ locale, current, config, editable, editing, verified, onEdit, onChange }: {
  locale: Locale; current: ConfigurationCurrent; config: RetainedConfig; editable: boolean; editing: boolean; verified: boolean;
  onEdit: (index: number | null) => void; onChange: (config: RetainedConfig) => void;
}) {
  const copy = workspaceMessages[locale];
  const change = (rules: Rule[]) => onChange({ ...config, rules });
  return <RuleTable controls={<Button disabled={!editable || editing || config.rules.length >= 128} onClick={() => onEdit(null)}>{copy.add}</Button>}
    view="configuration-v2-retained" rules={config.rules} reference={current.snapshot.running.config.rules}
    state={{ snapshot: current.snapshot, effective: { revision: current.snapshot.running.hash, state: verified ? 'verified' : 'unavailable', rules: [] } }}
    locale={locale} copy={firewallMessages[locale]} editable={editable} reorderable={editable} showCounters={false} verified={verified} editing={editing} supportsEnabled
    onToggle={(index, enabled) => change(config.rules.map((rule, position) => index === position ? { ...rule, enabled } : rule))}
    onMove={(from, to) => { const rules = [...config.rules], [rule] = rules.splice(from, 1); rules.splice(to, 0, rule!); change(rules); }}
    onEdit={onEdit} onRemove={(index) => change(config.rules.filter((_, position) => index !== position))} />;
}
