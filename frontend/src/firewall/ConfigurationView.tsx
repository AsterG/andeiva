import { DataTable, Surface } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import { consoleMessages } from './consoleMessages.js';
import { firewallMessages } from './messages.js';
import type { Rule, Snapshot } from './model.js';
import { formatPorts } from './model.js';
import { sameRuleAtPosition } from './rulePresentation.js';

export function ConfigurationView({ snapshot, locale }: { snapshot: Snapshot; locale: Locale }) {
  const copy = consoleMessages[locale];
  const labels = firewallMessages[locale];
  const revisions = [snapshot.candidate?.revision, snapshot.running, snapshot.startup];
  const keys = ['candidate', 'running', 'startup'] as const;
  const ids = [...new Set(revisions.flatMap((revision) => revision?.config.rules.map((rule) => rule.id) ?? []))];
  function changes(rule: Rule, position: number) {
    const previousPosition = snapshot.running.config.rules.findIndex((entry) => entry.id === rule.id);
    const previous = snapshot.running.config.rules[previousPosition];
    const values = (entry: Rule | undefined, index: number) => [entry ? String(index + 1) : copy.absent, entry ? entry.enabled === false ? copy.disabled : copy.active : copy.absent, entry ? labels[entry.action] : copy.absent, entry?.match.source ?? copy.absent, entry?.match.destination ?? copy.absent, entry?.match.protocol.toUpperCase() ?? copy.absent, entry ? formatPorts(entry.match.source_ports) : copy.absent, entry ? formatPorts(entry.match.destination_ports) : copy.absent];
    const before = values(previous, previousPosition); const after = values(rule, position);
    const fields = [copy.position, copy.active, labels.action, labels.source, labels.destination, labels.protocol, labels.source_ports, labels.destination_ports];
    return fields.flatMap((field, index) => before[index] === after[index] ? [] : [{ field, before: before[index], after: after[index] }]);
  }
  return <Surface title={copy.state} description={copy.stateHint}>
    <div className="console-state-cards">{keys.map((key, index) => <article key={key}><h3>{labels[key]}</h3><p>{copy[`${key}Hint`]}</p><p>{revisions[index] ? `${labels.rules}: ${revisions[index]!.config.rules.length}` : copy.noCandidate}</p><details><summary>{labels.target}</summary><code className="fw-hash">{revisions[index]?.hash ?? copy.noCandidate}</code><pre className="console-diff">{revisions[index] ? JSON.stringify(revisions[index]!.config, null, 2) : copy.noCandidate}</pre></details></article>)}</div>
    <DataTable caption={copy.compare}><thead><tr><th scope="col">{labels.id}</th>{keys.map((key) => <th key={key} scope="col">{labels[key]}</th>)}</tr></thead><tbody>{ids.map((id) => {
      return <tr key={id}><th scope="row">{id}</th>{revisions.map((revision, index) => {
        const position = revision?.config.rules.findIndex((rule) => rule.id === id) ?? -1;
        const rule = revision?.config.rules[position];
        return <td key={keys[index]}>{!rule ? copy.absent : <>{copy.position} {position + 1} · {rule.enabled === false ? copy.disabled : copy.active}<br />{sameRuleAtPosition(rule, position, snapshot.running.config.rules) ? copy.same : <details open><summary>{copy.changed}</summary><ul className="console-field-diff">{changes(rule, position).map((change) => <li key={change.field}><strong>{change.field}</strong>: {change.before} → {change.after}</li>)}</ul></details>}</>}</td>;
      })}</tr>;
    })}{ids.length === 0 && <tr><td colSpan={4}>{labels.emptyHistory}</td></tr>}</tbody></DataTable>
  </Surface>;
}
