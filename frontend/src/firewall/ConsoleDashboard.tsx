import { StatusBadge, Surface } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import { ConsoleIcon } from './ConsoleIcon.js';
import { consoleMessages } from './consoleMessages.js';
import { firewallMessages } from './messages.js';
import type { FirewallState } from './model.js';

export function ConsoleDashboard({ state, verified, locale, observed }: { state: FirewallState; verified: boolean; locale: Locale; observed?: string }) {
  const copy = consoleMessages[locale];
  const labels = firewallMessages[locale];
  const rules = state.snapshot.running.config.rules;
  const count = (value: number | bigint | null) => value === null ? copy.unavailable : value.toLocaleString(locale);
  const sums = verified ? state.effective.rules.reduce((value, rule) => ({ packets: value.packets + BigInt(rule.packets), bytes: value.bytes + BigInt(rule.bytes) }), { packets: 0n, bytes: 0n }) : null;
  const metrics = [[copy.total, rules.length, 'rules'], [copy.active, rules.filter((rule) => rule.enabled !== false).length, 'rules'], [copy.disabled, rules.filter((rule) => rule.enabled === false).length, 'rules'], [copy.packets, sums?.packets ?? null, 'traffic'], [copy.bytes, sums?.bytes ?? null, 'traffic']] as const;
  return <>
    <div className="console-kpis">{metrics.map(([title, value, icon]) => <article className="console-kpi" key={title}><ConsoleIcon name={icon} /><div><p>{title}</p><strong>{count(value)}</strong><small>{verified ? copy.sample : copy.stateUnknown}</small></div></article>)}</div>
    <div className="console-dashboard-grid">
      <Surface title={copy.geo}><div className="console-empty console-geo"><div className="console-world-map" aria-hidden="true" /><div className="console-map-caption"><strong>{copy.unavailable}</strong><p>{copy.geoHint}</p></div></div><p className="fw-meta">{copy.mapCredit}</p></Surface>
      <Surface title={copy.bandwidth}><div className="console-empty"><ConsoleIcon name="traffic" /><strong>{copy.unavailable}</strong><p>{copy.bandwidthHint}</p></div></Surface>
    </div>
    <div className="console-dashboard-lower">
      <Surface title={copy.state}><StatusBadge tone={state.snapshot.running.hash === state.snapshot.startup.hash ? 'success' : 'warning'}>{state.snapshot.running.hash === state.snapshot.startup.hash ? copy.persisted : copy.unsaved}</StatusBadge><p className="fw-meta">{copy.stateHint}</p><a href="#configuration">{copy.compare}</a></Surface>
      <Surface title={copy.health}><StatusBadge tone={verified ? state.effective.state === 'verified' ? 'success' : 'warning' : 'warning'}>{verified ? labels[state.effective.state] : copy.stateUnknown}</StatusBadge><p className="fw-meta">{verified && observed ? <time dateTime={observed}>{new Date(observed).toLocaleString(locale)}</time> : copy.valuesUnknown}</p><details><summary>{labels.effectiveRevision}</summary><code className="fw-hash">{verified ? state.effective.revision : copy.unavailable}</code></details></Surface>
      <Surface title={copy.resources}><strong>{copy.unavailable}</strong><p className="fw-meta">{copy.resourceHint}</p></Surface>
    </div>
  </>;
}
