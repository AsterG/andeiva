import { Button, Notice, StatusBadge, Surface } from '../design-system/components.js';
import type { Locale } from '../messages.js';
import type { ProductInfoState } from './productInfo.js';
import { systemMessages } from './systemMessages.js';

export function productVersionLabel(state: ProductInfoState, locale: Locale): string {
  const copy = systemMessages[locale];
  return state.state === 'ready' ? state.info.version ?? copy.development : state.state === 'loading' ? copy.loading : copy.updateUnavailable;
}

export function SystemInfoView({ state, locale, refresh }: { state: ProductInfoState; locale: Locale; refresh: () => void }) {
  const copy = systemMessages[locale];
  return <Surface title={copy.about} description={copy.intro} className="console-system-info">
    <div aria-busy={state.state === 'loading'} aria-live="polite">
      {state.state === 'loading' ? <Notice title={copy.loading}>{copy.sourceHint}</Notice> : state.state === 'unavailable' ? <Notice title={copy.unavailable}>{copy.unavailableHint}</Notice> : <>
        <dl className="console-system-facts">
          <div><dt>{copy.product}</dt><dd>{state.info.product}</dd></div>
          <div><dt>{copy.version}</dt><dd><strong>{state.info.version ?? copy.noVersion}</strong></dd></div>
          <div><dt>{copy.channel}</dt><dd><StatusBadge tone="info">{state.info.channel === 'experimental' ? copy.experimental : copy.development}</StatusBadge></dd></div>
          <div><dt>{copy.updates}</dt><dd>{copy.updateUnavailable}</dd></div>
        </dl>
        <p className="fw-meta">{copy.updateHint}</p>
        <p className="fw-meta">{copy.sourceHint}</p>
      </>}
    </div>
    <div className="ds-actions"><Button variant="secondary" disabled={state.state === 'loading'} onClick={refresh}>{copy.refresh}</Button></div>
  </Surface>;
}
