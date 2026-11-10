import { useEffect, useRef, useState } from 'react';
import { Button, Field, Notice, Surface, TextInput } from '../design-system/components.js';
import type { FirewallMessages } from './messages.js';
import { editRule, emptyRule, validateRule } from './model.js';
import type { Rule, RuleDraft, RuleErrors } from './model.js';
import type { RuleTableMessages } from './ruleTableMessages.js';
import type { ConsoleMessages } from './consoleMessages.js';

export function RuleEditor({ rules, index, copy, labels, consoleCopy, supportsEnabled, disabled, onSave, onCancel }: { rules: Rule[]; index: number | null; copy: FirewallMessages; labels: RuleTableMessages; consoleCopy?: ConsoleMessages; supportsEnabled: boolean; disabled: boolean; onSave: (rule: Rule) => void; onCancel: () => void }) {
  const [draft, setDraft] = useState<RuleDraft>(() => index === null ? { ...emptyRule } : editRule(rules[index]!));
  const [errors, setErrors] = useState<RuleErrors>({});
  const form = useRef<HTMLFormElement>(null);
  useEffect(() => {
    const opener = document.activeElement;
    form.current?.querySelector<HTMLInputElement>('input:not([type="checkbox"])')?.focus();
    return () => { requestAnimationFrame(() => { if (opener instanceof HTMLElement && opener.isConnected) opener.focus(); }); };
  }, []);
  return <Surface title={copy.editor} description={index === null ? copy.newRule : draft.id} className="fw-rule-editor">
    {consoleCopy && <details className="console-object-note"><summary>{consoleCopy.objects}</summary><p>{consoleCopy.objectsHint}</p></details>}
    <form ref={form} noValidate onSubmit={(event) => {
      event.preventDefault();
      if (disabled) return;
      const result = validateRule(draft, rules, index);
      setErrors(result.errors);
      if (result.rule) onSave(result.rule);
      else requestAnimationFrame(() => form.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
    }}>
      {Object.keys(errors).length > 0 && <Notice title={copy.validationError} live>{copy.invalidError}</Notice>}
      <fieldset disabled={disabled} className="fw-fields">
        {supportsEnabled && <div className="fw-enabled-field"><label><input type="checkbox" checked={draft.enabled ?? true} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} /> {labels.enabled}</label><p className="ds-field-hint">{labels.toggleHint}</p></div>}
        {(['id', 'source', 'destination', 'source_ports', 'destination_ports'] as const).map((key) => {
          const error = errors[key];
          return <Field key={key} id={`rule-${key}`} label={copy[key]} {...(error ? { error: copy[error] } : {})}>
            <TextInput id={`rule-${key}`} value={draft[key]} maxLength={key === 'id' ? 64 : 32} required spellCheck={false} autoComplete="off" aria-invalid={!!error} aria-describedby={error ? `rule-${key}-error` : undefined} onChange={(event) => { setDraft({ ...draft, [key]: event.target.value }); const next = { ...errors }; delete next[key]; setErrors(next); }} />
          </Field>;
        })}
        <Field id="rule-protocol" label={copy.protocol}><select id="rule-protocol" className="ds-select" value={draft.protocol} onChange={(event) => setDraft({ ...draft, protocol: event.target.value === 'udp' ? 'udp' : 'tcp' })}><option value="tcp">TCP</option><option value="udp">UDP</option></select></Field>
        <Field id="rule-action" label={copy.action}><select id="rule-action" className="ds-select" value={draft.action} onChange={(event) => setDraft({ ...draft, action: event.target.value === 'allow' ? 'allow' : 'deny' })}><option value="deny">{copy.deny}</option><option value="allow">{copy.allow}</option></select></Field>
      </fieldset>
      <details className="console-object-note"><summary>{consoleCopy?.fieldHelp ?? copy.editor}</summary><p>{copy.cidrHint}</p><p>{copy.portsHint}</p></details>
      <div className="ds-actions"><Button type="submit" disabled={disabled}>{copy.applyRule}</Button><Button variant="secondary" onClick={onCancel}>{copy.cancel}</Button></div>
    </form>
  </Surface>;
}
