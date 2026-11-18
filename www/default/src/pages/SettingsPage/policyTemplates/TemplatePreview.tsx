import React, { useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import { Badge } from '../../../components/shared/Badge';
import FieldHelp from '../../../components/shared/FieldHelp';
import { Link } from '../../../components/shared/Link';
import { defaultParameterValues, parseListInput, renderTemplate } from './regoTemplate';
import type { ParameterValues, PolicyTemplate } from './types';

/** Raw text of each setting field, so a list can be typed with its commas. */
export type FieldText = Record<string, string>;

function initialFieldText(template: PolicyTemplate): FieldText {
  return Object.fromEntries(
    template.parameters.map(p => [
      p.key,
      p.kind === 'string_list' ? p.default.join(', ') : String(p.default),
    ])
  );
}

function valuesFromText(template: PolicyTemplate, text: FieldText): ParameterValues {
  return Object.fromEntries(
    template.parameters.map(p => {
      const raw = text[p.key] ?? '';
      if (p.kind === 'integer') return [p.key, raw.trim() ? Number(raw) : NaN];
      return [p.key, p.kind === 'string' ? raw : parseListInput(raw)];
    })
  );
}

/** The Rego a template renders to with its settings as typed. */
export function renderWithText(template: PolicyTemplate, text: FieldText) {
  return renderTemplate(template, valuesFromText(template, text));
}

/**
 * The settings of one template and the Rego they render to, starting from `initialText` or the
 * defaults. Callers key the component that uses it by template id, so choosing another
 * template starts over.
 */
export function useTemplateSettings(template: PolicyTemplate, initialText?: FieldText) {
  const [fieldText, setFieldText] = useState<FieldText>(
    () => initialText ?? initialFieldText(template)
  );
  const rendered = renderWithText(template, fieldText);
  const usesDefaultSettings =
    rendered.rego === renderTemplate(template, defaultParameterValues(template)).rego;
  const setField = (key: string, value: string) =>
    setFieldText(prev => ({ ...prev, [key]: value }));
  return { fieldText, setField, rendered, usesDefaultSettings };
}

interface SettingsFieldsProps {
  template: PolicyTemplate;
  settings: ReturnType<typeof useTemplateSettings>;
  /** Prefix of the field ids and test ids, so two previews on a page don't collide. */
  idPrefix: string;
}

export const TemplateSettingsFields: React.FC<SettingsFieldsProps> = ({
  template,
  settings,
  idPrefix,
}) => (
  <>
    {template.parameters.map(p => {
      const id = `${idPrefix}-param-${p.key}`;
      const err = settings.rendered.errors[p.key];
      return (
        <div className="mb-3" key={p.key}>
          <label className="font-weight-bold" htmlFor={id}>
            {p.label}{' '}
            {p.help && (
              <FieldHelp testId={`field-help-${id}`} ariaLabel={`About ${p.label}`}>
                {p.help}
              </FieldHelp>
            )}
          </label>
          <input
            id={id}
            type={p.kind === 'integer' ? 'number' : 'text'}
            min={p.kind === 'integer' ? p.min : undefined}
            max={p.kind === 'integer' ? p.max : undefined}
            className={`form-control form-control-sm${p.kind === 'integer' ? ' policy-template-number' : ''}${err ? ' is-invalid' : ''}`}
            value={settings.fieldText[p.key] ?? ''}
            onChange={e => settings.setField(p.key, e.target.value)}
            data-testid={id}
          />
          {err && <div className="invalid-feedback">{err}</div>}
        </div>
      );
    })}
  </>
);

/** Each example's expected decision, with its sample input behind a toggle. */
export const TemplateHowItDecides: React.FC<{ template: PolicyTemplate; idPrefix: string }> = ({
  template,
  idPrefix,
}) => {
  const [open, setOpen] = useState<number | null>(null);
  if (template.examples.length === 0) return null;
  return (
    <>
      <div className="font-weight-bold mb-1">How it decides</div>
      <ul className="list-unstyled mb-2">
        {template.examples.map((ex, i) => (
          <li key={`${i}-${ex.name}`} className="policy-template-example-item">
            <div className="policy-template-example">
              <span>{ex.name}</span>
              <span className="d-flex align-items-center gap-2">
                <AppButton
                  variant="link"
                  className="p-0"
                  aria-expanded={open === i}
                  onClick={() => setOpen(o => (o === i ? null : i))}
                  data-testid={`${idPrefix}-example-input-${i}`}
                >
                  {open === i ? 'Hide input' : 'Show input'}
                </AppButton>
                <Badge
                  tone={ex.expected === 'allow' ? 'success' : 'danger'}
                  value={ex.expected.toUpperCase()}
                />
              </span>
            </div>
            {open === i && (
              <pre
                className="policy-preview-block rounded p-2 mb-1 small"
                data-testid={`${idPrefix}-example-input-${i}-json`}
              >
                <code>{JSON.stringify(ex.input, null, 2)}</code>
              </pre>
            )}
          </li>
        ))}
      </ul>
      {template.parameters.length > 0 && (
        <div className="small text-muted mb-2">Examples use the default settings.</div>
      )}
    </>
  );
};

export const TemplateDocsLink: React.FC<{ template: PolicyTemplate; testId: string }> = ({
  template,
  testId,
}) =>
  template.docs_href ? (
    <div className="mb-3">
      <Link href={template.docs_href} external variant="inline" testId={testId}>
        {template.docs_label ?? 'Docs'}
      </Link>
    </div>
  ) : null;
