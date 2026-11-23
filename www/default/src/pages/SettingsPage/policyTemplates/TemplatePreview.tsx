import React, { useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import { Badge } from '../../../components/shared/Badge';
import FieldHelp from '../../../components/shared/FieldHelp';
import { Link } from '../../../components/shared/Link';
import { sampleOf } from './regoTemplate';
import { samplePlaceholder } from './templateSettings';
import type { TemplateSettings } from './useTemplateSettings';
import type { PolicyTemplate } from './types';

/** Muted note under a preview drawn with the sample values of empty settings. */
export const SampleValuesNote: React.FC<{ testId: string }> = ({ testId }) => (
  <div className="small text-muted mb-2" data-testid={testId}>
    Shown with sample values for the empty settings.
  </div>
);

interface SettingsFieldsProps {
  template: PolicyTemplate;
  settings: TemplateSettings;
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
      const required = settings.missing.has(p.key);
      const requiredId = `${id}-required`;
      const err = required ? undefined : settings.rendered.errors[p.key];
      return (
        <div className="mb-3" key={p.key}>
          <div className="field-label-with-help">
            <label htmlFor={id} className="mb-0">
              {p.label}
            </label>
            {p.help && (
              <FieldHelp testId={`field-help-${id}`} ariaLabel={`About ${p.label}`}>
                {p.help}
              </FieldHelp>
            )}
          </div>
          {p.kind === 'choice' ? (
            <select
              id={id}
              className={`form-control dropdown-styling${err ? ' is-invalid' : ''}`}
              value={settings.fieldText[p.key] ?? ''}
              onChange={e => settings.setField(p.key, e.target.value)}
              data-testid={id}
            >
              {p.options.map(o => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          ) : (
            <input
              id={id}
              type={p.kind === 'integer' ? 'number' : p.kind === 'time_of_day' ? 'time' : 'text'}
              min={p.kind === 'integer' ? p.min : undefined}
              max={p.kind === 'integer' ? p.max : undefined}
              className={`form-control${p.kind === 'integer' ? ' policy-template-number' : ''}${p.kind === 'time_of_day' ? ' policy-template-time' : ''}${err ? ' is-invalid' : ''}`}
              value={settings.fieldText[p.key] ?? ''}
              placeholder={samplePlaceholder(template, p.key)}
              aria-required={sampleOf(p) !== undefined || undefined}
              aria-describedby={required ? requiredId : undefined}
              onChange={e => settings.setField(p.key, e.target.value)}
              data-testid={id}
            />
          )}
          {err && <div className="invalid-feedback">{err}</div>}
          {required && (
            <div className="small text-muted mt-1" id={requiredId} data-testid={requiredId}>
              Required before the template can be used.
            </div>
          )}
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
                className="policy-preview-block policy-template-example-input rounded p-2 mb-1 small"
                data-testid={`${idPrefix}-example-input-${i}-json`}
              >
                <code>{JSON.stringify(ex.input, null, 2)}</code>
              </pre>
            )}
          </li>
        ))}
      </ul>
      {template.parameters.length > 0 && (
        <div className="small text-muted mb-2">
          {template.parameters.some(p => sampleOf(p) !== undefined)
            ? 'Examples use the default settings and the sample values shown in empty fields.'
            : 'Examples use the default settings.'}
        </div>
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
