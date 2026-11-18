import React, { useMemo } from 'react';
import FormSelect, { type FormSelectOption } from '../../../components/shared/FormSelect';
import FieldHelp from '../../../components/shared/FieldHelp';
import { defaultDecision } from './regoTemplate';
import { usePolicyTemplates } from './usePolicyTemplates';
import type { PolicyTemplate, PolicyType } from './types';

export const BLANK_TEMPLATE_ID = 'blank';

interface TemplateFieldProps {
  policyType: PolicyType;
  /** The chosen template id, `blank`, or null once the Rego no longer follows one. */
  value: string | null;
  browseOpen: boolean;
  onPickBlank: () => void;
  onPickTemplate: (template: PolicyTemplate) => void;
  onBrowse: () => void;
}

const decisionLabel = (rego: string) =>
  defaultDecision(rego) === 'allow' ? 'Default allow' : 'Default deny';

/** The create form's Template field: Blank, then built-in, then organisation templates. */
const TemplateField: React.FC<TemplateFieldProps> = ({
  policyType,
  value,
  browseOpen,
  onPickBlank,
  onPickTemplate,
  onBrowse,
}) => {
  const { builtin, organization } = usePolicyTemplates(policyType);
  const all = useMemo(() => [...builtin, ...organization], [builtin, organization]);
  const options = useMemo<FormSelectOption<string>[]>(
    () => [
      {
        value: BLANK_TEMPLATE_ID,
        label: 'Blank',
        description: 'The default policy, which allows all traffic',
      },
      ...builtin.map(t => ({
        value: t.id,
        label: t.name,
        description: `${decisionLabel(t.rego)} · ${t.summary}`,
      })),
      ...organization.map(t => ({
        value: t.id,
        label: t.name,
        description: `Your organization · ${decisionLabel(t.rego)} · ${t.summary}`,
      })),
    ],
    [builtin, organization]
  );

  return (
    <div className="mb-3">
      <span className="font-weight-bold d-inline-flex align-items-center gap-1">
        Template{' '}
        <FieldHelp testId="field-help-policy-definition-template" ariaLabel="About Template">
          A template fills Name, Description and the Rego with a proven pattern. Settings use their
          defaults; open Browse templates to change them. You can edit everything before you save.
        </FieldHelp>
      </span>
      <div className="d-flex gap-2 align-items-start">
        <FormSelect
          className="flex-grow-1"
          value={value ?? ''}
          placeholder="Custom Rego"
          options={options}
          ariaLabel="Template"
          testid="policy-definition-template-select"
          onChange={id => {
            if (id === BLANK_TEMPLATE_ID) {
              onPickBlank();
              return;
            }
            const template = all.find(t => t.id === id);
            if (template) onPickTemplate(template);
          }}
        />
        <button
          type="button"
          className={`btn btn-sm btn-outline-primary text-nowrap${browseOpen ? ' active' : ''}`}
          aria-pressed={browseOpen}
          onClick={onBrowse}
          data-testid="policy-templates-browse-button"
        >
          <i className="fas fa-layer-group me-1" aria-hidden="true" />
          Browse templates
        </button>
      </div>
      <small className="form-text text-muted">
        Fills Name, Description and Rego. Choose Blank to start from the default policy.
      </small>
    </div>
  );
};

export default TemplateField;
