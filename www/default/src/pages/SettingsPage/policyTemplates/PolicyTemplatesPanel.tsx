import React, { useState } from 'react';
import { defaultDecision, insertTemplateRules } from './regoTemplate';
import { DecisionBadge } from './TemplateBadges';
import {
  TemplateDocsLink,
  TemplateHowItDecides,
  TemplateSettingsFields,
  useTemplateSettings,
} from './TemplatePreview';
import { useAllPolicyTemplates, usePolicyTemplates } from './usePolicyTemplates';
import { useTemplateFilter } from './useTemplateFilter';
import { CATEGORY_LABELS, type PolicyTemplate, type PolicyType } from './types';
import './PolicyTemplates.css';

type Source = 'builtin' | 'organization';

interface PolicyTemplatesPanelProps {
  policyType: PolicyType;
  /** The editor's current Rego, which Add to policy appends to. */
  existingPolicy?: string;
  /** `usesDefaultSettings` is false when a setting differs from its default. */
  onInsert: (template: PolicyTemplate, rego: string, usesDefaultSettings: boolean) => void;
}

const TYPE_LABEL: Record<PolicyType, string> = {
  gateway: 'Gateway',
  agent_surface: 'Agent Surfaces',
};

const ID_PREFIX = 'policy-templates';

/** The chosen template's settings, the lines it adds, its notes and Add to policy. */
const InsertPreview: React.FC<{
  template: PolicyTemplate;
  existingPolicy: string;
  onInsert: PolicyTemplatesPanelProps['onInsert'];
}> = ({ template, existingPolicy, onInsert }) => {
  const settings = useTemplateSettings(template);
  const { rendered, usesDefaultSettings } = settings;
  const insert = rendered.rego
    ? insertTemplateRules(existingPolicy, template.name, rendered.rego)
    : null;
  const forToolBinding = template.policy_input === 'mcp_tool';
  const refused = !!template.standalone || forToolBinding;
  const canInsert = !!insert?.added && !refused;

  return (
    <div className="policy-template-preview" data-testid="policy-templates-preview">
      <h6 className="fw-bold mb-1">{template.name}</h6>
      <p className="text-muted small mb-2">{template.description}</p>
      <div className="mb-3">
        <DecisionBadge decision={defaultDecision(template.rego)} prefix="Default" />
      </div>

      <TemplateSettingsFields template={template} settings={settings} idPrefix={ID_PREFIX} />

      {refused ? (
        <>
          <div
            className="alert alert-info py-2 px-3 small"
            data-testid={
              forToolBinding ? 'policy-templates-mcp-tool-note' : 'policy-templates-standalone-note'
            }
          >
            <i className="fas fa-info-circle me-2" aria-hidden="true" />
            {forToolBinding ? (
              <>
                This template is for a policy bound to MCP tools on the MCP Proxy hop, which reads{' '}
                <code>input.jwt</code> and the tool name. Use it as a whole policy.
              </>
            ) : (
              <>
                Use this template as a whole policy. Its rules allow requests outside what it
                restricts, so added to a policy they would allow requests that policy denies.
              </>
            )}
          </div>
          <pre
            className="policy-preview-block rounded p-2 mb-3 small"
            data-testid="policy-templates-rego-preview"
          >
            <code>{rendered.rego ?? 'Fix the settings above to see the Rego.'}</code>
          </pre>
        </>
      ) : (
        <>
          <div className="font-weight-bold mb-1">Added to the end of the policy</div>
          <pre
            className="policy-preview-block rounded p-2 mb-2 small"
            data-testid="policy-templates-insert-preview"
          >
            <code>
              {insert ? insert.added || '(none)' : 'Fix the settings above to see the rules.'}
            </code>
          </pre>
          {!template.builtin && insert?.added && (
            <div
              className="alert alert-warning py-2 px-3 small"
              data-testid="policy-templates-org-insert-warning"
            >
              <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
              This template was saved from a policy, so its rules are added as written. Rules
              combine with OR: check that none of them allows requests this policy should deny.
            </div>
          )}
          {insert && !insert.added && (
            <div className="text-muted small mb-2">
              This template adds no rules to an existing policy.
            </div>
          )}
        </>
      )}

      <TemplateHowItDecides template={template} idPrefix={ID_PREFIX} />
      <TemplateDocsLink template={template} testId="policy-templates-docs-link" />
      <div className="d-flex justify-content-end">
        <button
          type="button"
          className="btn btn-sm btn-primary"
          disabled={!canInsert}
          onClick={() => rendered.rego && onInsert(template, rendered.rego, usesDefaultSettings)}
          data-testid="policy-templates-insert-rules-button"
        >
          <i className="fas fa-plus me-1" aria-hidden="true" />
          Add to policy
        </button>
      </div>
    </div>
  );
};

/** The templates column's Add rules panel: pick a template and add its rules to the Rego. */
const PolicyTemplatesPanel: React.FC<PolicyTemplatesPanelProps> = ({
  policyType,
  existingPolicy = '',
  onInsert,
}) => {
  const { builtin, organization, loading, error } = usePolicyTemplates(policyType);
  const [source, setSource] = useState<Source>('builtin');
  const [selected, setSelected] = useState<PolicyTemplate | null>(null);

  const sourceTemplates = source === 'builtin' ? builtin : organization;
  const { query, setQuery, category, setCategory, categories, visible } =
    useTemplateFilter(sourceTemplates);
  // Templates written only for the other policy type, which this policy can't use.
  const otherTypeOnly = useAllPolicyTemplates().filter(e => !e.variants[policyType]).length;

  const switchSource = (next: Source) => {
    setSource(next);
    setCategory('all');
    setSelected(null);
  };

  return (
    <div className="card mb-3 policy-templates-panel" data-testid="policy-templates-panel">
      <div className="card-header py-3">
        <div className="small text-muted">
          <i className="fas fa-layer-group me-1 text-primary" aria-hidden="true" />
          Templates · {TYPE_LABEL[policyType]}
        </div>
        <h6 className="m-0 mt-1 font-weight-bold text-primary">Add rules from a template</h6>
        <div className="small text-muted">
          Pick a template, adjust its settings, and add its rules to the policy. Add several to
          combine them.
        </div>
      </div>
      <div className="card-body">
        <ul className="nav nav-tabs mb-2" role="tablist">
          {(
            [
              ['builtin', 'Built-in', builtin.length],
              ['organization', 'Your organization', organization.length],
            ] as const
          ).map(([key, label, count]) => (
            <li className="nav-item" role="presentation" key={key}>
              <button
                type="button"
                role="tab"
                aria-selected={source === key}
                className={`nav-link ${source === key ? 'active' : ''}`}
                onClick={() => switchSource(key)}
                data-testid={`policy-templates-tab-${key}`}
              >
                {label} · {count}
              </button>
            </li>
          ))}
        </ul>
        <input
          type="search"
          className="form-control form-control-sm mb-2"
          placeholder="e.g. role, trust, path"
          aria-label="Search templates"
          value={query}
          onChange={e => setQuery(e.target.value)}
          data-testid="policy-templates-search-input"
        />
        {categories.length > 1 && (
          <ul className="nav nav-pills custom-channel-tabs gap-2 mb-3">
            {(['all', ...categories] as const).map(key => (
              <li className="nav-item" key={key}>
                <button
                  type="button"
                  className={`nav-link py-1 ${category === key ? 'active' : ''}`}
                  aria-pressed={category === key}
                  onClick={() => setCategory(key)}
                  data-testid={`policy-templates-category-${key}`}
                >
                  {key === 'all' ? 'All' : CATEGORY_LABELS[key]}
                </button>
              </li>
            ))}
          </ul>
        )}

        {loading && (
          <div className="text-muted small">
            <span className="spinner-border spinner-border-sm me-2" role="status" />
            Loading templates…
          </div>
        )}
        {error && <div className="alert alert-danger py-2 px-3 small">{error}</div>}
        {!loading && source === 'organization' && organization.length === 0 && (
          <div className="text-muted small py-2" data-testid="policy-templates-organization-empty">
            No organization templates yet. Open a saved policy and choose{' '}
            <strong>Save as template</strong> to add one.
          </div>
        )}
        {!loading && sourceTemplates.length > 0 && visible.length === 0 && (
          <div className="text-muted small py-2">No templates match.</div>
        )}

        <div className="policy-templates-panel__layout">
          <div className="policy-templates-panel__list">
            <ul className="list-unstyled mb-0 policy-template-list">
              {visible.map(t => (
                <li key={t.id}>
                  <button
                    type="button"
                    className={`policy-template-row${selected?.id === t.id ? ' is-selected' : ''}`}
                    aria-pressed={selected?.id === t.id}
                    onClick={() => setSelected(t)}
                    data-testid={`policy-templates-row-${t.id}`}
                  >
                    <span className="policy-template-row__text">
                      <span className="policy-template-row__name">{t.name}</span>
                      <span className="policy-template-row__summary">{t.summary}</span>
                    </span>
                    <span className="d-flex flex-column align-items-end gap-1">
                      <DecisionBadge decision={defaultDecision(t.rego)} />
                      {t.policy_input === 'mcp_tool' && (
                        <span className="badge policy-template-reads">MCP tool policy</span>
                      )}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            {otherTypeOnly > 0 && (
              <div className="small text-muted mt-2" data-testid="policy-templates-other-type-note">
                {otherTypeOnly} {otherTypeOnly === 1 ? 'template is' : 'templates are'} for{' '}
                {policyType === 'gateway' ? 'Agent Surface' : 'Gateway'} policies only.
              </div>
            )}
          </div>

          {selected ? (
            <InsertPreview
              key={selected.id}
              template={selected}
              existingPolicy={existingPolicy}
              onInsert={onInsert}
            />
          ) : (
            <div
              className="policy-templates-panel__placeholder"
              data-testid="policy-templates-preview-empty"
            >
              <i className="fas fa-hand-pointer me-2" aria-hidden="true" />
              Pick a template to see its rules and settings.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PolicyTemplatesPanel;
