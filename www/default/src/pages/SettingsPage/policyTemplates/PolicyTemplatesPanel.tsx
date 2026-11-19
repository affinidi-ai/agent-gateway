import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import InfoBanner from '../../../components/shared/InfoBanner';
import { defaultDecision, insertTemplateRules, templateRole } from './regoTemplate';
import { DecisionBadge, TemplateOriginBadges, TemplateRoleBadge } from './TemplateBadges';
import TemplateFilterBar from './TemplateFilterBar';
import { TemplateDocsLink, TemplateHowItDecides, TemplateSettingsFields } from './TemplatePreview';
import { useTemplateSettings } from './useTemplateSettings';
import { galleryTemplates, type PolicyTemplateLibrary } from './usePolicyTemplates';
import { useTemplateFilter } from './useTemplateFilter';
import { POLICY_TYPE_NAMES, type PolicyTemplate, type PolicyType } from './types';
import './PolicyTemplates.css';

type Source = 'builtin' | 'organization';

interface PolicyTemplatesPanelProps {
  policyType: PolicyType;
  /** Every template, from `useAllPolicyTemplates`. */
  library: PolicyTemplateLibrary;
  /** The editor's current Rego, which Add to policy appends to. */
  existingPolicy?: string;
  /** On the create form whole policies are offered under Start from. */
  isCreateMode: boolean;
  /** `usesDefaultSettings` is false when a setting differs from its default. */
  onInsert: (template: PolicyTemplate, rego: string, usesDefaultSettings: boolean) => void;
}

const ID_PREFIX = 'policy-templates';

const addsRules = (t: PolicyTemplate) => templateRole(t) === 'rules';

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The chosen template's settings, the lines it adds, its notes and Add to policy. */
const InsertPreview: React.FC<{
  template: PolicyTemplate;
  existingPolicy: string;
  onInsert: PolicyTemplatesPanelProps['onInsert'];
}> = ({ template, existingPolicy, onInsert }) => {
  const settings = useTemplateSettings(template);
  const { rendered, usesDefaultSettings } = settings;
  // The preview sits under the list, so picking a row scrolls only as far as needed to show it.
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    headingRef.current?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
  }, []);
  const insert = rendered.rego
    ? insertTemplateRules(existingPolicy, template.name, rendered.rego)
    : null;
  const canInsert = !!insert?.added;

  return (
    <div className="policy-template-preview" data-testid="policy-templates-preview">
      <h6 ref={headingRef} className="fw-bold mb-1" data-testid="policy-templates-preview-heading">
        {template.name}
      </h6>
      <p className="text-muted small mb-2">{template.description}</p>
      <div className="d-flex flex-wrap gap-2 mb-3">
        <TemplateRoleBadge template={template} />
        <DecisionBadge decision={defaultDecision(template.rego)} />
        <TemplateOriginBadges template={template} />
      </div>

      <TemplateSettingsFields template={template} settings={settings} idPrefix={ID_PREFIX} />

      <div className="font-weight-bold mb-1">Added to the end of the policy</div>
      <pre
        className="policy-preview-block rounded p-2 mb-2 small"
        data-testid="policy-templates-insert-preview"
      >
        <code>{insert ? insert.added : 'Fix the settings above to see the rules.'}</code>
      </pre>
      {canInsert && defaultDecision(existingPolicy) === 'allow' && (
        <div data-testid="policy-templates-allow-default-note">
          <InfoBanner
            variant="warning"
            icon="fa-exclamation-triangle"
            collapsible={false}
            className="mb-2"
            summary="This policy allows every request by default, so these rules change nothing until you choose Deny by default."
          />
        </div>
      )}
      {canInsert && (
        <div data-testid="policy-templates-or-note">
          <InfoBanner
            collapsible={false}
            className="mb-2"
            summary={
              <>
                Allow rules combine with OR: a request passes when any allow rule matches. Its{' '}
                <code>default allow</code> line is not copied.
              </>
            }
          />
        </div>
      )}
      {!template.builtin && canInsert && (
        <div data-testid="policy-templates-org-insert-warning">
          <InfoBanner
            variant="warning"
            icon="fa-exclamation-triangle"
            collapsible={false}
            className="mb-2"
            summary="This template was saved from a policy, so its rules are added as written. Rules combine with OR: check that none of them allows requests this policy should deny."
          />
        </div>
      )}

      <TemplateHowItDecides template={template} idPrefix={ID_PREFIX} />
      <TemplateDocsLink template={template} testId="policy-templates-docs-link" />
      <div className="d-flex justify-content-end">
        <AppButton
          disabled={!canInsert}
          onClick={() => rendered.rego && onInsert(template, rendered.rego, usesDefaultSettings)}
          iconStart={<i className="fas fa-plus" aria-hidden="true" />}
          data-testid="policy-templates-insert-rules-button"
        >
          Add to policy
        </AppButton>
      </div>
    </div>
  );
};

/** The templates column's Add rules panel: pick a template and add its rules to the Rego. */
const PolicyTemplatesPanel: React.FC<PolicyTemplatesPanelProps> = ({
  policyType,
  library: { entries, loading: loadingByType, error },
  existingPolicy = '',
  isCreateMode,
  onInsert,
}) => {
  // This Type's list decides the spinner and empty states; the left-out note counts the other
  // Type too, so it waits for both.
  const loading = loadingByType[policyType];
  const allLoaded = !loadingByType.gateway && !loadingByType.agent_surface;
  const ofType = useMemo(() => galleryTemplates(entries, policyType), [entries, policyType]);
  const allBuiltin = useMemo(() => ofType.filter(t => t.builtin), [ofType]);
  const organization = useMemo(() => ofType.filter(t => !t.builtin), [ofType]);
  const [source, setSource] = useState<Source>('builtin');
  const [selected, setSelected] = useState<PolicyTemplate | null>(null);

  const builtin = useMemo(() => allBuiltin.filter(addsRules), [allBuiltin]);
  const organizationRules = useMemo(() => organization.filter(addsRules), [organization]);
  const sourceTemplates = source === 'builtin' ? builtin : organizationRules;
  const { query, setQuery, category, setCategory, categories, visible } =
    useTemplateFilter(sourceTemplates);
  // A template the search or category hides shows no preview until it is listed again.
  const shownSelected = visible.find(t => t.id === selected?.id) ?? null;
  const wholePolicies =
    allBuiltin.length + organization.length - builtin.length - organizationRules.length;
  const otherTypeOnly = entries.filter(e => !e.variants[policyType]).length;
  const leftOut = wholePolicies + otherTypeOnly;
  const otherTypeName =
    POLICY_TYPE_NAMES[policyType === 'gateway' ? 'agent_surface' : 'gateway'].name;

  const switchSource = (next: Source) => {
    setSource(next);
    setCategory('all');
    setSelected(null);
  };

  return (
    <div className="card shadow mb-4" data-testid="policy-templates-panel">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-layer-group" aria-hidden="true" /> Add rules from a template
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted small mb-2">Adds rules to the end of this policy.</p>
        <ul className="nav nav-tabs mb-2" role="tablist">
          {(
            [
              ['builtin', 'Default templates', builtin.length],
              ['organization', 'Organization templates', organizationRules.length],
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
                {label} ({count})
              </button>
            </li>
          ))}
        </ul>
        <TemplateFilterBar
          query={query}
          onQueryChange={setQuery}
          category={category}
          onCategoryChange={setCategory}
          categories={categories}
          testIdPrefix="policy-templates"
          fullWidth
          className="policy-template-filters--stacked mb-3"
        />

        {loading && (
          <div className="text-muted small">
            <span className="spinner-border spinner-border-sm me-2" role="status" />
            Loading templates…
          </div>
        )}
        {error && <div className="alert alert-danger py-2 px-3 small">{error}</div>}
        {!loading && source === 'organization' && organization.length === 0 && (
          <div className="text-muted small py-2" data-testid="policy-templates-organization-empty">
            No organization templates yet. These are templates you saved from a policy in this tab.
            To add one, open a saved policy and choose <strong>Save as template</strong>.
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
                      <TemplateRoleBadge template={t} />
                      <DecisionBadge decision={defaultDecision(t.rego)} />
                      <TemplateOriginBadges template={t} />
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            {allLoaded && leftOut > 0 && (
              <div className="small text-muted mt-2" data-testid="policy-templates-left-out-note">
                {`${plural(leftOut, 'template', 'templates')} left out: ${[
                  wholePolicies > 0 &&
                    plural(wholePolicies, 'is a whole policy', 'are whole policies'),
                  otherTypeOnly > 0 &&
                    `${plural(otherTypeOnly, 'is', 'are')} for ${otherTypeName} policies`,
                ]
                  .filter(Boolean)
                  .join(', ')}.`}
                {wholePolicies > 0 &&
                  (isCreateMode
                    ? ' Pick a whole policy under Start from.'
                    : ' Whole policies are offered only when creating a policy.')}
              </div>
            )}
          </div>

          {shownSelected ? (
            <InsertPreview
              key={shownSelected.id}
              template={shownSelected}
              existingPolicy={existingPolicy}
              onInsert={onInsert}
            />
          ) : (
            <div
              className="policy-templates-panel__placeholder"
              data-testid="policy-templates-preview-empty"
            >
              <i className="fas fa-hand-pointer me-2" aria-hidden="true" />
              Pick a template to preview the rules it adds.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PolicyTemplatesPanel;
