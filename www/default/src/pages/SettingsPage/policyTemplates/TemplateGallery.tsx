import React, { useEffect, useMemo, useState } from 'react';
import { BLANK_TEMPLATE_ID } from './policyDefaults';
import PolicySectionTitle from './PolicySectionTitle';
import { defaultDecision } from './regoTemplate';
import { DecisionBadge } from './TemplateBadges';
import { Link } from '../../../components/shared/Link';
import { templateEntryKey, useAllPolicyTemplates } from './usePolicyTemplates';
import { useTemplateFilter } from './useTemplateFilter';
import { CATEGORY_LABELS, type PolicyTemplate, type PolicyType } from './types';
import './PolicyTemplates.css';

const COLLAPSED_COUNT = 6;

const ONLY_LABEL: Record<PolicyType, string> = {
  gateway: 'Gateway only',
  agent_surface: 'Agent Surface only',
};

interface TemplateGalleryProps {
  policyType: PolicyType;
  step?: number;
  /** The chosen template id, `blank`, or null once the Rego no longer follows one. */
  appliedTemplateId: string | null;
  onPickBlank: () => void;
  onPickTemplate: (template: PolicyTemplate) => void;
  /** Opens the templates panel with the template selected, to change its settings. */
  onCustomise: (template: PolicyTemplate) => void;
}

/**
 * The create form's Start from section: Blank, then one card per built-in and organisation
 * template of either type. A template for the other type only sets the Type when chosen.
 */
const TemplateGallery: React.FC<TemplateGalleryProps> = ({
  policyType,
  step,
  appliedTemplateId,
  onPickBlank,
  onPickTemplate,
  onCustomise,
}) => {
  const entries = useAllPolicyTemplates();
  // Each card stands for the variant of the current Type, or the template's only variant.
  const all = useMemo(
    () =>
      entries
        .map(e => e.variants[policyType] ?? e.variants.gateway ?? e.variants.agent_surface)
        .filter((t): t is PolicyTemplate => !!t),
    [entries, policyType]
  );
  const { query, setQuery, category, setCategory, categories, visible } = useTemplateFilter(all);
  const [expanded, setExpanded] = useState(true);
  const [showAll, setShowAll] = useState(false);

  // A template used from the templates panel collapses the gallery too.
  useEffect(() => {
    if (appliedTemplateId && appliedTemplateId !== BLANK_TEMPLATE_ID) setExpanded(false);
  }, [appliedTemplateId]);

  const applied =
    entries.flatMap(e => Object.values(e.variants)).find(t => t?.id === appliedTemplateId) ?? null;
  const appliedKey = applied ? templateEntryKey(applied) : null;
  const filtering = query.trim() !== '' || category !== 'all';
  // The chosen template stays in view even when it is past the first few cards.
  const appliedIndex = visible.findIndex(t => templateEntryKey(t) === appliedKey);
  const shown =
    showAll || filtering || appliedIndex >= COLLAPSED_COUNT
      ? visible
      : visible.slice(0, COLLAPSED_COUNT);

  const pick = (template: PolicyTemplate | null) => {
    if (template) onPickTemplate(template);
    else onPickBlank();
    setExpanded(false);
  };

  const summaryName =
    appliedTemplateId === BLANK_TEMPLATE_ID ? 'Blank' : (applied?.name ?? 'Custom Rego');

  return (
    <section className="policy-section" data-testid="policy-template-gallery">
      <PolicySectionTitle step={step} title="Start from">
        {!expanded && (
          <button
            type="button"
            className="btn btn-sm btn-link p-0"
            onClick={() => setExpanded(true)}
            data-testid="policy-template-gallery-change-button"
          >
            Change
          </button>
        )}
      </PolicySectionTitle>

      {!expanded ? (
        <div
          className="policy-template-gallery__summary"
          data-testid="policy-template-gallery-summary"
        >
          <span>
            Started from <strong>{summaryName}</strong>
            {applied && (
              <span className="text-muted" data-testid="policy-definition-prefilled-hint">
                {' '}
                · Pre-filled from the template. Edit freely.
              </span>
            )}
          </span>
          {applied?.docs_href && (
            <Link
              href={applied.docs_href}
              external
              variant="inline"
              testId="policy-template-gallery-docs-link"
            >
              {applied.docs_label ?? 'Docs'}
            </Link>
          )}
          {applied && applied.parameters.length > 0 && (
            <button
              type="button"
              className="btn btn-sm btn-outline-primary"
              onClick={() => onCustomise(applied)}
              data-testid="policy-template-gallery-customise-button"
            >
              <i className="fas fa-sliders-h me-1" aria-hidden="true" />
              Customise settings
            </button>
          )}
        </div>
      ) : (
        <>
          <p className="text-muted small mb-2">
            Pick a proven pattern to fill the name, description and Rego, or start blank. You can
            edit everything and add rules from more templates before you create the policy.
          </p>
          <div className="d-flex flex-wrap gap-2 align-items-center mb-2">
            <input
              type="search"
              className="form-control form-control-sm policy-template-gallery__search"
              placeholder="Search templates, e.g. role, trust, path"
              aria-label="Search templates"
              value={query}
              onChange={e => setQuery(e.target.value)}
              data-testid="policy-template-gallery-search-input"
            />
            {categories.length > 1 && (
              <ul className="nav nav-pills custom-channel-tabs gap-2 m-0">
                {(['all', ...categories] as const).map(key => (
                  <li className="nav-item" key={key}>
                    <button
                      type="button"
                      className={`nav-link py-1 ${category === key ? 'active' : ''}`}
                      aria-pressed={category === key}
                      onClick={() => setCategory(key)}
                      data-testid={`policy-template-gallery-category-${key}`}
                    >
                      {key === 'all' ? 'All' : CATEGORY_LABELS[key]}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="policy-template-gallery">
            {!filtering && (
              <button
                type="button"
                className={`policy-template-row policy-template-card${appliedTemplateId === BLANK_TEMPLATE_ID ? ' is-selected' : ''}`}
                aria-pressed={appliedTemplateId === BLANK_TEMPLATE_ID}
                onClick={() => pick(null)}
                data-testid="policy-template-card-blank"
              >
                <span className="policy-template-row__name">Blank</span>
                <span className="policy-template-row__summary">
                  The default policy, which allows all traffic. Write your own rules.
                </span>
                <span className="policy-template-card__meta">
                  <DecisionBadge decision="allow" prefix="Default" />
                </span>
              </button>
            )}
            {shown.map(t => {
              const key = templateEntryKey(t);
              const selected = key === appliedKey;
              return (
                <button
                  key={key}
                  type="button"
                  className={`policy-template-row policy-template-card${selected ? ' is-selected' : ''}`}
                  aria-pressed={selected}
                  onClick={() => pick(t)}
                  data-testid={`policy-template-card-${key}`}
                >
                  <span className="policy-template-row__name">{t.name}</span>
                  <span className="policy-template-row__summary">{t.summary}</span>
                  <span className="policy-template-card__meta">
                    <DecisionBadge decision={defaultDecision(t.rego)} prefix="Default" />
                    {t.policy_type !== policyType && (
                      <span
                        className="badge policy-template-reads"
                        title={`Choosing it sets Type to ${t.policy_type === 'gateway' ? 'Gateway' : 'Agent Surfaces'}`}
                        data-testid="policy-template-card-type-badge"
                      >
                        {ONLY_LABEL[t.policy_type]}
                      </span>
                    )}
                    {t.policy_input === 'mcp_tool' && (
                      <span className="badge policy-template-reads">MCP tool policy</span>
                    )}
                    <span className="policy-template-row__summary">
                      {t.builtin ? CATEGORY_LABELS[t.category] : 'Your organization'}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
          {visible.length === 0 && <div className="text-muted small py-2">No templates match.</div>}
          <div className="d-flex justify-content-between align-items-center mt-2">
            {shown.length < visible.length ? (
              <button
                type="button"
                className="btn btn-sm btn-link p-0"
                onClick={() => setShowAll(true)}
                data-testid="policy-template-gallery-show-all"
              >
                Show all ({visible.length})
              </button>
            ) : (
              <span />
            )}
            {appliedTemplateId !== BLANK_TEMPLATE_ID && (
              <button
                type="button"
                className="btn btn-sm btn-link p-0"
                onClick={() => setExpanded(false)}
                data-testid="policy-template-gallery-collapse-button"
              >
                Keep the current policy
              </button>
            )}
          </div>
        </>
      )}
    </section>
  );
};

export default TemplateGallery;
