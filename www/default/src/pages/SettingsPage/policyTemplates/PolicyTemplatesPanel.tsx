import React, { useEffect, useRef, useState } from 'react';
import { CopyButton } from '../../../components/shared/CopyButton';
import FieldHelp from '../../../components/shared/FieldHelp';
import { Link } from '../../../components/shared/Link';
import {
  defaultDecision,
  defaultParameterValues,
  insertTemplateRules,
  parseListInput,
  renderTemplate,
} from './regoTemplate';
import { DecisionBadge } from './TemplateBadges';
import { useAllPolicyTemplates, usePolicyTemplates } from './usePolicyTemplates';
import { useTemplateFilter } from './useTemplateFilter';
import {
  CATEGORY_LABELS,
  type ParameterValues,
  type PolicyTemplate,
  type PolicyType,
} from './types';
import './PolicyTemplates.css';

type Source = 'builtin' | 'organization';

interface PolicyTemplatesPanelProps {
  /** `browse` replaces the form with a template; `insert` adds a template's rules to the Rego. */
  mode: 'browse' | 'insert';
  policyType: PolicyType;
  /** The editor's current Rego, which Add to policy appends to. */
  existingPolicy?: string;
  /** The template selected when the panel opens, such as one picked in the Start from gallery. */
  initialTemplateId?: string;
  /** Replaces the form with the template. Browse mode only. */
  onUse?: (template: PolicyTemplate, rego: string) => void;
  /** `usesDefaultSettings` is false when a setting differs from its default. */
  onInsert: (template: PolicyTemplate, rego: string, usesDefaultSettings: boolean) => void;
  /** Turns the Rego's `default allow` to false. */
  onSetDefaultDeny?: () => void;
  /** Hidden when undefined, for the panel that is always shown beside the editor. */
  onClose?: () => void;
  /** Scrolls the panel into view when it mounts, for a panel the user just opened. */
  scrollIntoViewOnOpen?: boolean;
}

const TYPE_LABEL: Record<PolicyType, string> = {
  gateway: 'Gateway',
  agent_surface: 'Agent Surfaces',
};

/** Raw text of each setting field, so a list can be typed with its commas. */
type FieldText = Record<string, string>;

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

const PolicyTemplatesPanel: React.FC<PolicyTemplatesPanelProps> = ({
  mode,
  policyType,
  existingPolicy = '',
  initialTemplateId,
  onUse,
  onInsert,
  onSetDefaultDeny,
  onClose,
  scrollIntoViewOnOpen = true,
}) => {
  const { builtin, organization, loading, error } = usePolicyTemplates(policyType);
  const [source, setSource] = useState<Source>('builtin');
  const [selected, setSelected] = useState<PolicyTemplate | null>(null);
  const [fieldText, setFieldText] = useState<FieldText>({});
  const rootRef = useRef<HTMLDivElement>(null);
  const initialApplied = useRef(false);

  // The panel opens in place, which can be below the fold on a long policy.
  useEffect(() => {
    if (scrollIntoViewOnOpen) {
      rootRef.current?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
    }
  }, [mode, scrollIntoViewOnOpen]);

  const sourceTemplates = source === 'builtin' ? builtin : organization;
  const { query, setQuery, category, setCategory, categories, visible } =
    useTemplateFilter(sourceTemplates);

  const select = (template: PolicyTemplate) => {
    setSelected(template);
    setFieldText(initialFieldText(template));
  };

  useEffect(() => {
    if (!initialTemplateId || initialApplied.current) return;
    const template = [...builtin, ...organization].find(t => t.id === initialTemplateId);
    if (!template) return;
    initialApplied.current = true;
    setSource(template.builtin ? 'builtin' : 'organization');
    setSelected(template);
    setFieldText(initialFieldText(template));
  }, [initialTemplateId, builtin, organization]);

  const switchSource = (next: Source) => {
    setSource(next);
    setCategory('all');
    setSelected(null);
  };

  const rendered = selected ? renderTemplate(selected, valuesFromText(selected, fieldText)) : null;
  const insert =
    selected && rendered?.rego
      ? insertTemplateRules(existingPolicy, selected.name, rendered.rego)
      : null;
  const forToolBinding = selected?.policy_input === 'mcp_tool';
  const insertRefused = !!selected?.standalone || forToolBinding;
  // Templates written only for the other policy type, which this policy can't use.
  const otherTypeOnly = useAllPolicyTemplates().filter(e => !e.variants[policyType]).length;
  const canInsert = !!insert?.added && !insertRefused;
  const usesDefaultSettings =
    !!selected &&
    rendered?.rego === renderTemplate(selected, defaultParameterValues(selected)).rego;

  return (
    <div
      ref={rootRef}
      className="card mb-3 policy-templates-panel"
      data-testid="policy-templates-panel"
    >
      <div className="card-header py-3 d-flex justify-content-between align-items-start">
        <div>
          <div className="small text-muted">
            <i className="fas fa-layer-group me-1 text-primary" aria-hidden="true" />
            Templates · {TYPE_LABEL[policyType]}
          </div>
          <h6 className="m-0 mt-1 font-weight-bold text-primary">
            {mode === 'insert' ? 'Add rules from a template' : 'Browse policy templates'}
          </h6>
          <div className="small text-muted">
            {mode === 'insert'
              ? 'Pick a template, adjust its settings, and add its rules to the end of the Rego. Add several to combine them.'
              : 'Use a template to start the policy from it.'}
          </div>
        </div>
        {onClose && (
          <button
            type="button"
            className="btn-close"
            aria-label="Close templates"
            onClick={onClose}
            data-testid="policy-templates-close-button"
          />
        )}
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
                    onClick={() => select(t)}
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
            {mode === 'insert' && otherTypeOnly > 0 && (
              <div className="small text-muted mt-2" data-testid="policy-templates-other-type-note">
                {otherTypeOnly} {otherTypeOnly === 1 ? 'template is' : 'templates are'} for{' '}
                {policyType === 'gateway' ? 'Agent Surface' : 'Gateway'} policies only.
              </div>
            )}
          </div>

          {selected && rendered ? (
            <div className="policy-template-preview" data-testid="policy-templates-preview">
              <div className="small text-muted text-uppercase fw-bold">Preview</div>
              <h6 className="fw-bold mb-1 mt-1">{selected.name}</h6>
              <p className="text-muted small mb-2">{selected.description}</p>
              <div className="d-flex flex-wrap gap-2 mb-3">
                <DecisionBadge decision={defaultDecision(selected.rego)} prefix="Default" />
                {selected.reads.map(r => (
                  <span key={r} className="badge policy-template-reads">
                    reads {r}
                  </span>
                ))}
              </div>

              {selected.parameters.map(p => {
                const id = `policy-template-param-${p.key}`;
                const err = rendered.errors[p.key];
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
                      value={fieldText[p.key] ?? ''}
                      onChange={e => setFieldText(prev => ({ ...prev, [p.key]: e.target.value }))}
                      data-testid={`policy-templates-param-${p.key}`}
                    />
                    {err && <div className="invalid-feedback">{err}</div>}
                  </div>
                );
              })}

              {mode === 'insert' && insert && !insertRefused ? (
                <>
                  <div className="font-weight-bold mb-1">Added to the end of the policy</div>
                  <pre
                    className="policy-preview-block rounded p-2 mb-2 small"
                    data-testid="policy-templates-insert-preview"
                  >
                    <code>{insert.added || '(none)'}</code>
                  </pre>
                </>
              ) : (
                <pre
                  className="policy-preview-block rounded p-2 mb-3 small"
                  data-testid="policy-templates-rego-preview"
                >
                  <code>{rendered.rego ?? 'Fix the settings above to see the Rego.'}</code>
                </pre>
              )}

              {mode !== 'insert' ? null : insertRefused ? (
                forToolBinding ? (
                  <div
                    className="alert alert-info py-2 px-3 small"
                    data-testid="policy-templates-mcp-tool-note"
                  >
                    <i className="fas fa-info-circle me-2" aria-hidden="true" />
                    This template is for a policy bound to MCP tools on the MCP Proxy hop, which
                    reads <code>input.jwt</code> and the tool name. Use it as a whole policy.
                  </div>
                ) : (
                  <div
                    className="alert alert-info py-2 px-3 small"
                    data-testid="policy-templates-standalone-note"
                  >
                    <i className="fas fa-info-circle me-2" aria-hidden="true" />
                    Use this template as a whole policy. Its rules allow requests outside what it
                    restricts, so added to a policy they would allow requests that policy denies.
                  </div>
                )
              ) : (
                insert && (
                  <>
                    {insert.existingDefault === 'allow' && (
                      <div
                        className="alert alert-warning py-2 px-3 small"
                        data-testid="policy-templates-allow-default-warning"
                      >
                        <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
                        The Rego in the editor allows every request by default, so added allow rules
                        change nothing. Change <code>default allow</code> to <code>false</code> for
                        them to take effect.
                        {onSetDefaultDeny && (
                          <div className="mt-2">
                            <button
                              type="button"
                              className="btn btn-sm btn-outline-primary"
                              onClick={onSetDefaultDeny}
                              data-testid="policy-templates-set-default-deny-button"
                            >
                              Deny by default
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                    {insert.existingDefault !== 'allow' && insert.droppedDefault && (
                      <div className="alert alert-info py-2 px-3 small">
                        <i className="fas fa-info-circle me-2" aria-hidden="true" />
                        The template&apos;s <code>package</code> and <code>default allow</code>{' '}
                        lines are left out; this policy keeps its own.
                      </div>
                    )}
                    {!insert.added && (
                      <div className="text-muted small mb-2">
                        This template adds no rules to an existing policy.
                      </div>
                    )}
                  </>
                )
              )}

              {selected.examples.length > 0 && (
                <>
                  <div className="font-weight-bold mb-1">How it decides</div>
                  <ul className="list-unstyled mb-2">
                    {selected.examples.map(ex => (
                      <li key={ex.name} className="policy-template-example">
                        <span>{ex.name}</span>
                        <span
                          className={`badge ${ex.expected === 'allow' ? 'text-bg-success' : 'text-bg-danger'}`}
                        >
                          {ex.expected.toUpperCase()}
                        </span>
                      </li>
                    ))}
                  </ul>
                  {selected.parameters.length > 0 && (
                    <div className="small text-muted mb-2">Examples use the default settings.</div>
                  )}
                </>
              )}
              {selected.docs_href && (
                <div className="mb-3">
                  <Link
                    href={selected.docs_href}
                    external
                    variant="inline"
                    testId="policy-templates-docs-link"
                  >
                    {selected.docs_label ?? 'Docs'}
                  </Link>
                </div>
              )}
              <div className="d-flex justify-content-end gap-2">
                <CopyButton
                  text={rendered.rego ?? ''}
                  variant="outline-primary"
                  label="Copy Rego"
                  title="Copy Rego"
                  disabled={!rendered.rego}
                  data-testid="policy-templates-copy-button"
                />
                {mode === 'insert' && (
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={!canInsert}
                    onClick={() =>
                      rendered.rego && onInsert(selected, rendered.rego, usesDefaultSettings)
                    }
                    data-testid="policy-templates-insert-rules-button"
                  >
                    <i className="fas fa-plus me-1" aria-hidden="true" />
                    Add to policy
                  </button>
                )}
                {mode === 'browse' && onUse && (
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={!rendered.rego}
                    onClick={() => rendered.rego && onUse(selected, rendered.rego)}
                    data-testid="policy-templates-use-button"
                  >
                    Use this template
                  </button>
                )}
              </div>
            </div>
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
