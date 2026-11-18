import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import { Badge } from '../../../components/shared/Badge';
import {
  ALLOW_ALL_POLICY,
  BLANK_TEMPLATE_ID,
  DEFAULT_POLICY,
  DEFAULT_TEMPLATE_KEY,
} from './policyDefaults';
import PolicySectionTitle from './PolicySectionTitle';
import { defaultDecision } from './regoTemplate';
import { DecisionBadge } from './TemplateBadges';
import TemplateFilterBar from './TemplateFilterBar';
import {
  renderWithText,
  TemplateDocsLink,
  TemplateHowItDecides,
  TemplateSettingsFields,
  useTemplateSettings,
  type FieldText,
} from './TemplatePreview';
import type { UsedTemplate } from './usePolicyTemplateActions';
import { templateEntryKey, useAllPolicyTemplates } from './usePolicyTemplates';
import { useTemplateFilter } from './useTemplateFilter';
import { CATEGORY_LABELS, POLICY_TYPE_NAMES, type PolicyTemplate, type PolicyType } from './types';
import './PolicyTemplates.css';

const COLLAPSED_COUNT = 6;
const ID_PREFIX = 'policy-template-gallery';

interface TemplateGalleryProps {
  policyType: PolicyType;
  step?: number;
  /** The policy's Rego, which says whether it still follows the used template. */
  policy: string;
  usedTemplate: UsedTemplate | null;
  onPickBlank: () => void;
  /** Fills the form from the template, with the Rego its settings render to. */
  onUseTemplate: (template: PolicyTemplate, rego: string, fieldText: FieldText) => void;
}

type FocusTarget = 'change' | 'card' | 'heading';

const DetailHeading = React.forwardRef<HTMLHeadingElement, { children: React.ReactNode }>(
  ({ children }, ref) => (
    <h6
      ref={ref}
      tabIndex={-1}
      className="fw-bold mb-1"
      data-testid="policy-template-gallery-detail-heading"
    >
      {children}
    </h6>
  )
);
DetailHeading.displayName = 'DetailHeading';

/** The Rego a detail renders to, collapsed until asked for; null while a setting is invalid. */
const ShowRego: React.FC<{ rego: string | null }> = ({ rego }) => {
  const [open, setOpen] = useState(false);
  const regoId = useId();
  return (
    <>
      <AppButton
        variant="link"
        className="p-0 mb-2"
        aria-expanded={open}
        aria-controls={regoId}
        onClick={() => setOpen(o => !o)}
        data-testid="policy-template-gallery-show-rego"
      >
        {open ? 'Hide Rego' : 'Show Rego'}
      </AppButton>
      {open && (
        <pre
          id={regoId}
          className="policy-preview-block rounded p-2 mb-3 small"
          data-testid="policy-template-gallery-rego"
        >
          <code>{rego ?? 'Fix the settings above to see the Rego.'}</code>
        </pre>
      )}
    </>
  );
};

/** The selected card's detail: settings, its Rego, how it decides, docs and Use this template. */
const GalleryDetail: React.FC<{
  template: PolicyTemplate;
  policyType: PolicyType;
  initialText?: FieldText;
  headingRef: React.Ref<HTMLHeadingElement>;
  hidden: boolean;
  onUse: (template: PolicyTemplate, rego: string, fieldText: FieldText) => void;
}> = ({ template, policyType, initialText, headingRef, hidden, onUse }) => {
  const settings = useTemplateSettings(template, initialText);
  return (
    <div
      className="policy-template-gallery__detail"
      hidden={hidden}
      data-testid="policy-template-gallery-detail"
    >
      <DetailHeading ref={headingRef}>{template.name}</DetailHeading>
      <p className="text-muted small mb-2">{template.description}</p>
      <div className="d-flex flex-wrap gap-2 mb-3">
        <DecisionBadge decision={defaultDecision(template.rego)} prefix="Default" />
        {template.policy_type !== policyType && (
          <Badge
            tone="secondary"
            value={`Using it sets Type to ${POLICY_TYPE_NAMES[template.policy_type].label}`}
          />
        )}
      </div>
      <TemplateSettingsFields template={template} settings={settings} idPrefix={ID_PREFIX} />
      <ShowRego rego={settings.rendered.rego} />
      <TemplateHowItDecides template={template} idPrefix={ID_PREFIX} />
      <TemplateDocsLink template={template} testId="policy-template-gallery-docs-link" />
      <div className="d-flex justify-content-end">
        <AppButton
          disabled={!settings.rendered.rego}
          onClick={() =>
            settings.rendered.rego && onUse(template, settings.rendered.rego, settings.fieldText)
          }
          data-testid="policy-template-gallery-use-button"
        >
          Use this template
        </AppButton>
      </div>
    </div>
  );
};

/**
 * The create form's Start from section: Allow all (blank), then one card per built-in and
 * organisation template of either type. Choosing a card shows its detail in place; Use this
 * template fills the form, and a template for the other type sets the Type.
 */
const TemplateGallery: React.FC<TemplateGalleryProps> = ({
  policyType,
  step,
  policy,
  usedTemplate,
  onPickBlank,
  onUseTemplate,
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

  const isDefault = policy === DEFAULT_POLICY[policyType];
  // The used template's card, or Deny by default while the Rego is still the new policy's own.
  const appliedId =
    usedTemplate?.id ?? (isDefault ? `${DEFAULT_TEMPLATE_KEY}:${policyType}` : null);
  const applied =
    entries.flatMap(e => Object.values(e.variants)).find(t => t?.id === appliedId) ?? null;
  const appliedKey =
    appliedId === BLANK_TEMPLATE_ID
      ? BLANK_TEMPLATE_ID
      : applied
        ? templateEntryKey(applied)
        : null;
  const usedRego =
    usedTemplate?.id === BLANK_TEMPLATE_ID
      ? ALLOW_ALL_POLICY[policyType]
      : usedTemplate && applied
        ? renderWithText(applied, usedTemplate.fieldText).rego
        : null;
  const prefilled = usedRego !== null && policy === usedRego;
  // The card whose detail is open: the applied one until the user picks another.
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const shownKey = selectedKey ?? appliedKey;
  const filtering = query.trim() !== '' || category !== 'all';
  // The selected template stays in view even when it is past the first few cards.
  const selectedIndex = visible.findIndex(t => templateEntryKey(t) === shownKey);
  const shown =
    showAll || filtering || selectedIndex >= COLLAPSED_COUNT
      ? visible
      : visible.slice(0, COLLAPSED_COUNT);
  // A detail stays mounted, keeping its settings, but shows only while its card does.
  const selected = all.find(t => templateEntryKey(t) === shownKey) ?? null;
  const detailHidden = shownKey === BLANK_TEMPLATE_ID ? filtering : selectedIndex < 0;

  const changeRef = useRef<HTMLButtonElement>(null);
  const filtersRef = useRef<HTMLDivElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [focusTarget, setFocusTarget] = useState<FocusTarget | null>(null);
  useEffect(() => {
    if (!focusTarget) return;
    if (focusTarget === 'change') changeRef.current?.focus();
    else if (focusTarget === 'heading') headingRef.current?.focus();
    else
      (
        gridRef.current?.querySelector<HTMLElement>('.is-selected') ??
        filtersRef.current?.querySelector<HTMLElement>('input')
      )?.focus();
    setFocusTarget(null);
  }, [focusTarget]);

  const collapse = () => {
    setSelectedKey(null);
    setExpanded(false);
    setFocusTarget('change');
  };
  const use = (template: PolicyTemplate, rego: string, fieldText: FieldText) => {
    onUseTemplate(template, rego, fieldText);
    collapse();
  };
  const useBlank = () => {
    onPickBlank();
    collapse();
  };

  const summaryName =
    usedTemplate && !prefilled
      ? 'Custom Rego'
      : usedTemplate?.id === BLANK_TEMPLATE_ID
        ? 'Allow all (blank)'
        : (applied?.name ?? 'Custom Rego');

  const card = (
    key: string,
    name: string,
    summary: string,
    meta: React.ReactNode,
    testId: string
  ) => (
    <button
      key={key}
      type="button"
      className={`policy-template-row policy-template-card${shownKey === key ? ' is-selected' : ''}`}
      aria-pressed={shownKey === key}
      onClick={() => {
        setSelectedKey(key);
        setFocusTarget('heading');
      }}
      data-testid={testId}
    >
      <span className="policy-template-row__name">{name}</span>
      <span className="policy-template-row__summary">{summary}</span>
      <span className="policy-template-card__meta">{meta}</span>
    </button>
  );

  return (
    <section className="policy-section" data-testid="policy-template-gallery">
      <PolicySectionTitle step={step} title="Start from">
        {!expanded && (
          <AppButton
            ref={changeRef}
            variant="link"
            className="p-0"
            onClick={() => {
              setExpanded(true);
              setFocusTarget('card');
            }}
            data-testid="policy-template-gallery-change-button"
          >
            Change
          </AppButton>
        )}
      </PolicySectionTitle>

      {!expanded ? (
        <div
          className="policy-template-gallery__summary"
          data-testid="policy-template-gallery-summary"
        >
          <span>
            Started from <strong>{summaryName}</strong>
            {prefilled && usedTemplate?.id !== BLANK_TEMPLATE_ID && (
              <span className="text-muted" data-testid="policy-definition-prefilled-hint">
                {' '}
                · Pre-filled from the template. Edit freely.
              </span>
            )}
          </span>
        </div>
      ) : (
        <>
          <p className="text-muted small mb-2">
            Pick a starting point to see what it does, then use it. You can add rules from more
            templates with <strong>Add rules from a template</strong>.
          </p>
          <div ref={filtersRef}>
            <TemplateFilterBar
              query={query}
              onQueryChange={setQuery}
              category={category}
              onCategoryChange={setCategory}
              categories={categories}
              testIdPrefix="policy-template-gallery"
              className="mb-2"
            />
          </div>

          <div className="policy-template-gallery" ref={gridRef}>
            {!filtering &&
              card(
                BLANK_TEMPLATE_ID,
                'Allow all (blank)',
                'Allows every request. Write your own rules.',
                <DecisionBadge decision="allow" prefix="Default" />,
                'policy-template-card-blank'
              )}
            {shown.map(t => {
              const key = templateEntryKey(t);
              return card(
                key,
                t.name,
                t.summary,
                <>
                  <DecisionBadge decision={defaultDecision(t.rego)} prefix="Default" />
                  {t.policy_type !== policyType && (
                    <Badge
                      tone="secondary"
                      value={`${POLICY_TYPE_NAMES[t.policy_type].name} only`}
                      data-testid="policy-template-card-type-badge"
                    />
                  )}
                  {t.policy_input === 'mcp_tool' && (
                    <Badge tone="secondary" value="MCP tool policy" />
                  )}
                  <span className="policy-template-row__summary">
                    {t.builtin ? CATEGORY_LABELS[t.category] : 'Your organization'}
                  </span>
                </>,
                `policy-template-card-${key}`
              );
            })}
          </div>
          {visible.length === 0 && <div className="text-muted small py-2">No templates match.</div>}
          {shown.length < visible.length && (
            <AppButton
              variant="link"
              className="p-0 mt-2"
              onClick={() => setShowAll(true)}
              data-testid="policy-template-gallery-show-all"
            >
              Show all ({visible.length})
            </AppButton>
          )}

          {shownKey === BLANK_TEMPLATE_ID ? (
            <div
              className="policy-template-gallery__detail"
              hidden={detailHidden}
              data-testid="policy-template-gallery-detail"
            >
              <DetailHeading ref={headingRef}>Allow all (blank)</DetailHeading>
              <p className="text-muted small mb-3">
                The default allow-all policy. Every request is allowed until you add rules and
                change <code>default allow</code> to <code>false</code>.
              </p>
              <ShowRego rego={ALLOW_ALL_POLICY[policyType]} />
              <div className="d-flex justify-content-end">
                <AppButton onClick={useBlank} data-testid="policy-template-gallery-use-button">
                  Use this template
                </AppButton>
              </div>
            </div>
          ) : (
            selected && (
              <GalleryDetail
                key={selected.id}
                template={selected}
                policyType={policyType}
                initialText={usedTemplate?.id === selected.id ? usedTemplate.fieldText : undefined}
                headingRef={headingRef}
                hidden={detailHidden}
                onUse={use}
              />
            )
          )}
        </>
      )}
    </section>
  );
};

export default TemplateGallery;
