import React, { useEffect, useRef, useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import { Badge } from '../../../components/shared/Badge';
import { BLANK_TEMPLATE_ID } from './policyDefaults';
import PolicySectionTitle from './PolicySectionTitle';
import type { PolicyStart } from './policyStart';
import { TemplateOriginBadges } from './TemplateBadges';
import { templateEntryKey } from './usePolicyTemplates';
import { CATEGORY_LABELS, type PolicyTemplate, type UsedTemplate } from './types';
import './PolicyTemplates.css';

const COLLAPSED_COUNT = 6;

interface TemplateGalleryProps {
  /** The cards for the policy's Type (`useTemplateGallery().cards`). */
  cards: PolicyTemplate[];
  /** Keys of the cards marked Agent surface only. */
  surfaceOnly: Set<string>;
  step?: number;
  /** What the policy started from, while its Rego still follows it (`policyStart`). */
  start: PolicyStart | null;
  usedTemplate: UsedTemplate | null;
  /** The cards show while expanded; collapsed, the section shows what the policy started from. */
  expanded: boolean;
  onExpand: () => void;
  /** Set once a template was used: Cancel closes the gallery without using another. */
  onCollapse?: () => void;
  /** The card whose detail the templates column shows, or null before one is picked. */
  selectedKey: string | null;
  onSelect: (key: string) => void;
  /** Starts a custom policy from `ALLOW_ALL_POLICY`, asking first when it replaces rules. */
  onCreateCustom: () => void;
}

type FocusTarget = 'change' | 'card';

/**
 * The create form's Start from section: one card per built-in and organisation template of the
 * policy's Type, then Create custom policy. Choosing a card shows its detail in the templates
 * column (`TemplateGalleryDetail`), where Use this template fills the form.
 */
const TemplateGallery: React.FC<TemplateGalleryProps> = ({
  cards,
  surfaceOnly,
  step,
  start,
  usedTemplate,
  expanded,
  onExpand,
  onCollapse,
  selectedKey,
  onSelect,
  onCreateCustom,
}) => {
  const [showAll, setShowAll] = useState(false);

  // The selected template stays in view even when it is past the first few cards.
  const selectedIndex = cards.findIndex(t => templateEntryKey(t) === selectedKey);
  const shown =
    showAll || selectedIndex >= COLLAPSED_COUNT ? cards : cards.slice(0, COLLAPSED_COUNT);

  const changeRef = useRef<HTMLButtonElement>(null);
  const sectionRef = useRef<HTMLElement>(null);
  const [focusTarget, setFocusTarget] = useState<FocusTarget | null>(null);
  useEffect(() => {
    if (!focusTarget) return;
    if (focusTarget === 'change') changeRef.current?.focus();
    else
      (
        sectionRef.current?.querySelector<HTMLElement>('.is-selected') ??
        sectionRef.current?.querySelector<HTMLElement>('.policy-template-card')
      )?.focus();
    setFocusTarget(null);
  }, [focusTarget]);

  // Use this template and Cancel collapse the gallery, which moves the focus to Change.
  const wasExpanded = useRef(expanded);
  useEffect(() => {
    if (wasExpanded.current && !expanded && usedTemplate) setFocusTarget('change');
    wasExpanded.current = expanded;
  }, [expanded, usedTemplate]);

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
      className={`policy-template-row policy-template-card${selectedKey === key ? ' is-selected' : ''}`}
      aria-pressed={selectedKey === key}
      onClick={() => onSelect(key)}
      data-testid={testId}
    >
      <span className="policy-template-row__name">{name}</span>
      <span className="policy-template-row__summary">{summary}</span>
      <span className="policy-template-card__meta">{meta}</span>
    </button>
  );

  return (
    <section className="policy-section" data-testid="policy-template-gallery" ref={sectionRef}>
      <PolicySectionTitle step={step} title="Start from">
        {!expanded && (
          <AppButton
            ref={changeRef}
            variant="link"
            className="p-0"
            onClick={() => {
              onExpand();
              setFocusTarget('card');
            }}
            data-testid="policy-template-gallery-change-button"
          >
            Change
          </AppButton>
        )}
        {expanded && onCollapse && (
          <AppButton
            variant="link"
            className="p-0"
            onClick={onCollapse}
            data-testid="policy-template-gallery-cancel-button"
          >
            Cancel
          </AppButton>
        )}
      </PolicySectionTitle>

      {!expanded ? (
        <div
          className="policy-template-gallery__summary"
          data-testid="policy-template-gallery-summary"
        >
          <span>
            Started from <strong>{start?.name ?? 'Custom Rego'}</strong>
            {start && start.templatesAdded > 0 ? (
              <span className="text-muted" data-testid="policy-template-gallery-added-count">
                {' '}
                · {start.templatesAdded} {start.templatesAdded === 1 ? 'template' : 'templates'}{' '}
                added
              </span>
            ) : (
              start &&
              usedTemplate &&
              usedTemplate.id !== BLANK_TEMPLATE_ID && (
                <span className="text-muted" data-testid="policy-definition-prefilled-hint">
                  {' '}
                  · Pre-filled from the template. Edit freely.
                </span>
              )
            )}
          </span>
        </div>
      ) : (
        <>
          <p className="text-muted small mb-2">
            Pick a template to see its details on the right, then use it to continue, or create a
            custom policy. You can add rules from more templates with{' '}
            <strong>Add rules from a template</strong>.
          </p>
          <div className="policy-template-gallery">
            {shown.map(t => {
              const key = templateEntryKey(t);
              return card(
                key,
                t.name,
                t.summary,
                <>
                  <TemplateOriginBadges template={t} />
                  {t.policy_input === 'mcp_tool' && (
                    <Badge tone="secondary" value="MCP tool policy" />
                  )}
                  <span className="policy-template-row__summary">
                    {t.builtin ? CATEGORY_LABELS[t.category] : 'Organization template'}
                  </span>
                  {surfaceOnly.has(key) && (
                    <span
                      className="policy-template-card__scope"
                      data-testid="policy-template-card-scope"
                    >
                      Agent surface only
                    </span>
                  )}
                </>,
                `policy-template-card-${key}`
              );
            })}
          </div>
          {shown.length < cards.length && (
            <AppButton
              variant="outline-secondary"
              className="mt-2"
              onClick={() => setShowAll(true)}
              data-testid="policy-template-gallery-show-all"
            >
              Show all ({cards.length})
            </AppButton>
          )}
          <div className="policy-template-gallery__custom">
            <span className="text-muted small">None of these fit?</span>
            <AppButton
              variant="outline-primary"
              className={selectedKey === BLANK_TEMPLATE_ID ? 'is-selected' : undefined}
              aria-pressed={selectedKey === BLANK_TEMPLATE_ID}
              onClick={onCreateCustom}
              data-testid="policy-template-gallery-create-custom-button"
            >
              <i className="fas fa-plus me-1" aria-hidden="true" />
              Create custom policy
            </AppButton>
          </div>
        </>
      )}
    </section>
  );
};

export default TemplateGallery;
