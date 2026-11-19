import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { AppButton } from '../../../components/shared/AppButton';
import { ALLOW_ALL_POLICY, BLANK_TEMPLATE_ID } from './policyDefaults';
import { CUSTOM_POLICY_NAME, replaceText, type PolicyStart } from './policyStart';
import { TemplateDocsLink, TemplateHowItDecides, TemplateSettingsFields } from './TemplatePreview';
import { useTemplateSettings } from './useTemplateSettings';
import type { FieldText, PolicyTemplate, PolicyType, UsedTemplate } from './types';
import './PolicyTemplates.css';

const ID_PREFIX = 'policy-template-gallery';

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

/**
 * Use this template. With `replaces` set, the first click asks in place before the Rego is
 * replaced, with the focus on Cancel; Cancel and Escape close it and return the focus to Use.
 */
const UseTemplateButton: React.FC<{
  replaces: string | null;
  disabled?: boolean;
  label?: string;
  onUse: () => void;
}> = ({ replaces, disabled, label = 'Use this template', onUse }) => {
  const [confirming, setConfirming] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const opened = useRef(false);
  useEffect(() => {
    if (confirming) cancelRef.current?.focus();
    else if (opened.current) buttonRef.current?.focus();
    opened.current = confirming;
  }, [confirming]);

  return (
    <>
      <div className="d-flex justify-content-end">
        <AppButton
          ref={buttonRef}
          disabled={disabled}
          aria-expanded={replaces ? confirming : undefined}
          onClick={() => (replaces ? setConfirming(true) : onUse())}
          data-testid="policy-template-gallery-use-button"
        >
          {label}
        </AppButton>
      </div>
      {replaces && confirming && (
        <div
          className="policy-template-replace"
          role="group"
          aria-label="Replace the policy"
          onKeyDown={e => {
            if (e.key === 'Escape') setConfirming(false);
          }}
          data-testid="policy-template-gallery-replace-confirm"
        >
          <span className="small">{replaces}</span>
          <AppButton
            variant="danger"
            onClick={onUse}
            data-testid="policy-template-gallery-replace-button"
          >
            Replace
          </AppButton>
          <AppButton
            ref={cancelRef}
            variant="outline-secondary"
            onClick={() => setConfirming(false)}
            data-testid="policy-template-gallery-replace-cancel-button"
          >
            Cancel
          </AppButton>
        </div>
      )}
    </>
  );
};

/** A template's detail: settings, its Rego, how it decides, docs and Use this template. */
const GalleryDetail: React.FC<{
  template: PolicyTemplate;
  initialText?: FieldText;
  headingRef: React.Ref<HTMLHeadingElement>;
  replaces: string | null;
  onUse: (template: PolicyTemplate, rego: string, fieldText: FieldText) => void;
}> = ({ template, initialText, headingRef, replaces, onUse }) => {
  const settings = useTemplateSettings(template, initialText);
  return (
    <div data-testid="policy-template-gallery-detail">
      <DetailHeading ref={headingRef}>{template.name}</DetailHeading>
      <p className="text-muted small mb-2">{template.description}</p>
      <TemplateSettingsFields template={template} settings={settings} idPrefix={ID_PREFIX} />
      <ShowRego rego={settings.rendered.rego} />
      <TemplateHowItDecides template={template} idPrefix={ID_PREFIX} />
      <TemplateDocsLink template={template} testId="policy-template-gallery-docs-link" />
      <UseTemplateButton
        replaces={replaces}
        disabled={!settings.rendered.rego}
        onUse={() =>
          settings.rendered.rego && onUse(template, settings.rendered.rego, settings.fieldText)
        }
      />
    </div>
  );
};

interface TemplateGalleryDetailProps {
  /** The Start from card whose detail is shown, or null before one is picked. */
  selectedKey: string | null;
  /** The template of the selected card, from the templates the page has already loaded. */
  selected: PolicyTemplate | null;
  policyType: PolicyType;
  /** The current Rego, which Use replaces. */
  policy: string;
  start: PolicyStart | null;
  /** False until a template is used: the user has seen no Rego yet, so Use never asks first. */
  templatePicked: boolean;
  usedTemplate: UsedTemplate | null;
  /** Changes when a card is clicked, which moves the focus to the detail's heading. */
  focusKey: number;
  onUseTemplate: (template: PolicyTemplate, rego: string, fieldText: FieldText) => void;
  onPickBlank: () => void;
}

/** The templates column's detail of the Start from card the user picked. */
const TemplateGalleryDetail: React.FC<TemplateGalleryDetailProps> = ({
  selectedKey,
  selected,
  policyType,
  policy,
  start,
  templatePicked,
  usedTemplate,
  focusKey,
  onUseTemplate,
  onPickBlank,
}) => {
  const replaces = useMemo(
    () => (templatePicked ? replaceText(policy, start) : null),
    [templatePicked, policy, start]
  );
  const headingRef = useRef<HTMLHeadingElement>(null);
  // Only a card click while the detail is shown moves the focus, not reopening the gallery.
  const focusedKey = useRef(focusKey);
  useEffect(() => {
    if (focusKey === focusedKey.current) return;
    focusedKey.current = focusKey;
    headingRef.current?.focus();
  }, [focusKey]);

  return (
    <div className="card shadow mb-4" data-testid="policy-template-gallery-detail-panel">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-file-shield" aria-hidden="true" /> Template details
        </h6>
      </div>
      <div className="card-body">
        {selectedKey === BLANK_TEMPLATE_ID ? (
          <div data-testid="policy-template-gallery-detail">
            <DetailHeading ref={headingRef}>{CUSTOM_POLICY_NAME}</DetailHeading>
            <p className="text-muted small mb-3">
              Write your own rules. It starts from the allow-all policy: every request is allowed
              until you add rules and change <code>default allow</code> to <code>false</code>.
            </p>
            <ShowRego rego={ALLOW_ALL_POLICY[policyType]} />
            <UseTemplateButton
              replaces={replaces}
              label="Create custom policy"
              onUse={onPickBlank}
            />
          </div>
        ) : selected ? (
          <GalleryDetail
            key={selected.id}
            template={selected}
            initialText={usedTemplate?.id === selected.id ? usedTemplate.fieldText : undefined}
            headingRef={headingRef}
            replaces={replaces}
            onUse={onUseTemplate}
          />
        ) : (
          <div
            className="policy-templates-panel__placeholder"
            data-testid="policy-template-gallery-detail-empty"
          >
            <i className="fas fa-hand-pointer me-2" aria-hidden="true" />
            Pick a template under Start from to see what it does, then use it.
          </div>
        )}
      </div>
    </div>
  );
};

export default TemplateGalleryDetail;
