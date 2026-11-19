import { useEffect, useMemo, useState } from 'react';
import { BLANK_TEMPLATE_ID } from './policyDefaults';
import { policyStart, replaceText } from './policyStart';
import {
  galleryTemplates,
  surfaceOnlyKeys,
  templateEntryKey,
  type TemplateEntry,
} from './policyTemplateLibrary';
import type { AddedRules, FieldText, PolicyTemplate, PolicyType, UsedTemplate } from './types';

interface TemplateGalleryOptions {
  /** False on a saved policy and for a user who can't edit policies: no gallery, no start. */
  enabled: boolean;
  /** Every template, from `POLICY_TEMPLATE_LIBRARY`. */
  entries: TemplateEntry[];
  policy: string;
  policyType: PolicyType;
  templatePicked: boolean;
  usedTemplate: UsedTemplate | null;
  addedRules: AddedRules[];
  onUseTemplate: (template: PolicyTemplate, rego: string, fieldText: FieldText) => void;
  onStartCustom: () => void;
}

/**
 * The Start from gallery of a new policy: whether it is open, the card whose detail is shown,
 * what the policy started from, and the actions that use a template or start a custom policy.
 */
export function useTemplateGallery({
  enabled,
  entries,
  policy,
  policyType,
  templatePicked,
  usedTemplate,
  addedRules,
  onUseTemplate,
  onStartCustom,
}: TemplateGalleryOptions) {
  const templates = useMemo(
    () => entries.flatMap(e => Object.values(e.variants)).filter((t): t is PolicyTemplate => !!t),
    [entries]
  );
  const [open, setOpen] = useState(true);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  // Changes on every card click, which moves the focus to the detail's heading.
  const [focusKey, setFocusKey] = useState(0);

  const choosing = enabled && !templatePicked;
  // Undoing the first Use shows the gallery again.
  useEffect(() => {
    if (choosing) setOpen(true);
  }, [choosing]);

  const start = useMemo(
    () => (enabled ? policyStart(policy, policyType, usedTemplate, templates, addedRules) : null),
    [enabled, policy, policyType, usedTemplate, templates, addedRules]
  );

  // The cards for the policy's Type, and on an Agent Surface policy the ones for surfaces only.
  const cards = useMemo(() => galleryTemplates(entries, policyType), [entries, policyType]);
  const surfaceOnly = useMemo(
    () => (policyType === 'agent_surface' ? surfaceOnlyKeys(entries) : new Set<string>()),
    [entries, policyType]
  );
  const selected = useMemo(
    () => cards.find(t => templateEntryKey(t) === selectedKey) ?? null,
    [cards, selectedKey]
  );

  const select = (key: string) => {
    setSelectedKey(key);
    setFocusKey(n => n + 1);
  };

  const close = () => {
    setOpen(false);
    setSelectedKey(null);
  };

  // Change reopens the gallery on the used template's card.
  const reopen = () => {
    const used = templates.find(t => t.id === usedTemplate?.id);
    setSelectedKey(
      usedTemplate?.id === BLANK_TEMPLATE_ID
        ? BLANK_TEMPLATE_ID
        : used
          ? templateEntryKey(used)
          : null
    );
    setOpen(true);
  };

  const pickTemplate = (template: PolicyTemplate, rego: string, fieldText: FieldText) => {
    onUseTemplate(template, rego, fieldText);
    close();
  };

  const startCustom = () => {
    onStartCustom();
    close();
  };

  // Create custom policy starts at once unless it replaces rules, which its detail asks about.
  const createCustom = () => {
    if (templatePicked && replaceText(policy, start)) select(BLANK_TEMPLATE_ID);
    else startCustom();
  };

  return {
    choosing,
    cards,
    surfaceOnly,
    open,
    selectedKey,
    selected,
    focusKey,
    start,
    startedFrom: usedTemplate && start ? start.name : null,
    select,
    close,
    reopen,
    pickTemplate,
    startCustom,
    createCustom,
  };
}
