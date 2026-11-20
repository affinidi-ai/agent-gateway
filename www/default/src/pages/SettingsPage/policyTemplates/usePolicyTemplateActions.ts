import { useRef, useState, type Dispatch, type SetStateAction } from 'react';
import { ALLOW_ALL_POLICY, BLANK_TEMPLATE_ID } from './policyDefaults';
import {
  parsePolicyRules,
  removeRule as removeRuleLines,
  removeRuleGroup,
  setDefaultDeny,
  type PolicyRule,
  type RuleGroup,
} from './regoRules';
import { showUndoToast } from '../../../utils/toaster';
import { insertTemplateRules } from './regoTemplate';
import {
  type AddedRules,
  type FieldText,
  type PolicyTemplate,
  type PolicyType,
  type UsedTemplate,
} from './types';

const UNDO_REGO = 'Undo restores the Rego from before this change.';
const UNDO_FORM = 'Undo restores the form from before this change.';

/** The policy form fields a template fills, and the Name a custom policy empties. */
export interface TemplateFormFields {
  name: string;
  description: string;
  policy_type: PolicyType;
  policy: string;
}

export interface InsertedTemplate {
  template: PolicyTemplate;
  usesDefaultSettings: boolean;
  /** Changes on every insert, so the examples check starts over. */
  key: number;
}

/** The policy editor's template state and the actions that change the Rego, each with Undo. */
export function usePolicyTemplateActions<T extends TemplateFormFields>(
  form: T,
  setForm: Dispatch<SetStateAction<T>>,
  isCreateMode: boolean
) {
  // Only Use and Create custom policy set it; whether the Rego still follows it is derived from the Rego.
  const [usedTemplate, setUsedTemplate] = useState<UsedTemplate | null>(null);
  // A new policy shows its Details and Policy sections only once a template is used.
  const [templatePicked, setTemplatePicked] = useState(!isCreateMode);
  const [insertedTemplate, setInsertedTemplate] = useState<InsertedTemplate | null>(null);
  const [justAdded, setJustAdded] = useState<string | null>(null);
  const [addedRules, setAddedRules] = useState<AddedRules[]>([]);
  const regoRef = useRef<HTMLTextAreaElement>(null);
  // The Description the last Use filled in.
  const filledDescriptionRef = useRef<string | null>(null);

  const applyTemplate = (template: PolicyTemplate, rego: string, fieldText: FieldText) => {
    const previous = { description: form.description, policy: form.policy };
    const previousUsed = usedTemplate;
    const previousPicked = templatePicked;
    const previousFilled = filledDescriptionRef.current;
    // A typed Description is kept; one the last Use filled, or an empty one, is replaced.
    const fillDescription = form.description === '' || form.description === previousFilled;
    filledDescriptionRef.current = template.description;
    setForm(f => ({
      ...f,
      description: fillDescription ? template.description : f.description,
      policy: rego,
    }));
    setUsedTemplate({ id: template.id, fieldText });
    setTemplatePicked(true);
    showUndoToast({
      message: `Filled from the template ${template.name}. ${UNDO_FORM}`,
      onUndo: () => {
        filledDescriptionRef.current = previousFilled;
        setForm(f => ({ ...f, ...previous }));
        setUsedTemplate(previousUsed);
        setTemplatePicked(previousPicked);
      },
    });
  };

  // A custom policy starts with an empty Name and Description.
  const pickBlank = () => {
    const previous = { name: form.name, description: form.description, policy: form.policy };
    const previousUsed = usedTemplate;
    const previousPicked = templatePicked;
    const previousFilled = filledDescriptionRef.current;
    filledDescriptionRef.current = null;
    setForm(f => ({ ...f, name: '', description: '', policy: ALLOW_ALL_POLICY[f.policy_type] }));
    setUsedTemplate({ id: BLANK_TEMPLATE_ID, fieldText: {} });
    setTemplatePicked(true);
    showUndoToast({
      message: `Started a custom policy. ${UNDO_FORM}`,
      onUndo: () => {
        filledDescriptionRef.current = previousFilled;
        setForm(f => ({ ...f, ...previous }));
        setUsedTemplate(previousUsed);
        setTemplatePicked(previousPicked);
      },
    });
  };

  // The panel stays open after an insert so rules from several templates can be combined.
  const insertTemplate = (template: PolicyTemplate, rego: string, usesDefaultSettings: boolean) => {
    const previousPolicy = form.policy;
    const previousInserted = insertedTemplate;
    const previousUsed = usedTemplate;
    const previousJustAdded = justAdded;
    const previousAddedRules = addedRules;
    const inserted = insertTemplateRules(form.policy, template.name, rego);
    setForm(f => ({ ...f, policy: inserted.policy }));
    setAddedRules(prev => [...prev, { name: template.name, body: inserted.added }]);
    setJustAdded(template.name);
    if (!isCreateMode) {
      setInsertedTemplate(prev => ({ template, usesDefaultSettings, key: (prev?.key ?? 0) + 1 }));
    }
    showUndoToast({
      message: `Added rules from the template ${template.name}. ${isCreateMode ? 'Create' : 'Save'} to keep them. ${UNDO_REGO}`,
      onUndo: () => {
        setForm(f => ({ ...f, policy: previousPolicy }));
        setInsertedTemplate(previousInserted);
        setUsedTemplate(previousUsed);
        setJustAdded(previousJustAdded);
        setAddedRules(previousAddedRules);
      },
    });
  };

  const editPolicy = (policy: string) => setForm(f => ({ ...f, policy }));

  const changePolicyWithUndo = (policy: string, message: string, onUndo?: () => void) => {
    const previousPolicy = form.policy;
    const previousUsed = usedTemplate;
    setForm(f => ({ ...f, policy }));
    showUndoToast({
      message: `${message} ${UNDO_REGO}`,
      onUndo: () => {
        setForm(f => ({ ...f, policy: previousPolicy }));
        setUsedTemplate(previousUsed);
        onUndo?.();
      },
    });
  };

  const removeGroup = (group: RuleGroup, message?: string) => {
    const name = group.source.kind === 'template' ? group.source.name : '';
    const previousInserted = insertedTemplate;
    const previousJustAdded = justAdded;
    const policy = removeRuleGroup(form.policy, group);
    // Another group from a template of the same name keeps its mark and examples card.
    const after = parsePolicyRules(policy);
    const nameRemains =
      after.ok && after.groups.some(g => g.source.kind === 'template' && g.source.name === name);
    if (!nameRemains) {
      if (name === justAdded) setJustAdded(null);
      if (name === insertedTemplate?.template.name) setInsertedTemplate(null);
    }
    changePolicyWithUndo(policy, message ?? `Removed the rules from the template ${name}.`, () => {
      setInsertedTemplate(previousInserted);
      setJustAdded(previousJustAdded);
    });
  };

  const removeRule = (rule: PolicyRule) => {
    const parsed = parsePolicyRules(form.policy);
    const group = parsed.ok
      ? parsed.groups.find(g => g.rules.some(r => r.startLine === rule.startLine))
      : undefined;
    if (group?.source.kind === 'template' && group.rules.length === 1) {
      removeGroup(
        group,
        `Removed the rule ${rule.head}, the last from the template ${group.source.name}.`
      );
      return;
    }
    changePolicyWithUndo(removeRuleLines(form.policy, rule), `Removed the rule ${rule.head}.`);
  };

  const denyByDefault = () =>
    changePolicyWithUndo(setDefaultDeny(form.policy), 'Requests are now denied by default.');

  /** Selects a rule's lines in the Rego textarea and scrolls them into view. */
  const showRule = (rule: PolicyRule) => {
    const textarea = regoRef.current;
    if (!textarea) return;
    const lines = form.policy.split('\n');
    const start =
      lines.slice(0, rule.startLine - 1).join('\n').length + (rule.startLine > 1 ? 1 : 0);
    const end = lines.slice(0, rule.endLine).join('\n').length;
    textarea.focus();
    textarea.setSelectionRange(start, end);
    const lineHeight = parseFloat(getComputedStyle(textarea).lineHeight) || 20;
    textarea.scrollTop = Math.max(0, (rule.startLine - 3) * lineHeight);
  };

  return {
    usedTemplate,
    templatePicked,
    setTemplatePicked,
    insertedTemplate,
    dismissInsertedTemplate: () => setInsertedTemplate(null),
    justAdded,
    addedRules,
    regoRef,
    applyTemplate,
    editPolicy,
    pickBlank,
    insertTemplate,
    removeGroup,
    removeRule,
    denyByDefault,
    showRule,
  };
}
