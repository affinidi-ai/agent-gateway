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
import { usePolicyTemplateServices } from './policyTemplateServices';
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

/** What the templates column shows instead of Add rules; null shows Add rules. */
export type TemplatePanel = 'save';

/** The policy form fields a template fills. */
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
  const { notifyUndo } = usePolicyTemplateServices();
  const [templatePanel, setTemplatePanel] = useState<TemplatePanel | null>(null);
  // Only Use and Allow all set it; whether the Rego still follows it is derived from the Rego.
  const [usedTemplate, setUsedTemplate] = useState<UsedTemplate | null>(null);
  // A new policy shows its Details and Policy sections only once a template is used.
  const [templatePicked, setTemplatePicked] = useState(!isCreateMode);
  const [insertedTemplate, setInsertedTemplate] = useState<InsertedTemplate | null>(null);
  const [justAdded, setJustAdded] = useState<string | null>(null);
  const [addedRules, setAddedRules] = useState<AddedRules[]>([]);
  const regoRef = useRef<HTMLTextAreaElement>(null);

  const togglePanel = (panel: TemplatePanel) => setTemplatePanel(p => (p === panel ? null : panel));

  const applyTemplate = (template: PolicyTemplate, rego: string, fieldText: FieldText) => {
    const previous = { name: form.name, description: form.description, policy: form.policy };
    const previousUsed = usedTemplate;
    const previousPicked = templatePicked;
    // Using the used template again keeps the name and description as typed.
    const reapplying = usedTemplate?.id === template.id;
    setForm(f => ({
      ...f,
      name: reapplying ? f.name : template.name,
      description: reapplying ? f.description : template.description,
      policy: rego,
    }));
    setUsedTemplate({ id: template.id, fieldText });
    setTemplatePicked(true);
    setTemplatePanel(null);
    notifyUndo({
      message: `Filled from the template ${template.name}. ${UNDO_FORM}`,
      onUndo: () => {
        setForm(f => ({ ...f, ...previous }));
        setUsedTemplate(previousUsed);
        setTemplatePicked(previousPicked);
      },
    });
  };

  const pickBlank = () => {
    const previousPolicy = form.policy;
    const previousUsed = usedTemplate;
    const previousPicked = templatePicked;
    setForm(f => ({ ...f, policy: ALLOW_ALL_POLICY[f.policy_type] }));
    setUsedTemplate({ id: BLANK_TEMPLATE_ID, fieldText: {} });
    setTemplatePicked(true);
    notifyUndo({
      message: `Started a custom policy. ${UNDO_REGO}`,
      onUndo: () => {
        setForm(f => ({ ...f, policy: previousPolicy }));
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
    notifyUndo({
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
    notifyUndo({
      message: `${message} ${UNDO_REGO}`,
      onUndo: () => {
        setForm(f => ({ ...f, policy: previousPolicy }));
        setUsedTemplate(previousUsed);
        onUndo?.();
      },
    });
  };

  const removeGroup = (group: RuleGroup) => {
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
    changePolicyWithUndo(policy, `Removed the rules from the template ${name}.`, () => {
      setInsertedTemplate(previousInserted);
      setJustAdded(previousJustAdded);
    });
  };

  const removeRule = (rule: PolicyRule) =>
    changePolicyWithUndo(removeRuleLines(form.policy, rule), `Removed the rule ${rule.head}.`);

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
    templatePanel,
    setTemplatePanel,
    togglePanel,
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
