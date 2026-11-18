import { useRef, useState, type Dispatch, type SetStateAction } from 'react';
import { showUndoToast } from '../../../utils/toaster';
import { BLANK_TEMPLATE_ID, DEFAULT_POLICY } from './policyDefaults';
import { removeRuleGroup, setDefaultDeny, type PolicyRule, type RuleGroup } from './regoRules';
import { defaultParameterValues, insertTemplateRules, renderTemplate } from './regoTemplate';
import type { PolicyTemplate, PolicyType } from './types';

/** What the templates column shows instead of Add rules; null shows Add rules. */
const TYPE_NAME: Record<PolicyType, string> = {
  gateway: 'Gateway',
  agent_surface: 'Agent Surfaces',
};

export type TemplatePanel = 'browse' | 'save';

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
  const [templatePanel, setTemplatePanel] = useState<TemplatePanel | null>(null);
  const [appliedTemplateId, setAppliedTemplateId] = useState<string | null>(BLANK_TEMPLATE_ID);
  const [insertedTemplate, setInsertedTemplate] = useState<InsertedTemplate | null>(null);
  const [justAdded, setJustAdded] = useState<string | null>(null);
  const regoRef = useRef<HTMLTextAreaElement>(null);

  const togglePanel = (panel: TemplatePanel) => setTemplatePanel(p => (p === panel ? null : panel));

  const applyTemplate = (template: PolicyTemplate, rego: string) => {
    const previous: TemplateFormFields = {
      name: form.name,
      description: form.description,
      policy_type: form.policy_type,
      policy: form.policy,
    };
    const previousTemplateId = appliedTemplateId;
    setForm(f => ({
      ...f,
      name: template.name,
      description: template.description,
      policy_type: template.policy_type,
      policy: rego,
    }));
    setAppliedTemplateId(template.id);
    setTemplatePanel(null);
    showUndoToast({
      message:
        template.policy_type === previous.policy_type
          ? `Filled from the template ${template.name}.`
          : `Filled from the template ${template.name}. Type set to ${TYPE_NAME[template.policy_type]}.`,
      onUndo: () => {
        setForm(f => ({ ...f, ...previous }));
        setAppliedTemplateId(previousTemplateId);
      },
    });
  };

  const pickTemplate = (template: PolicyTemplate) => {
    const { rego } = renderTemplate(template, defaultParameterValues(template));
    if (rego) applyTemplate(template, rego);
  };

  const pickBlank = () => {
    const previousPolicy = form.policy;
    const previousTemplateId = appliedTemplateId;
    setForm(f => ({ ...f, policy: DEFAULT_POLICY[f.policy_type] }));
    setAppliedTemplateId(BLANK_TEMPLATE_ID);
    showUndoToast({
      message: 'Rego reset to the default policy.',
      onUndo: () => {
        setForm(f => ({ ...f, policy: previousPolicy }));
        setAppliedTemplateId(previousTemplateId);
      },
    });
  };

  // The panel stays open after an insert so rules from several templates can be combined.
  const insertTemplate = (template: PolicyTemplate, rego: string, usesDefaultSettings: boolean) => {
    const previousPolicy = form.policy;
    const previousInserted = insertedTemplate;
    const previousTemplateId = appliedTemplateId;
    const previousJustAdded = justAdded;
    setForm(f => ({ ...f, policy: insertTemplateRules(f.policy, template.name, rego).policy }));
    setJustAdded(template.name);
    if (isCreateMode) {
      setAppliedTemplateId(null);
    } else {
      setInsertedTemplate(prev => ({ template, usesDefaultSettings, key: (prev?.key ?? 0) + 1 }));
    }
    showUndoToast({
      message: `Added rules from the template ${template.name}. ${isCreateMode ? 'Create' : 'Save'} to keep them.`,
      onUndo: () => {
        setForm(f => ({ ...f, policy: previousPolicy }));
        setInsertedTemplate(previousInserted);
        setAppliedTemplateId(previousTemplateId);
        setJustAdded(previousJustAdded);
      },
    });
  };

  const changePolicyWithUndo = (policy: string, message: string, onUndo?: () => void) => {
    const previousPolicy = form.policy;
    setForm(f => ({ ...f, policy }));
    if (isCreateMode) setAppliedTemplateId(null);
    showUndoToast({
      message,
      onUndo: () => {
        setForm(f => ({ ...f, policy: previousPolicy }));
        onUndo?.();
      },
    });
  };

  const removeGroup = (group: RuleGroup) => {
    const name = group.source.kind === 'template' ? group.source.name : '';
    const previousInserted = insertedTemplate;
    const previousJustAdded = justAdded;
    if (name === justAdded) setJustAdded(null);
    if (name === insertedTemplate?.template.name) setInsertedTemplate(null);
    changePolicyWithUndo(
      removeRuleGroup(form.policy, group),
      `Removed the rules from the template ${name}.`,
      () => {
        setInsertedTemplate(previousInserted);
        setJustAdded(previousJustAdded);
      }
    );
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
    templatePanel,
    setTemplatePanel,
    togglePanel,
    appliedTemplateId,
    setAppliedTemplateId,
    insertedTemplate,
    dismissInsertedTemplate: () => setInsertedTemplate(null),
    justAdded,
    regoRef,
    applyTemplate,
    pickTemplate,
    pickBlank,
    insertTemplate,
    removeGroup,
    denyByDefault,
    showRule,
  };
}
