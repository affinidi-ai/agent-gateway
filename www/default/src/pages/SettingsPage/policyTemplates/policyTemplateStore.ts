import { BUILTIN_POLICY_TEMPLATES } from './builtinPolicyTemplates';
import type {
  PolicyTemplate,
  PolicyTemplateCategory,
  PolicyTemplateExample,
  PolicyType,
} from './types';

/**
 * Policy templates served to the editor. Built-in templates ship with the dashboard;
 * organisation templates saved with {@link savePolicyTemplate} live for the browser
 * session only, until the gateway stores them.
 */

export interface NewPolicyTemplate {
  name: string;
  summary: string;
  category: PolicyTemplateCategory;
  policy_type: PolicyType;
  rego: string;
  reads: string[];
  examples: PolicyTemplateExample[];
}

let organizationTemplates: PolicyTemplate[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

export function subscribePolicyTemplates(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export async function listPolicyTemplates(policyType: PolicyType): Promise<PolicyTemplate[]> {
  return [...BUILTIN_POLICY_TEMPLATES, ...organizationTemplates].filter(
    t => t.policy_type === policyType
  );
}

export async function savePolicyTemplate(input: NewPolicyTemplate): Promise<PolicyTemplate> {
  const name = input.name.trim();
  if (!name) throw new Error('Enter a template name.');
  const taken = organizationTemplates.some(
    t => t.policy_type === input.policy_type && t.name.toLowerCase() === name.toLowerCase()
  );
  if (taken) throw new Error(`A template named "${name}" already exists.`);
  const template: PolicyTemplate = {
    id: `org:${nextId++}`,
    name,
    summary: input.summary.trim(),
    description: input.summary.trim(),
    category: input.category,
    policy_type: input.policy_type,
    rego: input.rego,
    parameters: [],
    reads: input.reads,
    examples: input.examples,
    builtin: false,
  };
  organizationTemplates = [...organizationTemplates, template];
  listeners.forEach(l => l());
  return template;
}

/** Clears saved organisation templates. Tests only. */
export function resetOrganizationTemplatesForTests(): void {
  organizationTemplates = [];
  listeners.forEach(l => l());
}
