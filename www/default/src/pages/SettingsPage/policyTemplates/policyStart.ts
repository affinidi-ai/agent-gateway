import {
  ALLOW_ALL_POLICY,
  BLANK_TEMPLATE_ID,
  DEFAULT_POLICY,
  DEFAULT_TEMPLATE_KEY,
} from './policyDefaults';
import { parsePolicyRules, removeRuleGroup, type ParsedPolicy } from './regoRules';
import { renderWithText } from './TemplatePreview';
import type { PolicyTemplate, PolicyType } from './types';
import type { AddedRules, UsedTemplate } from './usePolicyTemplateActions';

export const CUSTOM_POLICY_NAME = 'Custom policy';

export interface PolicyStart {
  /** The template the policy started from, or a custom policy. */
  name: string;
  /** Template groups added to the Rego since. */
  templatesAdded: number;
}

const trimEnd = (rego: string) => rego.replace(/\s+$/, '');

/**
 * For each rule group, the Type its template was written for when no template of that name
 * serves `policyType`, matched by name; null for every other group.
 */
export function groupsForOtherType(
  parsed: ParsedPolicy,
  policyType: PolicyType,
  templates: PolicyTemplate[]
): (PolicyType | null)[] {
  if (!parsed.ok) return [];
  const forType = new Set(templates.filter(t => t.policy_type === policyType).map(t => t.name));
  const writtenFor = new Map(
    templates.filter(t => !forType.has(t.name)).map(t => [t.name, t.policy_type] as const)
  );
  return parsed.groups.map(g =>
    g.source.kind === 'template' ? (writtenFor.get(g.source.name.trim()) ?? null) : null
  );
}

/**
 * What a new policy started from, while its Rego still follows it: each template group in the
 * Rego still holds exactly the lines Add to policy wrote, and the Rego without those groups
 * equals what the start renders to (the used template with its settings, `ALLOW_ALL_POLICY` for
 * Allow all, or `DEFAULT_POLICY`, Deny by default, when no template was used). Null, shown as
 * Custom Rego, after a hand edit anywhere, a removed rule of the start, or a Type change the
 * start doesn't serve.
 */
export function policyStart(
  policy: string,
  policyType: PolicyType,
  usedTemplate: UsedTemplate | null,
  templates: PolicyTemplate[],
  addedRules: AddedRules[]
): PolicyStart | null {
  const parsed = parsePolicyRules(policy);
  if (!parsed.ok) return null;
  const added = parsed.groups.filter(g => g.source.kind === 'template');
  const lines = policy.split('\n');
  const unmatched = [...addedRules];
  for (const group of added) {
    const name = group.source.kind === 'template' ? group.source.name.trim() : '';
    const body = lines.slice(group.startLine, group.endLine - 1).join('\n');
    const index = unmatched.findIndex(r => r.name.trim() === name && r.body === body);
    if (index < 0) return null;
    unmatched.splice(index, 1);
  }
  const base = added.reduceRight((rego, group) => removeRuleGroup(rego, group), policy);

  let start: { name: string; rego: string | null } | null;
  if (usedTemplate?.id === BLANK_TEMPLATE_ID) {
    start = { name: CUSTOM_POLICY_NAME, rego: ALLOW_ALL_POLICY[policyType] };
  } else {
    const id = usedTemplate?.id ?? `${DEFAULT_TEMPLATE_KEY}:${policyType}`;
    const template = templates.find(t => t.id === id);
    start = template
      ? {
          name: template.name,
          rego: usedTemplate
            ? renderWithText(template, usedTemplate.fieldText).rego
            : DEFAULT_POLICY[policyType],
        }
      : null;
  }
  if (!start?.rego || trimEnd(base) !== trimEnd(start.rego)) return null;
  return { name: start.name, templatesAdded: added.length };
}
