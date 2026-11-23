import type { PolicyTemplate, PolicyType } from './types';

/** One template as the gallery shows it: its variants for each policy type it serves. */
export interface TemplateEntry {
  key: string;
  variants: Partial<Record<PolicyType, PolicyTemplate>>;
}

/** The variants of a template share the catalogue id before `:`. */
export function templateEntryKey(template: PolicyTemplate): string {
  return template.id.split(':')[0];
}

/** Groups templates of both types into entries, keeping the order of their first variant. */
export function groupTemplateEntries(templates: readonly PolicyTemplate[]): TemplateEntry[] {
  const entries = new Map<string, TemplateEntry>();
  for (const template of templates) {
    const key = templateEntryKey(template);
    const entry = entries.get(key) ?? { key, variants: {} };
    entry.variants[template.policy_type] = template;
    entries.set(key, entry);
  }
  return Array.from(entries.values());
}

/** The gallery's templates for a Type: each entry's variant for it, skipping entries without one. */
export function galleryTemplates(
  entries: TemplateEntry[],
  policyType: PolicyType
): PolicyTemplate[] {
  return entries.map(e => e.variants[policyType]).filter((t): t is PolicyTemplate => !!t);
}

/** Keys of the entries that serve Agent Surface policies only. */
export function surfaceOnlyKeys(entries: TemplateEntry[]): Set<string> {
  return new Set(entries.filter(e => !e.variants.gateway).map(e => e.key));
}

/** Every template of both policy types, shared by the gallery and Add rules. */
export interface PolicyTemplateLibrary {
  entries: TemplateEntry[];
  /** The templates of both Types. */
  templates: readonly PolicyTemplate[];
}

/**
 * A library of `catalogue`, Agent Surface variants first in catalogue order, then the Gateway
 * ones, so the entries keep that order.
 */
export function buildTemplateLibrary(catalogue: readonly PolicyTemplate[]): PolicyTemplateLibrary {
  const ofType = (policyType: PolicyType) => catalogue.filter(t => t.policy_type === policyType);
  const templates = [...ofType('agent_surface'), ...ofType('gateway')];
  return { entries: groupTemplateEntries(templates), templates };
}
