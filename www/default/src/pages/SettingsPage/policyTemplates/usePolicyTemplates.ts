import { useCallback, useEffect, useMemo, useState } from 'react';
import { BUILTIN_POLICY_TEMPLATES } from './builtinPolicyTemplates';
import { listPolicyTemplates, subscribePolicyTemplates } from './policyTemplateStore';
import type { PolicyTemplate, PolicyType } from './types';

interface PolicyTemplatesState {
  builtin: PolicyTemplate[];
  organization: PolicyTemplate[];
  loading: boolean;
  error: string | null;
}

/** Templates of one policy type, split into built-in and organisation templates. */
export function usePolicyTemplates(policyType: PolicyType): PolicyTemplatesState {
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setTemplates(await listPolicyTemplates(policyType));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load policy templates');
    } finally {
      setLoading(false);
    }
  }, [policyType]);

  useEffect(() => {
    void load();
    return subscribePolicyTemplates(() => void load());
  }, [load]);

  const builtin = useMemo(() => templates.filter(t => t.builtin), [templates]);
  const organization = useMemo(() => templates.filter(t => !t.builtin), [templates]);
  return { builtin, organization, loading, error };
}

/** One template as the gallery shows it: its variants for each policy type it serves. */
export interface TemplateEntry {
  key: string;
  variants: Partial<Record<PolicyType, PolicyTemplate>>;
}

/** Built-in variants share the id before `:`; an organisation template is its own entry. */
export function templateEntryKey(template: PolicyTemplate): string {
  return template.builtin ? template.id.split(':')[0] : template.id;
}

/** Groups templates of both types into entries, keeping the order of their first variant. */
export function groupTemplateEntries(templates: PolicyTemplate[]): TemplateEntry[] {
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

/** Templates of every policy type, grouped into entries, built-in in catalogue order first. */
export function useAllPolicyTemplates(): TemplateEntry[] {
  const gateway = usePolicyTemplates('gateway');
  const surface = usePolicyTemplates('agent_surface');
  return useMemo(() => {
    const order = new Map(BUILTIN_POLICY_TEMPLATES.map((t, i) => [t.id, i]));
    const builtin = [...gateway.builtin, ...surface.builtin].sort(
      (a, b) => (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0)
    );
    return groupTemplateEntries([...builtin, ...gateway.organization, ...surface.organization]);
  }, [gateway.builtin, gateway.organization, surface.builtin, surface.organization]);
}
