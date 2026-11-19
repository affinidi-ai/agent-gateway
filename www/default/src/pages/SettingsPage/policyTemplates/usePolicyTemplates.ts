import { useEffect, useMemo, useState } from 'react';
import { usePolicyTemplateServices } from './policyTemplateServices';
import type { PolicyTemplate, PolicyType } from './types';

interface PolicyTemplatesState {
  builtin: PolicyTemplate[];
  organization: PolicyTemplate[];
  loading: boolean;
  error: string | null;
}

/**
 * Templates of one policy type from the store, split into built-in and organisation templates,
 * listed again after every save. A list that returns after a newer one started is dropped.
 */
export function usePolicyTemplates(policyType: PolicyType): PolicyTemplatesState {
  const { store } = usePolicyTemplateServices();
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let latest = 0;
    let active = true;
    const load = async () => {
      const request = ++latest;
      try {
        const listed = await store.list(policyType);
        if (!active || request !== latest) return;
        setTemplates(listed);
        setError(null);
      } catch (e) {
        if (!active || request !== latest) return;
        setError(e instanceof Error ? e.message : 'Failed to load policy templates');
      } finally {
        if (active && request === latest) setLoading(false);
      }
    };
    setLoading(true);
    void load();
    const unsubscribe = store.subscribe(() => void load());
    return () => {
      active = false;
      unsubscribe();
    };
  }, [store, policyType]);

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

/** Every template of both policy types, read once and shared by the gallery and Add rules. */
export interface PolicyTemplateLibrary {
  entries: TemplateEntry[];
  /** The built-in templates of both Types. */
  builtin: PolicyTemplate[];
  /** Whether each Type's list is still loading. */
  loading: Record<PolicyType, boolean>;
  error: string | null;
}

/**
 * Templates of every policy type, grouped into entries: built-in ones first, in the order the
 * store lists Agent Surface templates and then any Gateway-only ones, then organisation ones.
 */
export function useAllPolicyTemplates(): PolicyTemplateLibrary {
  const gateway = usePolicyTemplates('gateway');
  const surface = usePolicyTemplates('agent_surface');
  const entries = useMemo(
    () =>
      groupTemplateEntries([
        ...surface.builtin,
        ...gateway.builtin,
        ...gateway.organization,
        ...surface.organization,
      ]),
    [gateway.builtin, gateway.organization, surface.builtin, surface.organization]
  );
  const builtin = useMemo(
    () => [...surface.builtin, ...gateway.builtin],
    [gateway.builtin, surface.builtin]
  );
  return {
    entries,
    builtin,
    loading: { gateway: gateway.loading, agent_surface: surface.loading },
    error: gateway.error ?? surface.error,
  };
}
