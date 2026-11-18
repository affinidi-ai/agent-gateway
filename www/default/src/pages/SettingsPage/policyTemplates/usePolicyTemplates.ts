import { useCallback, useEffect, useState } from 'react';
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

  return {
    builtin: templates.filter(t => t.builtin),
    organization: templates.filter(t => !t.builtin),
    loading,
    error,
  };
}
