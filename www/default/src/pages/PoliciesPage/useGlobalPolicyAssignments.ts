import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';

export interface GlobalAssignment {
  policy_id: string;
  monitor_only: boolean;
}

interface GlobalPolicyAssignmentsPayload {
  assignments: Record<string, GlobalAssignment[]>;
}

export interface UseGlobalPolicyAssignments {
  loading: boolean;
  saving: boolean;
  error: string | null;
  clearError: () => void;
  isEnforced: (policyType: string, policyId: string) => boolean;
  isMonitorOnly: (policyType: string, policyId: string) => boolean;
  setEnforcement: (
    policyType: string,
    policyId: string,
    enforced: boolean,
    monitorOnly: boolean
  ) => Promise<void>;
}

/**
 * Load and mutate the appliance-wide (global) policy assignments — which
 * reusable policies are enforced on every object of a plane: every gateway
 * (`gateway`) or every agent surface (`agent_surface`), independent of each
 * object's own OPA configuration. The PUT sends the full map, so mutating one
 * plane preserves the other. Pass `enabled = false` to skip the fetch entirely.
 */
export function useGlobalPolicyAssignments(enabled: boolean): UseGlobalPolicyAssignments {
  const [assignments, setAssignments] = useState<Record<string, GlobalAssignment[]>>({});
  const [loading, setLoading] = useState(enabled);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const resp = await apiClient.fetch('/api/v1/policy-assignments');
      if (!resp.ok) throw new Error(`Failed to load policy assignments: ${resp.statusText}`);
      const data = (await resp.json()) as GlobalPolicyAssignmentsPayload;
      setAssignments(data.assignments ?? {});
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load policy assignments');
    } finally {
      setLoading(false);
    }
  }, [enabled]);

  useEffect(() => {
    load();
  }, [load]);

  const isEnforced = useCallback(
    (policyType: string, policyId: string) =>
      (assignments[policyType] ?? []).some(a => a.policy_id === policyId),
    [assignments]
  );

  const isMonitorOnly = useCallback(
    (policyType: string, policyId: string) =>
      (assignments[policyType] ?? []).some(a => a.policy_id === policyId && a.monitor_only),
    [assignments]
  );

  const setEnforcement = useCallback(
    async (policyType: string, policyId: string, enforced: boolean, monitorOnly: boolean) => {
      const next: Record<string, GlobalAssignment[]> = { ...assignments };
      const list = (next[policyType] ?? []).filter(a => a.policy_id !== policyId);
      if (enforced) list.push({ policy_id: policyId, monitor_only: monitorOnly });
      next[policyType] = list;
      try {
        setSaving(true);
        setError(null);
        const resp = await apiClient.fetch('/api/v1/policy-assignments', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ assignments: next }),
        });
        if (!resp.ok) {
          const detail = await resp.text().catch(() => '');
          throw new Error(detail || `Failed to update policy assignments: ${resp.statusText}`);
        }
        setAssignments(next);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to update policy assignments');
        throw e;
      } finally {
        setSaving(false);
      }
    },
    [assignments]
  );

  return {
    loading,
    saving,
    error,
    clearError: () => setError(null),
    isEnforced,
    isMonitorOnly,
    setEnforcement,
  };
}
