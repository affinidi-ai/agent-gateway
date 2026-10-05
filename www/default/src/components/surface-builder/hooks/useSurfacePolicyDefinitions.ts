import { useEffect, useState } from 'react';
import { apiClient } from '../../../api';
import type { SurfacePolicyDefinitionLoadState } from '../elements/policy/status';

/**
 * Fetches the ids of all `agent_surface` policy definitions once on mount.
 *
 * The surface builder uses the resulting set to flag a Policy node whose
 * attached definition no longer exists, and to gate Save while the list is
 * still loading. A load error is non-blocking (the backend validates policy
 * references on save) — see `policyDefinitionsBlockingReason`.
 */
export function useSurfacePolicyDefinitions(): SurfacePolicyDefinitionLoadState {
  const [state, setState] = useState<SurfacePolicyDefinitionLoadState>({
    status: 'loading',
    ids: null,
  });

  useEffect(() => {
    let alive = true;
    apiClient
      .fetch('/api/v1/policy-definitions?policy_type=agent_surface')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: Array<{ id?: string }>) => {
        if (!alive) return;
        const ids = new Set(
          (Array.isArray(data) ? data : []).map(p => p.id).filter(Boolean) as string[]
        );
        setState({ status: 'loaded', ids });
      })
      .catch((err: unknown) => {
        if (!alive) return;
        setState({
          status: 'error',
          ids: null,
          error: err instanceof Error ? err.message : 'Unknown error',
        });
      });
    return () => {
      alive = false;
    };
  }, []);

  return state;
}
