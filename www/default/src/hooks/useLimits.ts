import { useCallback, useEffect, useMemo, useState } from 'react';
import { apiClient, LimitItem } from '../api';

export interface LimitCheck {
  atLimit: boolean;
  current: number;
  limit: number;
  name: string;
  message: string;
}

/**
 * Fetches the appliance resource limits (GET /v1/limits) and exposes a
 * `checkLimit` that mirrors backend enforcement: a create is blocked when the
 * leaf dimension OR its umbrella parent is at capacity. A missing/unconfigured
 * dimension is treated as uncapped (returns null).
 */
export function useLimits() {
  const [items, setItems] = useState<LimitItem[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiClient.getLimits();
      setItems(Array.isArray(data) ? data : []);
    } catch {
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const byId = useMemo(() => new Map(items.map(i => [i.id, i])), [items]);

  const checkLimit = useCallback(
    (dimension: string): LimitCheck | null => {
      const candidates: LimitItem[] = [];
      const leaf = byId.get(dimension);
      if (leaf) candidates.push(leaf);
      const dot = dimension.lastIndexOf('.');
      if (dot > 0) {
        const parent = byId.get(dimension.slice(0, dot));
        if (parent) candidates.push(parent);
      }
      const blocking = candidates.find(c => c.current >= c.limit);
      if (!blocking) return null;
      return {
        atLimit: true,
        current: blocking.current,
        limit: blocking.limit,
        name: blocking.name,
        message: `You've reached the limit of ${blocking.limit} for ${blocking.name} (${blocking.current} of ${blocking.limit} in use). Upgrade your appliance tier to add more.`,
      };
    },
    [byId]
  );

  return { items, loading, refresh, checkLimit };
}
