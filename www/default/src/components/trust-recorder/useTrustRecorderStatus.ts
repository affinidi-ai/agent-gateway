import { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import type { TrustRecorderStatus } from '../../types';

export type TrustRecorderStatusView =
  | { phase: 'loading' }
  | { phase: 'error' }
  | { phase: 'ready'; status: TrustRecorderStatus | null };

export function useTrustRecorderStatus(surfaceId: string): TrustRecorderStatusView {
  const [view, setView] = useState<{ surfaceId: string; result: TrustRecorderStatusView } | null>(
    null
  );

  useEffect(() => {
    let cancelled = false;
    apiClient
      .getSurfaceTrustRecorderStatus(surfaceId)
      .then(status => {
        if (!cancelled) setView({ surfaceId, result: { phase: 'ready', status } });
      })
      .catch(() => {
        if (!cancelled) setView({ surfaceId, result: { phase: 'error' } });
      });
    return () => {
      cancelled = true;
    };
  }, [surfaceId]);

  return view?.surfaceId === surfaceId ? view.result : { phase: 'loading' };
}
