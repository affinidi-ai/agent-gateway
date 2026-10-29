import { useEffect, useState } from 'react';
import { apiClient } from '../api';
import { fetchSurfaceDeclarations, type SurfaceDeclarations } from '../utils/surfaceDeclarations';

export type SurfaceDeclarationsState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'unavailable' }
  | ({ status: 'ready' } & SurfaceDeclarations);

export function useSurfaceDeclarations(
  surfaceId: string | undefined,
  refreshKey?: unknown
): SurfaceDeclarationsState {
  const [state, setState] = useState<SurfaceDeclarationsState>({ status: 'idle' });

  useEffect(() => {
    if (!surfaceId) {
      setState({ status: 'idle' });
      return;
    }
    let cancelled = false;
    setState({ status: 'loading' });
    fetchSurfaceDeclarations((url, init) => apiClient.fetch(url, init), surfaceId).then(result => {
      if (cancelled) return;
      setState(result ? { status: 'ready', ...result } : { status: 'unavailable' });
    });
    return () => {
      cancelled = true;
    };
  }, [surfaceId, refreshKey]);

  return state;
}
