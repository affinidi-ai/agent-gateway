import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../api';
import {
  fetchAgentCardPreview,
  refreshAgentCardPreview,
  type AgentCardPreview,
  type CardJson,
  type RefreshResult,
} from '../utils/agentCardPreview';

export type AgentCardPreviewState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'unavailable' }
  | { status: 'ready'; preview: AgentCardPreview };

export interface ServedCardSnapshot {
  card: CardJson;
  fetchedAt: string | null;
}

export type PreviewRefreshResult = RefreshResult | { kind: 'stale' };

export interface UseAgentCardPreview {
  state: AgentCardPreviewState;
  refresh: () => Promise<PreviewRefreshResult>;
  reload: () => void;
  refreshing: boolean;
  lastServed: ServedCardSnapshot | null;
}

const fetcher = (url: string, init?: RequestInit) => apiClient.fetch(url, init);

function servedSnapshot(preview: AgentCardPreview): ServedCardSnapshot | null {
  if (!preview.supported || preview.fetch.status !== 'ok' || preview.after === null) return null;
  return { card: preview.after, fetchedAt: preview.fetched_at };
}

export function useAgentCardPreview(
  surfaceId: string | undefined,
  refreshKey?: unknown
): UseAgentCardPreview {
  const [state, setState] = useState<AgentCardPreviewState>({ status: 'idle' });
  const [refreshing, setRefreshing] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);
  const [served, setServed] = useState<{
    surfaceId: string;
    snapshot: ServedCardSnapshot;
  } | null>(null);
  const generation = useRef(0);

  const show = useCallback((id: string, preview: AgentCardPreview) => {
    setState({ status: 'ready', preview });
    const snapshot = servedSnapshot(preview);
    if (snapshot) setServed({ surfaceId: id, snapshot });
  }, []);

  useEffect(() => {
    generation.current += 1;
    const mine = generation.current;
    setRefreshing(false);
    if (!surfaceId) {
      setState({ status: 'idle' });
      return;
    }
    setState({ status: 'loading' });
    fetchAgentCardPreview(fetcher, surfaceId).then(preview => {
      if (generation.current !== mine) return;
      if (preview) show(surfaceId, preview);
      else setState({ status: 'unavailable' });
    });
    return () => {
      generation.current += 1;
    };
  }, [surfaceId, refreshKey, reloadTick, show]);

  const refresh = useCallback(async (): Promise<PreviewRefreshResult> => {
    if (!surfaceId) return { kind: 'error' };
    const mine = generation.current;
    setRefreshing(true);
    const result = await refreshAgentCardPreview(fetcher, surfaceId);
    if (generation.current !== mine) return { kind: 'stale' };
    setRefreshing(false);
    if (result.kind === 'ok') show(surfaceId, result.preview);
    return result;
  }, [surfaceId, show]);

  const reload = useCallback(() => setReloadTick(t => t + 1), []);

  const lastServed = served && served.surfaceId === surfaceId ? served.snapshot : null;

  return { state, refresh, reload, refreshing, lastServed };
}
