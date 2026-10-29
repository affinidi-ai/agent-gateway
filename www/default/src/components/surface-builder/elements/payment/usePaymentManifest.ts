import { useEffect, useRef, useState } from 'react';
import { apiClient } from '../../../../api';
import type { PaymentManifest } from '../../../../types';
import { manifestDrift } from './manifest';

interface LiveState {
  key: string;
  manifest: PaymentManifest | null;
  error: string | null;
  loading: boolean;
}

const EMPTY: LiveState = { key: '', manifest: null, error: null, loading: false };

const MANIFEST_ERROR_MESSAGES: Record<string, string> = {
  invalid_payment_surface_id: 'This is not a valid payment surface id.',
  gateway_not_found: 'The payment gateway is not known to this gateway.',
  payment_manifest_not_found:
    'agent-pay has no payment manifest for this surface. Check that it is a payment surface.',
  payment_manifest_rejected: 'agent-pay returned a payment manifest that could not be used.',
  payment_gateway_unavailable:
    'The payment gateway is not connected or did not answer. Try Refresh.',
};

function manifestErrorMessage(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === 'string' && MANIFEST_ERROR_MESSAGES[code]) {
    return MANIFEST_ERROR_MESSAGES[code];
  }
  const msg = err instanceof Error ? err.message : String(err);
  if (/timeout|timed out|504/i.test(msg)) return 'agent-pay did not answer in time. Try Refresh.';
  if (/503|not connected/i.test(msg)) return MANIFEST_ERROR_MESSAGES.payment_gateway_unavailable;
  return `Could not load the manifest: ${msg}`;
}

/**
 * The manifest to preview for the chosen payment surface. A saved
 * `manifest_snapshot` is shown until the selection changes or the operator
 * refreshes; after a refresh, `drift` lists what changed since the save.
 */
export function usePaymentManifest(
  gatewayId: string,
  surfaceId: string,
  snapshot: PaymentManifest | undefined
) {
  const initial = useRef({ gatewayId, surfaceId });
  const [refreshTick, setRefreshTick] = useState(0);
  const forceNext = useRef(false);
  const [live, setLive] = useState<LiveState>(EMPTY);
  const key = gatewayId && surfaceId ? `${gatewayId}\u0000${surfaceId}` : '';
  const snapshotMatches =
    !!snapshot &&
    gatewayId === initial.current.gatewayId &&
    surfaceId === initial.current.surfaceId;

  useEffect(() => {
    if (!key) {
      setLive(EMPTY);
      return;
    }
    if (snapshotMatches && refreshTick === 0) return;
    let cancelled = false;
    const force = forceNext.current;
    setLive({ key, manifest: null, error: null, loading: true });
    const timer = setTimeout(() => {
      forceNext.current = false;
      apiClient
        .getPaymentManifest(gatewayId, surfaceId, force)
        .then(manifest => {
          if (!cancelled) setLive({ key, manifest, error: null, loading: false });
        })
        .catch(err => {
          if (!cancelled) {
            setLive({ key, manifest: null, error: manifestErrorMessage(err), loading: false });
          }
        });
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, refreshTick, snapshotMatches]);

  const current = live.key === key ? live : EMPTY;
  const pending = !!key && live.key !== key && !(snapshotMatches && refreshTick === 0);
  const fetched = current.key !== '' && !current.loading && !current.error;
  const manifest = fetched ? current.manifest : snapshotMatches ? snapshot! : null;
  const drift =
    snapshotMatches && fetched && current.manifest
      ? manifestDrift(snapshot!, current.manifest)
      : [];

  return {
    manifest,
    source: fetched ? ('live' as const) : snapshotMatches ? ('snapshot' as const) : null,
    loading: current.loading || pending,
    error: current.error,
    drift,
    refresh: () => {
      forceNext.current = true;
      setRefreshTick(t => t + 1);
    },
  };
}
