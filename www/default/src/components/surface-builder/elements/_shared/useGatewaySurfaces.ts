import { useCallback, useEffect, useState } from 'react';
import { apiClient, type ApiError } from '../../../../api';
import type { PaymentManifest } from '../../../../types';
import { filterSelectableGateways, type GatewayRecord } from '../../../../utils/gateways';

export interface GatewayOption {
  id: string;
  name?: string;
}

/** A surface published by a remote gateway, as `GET /gateways/{id}/surfaces` lists it. */
export interface RemoteSurface {
  config_id: string;
  name: string;
  protocol?: string;
  tags: string[];
  is_payment_surface: boolean | null;
  has_manifest: boolean;
  description?: string;
  /** The surface's Payment Manifest, when the peer is an agent-pay gateway that publishes one. */
  payment_manifest?: PaymentManifest;
}

export interface GatewaySurfacesState {
  gateways: GatewayOption[];
  gatewaysLoading: boolean;
  gatewaysError: string | null;
  reloadGateways: () => void;
  surfaces: RemoteSurface[];
  surfacesLoading: boolean;
  surfacesError: string | null;
  refreshSurfaces: () => void;
}

interface RawSurface {
  config_id?: unknown;
  name?: unknown;
  description?: unknown;
  protocol?: unknown;
  tags?: unknown;
  is_payment_surface?: unknown;
  payment_manifest?: unknown;
}

const GATEWAYS_ERROR = 'Could not load the connected gateways.';

/** The active remote gateways a `fabric://` route can reach. */
export async function loadFabricGateways(): Promise<GatewayOption[]> {
  const { data } = await apiClient.get<GatewayRecord[]>('/gateways');
  return filterSelectableGateways(data).map(gw => ({ id: gw.id, name: gw.name }));
}

/** Split `fabric://{gateway_id}/{surface_id}` into its parts, or null for any other endpoint. */
export function parseFabricEndpoint(
  endpoint: unknown
): { gatewayId: string; surfaceId: string } | null {
  if (typeof endpoint !== 'string' || !endpoint.startsWith('fabric://')) return null;
  const rest = endpoint.slice('fabric://'.length);
  const slash = rest.indexOf('/');
  if (slash < 0) return { gatewayId: rest, surfaceId: '' };
  return { gatewayId: rest.slice(0, slash), surfaceId: rest.slice(slash + 1) };
}

const isManifest = (value: unknown): value is PaymentManifest =>
  !!value &&
  typeof value === 'object' &&
  typeof (value as { version?: unknown }).version === 'string';

/**
 * Whether a remote surface speaks `protocol`. A surface from a peer that does
 * not report its protocol is kept, and no protocol keeps every surface.
 */
export function surfaceMatchesProtocol(
  surface: { protocol?: string },
  protocol: string | null | undefined
): boolean {
  if (!protocol || !surface.protocol) return true;
  return surface.protocol.toLowerCase() === protocol.toLowerCase();
}

/** A readable message for a failed surface listing; the raw error text is never shown. */
export function surfacesErrorMessage(err: unknown): string {
  const status = (err as Partial<ApiError> | null)?.status;
  const message = err instanceof Error ? err.message.toLowerCase() : '';
  if (status === 503 || message.includes('not connected')) {
    return 'Gateway is not connected, so its surfaces cannot be listed. Refresh once it reconnects.';
  }
  if (status === 404) return 'Gateway not found. It may have been removed.';
  return 'Could not load surfaces from this gateway. Try Refresh.';
}

/** The surfaces of a `/surfaces` listing, which is a list or `{ channels: [...] }`. */
export function toRemoteSurfaces(data: unknown): RemoteSurface[] {
  const list: RawSurface[] = Array.isArray(data)
    ? data
    : Array.isArray((data as { channels?: unknown })?.channels)
      ? (data as { channels: RawSurface[] }).channels
      : [];
  return list
    .filter((s): s is RawSurface & { config_id: string } => typeof s?.config_id === 'string')
    .map(s => ({
      config_id: s.config_id,
      name: typeof s.name === 'string' && s.name ? s.name : s.config_id,
      protocol: typeof s.protocol === 'string' ? s.protocol : undefined,
      tags: Array.isArray(s.tags) ? s.tags.filter((t): t is string => typeof t === 'string') : [],
      is_payment_surface: typeof s.is_payment_surface === 'boolean' ? s.is_payment_surface : null,
      has_manifest: !!s.payment_manifest,
      ...(typeof s.description === 'string' && s.description ? { description: s.description } : {}),
      ...(isManifest(s.payment_manifest) ? { payment_manifest: s.payment_manifest } : {}),
    }));
}

/**
 * Loads the gateways a picker offers and the surfaces of the selected one. A
 * response for an earlier gateway is dropped, so it never lists under a later
 * one. `loadGateways` must be stable across renders; it is asked to bypass
 * any cache (`force`) when the gateways are reloaded. Surfaces are listed from
 * `{surfacesBasePath}/{id}/surfaces`: `/gateways` for a peer, `/payment-gateways`
 * for a payment gateway.
 */
export function useGatewaySurfaces({
  enabled,
  gatewayId,
  loadGateways,
  surfacesBasePath = '/gateways',
}: {
  enabled: boolean;
  gatewayId: string;
  loadGateways: (force: boolean) => Promise<GatewayOption[]>;
  surfacesBasePath?: '/gateways' | '/payment-gateways';
}): GatewaySurfacesState {
  const [gateways, setGateways] = useState<GatewayOption[]>([]);
  const [gatewaysLoading, setGatewaysLoading] = useState(enabled);
  const [gatewaysError, setGatewaysError] = useState<string | null>(null);
  const [gatewaysTick, setGatewaysTick] = useState(0);
  const [surfaces, setSurfaces] = useState<RemoteSurface[]>([]);
  const [surfacesLoading, setSurfacesLoading] = useState(false);
  const [surfacesError, setSurfacesError] = useState<string | null>(null);
  const [surfacesTick, setSurfacesTick] = useState(0);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setGatewaysLoading(true);
    setGatewaysError(null);
    loadGateways(gatewaysTick > 0)
      .then(list => {
        if (!cancelled) setGateways(list);
      })
      .catch(() => {
        if (cancelled) return;
        setGateways([]);
        setGatewaysError(GATEWAYS_ERROR);
      })
      .finally(() => {
        if (!cancelled) setGatewaysLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [enabled, loadGateways, gatewaysTick]);

  useEffect(() => {
    setSurfaces([]);
    setSurfacesError(null);
    if (!enabled || !gatewayId) {
      setSurfacesLoading(false);
      return;
    }
    let cancelled = false;
    setSurfacesLoading(true);
    const force = surfacesTick > 0 ? '?force_refresh=true' : '';
    apiClient
      .get(`${surfacesBasePath}/${encodeURIComponent(gatewayId)}/surfaces${force}`)
      .then(({ data }) => {
        if (!cancelled) setSurfaces(toRemoteSurfaces(data));
      })
      .catch((err: unknown) => {
        if (!cancelled) setSurfacesError(surfacesErrorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setSurfacesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [enabled, gatewayId, surfacesTick, surfacesBasePath]);

  const reloadGateways = useCallback(() => setGatewaysTick(t => t + 1), []);
  const refreshSurfaces = useCallback(() => setSurfacesTick(t => t + 1), []);

  return {
    gateways,
    gatewaysLoading,
    gatewaysError,
    reloadGateways,
    surfaces,
    surfacesLoading,
    surfacesError,
    refreshSurfaces,
  };
}
