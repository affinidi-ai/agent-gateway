import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../api';

interface Resolved {
  gatewayName?: string;
  surfaceName?: string;
}

interface GatewayLite {
  id?: string;
  gateway_id?: string;
  name?: string;
}

interface SurfaceLite {
  config_id?: string;
  name?: string;
}

function parseFabric(url: string | undefined): { gatewayId: string; surfaceId: string } | null {
  if (!url || !url.startsWith('fabric://')) return null;
  const rest = url.slice('fabric://'.length);
  const idx = rest.indexOf('/');
  if (idx <= 0) return null;
  const gatewayId = rest.slice(0, idx);
  const surfaceId = rest.slice(idx + 1).split('/')[0];
  if (!surfaceId) return null;
  return { gatewayId, surfaceId };
}

/**
 * Resolves `fabric://<gateway_id>/<surface_id>` endpoints to human-readable
 * names by querying `/gateways` and `/gateways/{id}/surfaces`. Returns a
 * `resolveFabric(url)` helper plus a `formatFabric(url)` helper that yields
 * `"<gatewayName> / <surfaceName>"` (falling back to ids when unresolved).
 */
export function useFabricResolver(seedUrls: Array<string | undefined>) {
  const [gateways, setGateways] = useState<Map<string, string>>(new Map());
  const [surfacesByGw, setSurfacesByGw] = useState<Map<string, Map<string, string>>>(new Map());
  const probedGws = useRef<Set<string>>(new Set());

  useEffect(() => {
    apiClient
      .get('/gateways')
      .then(res => {
        const list: GatewayLite[] = res.data || [];
        const m = new Map<string, string>();
        for (const g of list) {
          const id = g.gateway_id || g.id;
          if (id && g.name) m.set(id, g.name);
        }
        setGateways(m);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const wanted = new Set<string>();
    for (const u of seedUrls) {
      const parsed = parseFabric(u);
      if (parsed) wanted.add(parsed.gatewayId);
    }
    const toFetch: string[] = [];
    for (const gid of wanted) {
      if (!probedGws.current.has(gid)) {
        probedGws.current.add(gid);
        toFetch.push(gid);
      }
    }
    if (toFetch.length === 0) return;
    toFetch.forEach(gid => {
      apiClient
        .get(`/gateways/${gid}/surfaces`)
        .then(res => {
          const data = res.data;
          const list: SurfaceLite[] = Array.isArray(data) ? data : data?.channels || [];
          setSurfacesByGw(prev => {
            const next = new Map(prev);
            const inner = new Map<string, string>();
            for (const s of list) {
              if (s.config_id && s.name) inner.set(s.config_id, s.name);
            }
            next.set(gid, inner);
            return next;
          });
        })
        .catch(() => {});
    });
  }, [seedUrls]);

  const resolveFabric = useCallback(
    (url: string | undefined): Resolved | null => {
      const parsed = parseFabric(url);
      if (!parsed) return null;
      return {
        gatewayName: gateways.get(parsed.gatewayId),
        surfaceName: surfacesByGw.get(parsed.gatewayId)?.get(parsed.surfaceId),
      };
    },
    [gateways, surfacesByGw]
  );

  const formatFabric = useCallback(
    (url: string | undefined): { display: string; title: string } | null => {
      const parsed = parseFabric(url);
      if (!parsed || !url) return null;
      const resolved = resolveFabric(url);
      const gw = resolved?.gatewayName || parsed.gatewayId;
      const sf = resolved?.surfaceName || parsed.surfaceId;
      return { display: `${gw} / ${sf}`, title: url };
    },
    [resolveFabric]
  );

  return { resolveFabric, formatFabric };
}
