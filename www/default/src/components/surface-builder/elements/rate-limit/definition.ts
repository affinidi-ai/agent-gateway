import * as Cap from '../capabilities';
import { registry } from '../registry';
import type { NodeDefinition } from '../types';
import { positiveIntError } from '../validators';
import RateLimitPanel from './RateLimitPanel';
import { DOCS_URL } from '../../../../config/docs';

/**
 * Convert the panel's flat config shape into the wire-format
 * RateLimitConfig object. Reused by the per-TP `transit.points[].rate_limit`
 * slice (the TP factory) and the AP-level `access_point.rate_limit` slice.
 */
export function rateLimitConfigToWire(c: any): Record<string, any> | undefined {
  if (!c?.requests) return undefined;
  return {
    requests: parseInt(c.requests),
    window_secs: parseInt(c.window_secs) || 60,
    ...(c.burst ? { burst: parseInt(c.burst) } : {}),
  };
}

export const rateLimitDefinition: NodeDefinition = {
  type: 'rate-limit',
  label: 'Rate Limit',
  description: 'Per-route or per-caller request rate limiting',
  icon: '\uf625', // fa-gauge-high
  paletteIcon: 'fa-tachometer-alt',
  color: '#fd7e14',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.3,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 3,
  dropMode: 'edge',
  help: {
    title: 'Rate Limit',
    docLink: DOCS_URL.networkingElements,
    bodyHtml: `
      <p>Cap how fast requests can flow through this Surface, shared across
      every caller, not a separate allowance per caller. Once the cap is
      hit the Gateway short-circuits with a throttling error (HTTP 429 for
      HTTP-style protocols, or a JSON-RPC error for MCP) and the upstream
      agent never sees the request.</p>
      <p><strong>Where it docks:</strong> request side only. Drop on the
      caller → access-point arrow to limit the inbound surface.
      Per-Transit-Point limits live on the TP itself, not here.</p>
      <p><strong>Settings:</strong></p>
      <ul>
        <li><strong>Request limit</strong> and <strong>Time window
        (seconds)</strong> together set a steady rate (limit ÷ window),
        refilled continuously rather than reset at a fixed point in time:
        e.g. <code>1000</code> requests / <code>60</code> seconds allows
        roughly 16-17 requests/second, sustained.</li>
        <li><strong>Burst</strong> <em>(optional)</em>: allow short
        spikes above that steady rate before throttling kicks in</li>
      </ul>
      <p>The limit is per-Surface and shared across every caller; capacity
      refills continuously rather than resetting at a fixed point in
      time.</p>
    `,
  },
  // Rate limiting only makes sense on the request side (we don't throttle
  // server\u2192caller responses). Element only docks on request arrows.
  directionality: 'request',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.RATE_LIMIT_TARGET],
  },
  incompleteReason: c => {
    if (!c.requests) return 'Request limit is required';
    if (!c.window_secs) return 'Time window is required';
    return null;
  },
  validate: c => {
    const errs: Array<{ field?: string; message: string }> = [];
    const r = positiveIntError('requests', c.requests, 'Request limit');
    if (r) errs.push(r);
    const w = positiveIntError('window_secs', c.window_secs, 'Time window');
    if (w) errs.push(w);
    return errs;
  },
  ConfigPanel: RateLimitPanel,
  payloadPath: 'access_point.rate_limit',
  // Pre-fill defaults so a freshly-dropped rate limit "just works".
  defaultConfig: () => ({ requests: '1000', window_secs: '60' }),
  summary: c => (c?.requests ? `${c.requests}/${c.window_secs || 60}s` : null),
  buildPayload: ctx => {
    // Slot identity is the source of truth: the AP→MA `request:rate-limit`
    // slot is `ownedBy: 'source'` so an inbound rate limit always carries
    // that slotId. Per-TP rate-limit (handled by the transit contributor)
    // never carries this slotId. Per-TP nodes (parented to a TP) are
    // folded into `transit.points[]` by the TP factory — skip them here
    // so we don't double-write or end up with bogus `access_point.rate_limit`
    // data driven by a per-TP node.
    const inbound = ctx.nodesOfType('rate-limit').find(n => {
      // Skip TP-parented rate limits (handled by TP factory).
      if (n.parentId) {
        const parent = ctx.allNodes.find(p => p.id === n.parentId);
        if (parent && registry.isTransitPointType(parent.type)) return false;
      }
      return (
        n.slotId === 'request:rate-limit' ||
        (!n.slotId && (!n.parentId || n.parentId === 'access-point'))
      );
    });
    const value = rateLimitConfigToWire(inbound?.config);
    if (!value) return undefined;
    return [
      {
        path: 'access_point.rate_limit',
        value,
      },
    ];
  },
};
