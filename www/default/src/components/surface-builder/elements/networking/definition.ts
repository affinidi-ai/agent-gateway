import * as Cap from '../capabilities';
import { registry } from '../registry';
import type { NodeDefinition } from '../types';
import NetworkingPanel from './NetworkingPanel';
import { DOCS_URL } from '../../../../config/docs';

/**
 * Convert the panel's flat config shape into the wire-format
 * NetworkingConfig object. Returns `undefined` when no sub-feature is
 * enabled. Reused by both `target.networking` (this element) and the
 * per-TP `transit.points[].networking` slice (the TP factory).
 */
export function networkingConfigToWire(c: any): Record<string, any> | undefined {
  if (!c) return undefined;
  const out: any = {};
  if (c.timeout_secs) {
    out.timeout = {
      request_secs: parseInt(c.timeout_secs, 10),
      ...(c.connect_timeout_secs ? { connect_secs: parseInt(c.connect_timeout_secs, 10) } : {}),
      ...(c.idle_timeout_secs ? { idle_secs: parseInt(c.idle_timeout_secs, 10) } : {}),
    };
  }
  if (c.retry_enabled) {
    out.retry = {
      max_attempts: parseInt(c.retry_max, 10) || 3,
      ...(c.retry_initial_backoff_ms
        ? { initial_backoff_ms: parseInt(c.retry_initial_backoff_ms, 10) }
        : {}),
      ...(c.retry_max_backoff_ms ? { max_backoff_ms: parseInt(c.retry_max_backoff_ms, 10) } : {}),
      ...(c.retry_backoff_multiplier
        ? { backoff_multiplier: parseFloat(c.retry_backoff_multiplier) }
        : {}),
      ...(c.retry_status_codes
        ? {
            retryable_status_codes: String(c.retry_status_codes)
              .split(',')
              .map((s: string) => parseInt(s.trim(), 10))
              .filter((n: number) => !Number.isNaN(n)),
          }
        : {}),
    };
  }
  if (c.circuit_breaker_enabled) {
    out.circuit_breaker = {
      failure_threshold: parseInt(c.cb_threshold, 10) || 5,
      timeout_secs: parseInt(c.cb_recovery_secs, 10) || 30,
      ...(c.cb_success_threshold
        ? { success_threshold: parseInt(c.cb_success_threshold, 10) }
        : {}),
      ...(c.cb_window_secs ? { window_secs: parseInt(c.cb_window_secs, 10) } : {}),
    };
  }
  if (c.mirror_enabled) {
    out.mirror = {
      endpoint: c.mirror_endpoint || '',
      percentage: parseInt(c.mirror_percentage || '100', 10),
      // The panel's `mirror_async` flag is the inverse of the backend's
      // `wait_for_response`: async=true means fire-and-forget, i.e.
      // wait_for_response=false.
      ...(c.mirror_async !== undefined ? { wait_for_response: !c.mirror_async } : {}),
      ...(c.mirror_timeout_secs ? { timeout_secs: parseInt(c.mirror_timeout_secs, 10) } : {}),
    };
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

export const networkingDefinition: NodeDefinition = {
  type: 'networking',
  label: 'Networking',
  description: 'Timeout, retry, circuit breaker, and traffic mirroring',
  icon: '\uf6ff', // fa-network-wired
  paletteIcon: 'fa-network-wired',
  color: '#36b9cc',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.65,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 2,
  dropMode: 'edge',
  directionality: 'request',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.NETWORKING_TARGET],
  },
  help: {
    title: 'Networking',
    docLink: DOCS_URL.networkingElements,
    bodyHtml: `
      <p>Transport-level controls for how the Gateway talks to the
      upstream Managed Agent. Bundles four independent sub-features that
      you can mix and match. Enabling at least one is required for the
      element to be considered configured.</p>
      <p><strong>Where it docks:</strong> on the request edge into the
      Target.</p>
      <p><strong>Sub-features:</strong></p>
      <ul>
        <li><strong>Timeout</strong>: cap request, connect and idle
        durations. Hitting the cap fails the call with a timeout error.</li>
        <li><strong>Retry</strong>: automatic re-issue on retryable
        status codes with exponential back-off (initial / max backoff,
        multiplier, max attempts).</li>
        <li><strong>Circuit breaker</strong>: trip after
        <em>failure threshold</em> errors inside <em>window</em>; stay
        open for <em>timeout</em> seconds; close again after
        <em>success threshold</em> probes succeed. Protects the upstream
        from cascading failure.</li>
        <li><strong>Mirror</strong>: duplicate a percentage of live
        traffic to a shadow endpoint for testing. Fire-and-forget by
        default (<em>async</em>); when off the Gateway waits for the
        mirror response (still ignores its body) within
        <em>mirror timeout</em>.</li>
      </ul>
    `,
  },
  incompleteReason: c =>
    !(c.timeout_secs || c.retry_enabled || c.circuit_breaker_enabled || c.mirror_enabled)
      ? 'At least one networking option must be configured'
      : null,
  featureDependencies: [
    {
      description: 'Mirror percentage must be between 0 and 100',
      condition: c => !!c.mirror_enabled,
      check: c => {
        const p = Number(c.mirror_percentage);
        return !Number.isNaN(p) && p >= 0 && p <= 100;
      },
      severity: 'error',
      message: 'Mirror percentage must be between 0 and 100',
    },
    {
      description: 'Mirror requires an endpoint',
      condition: c => !!c.mirror_enabled,
      check: c => !!c.mirror_endpoint,
      severity: 'warning',
      message: 'Mirror requires a target endpoint',
    },
  ],
  ConfigPanel: NetworkingPanel,
  payloadPath: 'target.networking',
  // Pre-fill sensible defaults for every numeric option so toggling
  // a sub-feature on (retry / circuit breaker / mirror) gives a working
  // configuration immediately, with no empty fields to interpret.
  defaultConfig: () => ({
    timeout_secs: '30',
    connect_timeout_secs: '5',
    idle_timeout_secs: '90',
    retry_max: '3',
    retry_backoff_multiplier: '2',
    retry_initial_backoff_ms: '100',
    retry_max_backoff_ms: '5000',
    cb_threshold: '5',
    cb_success_threshold: '3',
    cb_recovery_secs: '30',
    cb_window_secs: '60',
    mirror_percentage: '100',
    mirror_timeout_secs: '5',
  }),
  summary: c => {
    const parts: string[] = [];
    if (c?.timeout_secs) parts.push(`Timeout: ${c.timeout_secs}s`);
    if (c?.retry_enabled) parts.push('Retry');
    if (c?.circuit_breaker_enabled) parts.push('CB');
    if (c?.mirror_enabled) parts.push('Mirror');
    return parts.length > 0 ? parts.join(' | ') : null;
  },
  buildPayload: ctx => {
    // Per-TP networking nodes are folded into `transit.points[]` by the
    // TP factory (it owns the entire transit.points slice), so they
    // must NOT contribute to `target.networking`. We additionally
    // require the node's ancestor chain to reach the `target` node so
    // an inbound networking blob (parented to access-point/policy)
    // doesn't accidentally clobber the target-side configuration.
    const reachesTarget = (n: any): boolean => {
      let cur: any = n;
      const seen = new Set<string>();
      while (cur?.parentId && !seen.has(cur.parentId)) {
        seen.add(cur.parentId);
        const parent = ctx.allNodes.find(p => p.id === cur.parentId);
        if (!parent) return false;
        if (registry.isTransitPointType(parent.type)) return false;
        if (parent.type === 'target') return true;
        cur = parent;
      }
      return false;
    };
    const node = ctx.nodesOfType('networking').find(reachesTarget);
    const out = networkingConfigToWire(node?.config);
    if (!out) return undefined;
    return [{ path: 'target.networking', value: out }];
  },
};
