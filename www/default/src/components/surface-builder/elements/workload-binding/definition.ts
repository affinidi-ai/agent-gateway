import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import { isTransitPointType } from '../edges/archetypes';
import {
  defaultWorkloadBindingConfig,
  validateWorkloadBinding,
  workloadBindingApiToForm,
  workloadBindingFormToApi,
  type WorkloadBindingFormConfig,
} from './config';
import WorkloadBindingPanel from './WorkloadBindingPanel';
import { DOCS_URL } from '../../../../config/docs';

/**
 * Workload Binding — binds the managed-agent identity plus a caller-context
 * allowlist into the outbound `agent-identity-credential/v1` VP so a downstream
 * gateway (GW2) can verify who the workload is acting for. It docks on two
 * request edges:
 *
 *  - **MA → Transit Point** (`ma-tp`) — per-Transit-Point. The Transit Point
 *    factory folds the TP-parented node into
 *    `transit.points[i].workload_binding`, so no `buildPayload` runs for those.
 *  - **MA → External** (`ma-external`) — the primary target leg. The element
 *    owns the `target.workload_binding` slice itself via `buildPayload`, and
 *    `reachesTarget` guards it so a TP-parented node never double-writes.
 */
export const workloadBindingDefinition: NodeDefinition = {
  type: 'workload-binding',
  label: 'Workload Binding',
  description:
    'Bind managed-agent identity + caller context into the outbound identity credential (Target or Transit Point)',
  icon: '\uf0c1', // fa-link
  paletteIcon: 'fa-link',
  color: '#e67e22',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.85,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 6,
  dropMode: 'edge',
  directionality: 'request',
  edgeSnap: {
    radius: 100000,
    archetypes: ['ma-tp', 'ma-external'],
  },
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.WORKLOAD_BINDING_TARGET],
  },
  help: {
    title: 'Workload Binding',
    docLink: DOCS_URL.outboundBindingElements,
    bodyHtml: `
      <p>Adds the <strong>managed-agent identity</strong> and a chosen
      set of <strong>caller-context</strong> claims to the outbound
      identity credential presented to the destination, so a downstream
      Agent Gateway can verify <em>which workload</em> is acting and
      <em>on whose behalf</em>.</p>
      <p><strong>Requires identity injection</strong> on the same leg.
      Workload Binding enriches that credential; on its own it has
      nothing to bind into.</p>
      <p><strong>Where it docks:</strong> the request edge into the Target
      (MA → External) or into a Transit Point (MA → TP). Each leg carries
      its own binding, applied just to that outbound route.</p>
      <p><strong>Caller source:</strong></p>
      <ul>
        <li><strong>Transit token</strong>: read caller claims from the
        signed transit token presented to this TP.</li>
        <li><strong>Authorization bearer JWT</strong>: read caller
        claims from the inbound <code>Authorization: Bearer</code> JWT.</li>
        <li><strong>DID authentication</strong>: use the DID resolved
        by the surface's DID Auth source authentication. The DID becomes
        the caller identity and its <code>SHA-256</code> hash the
        delegation-vault user key.</li>
      </ul>
      <p>The <strong>caller field allowlist</strong> selects which
      top-level caller claims are copied into the binding; only listed
      claims cross the boundary.</p>
    `,
  },
  incompleteReason: (config: WorkloadBindingFormConfig) =>
    config?.enabled ? null : 'Enable workload binding to bind caller context',
  validate: (config: WorkloadBindingFormConfig) =>
    validateWorkloadBinding(config).map(e => ({ field: e.field, message: e.message })),
  featureDependencies: [
    {
      description:
        'caller_source=did sources the caller identity from a DID-authenticated session, so the surface must authenticate the caller with DID Auth',
      condition: c => c?.enabled === true && c?.caller_source === 'did',
      check: (_c, ctx) =>
        ctx.allNodes.some(n => n.type === 'caller-auth' && n.config?.method_type === 'did_auth'),
      severity: 'error',
      message: 'caller_source=did requires a Caller Context element using DID Auth on this surface',
    },
  ],
  defaultConfig: () => ({ ...defaultWorkloadBindingConfig(), enabled: true }),
  ConfigPanel: WorkloadBindingPanel,
  /**
   * Hydrate panel state from a `target.workload_binding` slice (ma-external)
   * or a `transit.points[i].workload_binding` slice (ma-tp). Both share the
   * same wire shape, so one converter serves both.
   */
  configFromPayload: slice => workloadBindingApiToForm(slice),
  /**
   * Own the `target.workload_binding` slice for the MA→EXT leg only. A
   * TP-parented node is folded by the Transit Point factory, so `reachesTarget`
   * skips any node whose ancestor chain passes through a Transit Point.
   */
  buildPayload: ctx => {
    const reachesTarget = (n: { id: string; parentId?: string }): boolean => {
      let cur: { id: string; parentId?: string } | undefined = n;
      const seen = new Set<string>();
      while (cur?.parentId && !seen.has(cur.parentId)) {
        seen.add(cur.parentId);
        const parent = ctx.allNodes.find(p => p.id === cur!.parentId);
        if (!parent) return false;
        if (isTransitPointType(parent.type)) return false;
        if (parent.type === 'target') return true;
        cur = parent;
      }
      return false;
    };
    const node = ctx.nodesOfType('workload-binding').find(reachesTarget);
    const wb = workloadBindingFormToApi(node?.config as WorkloadBindingFormConfig | undefined);
    if (!wb) return undefined;
    const slices: PayloadSlice[] = [{ path: 'target.workload_binding', value: wb }];
    return slices;
  },
  summary: (config: WorkloadBindingFormConfig) => {
    if (!config?.enabled) return 'disabled';
    const n = config.caller_context_fields?.length ?? 0;
    const src =
      config.caller_source === 'authorization_bearer_jwt'
        ? 'bearer JWT'
        : config.caller_source === 'did'
          ? 'DID Auth'
          : 'transit token';
    return `${src} · ${n} caller field${n === 1 ? '' : 's'}`;
  },
};
