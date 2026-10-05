import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import type { CanvasNode } from '../../SurfaceCanvas';
import { isTransitPointType } from '../edges/archetypes';
import CustomMetadataPanel from './CustomMetadataPanel';
import { DOCS_URL } from '../../../../config/docs';

/**
 * Build a single custom-metadata slice from the nodes that belong to one
 * direction. Returns `undefined` when no node in that direction has any
 * meaningful entries.
 */
function buildSlice(nodes: any[]): any | undefined {
  if (nodes.length === 0) return undefined;
  const entries = nodes.flatMap(n => n.config?.entries || []).filter((e: any) => e?.key);
  if (entries.length === 0) return undefined;
  const value: any = {
    enabled: true,
    payload: Object.fromEntries(entries.map((e: any) => [e.key, e.value || ''])),
  };
  const injTarget = nodes.find(n => n.config?.injection_target)?.config?.injection_target;
  if (injTarget) value.injection_target = injTarget;
  return value;
}

function parentIsTransitPoint(node: CanvasNode, allNodes: CanvasNode[]): boolean {
  const parent = node.parentId ? allNodes.find(n => n.id === node.parentId) : undefined;
  return !!parent && isTransitPointType(parent.type);
}

export const customMetadataDefinition: NodeDefinition = {
  type: 'custom-metadata',
  label: 'Metadata Injection',
  description: 'Inject custom request or response headers, extensions, or body fields',
  icon: '\uf02c', // fa-tags
  paletteIcon: 'fa-tags',
  color: '#6c757d',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.6,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 4,
  dropMode: 'edge',
  help: {
    title: 'Metadata Injection',
    docLink: DOCS_URL.metadataElements,
    bodyHtml: `
      <p>Inject a fixed set of <strong>key/value pairs</strong> into every
      request or response that flows through this Surface. The Agent
      Gateway adds them at the configured location (the upstream agent
      never knows where they came from).</p>
      <p><strong>Direction:</strong> set by drop position. Drop on the
      <strong>request</strong> arrow to inject on the way in; drop on
      the <strong>response</strong> arrow to inject on the way out. You
      can drop more than one node per direction; their entries are
      merged.</p>
      <p>Every pair is added to both the HTTP request/response headers
      and the protocol's own metadata field (<code>_meta</code>).</p>
      <p>Typical uses: stamp a tenant id, attach a routing hint for the
      managed agent, mark every response with a trace identifier.</p>
    `,
  },
  directionality: 'either',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.METADATA_TARGET],
  },
  incompleteReason: c => {
    const hasInjectionEntries = Array.isArray(c.entries) && c.entries.length > 0;
    if (!hasInjectionEntries) return 'Add at least one metadata entry';
    if (!c.entries.every((e: any) => e?.key)) return 'All entries must have a key';
    return null;
  },
  ConfigPanel: CustomMetadataPanel,
  payloadPath: 'target.custom_metadata',
  responsePayloadPath: 'target.response_custom_metadata',
  configFromPayload: slice => {
    // Hydrate the persisted `{ enabled, payload: {k:v}, injection_target }`
    // shape back into the panel's `{ entries: [{key, value, target}] }`
    // form. Without this round-trip, a saved metadata element reloads
    // with no entries and the panel reports "must have at least one
    // entry" even though the underlying payload has them.
    if (!slice || typeof slice !== 'object') return { entries: [] };
    const payload = slice.payload && typeof slice.payload === 'object' ? slice.payload : {};
    const target = slice.injection_target || 'header';
    const entries = Object.entries(payload).map(([key, value]) => ({
      key,
      value: typeof value === 'string' ? value : String(value ?? ''),
      target,
    }));
    return {
      entries,
      ...(slice.injection_target ? { injection_target: slice.injection_target } : {}),
    };
  },
  buildPayload: ctx => {
    const all = ctx.nodesOfType('custom-metadata');
    if (all.length === 0) return undefined;
    const requestNodes = all.filter(n => (n.direction ?? 'request') === 'request');
    const responseNodes = all.filter(n => n.direction === 'response');
    const nonTransitRequestNodes = requestNodes.filter(n => !parentIsTransitPoint(n, ctx.allNodes));
    const slices: PayloadSlice[] = [];
    const reqValue = buildSlice(nonTransitRequestNodes);
    if (reqValue) slices.push({ path: 'target.custom_metadata', value: reqValue });
    const respValue = buildSlice(responseNodes.filter(n => !parentIsTransitPoint(n, ctx.allNodes)));
    if (respValue) slices.push({ path: 'target.response_custom_metadata', value: respValue });
    return slices.length > 0 ? slices : undefined;
  },
};
