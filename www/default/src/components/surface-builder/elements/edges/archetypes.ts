/**
 * Edge archetype catalogue + drop dispatcher.
 *
 * Slot inventory is typed: one slot per (element-type, direction) per
 * archetype, each carrying its own `payloadPathTemplate`. The catch-all
 * `'*'` sentinel is kept as a low-priority fallback so unknown element
 * types still attach (and so existing tests that verify generic-mw
 * dispatch keep passing), but every shipped element resolves to a typed
 * slot.
 */

import type { SurfaceNodeType } from '../../nodeTypes';
import type { DerivedEdge, EdgeArchetypeDef, SlotDef, SlotDirection, SlotId } from './types';
import type { CanvasNode } from '../../SurfaceCanvas';

/** Sentinel meaning "any element type that matches this slot's direction". */
export const ANY_EDGE_MW = '*' as const;
export type SlotAccepts = ReadonlyArray<SurfaceNodeType> | typeof ANY_EDGE_MW;

/**
 * Concrete slot type used by the runtime catalogue. We narrow `accepts`
 * here to allow the `'*'` sentinel; the public `SlotDef` keeps a strict
 * array shape so callers outside this module can rely on it.
 */
export interface RuntimeSlotDef extends Omit<SlotDef, 'accepts'> {
  accepts: SlotAccepts;
}

export interface RuntimeEdgeArchetypeDef extends Omit<EdgeArchetypeDef, 'slots'> {
  slots: ReadonlyArray<RuntimeSlotDef>;
}

/**
 * Typed slot factory. Each element type that can sit on an edge gets
 * its own slot with a stable id (`${direction}:${type}`), a canonical
 * render order, and the AgentSurface payload path it writes to.
 *
 * `cardinality: 'one'` is the default: every element type writes to a
 * single object key per (edge × direction), so a second drop is a slot
 * conflict, not a chain extension.
 */
function typedSlot(
  type: SurfaceNodeType,
  direction: SlotDirection,
  order: number,
  payloadPathTemplate: string,
  label: string,
  extras: Partial<RuntimeSlotDef> = {}
): RuntimeSlotDef {
  // `identity` is the one element with multiple typed slots that share
  // the same (type, direction) tuple (inbound/protected/external), so
  // the default `${direction}:${type}` id would collide between
  // AP→MA's `response:identity` (protected) and MA→External's
  // `response:identity` (external). Disambiguate identity slot ids by
  // suffixing the payload-path leaf so `findSlotById` round-trips a
  // node's persisted `slotId` back to the correct payload path.
  const id =
    type === 'trust-check' && payloadPathTemplate
      ? // trust-check has a `_list` slot on both legs with identical
        // path tails (`trust_check_list`). Encode the full path so
        // ap-ma vs ma-tp slot ids stay distinct for `findSlotById`.
        `${direction}:${type}-${payloadPathTemplate.replace(/\./g, '_')}`
      : type === 'identity' && payloadPathTemplate
        ? `${direction}:${type}-${payloadPathTemplate.split('.').pop()}`
        : `${direction}:${type}`;
  return {
    id,
    direction,
    order,
    accepts: [type],
    cardinality: 'one',
    payloadPathTemplate,
    label,
    ...extras,
  };
}

/** Catch-all slot (unknown element types). Lowest priority. */
function catchAllSlot(direction: SlotDirection, order = 1000): RuntimeSlotDef {
  return {
    id: `${direction}:mw`,
    direction,
    order,
    accepts: ANY_EDGE_MW,
    cardinality: 'many',
    payloadPathTemplate: '',
    label: `${direction === 'request' ? 'Request' : 'Response'} middleware`,
  };
}

const apMaArchetype: RuntimeEdgeArchetypeDef = {
  id: 'ap-ma',
  matches: (s, t) => s.type === 'access-point' && t.type === 'target',
  directions: ['request', 'response'],
  slots: [
    // Request slots are ordered by the inbound execution seam where practical.
    // Caller authentication/source context runs before rate limiting. Header
    // Metadata Mapping runs after those gates and body read, before identity,
    // trust, policy, and forwarding controls consume the normalized metadata.
    // `request:policy-inbound` is the exception: runtime evaluates it before
    // target policy, but its slot order must stay after `request:policy` so a
    // newly dropped Policy still targets `target.policy` by default.
    typedSlot(
      'caller-auth',
      'request',
      5,
      'access_point.caller_authentication',
      'Caller authentication'
    ),
    typedSlot('rate-limit', 'request', 10, 'access_point.rate_limit', 'Rate limit'),
    typedSlot(
      'metadata-extraction',
      'request',
      20,
      'access_point.header_metadata_mapping',
      'Metadata extraction'
    ),
    typedSlot('payment', 'request', 40, 'target.payment_policy', 'Payment'),
    typedSlot(
      'extension-validation',
      'request',
      50,
      'access_point.extension_validation',
      'Extension validation'
    ),
    typedSlot('extension-rules', 'request', 55, 'target.extension_rules', 'Extension rules'),
    // Slot 1 — inbound identity (CA → AP request). Independent of the
    // response-side protected_identity slot. See `ChannelIdentitySlots`.
    typedSlot('identity', 'request', 60, 'identity_slots.inbound', 'Inbound identity (caller)', {
      ownedBy: 'source',
    }),
    typedSlot('custom-metadata', 'request', 70, 'target.custom_metadata', 'Metadata injection'),
    typedSlot(
      'trust-check',
      'request',
      80,
      'access_point.trust_check_list',
      'Trust check (caller leg)',
      { cardinality: 'one' }
    ),
    typedSlot('policy', 'request', 90, 'target.policy', 'Policy'),
    // Inbound policy variant: dropping a second `policy` on the AP-side
    // writes to a different payload key. tryDrop never picks this slot
    // (the typed `policy` slot above wins on order), but `nodesFromPayload`
    // emits it so existing surfaces with inbound policies still hydrate.
    {
      id: 'request:policy-inbound',
      direction: 'request',
      order: 91,
      accepts: ['policy'],
      cardinality: 'one',
      ownedBy: 'source',
      payloadPathTemplate: 'access_point.inbound_policy',
      label: 'Inbound policy',
    },
    typedSlot('networking', 'request', 100, 'target.networking', 'Networking'),
    catchAllSlot('request'),
    // Response: only elements with a response path live here.
    typedSlot('policy', 'response', 70, 'target.response_policy', 'Response policy'),
    // Slot 2 — protected agent identity (MA → AP response). Extracts the
    // managed-agent's identity from its reply so downstream hops can use it.
    typedSlot(
      'identity',
      'response',
      75,
      'identity_slots.protected',
      'Protected identity (from MA)',
      { ownedBy: 'target' }
    ),
    typedSlot(
      'trust-recorder',
      'response',
      77,
      'access_point.trust_recorder',
      'Trust Recorder (write records)',
      { ownedBy: 'target' }
    ),
    typedSlot(
      'custom-metadata',
      'response',
      80,
      'target.response_custom_metadata',
      'Response custom metadata'
    ),
    catchAllSlot('response'),
  ],
};

/**
 * Edge between the Managed Agent (target) and the External Target
 * representation downstream of it. The "external" endpoint is one of:
 *   - `npc-endpoint` — the auto-spawned External Target NPC for direct
 *     URL targets.
 *   - `local-gateway-hop` / `remote-gateway` — the synthesised view
 *     nodes for fabric:// destinations (G2G).
 *
 * Identity sits on the response arrow (External → MA). Networking is
 * also dropable here on the request arrow as an alias for the same
 * `target.networking` slot exposed on AP→MA — conceptually MA→External
 * IS the upstream call this config governs, so the user can land it on
 * whichever rendering of the hop they prefer.
 */
const maExternalArchetype: RuntimeEdgeArchetypeDef = {
  id: 'ma-external',
  matches: (s, t) =>
    s.type === 'target' &&
    (t.type === 'npc-endpoint' || t.type === 'local-gateway-hop' || t.type === 'remote-gateway'),
  directions: ['request', 'response'],
  slots: [
    typedSlot('networking', 'request', 50, 'target.networking', 'Networking', {
      ownedBy: 'source',
    }),
    typedSlot('rate-limit', 'request', 55, 'access_point.rate_limit', 'Rate limit', {
      ownedBy: 'source',
    }),
    typedSlot(
      'identity',
      'response',
      10,
      'identity_slots.external',
      'External identity (from external agent)',
      { ownedBy: 'source' }
    ),
    // Surface-wide MCP Tool Gating on the response leg from the external
    // target (the MCP server). Owned by the MA (edge source) so it writes to
    // the target-wide `target.mcp_tool_gating`, not a per-endpoint slot.
    typedSlot('mcp-tool-gating', 'response', 20, 'target.mcp_tool_gating', 'MCP Tool Gating', {
      ownedBy: 'source',
    }),
    typedSlot(
      'credential-delegation',
      'request',
      60,
      'outbound_credentials',
      'Credential Delegation',
      { ownedBy: 'source' }
    ),
    // Primary-target (MA→EXT) workload binding. Writes to
    // `target.workload_binding`; the workload-binding element owns the slice
    // via its own buildPayload (unlike the per-TP path, which the Transit
    // Point factory folds).
    typedSlot('workload-binding', 'request', 65, 'target.workload_binding', 'Workload Binding', {
      ownedBy: 'source',
    }),
  ],
};

const maTpArchetype: RuntimeEdgeArchetypeDef = {
  id: 'ma-tp',
  matches: (s, t) => s.type === 'target' && isTransitPointType(t.type),
  directions: ['request', 'response'],
  slots: [
    // Request slots are ordered by the outbound execution seam so auto-layout
    // renders the chain in the same order the Transit Point pipeline runs it.
    // Header mapping must appear before managed-agent identity because mapped
    // headers can become the metadata evidence identity extraction reads.
    // We intentionally do not declare a catch-all here so a misplaced drop is
    // rejected with a clear message instead of silently lost at save time.
    typedSlot('policy', 'request', 70, 'transit.points[{owner}].policy', 'Per-TP request policy', {
      ownedBy: 'target',
    }),
    // Target-leg trust-check writes to `target.trust_check_list` — a
    // target-wide (not per-TP) list — so the canvas node is owned by
    // the MA (edge source), same as hydration parents it. `ownedBy:
    // 'source'` keeps drop-parent and hydration-parent in agreement;
    // `deriveEdges` binds the MA-child node to every ma-tp edge so
    // snapping works on any MA→TP arrow.
    typedSlot('trust-check', 'request', 60, 'target.trust_check_list', 'Trust check (target leg)', {
      ownedBy: 'source',
      cardinality: 'one',
    }),
    typedSlot(
      'policy',
      'response',
      0,
      'transit.points[{owner}].response_policy',
      'Per-TP response policy',
      {
        ownedBy: 'target',
      }
    ),
    // Per-Transit-Point MCP Tool Gating on the response leg from a Transit
    // Point. Owned by the TP (edge target) so each TP carries its own gate,
    // written to `transit.points[{owner}].mcp_tool_gating` (like the per-TP
    // request/response policy). Independent of the surface-wide
    // `target.mcp_tool_gating` on the ma-external edge.
    typedSlot(
      'mcp-tool-gating',
      'response',
      5,
      'transit.points[{owner}].mcp_tool_gating',
      'MCP Tool Gating',
      {
        ownedBy: 'target',
      }
    ),
    typedSlot(
      'networking',
      'request',
      90,
      'transit.points[{owner}].networking',
      'Per-TP networking',
      { ownedBy: 'target' }
    ),
    typedSlot(
      'metadata-extraction',
      'request',
      20,
      'transit.points[{owner}].header_metadata_mapping',
      'Metadata extraction',
      { ownedBy: 'target' }
    ),
    typedSlot(
      'rate-limit',
      'request',
      10,
      'transit.points[{owner}].rate_limit',
      'Per-TP rate limit',
      { ownedBy: 'target' }
    ),
    // Per-TP outbound managed-agent identity. The node is owned by the
    // Transit Point and writes to `transit.points[{owner}].managed_identity`.
    // It resolves who the managed agent is when that managed agent initiates
    // a request through this TP.
    typedSlot(
      'identity',
      'request',
      30,
      'transit.points[{owner}].managed_identity',
      'Outbound managed-agent identity (this Transit Point)',
      { ownedBy: 'target' }
    ),
    // Per-TP workload binding (MA → TP request, this TP only). Writes to
    // `transit.points[{owner}].workload_binding`; the TP factory folds
    // the node in, same as per-TP managed identity.
    typedSlot(
      'workload-binding',
      'request',
      40,
      'transit.points[{owner}].workload_binding',
      'Per-TP workload binding',
      { ownedBy: 'target' }
    ),
  ],
};

export const EDGE_ARCHETYPES: ReadonlyArray<RuntimeEdgeArchetypeDef> = [
  apMaArchetype,
  maExternalArchetype,
  maTpArchetype,
];

export function isTransitPointType(type: string): boolean {
  return type.startsWith('transit-point-');
}

export function getArchetype(id: string): RuntimeEdgeArchetypeDef | undefined {
  return EDGE_ARCHETYPES.find(a => a.id === id);
}

/**
 * Resolve the archetype id for a (source-type, target-type) pair. Returns
 * undefined for pairs that no archetype matches (e.g. surface → AP, NPC
 * links, decorative connectors). Used by the canvas drop snap logic to
 * filter `findNearestEdge` candidates by archetype.
 */
export function findArchetypeForPair(
  srcType: SurfaceNodeType,
  tgtType: SurfaceNodeType
): string | undefined {
  const s = { type: srcType } as CanvasNode;
  const t = { type: tgtType } as CanvasNode;
  for (const arch of EDGE_ARCHETYPES) {
    // Archetype membership is undirected: response-leg visual links are
    // rendered with source/target swapped (e.g. MA→AP on the ap-ma
    // archetype), so try both orderings to keep drop-time archetype
    // filters direction-agnostic.
    if (arch.matches(s, t) || arch.matches(t, s)) return arch.id;
  }
  return undefined;
}

/**
 * Look up a slot by id across every archetype. Slot ids are unique in
 * practice (archetype + slot id is the formal key, but every typed
 * slot we ship has a globally unique id today). Returns undefined if
 * no archetype declares the slot — use this from `buildPayload` to
 * resolve a node's persisted `slotId` back to its `payloadPathTemplate`
 * without having to re-walk the derived edges.
 */
export function findSlotById(
  slotId: string
): { archetype: RuntimeEdgeArchetypeDef; slot: RuntimeSlotDef } | undefined {
  for (const archetype of EDGE_ARCHETYPES) {
    const slot = archetype.slots.find(s => s.id === slotId);
    if (slot) return { archetype, slot };
  }
  return undefined;
}

/** Result of `tryDrop`. */
export type TryDropResult =
  | { ok: true; slotId: SlotId }
  | { ok: false; reason: string; conflictingNodeId?: string };

/**
 * Decide whether `type` can be dropped on `edge` in `direction`.
 *
 * Selection rules:
 *  1. Filter slots to those whose direction matches and whose `accepts`
 *     includes the type (or is the `'*'` sentinel).
 *  2. Prefer a typed slot over the `'*'` catch-all. On ties, prefer the
 *     lower `order` value.
 *  3. A `'one'` slot already occupied is rejected with the conflicting
 *     occupant's id (so the caller can select it).
 *
 * Pure function over the catalogue — no registry lookups, no I/O.
 */
export function tryDrop(
  edge: DerivedEdge,
  type: SurfaceNodeType,
  direction: SlotDirection,
  /**
   * Optional lookup so the catch-all `cardinality: 'many'` slot can
   * enforce one occupant *per type*. Without this, callers fall back
   * to the legacy "any number of any type" behaviour the early tests
   * relied on.
   */
  nodeTypeById?: (id: string) => SurfaceNodeType | undefined,
  /**
   * Optional slot-applicability filter. Used by the canvas to hide
   * structurally-unreachable slots (e.g. the surface-wide external
   * identity slot on plain-URL inbound surfaces) without removing
   * them from the archetype catalogue. Receives a runtime slot and
   * the edge being considered; return `false` to skip the slot.
   */
  slotFilter?: (slot: RuntimeSlotDef, edge: DerivedEdge) => boolean
): TryDropResult {
  const archetype = getArchetype(edge.archetype);
  if (!archetype) {
    return { ok: false, reason: `Unknown edge archetype "${edge.archetype}".` };
  }
  if (!archetype.directions.includes(direction)) {
    return { ok: false, reason: `This edge has no ${direction} direction.` };
  }

  const candidates = archetype.slots.filter(
    s => s.direction === direction && slotAccepts(s, type) && (!slotFilter || slotFilter(s, edge))
  );
  if (candidates.length === 0) {
    // Only steer the user to AP→MA when the element actually has a typed
    // slot there (the catch-all accepts everything, so it doesn't count).
    // MCP Tool Gating, for instance, docks only on the EXT/MCP-TP response
    // legs — telling the user to drop it on AP→MA would be wrong.
    const apMa = getArchetype('ap-ma');
    const droppableOnApMa = !!apMa?.slots.some(
      s => s.accepts !== ANY_EDGE_MW && slotAccepts(s, type)
    );
    return {
      ok: false,
      reason:
        edge.archetype === 'ma-tp'
          ? droppableOnApMa
            ? `${type} is a transit-wide setting — drop it on the AP→MA edge instead.`
            : `${type} can't be placed on this Transit Point.`
          : `No slot on this edge accepts a ${type}.`,
    };
  }

  const sorted = [...candidates].sort((a, b) => {
    const aSpec = a.accepts === ANY_EDGE_MW ? 1 : 0;
    const bSpec = b.accepts === ANY_EDGE_MW ? 1 : 0;
    if (aSpec !== bSpec) return aSpec - bSpec;
    return a.order - b.order;
  });

  for (const slot of sorted) {
    const occupants = edge.slots.get(slot.id) ?? [];
    if (slot.cardinality === 'one' && occupants.length > 0) {
      return {
        ok: false,
        reason: `${slot.label} already in use; remove it first.`,
        conflictingNodeId: occupants[0],
      };
    }
    // Catch-all slot: only allow one occupant per type. Without
    // this, dropping a second `custom-metadata` (or any other type)
    // on a chain stacks duplicates that the payload builder
    // silently drops on save.
    if (slot.cardinality === 'many' && slot.accepts === ANY_EDGE_MW && nodeTypeById) {
      const dup = occupants.find(id => nodeTypeById(id) === type);
      if (dup) {
        return {
          ok: false,
          reason: `${type} already on this edge; remove it first.`,
          conflictingNodeId: dup,
        };
      }
    }
    return { ok: true, slotId: slot.id };
  }
  return { ok: false, reason: 'No eligible slot.' };
}

function slotAccepts(slot: RuntimeSlotDef, type: SurfaceNodeType): boolean {
  if (slot.accepts === ANY_EDGE_MW) return true;
  return slot.accepts.includes(type);
}

/**
 * Find the derived edge that a drag-over / drop interaction touches.
 *
 * The drop hit-test reports a pair of d3 link endpoints. Each endpoint
 * may be a logical edge endpoint (AP, MA, TP) or any of the slot
 * occupants chained between them. The edge owning *both* endpoints is
 * the unique answer, since chains never cross archetype boundaries.
 *
 * Returns `undefined` when no edge contains both endpoints — typically
 * means the hit landed on a non-pipeline link (NPC, decorative).
 */
export function findEdgeForHit(
  edges: ReadonlyArray<DerivedEdge>,
  srcId: string,
  tgtId: string
): DerivedEdge | undefined {
  for (const edge of edges) {
    const ids = new Set<string>();
    ids.add(edge.endpoints.source);
    ids.add(edge.endpoints.target);
    for (const list of edge.slots.values()) {
      for (const id of list) ids.add(id);
    }
    if (ids.has(srcId) && ids.has(tgtId)) return edge;
  }
  return undefined;
}

/** Get the runtime slot definition by id within an archetype. */
export function getSlot(archetypeId: string, slotId: SlotId): RuntimeSlotDef | undefined {
  const arch = getArchetype(archetypeId);
  if (!arch) return undefined;
  return arch.slots.find(s => s.id === slotId);
}

/**
 * Build the surface-context slot filter consumed by `tryDrop` and the
 * canvas drop-target highlighter.
 *
 * Today the only structurally-unreachable slot is
 * `response:identity-external` on the MA→External edge: it writes to
 * the surface-wide `identity_slots.external` field, which is only
 * populated by the outbound pipeline (per-TP today). When the surface
 * has no Transit Points AND the MA endpoint is a plain URL (not
 * `fabric://`), there's no outbound pipeline at all — so dropping
 * Agent Identity there is misleading UX. The External Target NPC node
 * itself stays visible (UI sugar for the MA endpoint); only the
 * identity slot offer is hidden.
 *
 * Returns `undefined` when no filtering is needed (caller can omit the
 * arg). Otherwise returns a predicate that returns `false` for the
 * hidden slot.
 *
 * A second class of hidden slot is protocol-scoped `ma-tp` request slots
 * whose target-leg pipeline stage is only implemented for A2A/AP2 Transit
 * Points: Header Metadata Mapping (`request:metadata-extraction`) and the
 * target-leg Trust Check (`request:trust-check-target_trust_check_list`).
 * The MCP outbound pipeline has no target-leg counterpart for these yet,
 * so they are offered only on `transit-point-a2a` / `transit-point-ap2`
 * edges — an MCP Transit Point never exposes them, and the caller-leg
 * (AP→MA) Trust Check remains available for MCP.
 */
export function makeSurfaceSlotFilter(
  managedAgentEndpoint: string | undefined,
  hasTransitPoints: boolean,
  allNodes: ReadonlyArray<CanvasNode> = []
): ((slot: RuntimeSlotDef, edge: DerivedEdge) => boolean) | undefined {
  const endpoint = typeof managedAgentEndpoint === 'string' ? managedAgentEndpoint.trim() : '';
  const isFabric = endpoint.startsWith('fabric://');
  const shouldHideExternalIdentity = !isFabric && !hasTransitPoints;
  const nodeById = new Map(allNodes.map(n => [n.id, n] as const));
  const hasProtocolScopedTpSlot = allNodes.some(n => isTransitPointType(n.type));
  if (!shouldHideExternalIdentity && !hasProtocolScopedTpSlot) return undefined;
  const isA2aFamilyTp = (edge: DerivedEdge): boolean => {
    const tp = nodeById.get(edge.endpoints.target);
    return tp?.type === 'transit-point-a2a' || tp?.type === 'transit-point-ap2';
  };
  const isMcpTp = (edge: DerivedEdge): boolean =>
    nodeById.get(edge.endpoints.target)?.type === 'transit-point-mcp';
  return (slot, edge) => {
    if (shouldHideExternalIdentity && slot.id === 'response:identity-external') return false;
    // Header Metadata Mapping and the target-leg Trust Check have no MCP
    // target-leg implementation, so only offer them on A2A/AP2 TPs.
    if (
      edge.archetype === 'ma-tp' &&
      (slot.id === 'request:metadata-extraction' ||
        slot.id === 'request:trust-check-target_trust_check_list')
    ) {
      return isA2aFamilyTp(edge);
    }
    // MCP Tool Gating firewalls a TP's MCP tool surface, so it applies only
    // to an MCP Transit Point — never an A2A/AP2/HTTP one, even on an MCP
    // surface.
    if (edge.archetype === 'ma-tp' && slot.id === 'response:mcp-tool-gating') {
      return isMcpTp(edge);
    }
    return true;
  };
}

/**
 * Resolve a slot's `payloadPathTemplate` into a concrete dot path.
 *
 * `{owner}` is substituted with the owning endpoint's id (per
 * `slot.ownedBy`). Returns `undefined` for slots with an empty
 * template (e.g. the `'*'` catch-all, which is informational only and
 * never participates in routing).
 */
export function resolvePayloadPath(slot: RuntimeSlotDef, edge: DerivedEdge): string | undefined {
  const tpl = slot.payloadPathTemplate;
  if (!tpl) return undefined;
  if (!tpl.includes('{owner}')) return tpl;
  const owner = slot.ownedBy === 'source' ? edge.endpoints.source : edge.endpoints.target;
  return tpl.replace('{owner}', owner);
}

/**
 * Locate the slot a node occupies within the derived edge graph.
 *
 * Walks every edge's slot map looking for `nodeId`. Returns the first
 * `(edge, slot)` pair found — slot ids are unique within an archetype
 * and a node is only ever an occupant of one slot.
 *
 * Returns `undefined` for nodes that aren't edge slot occupants
 * (anchors, surface-wide elements, decorative nodes).
 */
export function findSlotForNode(
  edges: ReadonlyArray<DerivedEdge>,
  nodeId: string
): { edge: DerivedEdge; slot: RuntimeSlotDef } | undefined {
  for (const edge of edges) {
    for (const [slotId, occupants] of edge.slots.entries()) {
      if (!occupants.includes(nodeId)) continue;
      const slot = getSlot(edge.archetype, slotId);
      if (!slot) continue;
      return { edge, slot };
    }
  }
  return undefined;
}
