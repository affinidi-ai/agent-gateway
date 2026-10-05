/**
 * Read-only `deriveEdges(nodes)` adapter. Reconstructs `DerivedEdge[]`
 * from today's `parentId` + direction + per-TP-policy conventions
 * without changing any behaviour.
 *
 * Behavioural callers (renderer, drop handler) still use their existing
 * paths. This adapter provides a tested oracle for the derived model
 * while callers migrate over.
 */

import type { CanvasNode } from '../../SurfaceCanvas';
import type { DerivedEdge, SlotId, SlotDirection } from './types';
import { isTransitPointType, getArchetype, ANY_EDGE_MW } from './archetypes';

/**
 * Resolve the slot id an occupant belongs to within an archetype, by
 * matching the element's `type` against each slot's `accepts`. Falls
 * back to the direction's catch-all `'*'` slot when the archetype
 * declares one. Returns `undefined` when no slot matches AND no
 * catch-all exists, so callers can drop the orphan instead of
 * inventing a phantom slot id (e.g. `ma-tp` deliberately rejects
 * non-policy middleware).
 */
function slotForOccupant(
  archetypeId: string,
  occupantType: string,
  direction: SlotDirection
): SlotId | undefined {
  const arch = getArchetype(archetypeId);
  if (!arch) return undefined;
  let catchAll: SlotId | undefined;
  for (const s of arch.slots) {
    if (s.direction !== direction) continue;
    if (s.accepts === ANY_EDGE_MW) {
      catchAll = s.id;
      continue;
    }
    if (s.accepts.includes(occupantType as never)) return s.id;
  }
  return catchAll;
}

// Archetypes themselves now live in `./archetypes.ts`. This module is
// the read-only adapter that reconstructs `DerivedEdge[]` from today's
// `parentId` + `direction` + per-TP-policy conventions.

function isEdgeMiddleware(type: string): boolean {
  // The current renderer treats anything whose dropMode is 'edge' as
  // chain middleware. The adapter uses the same heuristic today: a
  // node is middleware on an edge when it has a parentId, is not an
  // anchor, is not a canvas-only decoration, and is not the inferred
  // per-TP policy (handled separately).
  if (
    type === 'access-point' ||
    type === 'target' ||
    type === 'human' ||
    type === 'caller' ||
    type === 'surface'
  ) {
    return false;
  }
  if (isTransitPointType(type)) return false;
  if (type === 'npc-endpoint') return false;
  if (type === 'local-gateway-hop' || type === 'remote-gateway') return false;
  if (type === 'identity') return false;
  // MCP Tool Gating is a per-endpoint response slot (ma-external, and
  // per-TP on ma-tp). Recovered explicitly like identity so the ap-ma /
  // ma-tp catch-all response chain doesn't claim it onto the wrong arrow.
  if (type === 'mcp-tool-gating') return false;
  return true;
}

interface AdapterContext {
  byId: Map<string, CanvasNode>;
  childrenOf: Map<string, CanvasNode[]>;
}

function buildContext(nodes: CanvasNode[]): AdapterContext {
  const byId = new Map<string, CanvasNode>();
  const childrenOf = new Map<string, CanvasNode[]>();
  for (const n of nodes) {
    byId.set(n.id, n);
  }
  for (const n of nodes) {
    if (!n.parentId) continue;
    const arr = childrenOf.get(n.parentId) ?? [];
    arr.push(n);
    childrenOf.set(n.parentId, arr);
  }
  return { byId, childrenOf };
}

/**
 * Walk the request chain backwards from `targetId` until we reach
 * `expectedSourceId` (or run out). Returns the chain in source→target
 * order, EXCLUDING the endpoints themselves.
 */
function walkRequestChain(
  ctx: AdapterContext,
  expectedSourceId: string,
  targetId: string
): string[] {
  const chain: string[] = [];
  let cur = ctx.byId.get(targetId);
  for (let i = 0; cur && i < 32; i++) {
    const parent = cur.parentId ? ctx.byId.get(cur.parentId) : undefined;
    if (!parent) break;
    if (parent.id === expectedSourceId) return chain;
    if (!isEdgeMiddleware(parent.type)) break;
    chain.unshift(parent.id);
    cur = parent;
  }
  return chain;
}

/** Response middleware sits as direct children of the response source with `direction === 'response'`. */
function collectResponseMw(ctx: AdapterContext, respSourceId: string): string[] {
  const kids = ctx.childrenOf.get(respSourceId) ?? [];
  // Excludes per-endpoint occupants of OTHER archetypes' slots (e.g.
  // `identity` lives on ma-external as a child of MA but must not
  // also be claimed by ap-ma's response chain). `isEdgeMiddleware`
  // is the canonical "is this a chain mw type" predicate.
  return kids.filter(k => k.direction === 'response' && isEdgeMiddleware(k.type)).map(k => k.id);
}

function makeEdge(archetype: string, sourceId: string, targetId: string): DerivedEdge {
  return {
    id: `${archetype}:${sourceId}:${targetId}`,
    archetype,
    endpoints: { source: sourceId, target: targetId },
    slots: new Map<SlotId, string[]>(),
  };
}

function pushSlot(edge: DerivedEdge, slotId: SlotId, occupantId: string): void {
  const list = edge.slots.get(slotId) ?? [];
  list.push(occupantId);
  edge.slots.set(slotId, list);
}

/**
 * Pure derivation. Reads `nodes` and emits one `DerivedEdge` per logical
 * edge in the surface, with each slot populated from today's encoding.
 *
 * No side effects, no I/O, no registry access. Safe to call per render.
 */
export function deriveEdges(nodes: ReadonlyArray<CanvasNode>): DerivedEdge[] {
  const ctx = buildContext(nodes as CanvasNode[]);
  const out: DerivedEdge[] = [];

  const ap = nodes.find(n => n.type === 'access-point' && !n.parentId);
  const ma = nodes.find(n => n.type === 'target');
  const tps = nodes.filter(n => isTransitPointType(n.type));

  // ── AP ↔ MA ────────────────────────────────────────────────────────
  if (ap && ma) {
    const edge = makeEdge('ap-ma', ap.id, ma.id);

    // Request chain: AP → … mw … → MA. Bucket each occupant into its
    // typed slot (one per element type) — the renderer walks slots in
    // declared order and emits a deterministic chain.
    const reqChain = walkRequestChain(ctx, ap.id, ma.id);
    for (const id of reqChain) {
      const node = ctx.byId.get(id);
      const slotId = slotForOccupant('ap-ma', node?.type ?? '', 'request');
      if (slotId) pushSlot(edge, slotId, id);
    }

    // Response mw: children of MA (response source) with direction=response.
    for (const id of collectResponseMw(ctx, ma.id)) {
      const node = ctx.byId.get(id);
      const slotId = slotForOccupant('ap-ma', node?.type ?? '', 'response');
      if (slotId) pushSlot(edge, slotId, id);
    }

    // Hydrated Header Metadata Mapping is represented by a request-side
    // Metadata Extraction node with a slot id but no chain parentage.
    // Bind it explicitly so AP-owned header mapping reloads on the
    // AP→MA request seam instead of floating on the canvas.
    const apRequestMetadataExtraction = nodes.find(
      n =>
        n.type === 'metadata-extraction' &&
        (n.direction ?? 'request') === 'request' &&
        n.slotId === 'request:metadata-extraction' &&
        n.id === 'metadata-extraction'
    );
    if (
      apRequestMetadataExtraction &&
      !(edge.slots.get('request:metadata-extraction') ?? []).includes(
        apRequestMetadataExtraction.id
      )
    ) {
      pushSlot(edge, 'request:metadata-extraction', apRequestMetadataExtraction.id);
    }

    // Per-endpoint identity slots (excluded from chain mw above):
    //   request:identity-inbound   — child of AP (ownedBy: 'source')
    //   response:identity-protected — child of MA (ownedBy: 'target')
    // Without this explicit recovery the dropped node sits in the
    // graph but is never bound to a slot, so the renderer treats it
    // as free-floating instead of locking it onto the AP→MA arrow.
    const apKidsForIdentity = ctx.childrenOf.get(ap.id) ?? [];
    const inboundIdentity = apKidsForIdentity.find(
      c =>
        c.type === 'identity' &&
        (c.id === 'identity-inbound' || c.slotId === 'request:identity-inbound')
    );
    if (inboundIdentity) pushSlot(edge, 'request:identity-inbound', inboundIdentity.id);
    const maKidsForIdentity = ctx.childrenOf.get(ma.id) ?? [];
    const protectedIdentity = maKidsForIdentity.find(
      c =>
        c.type === 'identity' &&
        (c.id === 'identity-protected' ||
          c.slotId === 'response:identity-protected' ||
          // Legacy bare slotId predates external/protected disambiguation;
          // only claim it when the id resolves to identity-protected so
          // identity-external stays on ma-external.
          (c.slotId === 'response:identity' && c.id === 'identity-protected'))
    );
    if (protectedIdentity) pushSlot(edge, 'response:identity-protected', protectedIdentity.id);

    out.push(edge);
  }

  // ── MA ↔ TP (one edge per TP) ───────────────────────────────────────
  if (ma) {
    for (const tp of tps) {
      const edge = makeEdge('ma-tp', ma.id, tp.id);

      // Per-TP request/response policy: child of TP, type === 'policy'.
      // Per-TP networking sits in the same per-endpoint slot family
      // (ownedBy: 'target', request direction). Surface both via direct
      // child lookup so they hydrate even though they're not in the
      // walkRequestChain path.
      const tpKids = ctx.childrenOf.get(tp.id) ?? [];
      for (const k of tpKids) {
        if (k.type === 'policy') {
          const dir = k.direction ?? 'request';
          if (dir === 'request') {
            pushSlot(edge, 'request:policy', k.id);
          } else if (dir === 'response') {
            pushSlot(edge, 'response:policy', k.id);
          }
        } else if (k.type === 'networking' && (k.direction ?? 'request') === 'request') {
          if (!k.slotId || k.slotId === 'request:networking') {
            pushSlot(edge, 'request:networking', k.id);
          }
        } else if (k.type === 'rate-limit' && (k.direction ?? 'request') === 'request') {
          if (!k.slotId || k.slotId === 'request:rate-limit') {
            pushSlot(edge, 'request:rate-limit', k.id);
          }
        } else if (k.type === 'trust-check' && (k.direction ?? 'request') === 'request') {
          // Legacy blobs (pre-`ownedBy: 'source'` fix) may have
          // parented the target-leg trust-check on the TP; keep
          // hydrating those into the same slot so old surfaces still
          // snap.
          if (!k.slotId || k.slotId === 'request:trust-check-target_trust_check_list') {
            pushSlot(edge, 'request:trust-check-target_trust_check_list', k.id);
          }
        } else if (k.type === 'workload-binding' && (k.direction ?? 'request') === 'request') {
          // Per-TP workload binding is a per-endpoint request slot
          // (`ownedBy: 'target'`), so it parents directly on the TP and
          // is not part of the walkRequestChain path — recover it here
          // like policy/networking/rate-limit, otherwise the dropped
          // node stays free-floating instead of locking onto the MA→TP
          // arrow.
          if (!k.slotId || k.slotId === 'request:workload-binding') {
            pushSlot(edge, 'request:workload-binding', k.id);
          }
        }
      }

      // Target-leg trust-check is `ownedBy: 'source'` and writes to a
      // target-wide list, so the canonical parent is MA. Bind the
      // single MA-child node to every ma-tp edge so it renders as a
      // slot occupant on whichever MA→TP arrow the user snaps it to.
      const trustCheckTargetNode = (ctx.childrenOf.get(ma.id) ?? []).find(
        c =>
          c.type === 'trust-check' &&
          (c.id === 'trust-check-target' ||
            c.slotId === 'request:trust-check-target_trust_check_list')
      );
      if (trustCheckTargetNode) {
        pushSlot(edge, 'request:trust-check-target_trust_check_list', trustCheckTargetNode.id);
      }

      // Generic request mw chain between MA and TP. Anything that's not
      // a per-TP policy gets bucketed into its typed slot or the
      // catch-all.
      const reqChain = walkRequestChain(ctx, ma.id, tp.id);
      for (const id of reqChain) {
        const node = ctx.byId.get(id);
        const slotId = slotForOccupant('ma-tp', node?.type ?? '', 'request');
        if (slotId) pushSlot(edge, slotId, id);
      }

      // Response mw: children of TP with direction=response, MINUS the
      // per-TP response policy already accounted for above.
      const respMw = collectResponseMw(ctx, tp.id);
      const perTpRespPolicyIds = new Set(edge.slots.get('response:policy') ?? []);
      for (const id of respMw) {
        if (perTpRespPolicyIds.has(id)) continue;
        const node = ctx.byId.get(id);
        const slotId = slotForOccupant('ma-tp', node?.type ?? '', 'response');
        if (slotId) pushSlot(edge, slotId, id);
      }

      // Per-TP Header Metadata Mapping (request, ownedBy: 'target').
      // The Metadata Extraction element parents to the TP because the
      // TP factory owns `transit.points[{owner}].header_metadata_mapping`.
      const tpHeaderMetadata = tpKids.find(
        k =>
          k.type === 'metadata-extraction' &&
          (k.slotId === 'request:metadata-extraction' || k.id === `metadata-extraction-${tp.id}`)
      );
      if (tpHeaderMetadata) pushSlot(edge, 'request:metadata-extraction', tpHeaderMetadata.id);

      // Per-TP managed identity (request, ownedBy: 'target'). Identity is
      // excluded from request middleware so recover it explicitly. Older
      // saved canvases used the response slot; rebind them to the request
      // slot so existing surfaces migrate visually without losing config.
      const tpIdentity = tpKids.find(
        k =>
          k.type === 'identity' &&
          (k.slotId === 'request:identity-managed_identity' ||
            k.slotId === 'response:identity-managed_identity' ||
            k.id === `identity-${tp.id}-request` ||
            k.id === `identity-${tp.id}-response`)
      );
      if (tpIdentity) pushSlot(edge, 'request:identity-managed_identity', tpIdentity.id);

      // Per-TP MCP Tool Gating (response, ownedBy: 'target'). Excluded from
      // the response middleware chain (see `isEdgeMiddleware`) so recover it
      // explicitly like the per-TP policy/identity — otherwise the dropped
      // circle floats instead of locking onto this MA→TP arrow.
      const tpMcpToolGating = tpKids.find(
        k =>
          k.type === 'mcp-tool-gating' &&
          (k.slotId === 'response:mcp-tool-gating' || k.id === `mcp-tool-gating-${tp.id}`)
      );
      if (tpMcpToolGating) pushSlot(edge, 'response:mcp-tool-gating', tpMcpToolGating.id);

      out.push(edge);
    }
  }

  // ── MA ↔ External (one edge per visible target → external arrow) ──
  // The "external" endpoint is one of:
  //   - `npc-endpoint` parented on `target` (direct URL targets)
  //   - the synthesised `local-gateway-hop` parented on `target` (the
  //     first hop of a fabric:// chain — the second hop, `hop → remote-gateway`,
  //     is decorative and is not made droppable for Agent Identity).
  //
  // Identity is the only element that lives on this edge. It uses
  // `ownedBy: 'source'` (per-endpoint slot) so the dropped node is a
  // direct child of `target` with canonical id `identity-target`. The
  // npc/hop's parent stays unchanged.
  if (ma) {
    const externalTypes = new Set<string>(['npc-endpoint', 'local-gateway-hop', 'remote-gateway']);
    // Recover the per-endpoint identity occupant attached to MA. There
    // is at most one (canonical id `identity-target`) — we surface it on
    // every ma-external edge so the user sees the slot occupied no
    // matter which arrow they look at.
    const identityNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'identity' &&
        (c.id === 'identity-external' ||
          c.slotId === 'response:identity-external' ||
          // Legacy slotId used before identity slots were disambiguated.
          // Only treat the bare `response:identity` as external when the
          // node id resolves to identity-external — otherwise it belongs
          // to AP→MA's protected slot and stays there.
          (c.slotId === 'response:identity' && c.id === 'identity-external'))
    );
    // ma-external networking is per-endpoint with ownedBy: 'source' on
    // the request direction — i.e. a child of MA.
    const networkingExternalNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'networking' &&
        (c.direction ?? 'request') === 'request' &&
        (!c.slotId || c.slotId === 'request:networking')
    );
    // ma-external rate-limit is per-endpoint with ownedBy: 'source'.
    const rateLimitExternalNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'rate-limit' &&
        (c.direction ?? 'request') === 'request' &&
        c.slotId === 'request:rate-limit'
    );
    // ma-external credential-delegation is per-endpoint with
    // ownedBy: 'source' on the request direction (child of MA).
    // Without this explicit recovery the dropped node sits in the
    // graph but isn't bound to a slot, so the renderer treats it as
    // free-floating instead of locking it onto the MA→External arrow.
    const credentialDelegationNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'credential-delegation' &&
        (c.direction ?? 'request') === 'request' &&
        (!c.slotId || c.slotId === 'request:credential-delegation')
    );
    // ma-external workload-binding is per-endpoint with ownedBy: 'source'
    // on the request direction (child of MA). The TP-scoped workload
    // binding parents on its Transit Point instead, so it is handled in
    // the ma-tp loop above and never matches this MA-child lookup.
    const workloadBindingExternalNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'workload-binding' &&
        (c.direction ?? 'request') === 'request' &&
        (!c.slotId || c.slotId === 'request:workload-binding')
    );
    // ma-external MCP Tool Gating is a per-endpoint response slot
    // (`ownedBy: 'source'`) — a child of MA on the response direction.
    // Recover it explicitly so the dropped circle locks onto the
    // External→MA arrow instead of floating onto the AP→MA catch-all.
    const mcpToolGatingExternalNode = (ctx.childrenOf.get(ma.id) ?? []).find(
      c =>
        c.type === 'mcp-tool-gating' &&
        (c.direction ?? 'response') === 'response' &&
        (!c.slotId || c.slotId === 'response:mcp-tool-gating')
    );
    for (const n of nodes) {
      if (!externalTypes.has(n.type)) continue;
      if (n.parentId !== ma.id) continue;
      const edge = makeEdge('ma-external', ma.id, n.id);
      if (identityNode) pushSlot(edge, 'response:identity-external', identityNode.id);
      if (networkingExternalNode) pushSlot(edge, 'request:networking', networkingExternalNode.id);
      if (rateLimitExternalNode) pushSlot(edge, 'request:rate-limit', rateLimitExternalNode.id);
      if (credentialDelegationNode)
        pushSlot(edge, 'request:credential-delegation', credentialDelegationNode.id);
      if (workloadBindingExternalNode)
        pushSlot(edge, 'request:workload-binding', workloadBindingExternalNode.id);
      if (mcpToolGatingExternalNode)
        pushSlot(edge, 'response:mcp-tool-gating', mcpToolGatingExternalNode.id);
      out.push(edge);
    }
  }

  return out;
}
