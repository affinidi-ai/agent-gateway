import React, { useRef, useEffect, useCallback, useMemo, useState } from 'react';
import * as d3 from 'd3';
import { registry as _registry } from './elements';
import { buildSurfaceContext } from './elements/surfaceContext';
import type { SurfaceNodeType } from './nodeTypes';
import { deriveEdges } from './elements/edges/deriveEdges';
import {
  getArchetype,
  findArchetypeForPair,
  findSlotForNode,
  tryDrop,
  findEdgeForHit,
  getSlot,
  makeSurfaceSlotFilter,
} from './elements/edges/archetypes';
import type { DerivedEdge, SlotDirection } from './elements/edges/types';
import { isSyntheticFabricNodeId } from './elements/synthesizeFabric';
import { fetchRoutingConfig } from './elements/access-point/defaults';
import {
  POLICY_UNCONFIGURED_DASH,
  policyDefinitionMissing,
  policyDefinitionMissingReason,
} from './elements/policy/status';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface CanvasNode {
  id: string;
  type: SurfaceNodeType;
  label: string;
  sublabel?: string;
  configured: boolean;
  config?: any;
  /**
   * Which node's outgoing edge this node sits on.
   * parentId = undefined → connects FROM the surface center.
   * parentId = 'some-id' → connects FROM that node.
   * Chains: Surface → AP → Target, Surface → Net → TP
   */
  parentId?: string;
  /** For NPC nodes: persisted canvas position */
  position?: { x: number; y: number };
  /** For NPC nodes: description shown below name */
  description?: string;
  /** For NPC connections: 'outbound' = parent→this, 'inbound' = this→parent */
  connectionDirection?: 'outbound' | 'inbound';
  /**
   * Pipeline arrow this middleware sits on.
   *  - undefined for non-middleware nodes (AP, target, transit-points,
   *    surface-wide elements, NPCs).
   *  - 'request'  for middleware on a request arrow (caller → agent).
   *  - 'response' for middleware on a response arrow (agent → caller).
   *
   * Set at drop time from the arrow the user dropped on. Determines which
   * payload slice the element writes to (e.g. `target.custom_metadata` vs
   * `target.response_custom_metadata`).
   */
  direction?: 'request' | 'response';
  /** User-adjusted radius override */
  radius?: number;
  /**
   * Slot identity from the edge archetype catalogue (e.g.
   * `'request:policy'`, `'request:policy-inbound'`). Set at drop time
   * by `handleDrop` and at hydration time by `nodesFromPayload`. The
   * authoritative key for which payload path this node writes to;
   * elements should read this rather than re-derive routing from
   * `parentId`/`direction`/`type`.
   *
   * Optional only because legacy/decorative nodes (NPCs, human, caller,
   * surface anchors, transit-points) do not occupy edge slots.
   */
  slotId?: string;
}

interface D3Node extends d3.SimulationNodeDatum {
  id: string;
  type: SurfaceNodeType;
  label: string;
  sublabel?: string;
  configured: boolean;
  radius: number;
  parentId?: string;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  /**
   * For middleware nodes (dropMode === 'edge'): cached pipeline geometry
   * (the original parent and child anchor nodes of the undivided pipeline
   * link). Used so a split sub-link's non-middleware endpoint is computed
   * as if the link were the full pipeline — same direction, same radius
   * shortening, same perpendicular offset — regardless of where the
   * middleware sits.
   */
  _pipe?: { parent: D3Node; child: D3Node };
  /**
   * For middleware nodes: the cached parameter `t` (0..1) along the
   * canonical pipe (from `_pipe.parent` to `_pipe.child`). Used by
   * the simulation tick to reproject the middleware whenever a pipe
   * anchor moves (e.g. while the user drags the MA), so middleware
   * slide along with their pipe in real time instead of waiting
   * until drag end.
   */
  _pipeT?: number;
  /**
   * For middleware nodes: the slot direction (`request` or `response`)
   * the node was placed on. Cached alongside `_pipe` so the drag
   * handler can compute the lateral offset without inspecting the
   * link graph (which no longer carries middleware as endpoints).
   */
  direction?: 'request' | 'response';
}

interface D3Link extends d3.SimulationLinkDatum<D3Node> {
  source: string | D3Node;
  target: string | D3Node;
  type: 'primary' | 'middleware';
  droppable?: boolean; // whether edge-type items can be dropped on this link
  /**
   * Pipeline arrow direction this link represents. Set on every primary link
   * and on every middleware link so drop hit-testing can pick the right
   * arrow. Undefined for non-pipeline links (decorative / NPC links).
   */
  direction?: 'request' | 'response';
  /**
   * Render with arrowheads on BOTH ends (no separate response link).
   * Used for connector edges that merely indicate a relationship the
   * surface owner cannot manage — e.g. TP ↔ external agent.
   */
  bidirectional?: boolean;
  /**
   * For canonical pipe links: the ordered list of middleware node ids
   * that visually sit on this line (sorted by their projected `t`).
   * Middleware are rendered as standalone glyphs on top of the line,
   * not as their own edges. Empty when the pipe has no middleware.
   */
  occupants?: string[];
}

/** Where each element type can be dropped */
export type DropTarget = 'canvas' | 'edge' | 'node';

/** Context passed from canvas to wizard on drop */
export interface DropContext {
  /** For edge drops: source node of the edge */
  edgeSourceId?: string;
  /** For edge drops: target node of the edge */
  edgeTargetId?: string;
  /**
   * For edge drops: which arrow was hit — the request arrow
   * (parent→child, follows the visible data flow) or the response arrow
   * (child→parent, drawn alongside in the opposite direction).
   * Used by the builder hook to set `node.direction` and to skip re-parenting
   * for response-direction drops.
   */
  edgeDirection?: 'request' | 'response';
  /** For node drops: the node being dropped on */
  targetNodeId?: string;
  /**
   * Surface-relative drop position (offset from the surface centre).
   * Set for edge-constrained drops (Access Point, Transit Point) so the
   * wizard can persist the snapped position immediately and survive a
   * save/reload round-trip. Optional for other drops, which derive
   * position via d3 layout instead.
   */
  position?: { x: number; y: number };
  /**
   * Programmatic-drop hook: invoked synchronously with the newly
   * minted node id whenever the drop successfully creates a node.
   * Not called when the drop is rejected (e.g. occupied slot).
   * Used by the templates engine to merge config overrides onto the
   * freshly-seeded node.
   */
  onCreated?: (newNodeId: string) => void;
}

export interface SurfaceCanvasProps {
  surfaceName: string;
  protocol: string;
  nodes: CanvasNode[];
  surfacePolicyIds: Set<string> | null;
  onNodeClick: (nodeId: string) => void;
  onCanvasClick?: () => void;
  onDrop: (type: SurfaceNodeType, context?: DropContext) => void;
  onNodeMove?: (nodeId: string, x: number, y: number) => void;
  /**
   * Variant of `onNodeMove` for SYSTEM-driven position writes — i.e.
   * positions the canvas computes itself during render (auto-placement
   * of surface-wide nodes, edge-middleware projection re-syncs after a
   * layout reflow). The page wires this to a no-commit setter so these
   * implicit reflows do NOT show up as separate undo steps. Falls back
   * to `onNodeMove` when not supplied — consumers that don't care
   * about undo granularity keep working unchanged.
   */
  onSystemNodeMove?: (nodeId: string, x: number, y: number) => void;
  onNodeResize?: (nodeId: string, radius: number) => void;
  /**
   * Called whenever the multi-selection set changes (lasso end,
   * shift-click, background click). Receives the current ids.
   */
  onMultiSelectionChange?: (ids: string[]) => void;
  /**
   * The current single-selection node id (the one shown in the sidebar).
   * Used to seed the multi-selection set on shift-click so a plain click
   * followed by shift-clicks grows the selection instead of replacing it.
   */
  selectedNodeId?: string | null;
  /**
   * Externally-controlled multi-selection. When provided, the canvas
   * re-syncs its internal `selectedNodesRef` and the d3 `.lasso-selected`
   * class to match this prop. This is the path React uses to push
   * selection edits (e.g. unticking a node in the multi-select panel)
   * back into the canvas.
   */
  multiSelectedIds?: string[];
  /**
   * Bumped by the parent on every undo / redo. The canvas re-syncs each
   * node's d3 position from `node.position` when this changes so the
   * visual reverts along with state.
   */
  externalRevision?: number;
  /**
   * Bumped by the parent to request a reset of pan & zoom (animated to
   * identity transform). Used by auto-layout to recentre the view
   * after rearranging nodes, mirroring the centre/reset-view button.
   */
  resetViewRev?: number;
  /**
   * Tracks the latest fit request handled across canvas mounts. The
   * owner must outlive this component so mount-time requests are not
   * mistaken for the initial revision and skipped.
   */
  handledResetViewRevRef: React.MutableRefObject<number>;
  /**
   * When true, node drags quantise to the grid by default and the
   * shift modifier disables quantisation. When false (the default),
   * drags are free-form and shift forces quantisation. Toggled by the
   * grid button in the canvas toolbar.
   */
  gridSnap?: boolean;
  /**
   * Optional shared mutable ref for the surface rectangle size. When
   * provided, the canvas seeds its internal size ref from it on first
   * render and writes back on every resize. Lets the page persist the
   * size in the canvas blob and re-hydrate on reload. Object identity
   * must be stable across renders (created via `useRef`).
   */
  surfaceSizeRef?: React.MutableRefObject<{ w: number; h: number } | null>;
  /**
   * Externally-driven surface size. When this prop changes (e.g. on
   * undo/redo where the parent's history reverts to a different size),
   * the canvas re-applies it via the same machinery used by the live
   * resize gesture, cascading edge-constrained / surface-wide nodes
   * back into place. Pass the current value of `state.surfaceSize`.
   */
  surfaceSize?: { w: number; h: number };
  /**
   * Called once at the end of a surface-resize gesture with the final
   * size and every cascading node-position change. The parent should
   * commit these as a single undo snapshot so the next undo reverts
   * size and positions atomically.
   */
  onSurfaceResize?: (
    size: { w: number; h: number },
    moves: ReadonlyArray<{ id: string; x: number; y: number }>
  ) => void;
  /**
   * Optional shared mutable ref for the d3 zoom transform (pan + scale).
   * When seeded with a non-null value the canvas restores it after
   * rebuild; the canvas writes the live transform back on every zoom
   * event so the page can persist it in the canvas blob.
   */
  canvasViewRef?: React.MutableRefObject<{ x: number; y: number; k: number } | null>;
  /**
   * Optional ref the canvas fills with an imperative "download PNG"
   * trigger so the parent can render the camera button in its own
   * toolbar widget. The canvas writes once on mount; the parent calls
   * `exportPngRef.current?.()`.
   */
  exportPngRef?: React.MutableRefObject<(() => void) | null>;
  /**
   * Optional ref the canvas fills with an imperative "reset pan/zoom"
   * trigger. Same lifting pattern as `exportPngRef` so the parent
   * owns the crosshairs button in its toolbar.
   */
  resetViewRef?: React.MutableRefObject<(() => void) | null>;
}

/**
 * Returns a human-readable reason why a node is in a fault state, or null
 * if it is fully configured AND validates. Combines `incompleteReason`
 * (missing required fields) with the first validator error (malformed
 * values) so the canvas mirrors the sidebar.
 */
export function getIncompleteReason(
  type: SurfaceNodeType,
  config: any,
  surfacePolicyIds?: Set<string> | null
): string | null {
  const reason = _registry.getFaultReason(type, config);
  if (reason) return reason;
  return policyDefinitionMissingReason({ type, config }, surfacePolicyIds ?? null);
}

/**
 * IDs of nodes whose `featureDependencies` raise at least one
 * error-severity warning in the current surface context. Rendered with a
 * "marching ants" animated ring so the canvas surfaces missing-dependency
 * problems (e.g. credential-delegation without source auth) the same way
 * incomplete config does, but visually distinct.
 */
export function computeFeatureErrorIds(nodes: CanvasNode[], protocol: string): Set<string> {
  const ctx = buildSurfaceContext(protocol, nodes);
  const ids = new Set<string>();
  for (const n of nodes) {
    if (n.type === 'surface') continue;
    const ws = _registry.getDependencyWarnings(n.type, n.config, ctx);
    if (ws.some(w => w.severity === 'error')) ids.add(n.id);
  }
  return ids;
}

// ─── Drop semantics ─────────────────────────────────────────────────────────

/**
 * Classifies where each element type should be dropped:
 * - canvas: creates a new flow node connected to surface
 * - edge: inserts as intermediate node ON an edge (becomes visible inline)
 * - node: configures the target node (adds capability, no new visual node)
 *
 * Reads `dropMode` directly from the element registry.
 */
function getDropTarget(type: SurfaceNodeType): DropTarget {
  return (_registry.get(type)?.dropMode as DropTarget) ?? 'canvas';
}

// ─── Color/size mappings ────────────────────────────────────────────────────
// (moved below — derived from the element registry)

// Surface geometry constants
const SURFACE_RECT_WIDTH = 336;
const SURFACE_RECT_HEIGHT = 294;
const TARGET_SQUARE_SIZE = 56;

// AP/TP radius scales proportionally with the surface width.
const EDGE_NODE_RADIUS_RATIO = 26 / SURFACE_RECT_WIDTH;
const MIN_EDGE_NODE_RADIUS = 18;
const MAX_EDGE_NODE_RADIUS = 40;
function getEdgeNodeRadius(surfaceW: number): number {
  return Math.max(
    MIN_EDGE_NODE_RADIUS,
    Math.min(MAX_EDGE_NODE_RADIUS, surfaceW * EDGE_NODE_RADIUS_RATIO)
  );
}

// ─── Registry-backed lookup tables ──────────────────────────────────────────
// These derive from the element registry so adding a new element type only
// requires creating a new definition file. The constants below preserve the
// historical Record<SurfaceNodeType, T> shape so the rest of this file stays simple.

function buildRecord<T>(
  getter: (type: SurfaceNodeType) => T | undefined,
  fallback: T
): Record<SurfaceNodeType, T> {
  const out = {} as Record<SurfaceNodeType, T>;
  for (const def of _registry.all()) {
    const v = getter(def.type as SurfaceNodeType);
    out[def.type as SurfaceNodeType] = v === undefined ? fallback : v;
  }
  return out;
}

const NODE_RADIUS: Record<SurfaceNodeType, number> = buildRecord(
  t => _registry.get(t)?.defaultRadius,
  30
);

const NODE_COLORS: Record<SurfaceNodeType, string> = buildRecord(
  t => _registry.get(t)?.color,
  '#adb5bd'
);

const NODE_ICONS: Record<SurfaceNodeType, string> = buildRecord(t => _registry.get(t)?.icon, '');

// Cached base64 data: URL for the Font Awesome solid woff2. Used by PNG
// export so the FA glyphs drawn as <text> in the canvas SVG render in the
// exported PNG (the browser cannot reach external @font-face declarations
// when rasterizing an SVG via Image + data URL). Resolved lazily on first
// export; null means the fetch failed and we should fall back to no embed.
let _faSolidDataUrlPromise: Promise<string | null> | null = null;
function fetchFontAwesomeSolidDataUrl(): Promise<string | null> {
  if (_faSolidDataUrlPromise) return _faSolidDataUrlPromise;
  _faSolidDataUrlPromise = (async () => {
    try {
      const resp = await fetch(
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-solid-900.woff2',
        { mode: 'cors' }
      );
      if (!resp.ok) return null;
      const buf = await resp.arrayBuffer();
      let binary = '';
      const bytes = new Uint8Array(buf);
      for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
      return `data:font/woff2;base64,${btoa(binary)}`;
    } catch {
      return null;
    }
  })();
  return _faSolidDataUrlPromise;
}

// Surface body fill (rgba over white). Both the translucent rgba (used as the
// rect fill) and the equivalent opaque hex (used as text-label stroke for
// elements that sit inside the surface, so the halo blends in) are kept here
// so they stay in sync.
const SURFACE_FILL = 'rgba(78, 115, 223, 0.04)';

const NODE_X_WEIGHT: Record<SurfaceNodeType, number> = buildRecord(
  t => _registry.get(t)?.xWeight,
  0.5
);

const NPC_TYPES: SurfaceNodeType[] = _registry
  .all()
  .filter(d => d.paletteCategory === 'npc')
  .map(d => d.type as SurfaceNodeType);
const isNpcType = (type: SurfaceNodeType) => NPC_TYPES.includes(type);

const EDGE_CONSTRAINED_TYPES: SurfaceNodeType[] = _registry
  .all()
  .filter(d => d.edgeConstrained)
  .map(d => d.type as SurfaceNodeType);

const SURFACE_WIDE_TYPES: SurfaceNodeType[] = _registry
  .all()
  .filter(d => d.surfaceWide)
  .map(d => d.type as SurfaceNodeType);

/**
 * Node types that must remain visually inside the surface rectangle
 * (e.g. Managed Agent). Distinct from `SURFACE_WIDE_TYPES` (which
 * auto-arrange in a grid and are clamped on resize): contained nodes
 * keep their freeform position, so surface resize is instead clamped
 * to never crop them out of the rectangle.
 */
const CONTAINED_IN_SURFACE_TYPES: SurfaceNodeType[] = _registry
  .all()
  .filter(d => d.containedInSurface)
  .map(d => d.type as SurfaceNodeType);

/**
 * Compute the next free grid slot INSIDE the surface for a surface-wide node.
 * Slots fill bottom-left → right, then stack upward. The slot index is the
 * position of `nodeId` within the ordered list of surface-wide nodes so the
 * placement is deterministic and stable across rebuilds.
 */
function computeSurfaceWideSlot(
  nodeId: string,
  allNodes: CanvasNode[],
  surfaceX: number,
  surfaceY: number,
  halfW: number,
  halfH: number
): { x: number; y: number } {
  const SLOT = 60;
  const PAD = 12;
  const innerW = halfW * 2 - PAD * 2;
  const cols = Math.max(1, Math.floor(innerW / SLOT));
  const surfaceWideOrdered = allNodes.filter(n => SURFACE_WIDE_TYPES.includes(n.type));
  const idx = Math.max(
    0,
    surfaceWideOrdered.findIndex(n => n.id === nodeId)
  );
  const col = idx % cols;
  const row = Math.floor(idx / cols);
  // Bottom-left first, then right, then up.
  const x = surfaceX - halfW + PAD + SLOT / 2 + col * SLOT;
  const y = surfaceY + halfH - PAD - SLOT / 2 - row * SLOT;
  return { x, y };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Padding (in px) reserved on edge-bound nodes' slide extent so
 * they can't be dragged all the way into the surface corner. The
 * connecting arrows now leave a dynamic gap for the node's text
 * label, so without this padding an edge-bound node can slip past
 * the arrow head into the corner where the connection visually
 * detaches. ~36px matches the largest `Math.abs(uxp) * 36` clearance
 * applied in the link geometry below.
 */
const EDGE_SLIDE_CORNER_PADDING = 36;

/**
 * Constrain a point to the perimeter of the surface rectangle.
 * Given a point (px, py) relative to the surface center (sx, sy),
 * returns the closest point on the rectangle's edge. When sliding
 * along an edge, the position along that edge is also clamped
 * inward by `EDGE_SLIDE_CORNER_PADDING` so the node always sits
 * within reach of its connecting arrow's label-aware endpoint.
 */
function constrainToSurfaceEdge(
  px: number,
  py: number,
  sx: number,
  sy: number,
  halfW: number,
  halfH: number
): { x: number; y: number } {
  // Convert to surface-local coords
  const lx = px - sx;
  const ly = py - sy;

  // Clamp to rect
  const cx = Math.max(-halfW, Math.min(halfW, lx));
  const cy = Math.max(-halfH, Math.min(halfH, ly));

  // Find nearest edge
  const distLeft = Math.abs(cx - -halfW);
  const distRight = Math.abs(cx - halfW);
  const distTop = Math.abs(cy - -halfH);
  const distBottom = Math.abs(cy - halfH);
  const minDist = Math.min(distLeft, distRight, distTop, distBottom);

  // Maximum inward clamps along each axis. Never exceed the surface
  // half-extent (handles vanishingly small surfaces gracefully).
  const padX = Math.min(EDGE_SLIDE_CORNER_PADDING, Math.max(0, halfW - 1));
  const padY = Math.min(EDGE_SLIDE_CORNER_PADDING, Math.max(0, halfH - 1));

  let ex = cx;
  let ey = cy;
  if (minDist === distLeft) {
    ex = -halfW;
    ey = Math.max(-halfH + padY, Math.min(halfH - padY, cy));
  } else if (minDist === distRight) {
    ex = halfW;
    ey = Math.max(-halfH + padY, Math.min(halfH - padY, cy));
  } else if (minDist === distTop) {
    ey = -halfH;
    ex = Math.max(-halfW + padX, Math.min(halfW - padX, cx));
  } else {
    ey = halfH;
    ex = Math.max(-halfW + padX, Math.min(halfW - padX, cx));
  }

  return { x: sx + ex, y: sy + ey };
}

/**
 * Perpendicular offset (in px) applied to BOTH primary directions so the
 * request and response arrows sit symmetrically around an imaginary
 * centerline between the two nodes.
 *
 * Both directions use the SAME SIGNED offset in the line-local frame.
 * Because request and response links traverse the node pair in opposite
 * directions, the line-local perpendicular vector itself reverses
 * \u2014 same signed offset \u2192 opposite global sides \u2192 visible parallel gap
 * (total separation = 2 * LATERAL_OFFSET_PX).
 */
const LATERAL_OFFSET_PX = 28;
const LATERAL_NODE_CLEARANCE_PX = 4;

/**
 * Effective half-extent perpendicular to the pipe direction. For the
 * target (square) node we use half the square size; for circular nodes
 * the radius. Used to scale the lateral separation between the
 * request/response arrows so they stay clear of larger node bodies.
 */
function pipeAnchorRadius(node: D3Node): number {
  if (node.type === 'target') return node.radius || TARGET_SQUARE_SIZE / 2;
  return node.radius || 24;
}

function lateralOffsetFor(
  direction?: 'request' | 'response',
  srcR?: number,
  tgtR?: number
): number {
  if (direction !== 'request' && direction !== 'response') return 0;
  if (srcR != null && tgtR != null) {
    return Math.max(LATERAL_OFFSET_PX, Math.min(srcR, tgtR) + LATERAL_NODE_CLEARANCE_PX);
  }
  return LATERAL_OFFSET_PX;
}

/**
 * Find the nearest droppable edge to (x, y), optionally filtered by
 * direction. When `directionFilter` is set, only links whose `direction`
 * matches (or links with no direction at all, e.g. NPC) are considered —
 * this lets request-only / response-only elements never accidentally land
 * on the wrong arrow. Hit-test takes the per-direction lateral offset into
 * account so the cursor matches the visually rendered arrow.
 */
function findNearestEdge(
  x: number,
  y: number,
  links: D3Link[],
  threshold: number,
  directionFilter?: 'request' | 'response' | 'either',
  linkFilter?: (link: D3Link, src: D3Node, tgt: D3Node) => boolean
): D3Link | null {
  let nearest: D3Link | null = null;
  let minDist = threshold;
  for (const link of links) {
    if (link.droppable === false) continue;
    if (directionFilter && directionFilter !== 'either' && link.direction !== directionFilter) {
      // Strict direction match — do not match links without a direction
      // when the element insists on one.
      continue;
    }
    const src = link.source as D3Node;
    const tgt = link.target as D3Node;
    if (typeof src === 'string' || typeof tgt === 'string') continue;
    if (src.x == null || src.y == null || tgt.x == null || tgt.y == null) continue;
    if (linkFilter && !linkFilter(link, src, tgt)) continue;
    let ax = src.x;
    let ay = src.y;
    let bx = tgt.x;
    let by = tgt.y;
    const lateral = lateralOffsetFor(link.direction, pipeAnchorRadius(src), pipeAnchorRadius(tgt));
    if (lateral !== 0) {
      const ddx = bx - ax;
      const ddy = by - ay;
      const dlen = Math.sqrt(ddx * ddx + ddy * ddy) || 1;
      const nx = -ddy / dlen;
      const ny = ddx / dlen;
      ax += nx * lateral;
      ay += ny * lateral;
      bx += nx * lateral;
      by += ny * lateral;
    }
    const dist = pointToSegmentDist(x, y, ax, ay, bx, by);
    if (dist < minDist) {
      minDist = dist;
      nearest = link;
    }
  }
  return nearest;
}

function findNearestNode(
  x: number,
  y: number,
  d3Nodes: D3Node[],
  threshold: number
): D3Node | null {
  let nearest: D3Node | null = null;
  let minDist = threshold;
  for (const node of d3Nodes) {
    if (node.type === 'surface') continue;
    const dx = (node.x || 0) - x;
    const dy = (node.y || 0) - y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    const r = node.radius;
    if (dist < r + threshold && dist < minDist) {
      minDist = dist;
      nearest = node;
    }
  }
  return nearest;
}

function pointToSegmentDist(
  px: number,
  py: number,
  ax: number,
  ay: number,
  bx: number,
  by: number
): number {
  const dx = bx - ax;
  const dy = by - ay;
  const lenSq = dx * dx + dy * dy;
  if (lenSq === 0) return Math.sqrt((px - ax) ** 2 + (py - ay) ** 2);
  let t = ((px - ax) * dx + (py - ay) * dy) / lenSq;
  t = Math.max(0, Math.min(1, t));
  const projX = ax + t * dx;
  const projY = ay + t * dy;
  return Math.sqrt((px - projX) ** 2 + (py - projY) ** 2);
}

// ─── Per-node geometry helpers ──────────────────────────────────────────────
// `applyNodeGeometry` is the single source of truth for "given a node and a
// new radius, update every visual attribute that depends on it" — main shape,
// unconfigured ring, label offsets, icon font-size, resize-handle position
// and the label background. Used by the per-node resize drag handler.

interface ShapeKind {
  kind: 'rect' | 'circle';
  /** icon font-size as a fraction of radius */
  iconScale: number;
}

function getShapeKind(type: SurfaceNodeType): ShapeKind {
  // The Managed Agent (target) renders larger than other shapes so its icon
  // fills more of the square; everything else uses 0.55.
  if (type === 'target') return { kind: 'rect', iconScale: 0.9 };
  const def = _registry.get(type);
  if (def?.shape === 'rect' || def?.shape === 'diamond') {
    return { kind: 'rect', iconScale: 0.55 };
  }
  return { kind: 'circle', iconScale: 0.55 };
}

function getResizeRange(type: SurfaceNodeType): { min: number; max: number } {
  if (EDGE_CONSTRAINED_TYPES.includes(type)) {
    return { min: MIN_EDGE_NODE_RADIUS, max: MAX_EDGE_NODE_RADIUS };
  }
  const range = _registry.get(type)?.resizeRange;
  return { min: range?.min ?? 16, max: range?.max ?? 60 };
}

function applyNodeGeometry(
  g: d3.Selection<Element, unknown, null, undefined>,
  d: D3Node,
  r: number
): void {
  d.radius = r;
  const { kind, iconScale } = getShapeKind(d.type);
  if (kind === 'rect') {
    const size = r * 2;
    g.select('.main-rect').attr('x', -r).attr('y', -r).attr('width', size).attr('height', size);
    g.select('.unconfigured-ring')
      .attr('x', -(r + 5))
      .attr('y', -(r + 5))
      .attr('width', size + 10)
      .attr('height', size + 10);
  } else {
    g.select('.node-bg').attr('r', r + 1);
    g.select('.main-circle').attr('r', r);
    g.select('.unconfigured-ring').attr('r', r + 5);
  }
  g.select('.node-type-label').attr('dy', -(r + 10));
  g.select('.node-label').attr('dy', r + 16);
  g.select('.npc-description').attr('dy', r + 30);
  g.select('.node-incomplete-reason').attr('dy', r + (d.label && d.label.length > 0 ? 30 : 16));
  g.select('.node-icon').attr('font-size', `${Math.round(r * iconScale)}px`);
  g.select('.node-protocol-badge').attr('transform', `translate(${r}, 0)`);
  g.select('.node-resize-handle')
    .attr('cx', r * 0.7)
    .attr('cy', r * 0.7);

  const labelEl = g.select('.node-label').node() as SVGTextElement | null;
  const labelBg = g.select('.label-bg');
  if (labelEl && !labelBg.empty()) {
    const bbox = labelEl.getBBox();
    if (bbox.width > 0) {
      labelBg
        .attr('x', bbox.x - 4)
        .attr('y', bbox.y - 2)
        .attr('width', bbox.width + 8)
        .attr('height', bbox.height + 4);
    }
  }
}

// Distance the synthesised remote-gateway sits past its anchor along
// the outward axis (perimeter hop for Target routes, the Transit Point
// itself for collapsed TP routes), and the further drop to the
// remote-channel. Shared by the build-effect pin pass and the
// externalRevision re-sync so manual and auto-layout agree.
const SYNTH_REMOTE_BEYOND_HOP = 165;
const SYNTH_REMOTE_CHANNEL_DROP = 160;

/**
 * Pin the synthesised fabric:// chain (hop / remote-gateway /
 * remote-channel) onto live d3 positions. Runs from both the canvas
 * build effect (full rebuild) and the externalRevision re-sync effect
 * (auto-layout / undo) so the chain always follows the live parent
 * (target/TP) instead of the grid-snapped position hint baked into the
 * synthesised CanvasNode — which drifts a few pixels off an
 * edge-constrained parent and, on auto-layout (no full rebuild), would
 * otherwise leave the chain frozen wherever it last landed.
 *
 * Target (managed-agent → external) routes keep the `local-gateway-hop`
 * on the surface perimeter with the remote-gateway one step beyond it.
 * Transit Point routes collapse the hop (the TP already sits on the
 * perimeter) and pin the remote-gateway radially outward from the
 * surface centre through the TP, with the remote-channel one more step
 * along the same axis.
 */
function pinSyntheticFabricChain(
  d3Nodes: D3Node[],
  nodes: CanvasNode[],
  surfaceX: number,
  surfaceY: number,
  surfaceSize: { w: number; h: number }
): void {
  // ── Target / managed-agent hop chain ──
  d3Nodes.forEach(dn => {
    if (dn.type !== 'local-gateway-hop') return;
    const cn = nodes.find(n => n.id === dn.id);
    if (!cn?.parentId) return;
    const parentDn = d3Nodes.find(p => p.id === cn.parentId);
    if (!parentDn || parentDn.x == null || parentDn.y == null) return;
    const halfW = surfaceSize.w / 2;
    const halfH = surfaceSize.h / 2;
    const dx = parentDn.x - surfaceX;
    const dy = parentDn.y - surfaceY;
    // A managed-agent (Target) parent can sit anywhere inside the
    // surface and middleware re-parenting shifts its persisted
    // position, so reading its offset as a direction sends the chain
    // to a random side — always emit the target's chain due east.
    const parentIsTarget = parentDn.type === 'target';
    let dirX = parentIsTarget ? 1 : dx;
    let dirY = parentIsTarget ? 0 : dy;
    if (Math.abs(dirX) < 0.5 && Math.abs(dirY) < 0.5) {
      dirX = 1;
      dirY = 0;
    }
    // Snap the hop onto the surface perimeter along the outward axis.
    let hopAbsX = parentDn.x;
    let hopAbsY = parentDn.y;
    const tCandidates: number[] = [];
    if (Math.abs(dirX) > 0.001) {
      const edgeX = dirX > 0 ? halfW : -halfW;
      const t = (edgeX - dx) / dirX;
      if (t > 0.05) tCandidates.push(t);
    }
    if (Math.abs(dirY) > 0.001) {
      const edgeY = dirY > 0 ? halfH : -halfH;
      const t = (edgeY - dy) / dirY;
      if (t > 0.05) tCandidates.push(t);
    }
    if (tCandidates.length > 0) {
      const tEdge = Math.min(...tCandidates);
      hopAbsX = parentDn.x + dirX * tEdge;
      hopAbsY = parentDn.y + dirY * tEdge;
    } else {
      const len = Math.hypot(dirX, dirY) || 1;
      hopAbsX = parentDn.x + (dirX / len) * SYNTH_REMOTE_BEYOND_HOP;
      hopAbsY = parentDn.y + (dirY / len) * SYNTH_REMOTE_BEYOND_HOP;
    }
    // Lock the chain to the parent's band so arrows render straight.
    hopAbsY = parentDn.y;
    dn.x = hopAbsX;
    dn.y = hopAbsY;
    dn.fx = hopAbsX;
    dn.fy = hopAbsY;

    const remoteCn = nodes.find(n => n.type === 'remote-gateway' && n.parentId === dn.id);
    if (!remoteCn) return;
    const remoteDn = d3Nodes.find(p => p.id === remoteCn.id);
    if (!remoteDn) return;
    const len = Math.hypot(dirX, dirY) || 1;
    const rx = hopAbsX + (dirX / len) * SYNTH_REMOTE_BEYOND_HOP;
    const ry = hopAbsY; // straight outward, same band
    remoteDn.x = rx;
    remoteDn.y = ry;
    remoteDn.fx = rx;
    remoteDn.fy = ry;

    const channelCn = nodes.find(n => n.type === 'remote-channel' && n.parentId === remoteCn.id);
    if (!channelCn) return;
    const channelDn = d3Nodes.find(p => p.id === channelCn.id);
    if (!channelDn) return;
    const cx = rx;
    const cy = ry + SYNTH_REMOTE_CHANNEL_DROP;
    channelDn.x = cx;
    channelDn.y = cy;
    channelDn.fx = cx;
    channelDn.fy = cy;
  });

  // ── Transit Point collapsed chain (hop omitted) ──
  // The TP already sits on the surface perimeter, so the hop is
  // collapsed and the remote-gateway is parented directly on the TP.
  // Pin the remote-gateway and remote-channel radially outward from
  // the surface centre through the TP so the chain reads as a straight
  // line pointing off-surface.
  d3Nodes.forEach(dn => {
    if (dn.type !== 'remote-gateway') return;
    const cn = nodes.find(n => n.id === dn.id);
    if (!cn?.parentId) return;
    const parentDn = d3Nodes.find(p => p.id === cn.parentId);
    if (!parentDn || parentDn.x == null || parentDn.y == null) return;
    // Hop-parented remotes (Target routes) are handled by the loop
    // above; only collapsed TP routes are handled here.
    if (!_registry.isTransitPointType(parentDn.type)) return;
    let dirX = parentDn.x - surfaceX;
    let dirY = parentDn.y - surfaceY;
    if (Math.abs(dirX) < 0.5 && Math.abs(dirY) < 0.5) {
      dirX = 0;
      dirY = -1;
    }
    const len = Math.hypot(dirX, dirY) || 1;
    const ux = dirX / len;
    const uy = dirY / len;
    const rx = parentDn.x + ux * SYNTH_REMOTE_BEYOND_HOP;
    const ry = parentDn.y + uy * SYNTH_REMOTE_BEYOND_HOP;
    dn.x = rx;
    dn.y = ry;
    dn.fx = rx;
    dn.fy = ry;

    const channelCn = nodes.find(n => n.type === 'remote-channel' && n.parentId === cn.id);
    if (!channelCn) return;
    const channelDn = d3Nodes.find(p => p.id === channelCn.id);
    if (!channelDn) return;
    const reach = SYNTH_REMOTE_BEYOND_HOP + SYNTH_REMOTE_CHANNEL_DROP;
    const cx = parentDn.x + ux * reach;
    const cy = parentDn.y + uy * reach;
    channelDn.x = cx;
    channelDn.y = cy;
    channelDn.fx = cx;
    channelDn.fy = cy;
  });
}

// ─── Component ──────────────────────────────────────────────────────────────

const SurfaceCanvas: React.FC<SurfaceCanvasProps> = ({
  surfaceName,
  protocol,
  nodes,
  surfacePolicyIds,
  onNodeClick,
  onCanvasClick,
  onDrop,
  onNodeMove,
  onSystemNodeMove,
  onNodeResize,
  onMultiSelectionChange,
  selectedNodeId,
  multiSelectedIds,
  externalRevision,
  resetViewRev,
  handledResetViewRevRef,
  gridSnap = false,
  surfaceSizeRef: externalSurfaceSizeRef,
  surfaceSize,
  onSurfaceResize,
  canvasViewRef: externalCanvasViewRef,
  exportPngRef,
  resetViewRef,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  // Bumped whenever the container's measured size changes from one nonzero
  // value to another (or 0 → nonzero on first reveal). The rebuild effect
  // depends on this so the canvas re-lays out when its tab is finally shown.
  const [sizeKey, setSizeKey] = useState(0);
  // Bumped once the routing config (outbound listener list) has loaded.
  // Feature-dependency rules that validate a transit point's listen
  // address against the configured outbound listeners read a module-level
  // cache that is populated asynchronously; flipping this state forces the
  // draw effects below to re-run `computeFeatureErrorIds` so the TP fault
  // ring appears as soon as the data is available, without needing the
  // user to open a config panel first.
  const [routingReady, setRoutingReady] = useState(false);
  useEffect(() => {
    let alive = true;
    void fetchRoutingConfig()
      .then(() => {
        if (alive) setRoutingReady(true);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  // Keep a ref too so the heavy rebuild effect can read the latest set without
  // taking it as a dependency in places that would restart the force simulation.
  const surfacePolicyIdsRef = useRef<Set<string> | null>(null);
  useEffect(() => {
    surfacePolicyIdsRef.current = surfacePolicyIds;
  }, [surfacePolicyIds]);
  const lastSizeRef = useRef<{ w: number; h: number }>({ w: 0, h: 0 });
  // Captured on every rebuild so the surfaceSize-prop effect (driven by
  // undo/redo, where the parent reverts state.surfaceSize) can re-apply
  // a size change through the same machinery the live drag uses, with
  // its full cascade onto edge-constrained / surface-wide nodes.
  const applySurfaceSizeRef = useRef<
    ((newW: number, newH: number, newSx: number, newSy: number) => void) | null
  >(null);
  const simulationRef = useRef<d3.Simulation<D3Node, D3Link> | null>(null);
  const d3NodesRef = useRef<D3Node[]>([]);
  const d3LinksRef = useRef<D3Link[]>([]);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  // Last AP position used by the caller/human re-anchor effect. Lets
  // us skip the re-anchor when AP didn't actually move, so user drags
  // of the synthetic caller/human nodes don't get stomped on every
  // unrelated re-render.
  const prevApPosRef = useRef<{ x: number; y: number } | null>(null);
  // Last externalRevision we re-anchored on. Bumps from auto-layout /
  // undo / hydrate must always force a re-anchor even when AP itself
  // didn't move — that's the whole point of pressing auto-layout
  // after manually dragging the chain out of shape.
  const prevAnchorRevisionRef = useRef<number | null>(null);
  // Persist node positions across rebuilds so the graph stays stable.
  //
  // Positions are stored as **offsets from the surface center** (dx, dy).
  // The surface itself is always anchored to the live container center, so
  // when the SVG resizes (e.g. tab switch with display:none/block), the
  // surface re-centers and every node moves with it — keeping the layout
  // visually identical regardless of canvas size.
  const positionsRef = useRef<
    Map<string, { dx: number; dy: number; fdx: number | null; fdy: number | null }>
  >(new Map());
  // Pending drop position — used to place new nodes where they were dropped
  const pendingDropPos = useRef<{ x: number; y: number } | null>(null);
  // Drag-time hint shown next to the cursor: resolves the slot label or
  // the rejection reason for the dragged element type at the current
  // hover position. Cleared on dragleave/drop.
  const [dragHint, setDragHint] = useState<{
    x: number;
    y: number;
    text: string;
    ok: boolean;
  } | null>(null);
  // Drag-time error message anchored to the bottom-left of the canvas.
  // Used for structural rejections (wrong direction, capability
  // mismatch, no edge under cursor) so the user gets a stable, readable
  // explanation without the noise of a cursor-tracking pill.
  const [dragStatus, setDragStatus] = useState<string | null>(null);
  // Resizable surface dimensions. If the parent provided an external
  // ref (so the saved canvas blob can seed/round-trip the size), use it
  // to seed the initial value; resize handlers also write back to it
  // so the page can persist the dimensions. Falls back to the
  // `surfaceSize` prop (state-driven) so the wizard / detail page can
  // hydrate from history without juggling refs.
  const surfaceSizeRef = useRef<{ w: number; h: number }>({
    w: externalSurfaceSizeRef?.current?.w ?? surfaceSize?.w ?? SURFACE_RECT_WIDTH,
    h: externalSurfaceSizeRef?.current?.h ?? surfaceSize?.h ?? SURFACE_RECT_HEIGHT,
  });
  // Mirror the seed back into the external ref on first render so reads
  // before any resize see a populated value.
  if (externalSurfaceSizeRef && externalSurfaceSizeRef.current == null) {
    externalSurfaceSizeRef.current = { ...surfaceSizeRef.current };
  }
  // Lasso selection state
  const selectedNodesRef = useRef<Set<string>>(new Set());
  const onMultiSelectionChangeRef = useRef(onMultiSelectionChange);
  useEffect(() => {
    onMultiSelectionChangeRef.current = onMultiSelectionChange;
  }, [onMultiSelectionChange]);
  // Mirror the sidebar's single-selection so the d3 click handlers (which
  // are baked once per rebuild) can read the latest value.
  const selectedNodeIdRef = useRef(selectedNodeId);
  useEffect(() => {
    selectedNodeIdRef.current = selectedNodeId;
  }, [selectedNodeId]);
  const emitMultiSelection = () => {
    onMultiSelectionChangeRef.current?.(Array.from(selectedNodesRef.current));
  };

  // Stable structural fingerprint — only changes when nodes are added/removed/reordered
  const structureKey = useMemo(
    () => nodes.map(n => `${n.id}:${n.type}:${n.parentId || ''}`).join('|'),
    [nodes]
  );

  const handleDragOver = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();

      // Determine dragged type from MIME types (getData is blocked during dragover)
      const types = Array.from(e.dataTransfer.types);
      const typeMatch = types.find(t => t.startsWith('application/surface-type-'));
      const type = typeMatch
        ? (typeMatch.replace('application/surface-type-', '') as SurfaceNodeType)
        : null;

      const container = e.currentTarget as HTMLElement;
      container.classList.add('drag-over');

      // Tooltip text computed below; cleared if no useful info to show.
      let hint: { text: string; ok: boolean } | null = null;

      if (svgRef.current && type) {
        const dropTarget = getDropTarget(type);
        const svg = d3.select(svgRef.current);
        svg.selectAll('.link-highlight').classed('link-highlight', false);
        svg.selectAll('.link-valid').classed('link-valid', false);
        svg.selectAll('.node-highlight').classed('node-highlight', false);

        const rect = svgRef.current.getBoundingClientRect();
        const transform = d3.zoomTransform(svgRef.current);
        const [mx, my] = transform.invert([e.clientX - rect.left, e.clientY - rect.top]);

        if (dropTarget === 'edge') {
          const directionality = _registry.get(type)?.directionality;
          const filter =
            directionality === 'request' || directionality === 'response'
              ? directionality
              : 'either';
          // Pre-compute every derivedEdge × direction the dragged type
          // can land on, then highlight every rendered sub-link
          // belonging to those chains. Gives the user an at-a-glance
          // map of valid drop targets before they go searching.
          const edges = deriveEdges(nodes);
          const slotFilter = makeSurfaceSlotFilter(
            nodes.find(n => n.type === 'target')?.config?.endpoint,
            nodes.some(n => _registry.isTransitPointType(n.type)),
            nodes
          );
          // Element-declared edgeSnap archetype allow-list. When present, the
          // drop only snaps to these archetypes (see `handleDrop`), so the
          // broad valid-drop highlight must honour the same list — otherwise
          // an archetype the drop rejects (e.g. AP→MA for an EXT/TP-only
          // element) still lights up green and confuses the user.
          const dragSnapArchetypes = _registry.get(type)?.edgeSnap?.archetypes;
          const validEdgeSpan = new Map<string, Set<string>>(); // edgeId → set of node ids
          const validDirections = new Map<string, Set<SlotDirection>>();
          for (const edge of edges) {
            const arch = getArchetype(edge.archetype);
            if (!arch) continue;
            if (dragSnapArchetypes && !dragSnapArchetypes.includes(edge.archetype)) continue;
            // Capability gate: skip edges that don't satisfy the
            // dragged element's `requires.dropOnEdge`. Mirrors the
            // check in useSurfaceBuilder.handleDrop so the highlight
            // matches what the drop would actually accept.
            const srcType = nodes.find(n => n.id === edge.endpoints.source)?.type;
            const tgtType = nodes.find(n => n.id === edge.endpoints.target)?.type;
            if (
              srcType &&
              tgtType &&
              !_registry.canDropOnEdge(type, srcType, tgtType) &&
              !_registry.canDropOnEdge(type, tgtType, srcType)
            ) {
              continue;
            }
            for (const dir of arch.directions) {
              if (filter !== 'either' && dir !== filter) continue;
              const r = tryDrop(
                edge,
                type,
                dir,
                id => nodes.find(n => n.id === id)?.type,
                slotFilter
              );
              if (!r.ok) continue;
              const span = validEdgeSpan.get(edge.id) ?? new Set<string>();
              span.add(edge.endpoints.source);
              span.add(edge.endpoints.target);
              for (const list of edge.slots.values()) {
                for (const id of list) span.add(id);
              }
              validEdgeSpan.set(edge.id, span);
              const dirs = validDirections.get(edge.id) ?? new Set<SlotDirection>();
              dirs.add(dir);
              validDirections.set(edge.id, dirs);
            }
          }
          // Mark every rendered chain link whose endpoints both belong
          // to a valid edge span AND whose direction matches.
          if (validEdgeSpan.size > 0) {
            const allValidNodeIds = new Set<string>();
            validEdgeSpan.forEach(s => s.forEach(id => allValidNodeIds.add(id)));
            svg
              .selectAll<SVGLineElement, D3Link>('.link')
              .filter(d => {
                const s = (d.source as D3Node).id;
                const t = (d.target as D3Node).id;
                if (!allValidNodeIds.has(s) || !allValidNodeIds.has(t)) return false;
                if (!d.direction) return false;
                for (const [eid, span] of validEdgeSpan.entries()) {
                  if (span.has(s) && span.has(t)) {
                    const dirs = validDirections.get(eid);
                    if (dirs?.has(d.direction)) return true;
                  }
                }
                return false;
              })
              .classed('link-valid', true);
          }

          const snap = _registry.get(type)?.edgeSnap;
          const allowedArchetypes = snap?.archetypes;
          const snapRadius = snap?.radius ?? 50;
          const archetypeFilter = allowedArchetypes
            ? (_link: D3Link, s: D3Node, t: D3Node) => {
                const archId = findArchetypeForPair(s.type, t.type);
                return !!archId && allowedArchetypes.includes(archId);
              }
            : undefined;
          const nearest = findNearestEdge(
            mx,
            my,
            d3LinksRef.current,
            snapRadius,
            filter,
            archetypeFilter
          );
          const label = _registry.get(type)?.label ?? type;
          const cannotDropMsg = `Cannot drop ${label} here`;
          let status: string | null = null;
          if (nearest) {
            const src = nearest.source as D3Node;
            const tgt = nearest.target as D3Node;
            const direction: SlotDirection =
              nearest.direction === 'response' ? 'response' : 'request';
            const edge = findEdgeForHit(edges, src.id, tgt.id);
            const edgeIsValid = !!edge && (validDirections.get(edge.id)?.has(direction) ?? false);
            if (edgeIsValid && edge) {
              svg
                .selectAll<SVGLineElement, D3Link>('.link')
                .filter(
                  d => (d.source as D3Node).id === src.id && (d.target as D3Node).id === tgt.id
                )
                .classed('link-highlight', true);
              const result = tryDrop(
                edge,
                type,
                direction,
                id => {
                  return nodes.find(n => n.id === id)?.type;
                },
                slotFilter
              );
              if (result.ok) {
                const slot = getSlot(edge.archetype, result.slotId);
                hint = { text: slot?.label ?? result.slotId, ok: true };
              } else {
                status = cannotDropMsg;
              }
            } else if (edge) {
              status = cannotDropMsg;
            }
          } else if (validEdgeSpan.size === 0) {
            status = `${label} has no valid drop target on this surface`;
          }
          setDragStatus(status);
        } else if (dropTarget === 'node') {
          const nearest = findNearestNode(mx, my, d3NodesRef.current, 40);
          if (nearest) {
            svg.select(`[data-node-id="${nearest.id}"]`).classed('node-highlight', true);
          }
        }
      }

      e.dataTransfer.dropEffect = 'copy';

      // Position relative to the container (clientRect-based, so it
      // tracks the cursor without needing the SVG transform).
      const containerRect = container.getBoundingClientRect();
      if (hint) {
        setDragHint({
          x: e.clientX - containerRect.left + 14,
          y: e.clientY - containerRect.top + 14,
          text: hint.text,
          ok: hint.ok,
        });
      } else {
        setDragHint(null);
      }
    },
    [nodes]
  );

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    // Only clear when actually leaving the container, not entering child elements
    const related = e.relatedTarget as Node | null;
    if (related && (e.currentTarget as HTMLElement).contains(related)) return;
    e.currentTarget.classList.remove('drag-over');
    setDragHint(null);
    setDragStatus(null);
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      svg.selectAll('.link-highlight').classed('link-highlight', false);
      svg.selectAll('.link-valid').classed('link-valid', false);
      svg.selectAll('.node-highlight').classed('node-highlight', false);
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.currentTarget.classList.remove('drag-over');
      setDragHint(null);
      setDragStatus(null);
      const type = e.dataTransfer.getData('application/surface-element') as SurfaceNodeType;
      if (!type) return;

      if (svgRef.current) {
        const svg = d3.select(svgRef.current);
        svg.selectAll('.link-highlight').classed('link-highlight', false);
        svg.selectAll('.link-valid').classed('link-valid', false);
        svg.selectAll('.node-highlight').classed('node-highlight', false);
      }

      const dropTarget = getDropTarget(type);

      if (dropTarget === 'edge' && svgRef.current) {
        const rect = svgRef.current.getBoundingClientRect();
        const transform = d3.zoomTransform(svgRef.current);
        const [mx, my] = transform.invert([e.clientX - rect.left, e.clientY - rect.top]);
        pendingDropPos.current = { x: mx, y: my };
        const directionality = _registry.get(type)?.directionality;
        const filter =
          directionality === 'request' || directionality === 'response' ? directionality : 'either';
        const snap = _registry.get(type)?.edgeSnap;
        const allowedArchetypes = snap?.archetypes;
        const snapRadius = snap?.radius ?? 60;
        const archetypeFilter = allowedArchetypes
          ? (_link: D3Link, s: D3Node, t: D3Node) => {
              const archId = findArchetypeForPair(s.type, t.type);
              return !!archId && allowedArchetypes.includes(archId);
            }
          : undefined;
        const nearest = findNearestEdge(
          mx,
          my,
          d3LinksRef.current,
          snapRadius,
          filter,
          archetypeFilter
        );
        if (nearest) {
          const src = nearest.source as D3Node;
          const tgt = nearest.target as D3Node;
          // Persist the surface-relative drop position so the new
          // node lands where the user dropped it (instead of being
          // projected onto whatever pendingDropPos.current happens to
          // hold during the next rebuild).
          const surf = d3NodesRef.current.find(n => n.id === '__surface__');
          const sx = surf?.x ?? 0;
          const sy = surf?.y ?? 0;
          onDrop(type, {
            edgeSourceId: src.id,
            edgeTargetId: tgt.id,
            edgeDirection: nearest.direction,
            position: { x: mx - sx, y: my - sy },
          });
        }
        // If no edge nearby, drop is rejected (policy must be on an edge)
      } else if (dropTarget === 'node' && svgRef.current) {
        const rect = svgRef.current.getBoundingClientRect();
        const transform = d3.zoomTransform(svgRef.current);
        const [mx, my] = transform.invert([e.clientX - rect.left, e.clientY - rect.top]);
        pendingDropPos.current = { x: mx, y: my };
        const nearest = findNearestNode(mx, my, d3NodesRef.current, 50);
        if (nearest) {
          onDrop(type, { targetNodeId: nearest.id });
        } else {
          onDrop(type);
        }
      } else {
        // Canvas drop without SVG — use center as fallback
        if (svgRef.current) {
          const rect = svgRef.current.getBoundingClientRect();
          const transform = d3.zoomTransform(svgRef.current);
          const [mx, my] = transform.invert([e.clientX - rect.left, e.clientY - rect.top]);
          pendingDropPos.current = { x: mx, y: my };
          // Edge-constrained types (AP, TP) are snapped to the
          // surface perimeter on render. Persist the snapped position
          // surface-relative so a fresh drop survives save/reload
          // (without this, AP/TP defaults to the right edge after
          // reload because the stored CanvasNode has no `position`).
          if (EDGE_CONSTRAINED_TYPES.includes(type)) {
            const surf = d3NodesRef.current.find(n => n.id === '__surface__');
            const sx = surf?.x ?? 0;
            const sy = surf?.y ?? 0;
            const pt = constrainToSurfaceEdge(
              mx,
              my,
              sx,
              sy,
              surfaceSizeRef.current.w / 2,
              surfaceSizeRef.current.h / 2
            );
            onDrop(type, { position: { x: pt.x - sx, y: pt.y - sy } });
            return;
          }
        }
        onDrop(type);
      }
    },
    [onDrop]
  );

  // ─── Observe container size; trigger a rebuild once it becomes nonzero ────
  useEffect(() => {
    const el = containerRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(() => {
      const w = el.clientWidth;
      const h = el.clientHeight;
      if (w === 0 || h === 0) return;
      const last = lastSizeRef.current;
      if (Math.abs(last.w - w) < 1 && Math.abs(last.h - h) < 1) return;
      lastSizeRef.current = { w, h };
      // Keep the SVG's intrinsic size and viewBox in sync with the
      // container immediately so the content never gets scaled by the
      // default `preserveAspectRatio` (xMidYMid meet) into a
      // letterboxed sub-rectangle while we wait for the React effect
      // to re-run.
      if (svgRef.current) {
        const svg = d3.select(svgRef.current);
        svg.attr('width', w).attr('height', h).attr('viewBox', `0 0 ${w} ${h}`);
      }
      setSizeKey(k => k + 1);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // ─── Full rebuild only when structure changes ─────────────────────────────
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const container = containerRef.current;
    const measuredW = container.clientWidth;
    const measuredH = container.clientHeight;
    // If the container hasn't been laid out yet (e.g. inside a hidden tab),
    // bail out. The ResizeObserver above will bump sizeKey when it gains a
    // size, which will re-run this effect.
    if (measuredW === 0 || measuredH === 0) {
      return;
    }
    const width = measuredW;
    const height = measuredH;
    const centerY = height / 2;

    const svg = d3.select(svgRef.current);
    // Save current zoom transform before clearing
    const savedTransform = d3.zoomTransform(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('width', width).attr('height', height).attr('viewBox', `0 0 ${width} ${height}`);

    // Defs
    const defs = svg.append('defs');

    // Background dot-grid pattern, shown only when snap-to-grid is on.
    // Spacing matches GRID_SNAP (10px in canvas user-space) so dots sit
    // exactly on the quantised positions. Dot colour is themed via CSS
    // on the `.canvas-grid-dot` class so it stays subtle in light/dark.
    const gridPattern = defs
      .append('pattern')
      .attr('id', 'canvas-grid-dots')
      .attr('width', 10)
      .attr('height', 10)
      .attr('patternUnits', 'userSpaceOnUse');
    gridPattern
      .append('circle')
      .attr('class', 'canvas-grid-dot')
      .attr('cx', 0)
      .attr('cy', 0)
      .attr('r', 0.9);

    const shadow = defs
      .append('filter')
      .attr('id', 'node-shadow')
      .attr('x', '-30%')
      .attr('y', '-30%')
      .attr('width', '160%')
      .attr('height', '160%');
    shadow
      .append('feDropShadow')
      .attr('dx', 0)
      .attr('dy', 2)
      .attr('stdDeviation', 3)
      .attr('flood-color', 'rgba(0,0,0,0.12)');

    defs
      .append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 8)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', '#adb5bd');

    // Reverse arrowhead for bidirectional links (drawn at the source end).
    defs
      .append('marker')
      .attr('id', 'arrow-start')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 2)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M10,-4L2,0L10,4')
      .attr('fill', '#adb5bd');

    // Arrowhead for the credential-delegation redrive loop. Light
    // grey to match the curve — it's secondary information so it
    // shouldn't stand out against the main pipeline arrows.
    defs
      .append('marker')
      .attr('id', 'cd-redrive-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 8)
      .attr('refY', 0)
      .attr('markerWidth', 5)
      .attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', '#adb5bd');

    const g = svg.append('g').attr('class', 'main-group');

    // Transparent background rect to catch clicks/lasso on empty canvas area
    const canvasBg = g
      .append('rect')
      .attr('class', 'canvas-bg')
      .attr('width', width * 3)
      .attr('height', height * 3)
      .attr('x', -width)
      .attr('y', -height)
      .attr('fill', gridSnapRef.current ? 'url(#canvas-grid-dots)' : 'transparent')
      .on('click', () => {
        // Plain click on background (no shift) deselects and fires onCanvasClick
        if (selectedNodesRef.current.size > 0) {
          selectedNodesRef.current.clear();
          svg.selectAll('.node').classed('lasso-selected', false);
          emitMultiSelection();
        }
        if (onCanvasClick) onCanvasClick();
      });

    // Lasso selection rectangle (hidden initially)
    const lassoRect = g
      .append('rect')
      .attr('class', 'lasso-rect')
      .attr('fill', 'rgba(78, 115, 223, 0.08)')
      .attr('stroke', '#4e73df')
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '4 2')
      .attr('pointer-events', 'none')
      .attr('visibility', 'hidden');

    // Lasso drag behavior on canvas background (Shift + drag only)
    let lassoStart: { x: number; y: number } | null = null;
    let lassoActive = false;
    canvasBg.call(
      d3
        .drag<SVGRectElement, unknown>()
        .filter(event => event.shiftKey)
        .on('start', event => {
          // Clear previous selection
          selectedNodesRef.current.clear();
          svg.selectAll('.node').classed('lasso-selected', false);
          emitMultiSelection();
          lassoStart = { x: event.x, y: event.y };
          lassoActive = false;
          lassoRect
            .attr('x', event.x)
            .attr('y', event.y)
            .attr('width', 0)
            .attr('height', 0)
            .attr('visibility', 'hidden');
        })
        .on('drag', event => {
          if (!lassoStart) return;
          lassoActive = true;
          const x = Math.min(lassoStart.x, event.x);
          const y = Math.min(lassoStart.y, event.y);
          const w = Math.abs(event.x - lassoStart.x);
          const h = Math.abs(event.y - lassoStart.y);
          lassoRect
            .attr('x', x)
            .attr('y', y)
            .attr('width', w)
            .attr('height', h)
            .attr('visibility', 'visible');
          // Live highlight nodes inside lasso
          const selIds = new Set<string>();
          d3Nodes.forEach(n => {
            if (n.type === 'surface') return;
            const nx = n.x || 0;
            const ny = n.y || 0;
            if (nx >= x && nx <= x + w && ny >= y && ny <= y + h) {
              selIds.add(n.id);
            }
          });
          svg
            .selectAll<SVGGElement, D3Node>('.node')
            .classed('lasso-selected', d => selIds.has(d.id));
        })
        .on('end', event => {
          lassoRect.attr('visibility', 'hidden');
          if (!lassoStart || !lassoActive) {
            // Was just a shift-click, not a drag — clear selection
            lassoStart = null;
            return;
          }
          // Determine final selection
          const x = Math.min(lassoStart.x, event.x);
          const y = Math.min(lassoStart.y, event.y);
          const w = Math.abs(event.x - lassoStart.x);
          const h = Math.abs(event.y - lassoStart.y);
          const selIds = new Set<string>();
          d3Nodes.forEach(n => {
            if (n.type === 'surface') return;
            const nx = n.x || 0;
            const ny = n.y || 0;
            if (nx >= x && nx <= x + w && ny >= y && ny <= y + h) {
              selIds.add(n.id);
            }
          });
          selectedNodesRef.current = selIds;
          svg
            .selectAll<SVGGElement, D3Node>('.node')
            .classed('lasso-selected', d => selIds.has(d.id));
          emitMultiSelection();
          lassoStart = null;
        }) as any
    );

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.4, 3])
      .filter(event => {
        // Shift+click is reserved for lasso; allow normal pan otherwise
        if ((event.type === 'mousedown' || event.type === 'touchstart') && event.shiftKey)
          return false;
        return true;
      })
      .on('start', event => {
        if (event.sourceEvent && event.sourceEvent.type !== 'wheel') {
          svg.style('cursor', 'grabbing');
        }
      })
      .on('zoom', event => {
        g.attr('transform', event.transform);
        // Mirror the live transform into the external ref so the page
        // can persist it in the canvas blob on save.
        if (externalCanvasViewRef) {
          externalCanvasViewRef.current = {
            x: event.transform.x,
            y: event.transform.y,
            k: event.transform.k,
          };
        }
      })
      .on('end', () => {
        svg.style('cursor', 'grab');
      });
    svg.style('cursor', 'grab');
    svg.call(zoom);
    zoomRef.current = zoom;
    // Restore previous zoom transform so canvas doesn't snap on rebuild.
    // Priority: in-DOM saved transform (live edits), then external ref
    // (page-supplied seed from the persisted canvas blob).
    if (savedTransform.k !== 1 || savedTransform.x !== 0 || savedTransform.y !== 0) {
      svg.call(zoom.transform, savedTransform);
    } else if (externalCanvasViewRef?.current) {
      const v = externalCanvasViewRef.current;
      svg.call(zoom.transform, d3.zoomIdentity.translate(v.x, v.y).scale(v.k));
    }

    // Build D3 nodes — reuse saved positions for existing nodes.
    // Surface center is the origin for all node offsets and is always
    // re-derived from the live container so layouts survive container resizes.
    const surfaceX = width * 0.5;
    const surfaceY = centerY;
    const savedPositions = positionsRef.current;
    // Clean stale entries (surface, human, caller are virtual node ids)
    const activeIds = new Set(['__human__', '__caller__', ...nodes.map(n => n.id)]);
    for (const id of savedPositions.keys()) {
      if (!activeIds.has(id)) savedPositions.delete(id);
    }
    // Synthesised fabric:// chain nodes (hop / remote-gw / remote-channel)
    // are recomputed every render from the underlying target/TP and must
    // never be pinned by a cached `positionsRef` entry — otherwise the
    // chain freezes at whatever stray position the first render produced
    // and only an auto-layout would re-derive it. Drop their cache so the
    // seed loop below re-applies the freshly-synthesised `n.position`.
    for (const id of Array.from(savedPositions.keys())) {
      if (isSyntheticFabricNodeId(id)) savedPositions.delete(id);
    }
    // Seed positions from node.position prop (restored on undo). Stored values
    // are offsets from the surface center.
    for (const n of nodes) {
      if (n.position && !savedPositions.has(n.id)) {
        savedPositions.set(n.id, {
          dx: n.position.x,
          dy: n.position.y,
          fdx: n.position.x,
          fdy: n.position.y,
        });
      }
    }
    const d3Nodes: D3Node[] = [
      {
        id: '__surface__',
        type: 'surface',
        label: surfaceName || 'Agent Surface',
        sublabel: protocol.toUpperCase(),
        configured: true,
        radius: NODE_RADIUS['surface'],
        x: surfaceX,
        y: surfaceY,
        fx: surfaceX,
        fy: surfaceY,
      },
      ...nodes.map(n => {
        const saved = savedPositions.get(n.id);
        // Saved offsets resolved against the live surface center.
        const savedAbs = saved
          ? {
              x: surfaceX + saved.dx,
              y: surfaceY + saved.dy,
              fx: saved.fdx == null ? null : surfaceX + saved.fdx,
              fy: saved.fdy == null ? null : surfaceY + saved.fdy,
            }
          : null;
        // Use pending drop position for new nodes (no saved position).
        // Drop positions arrive in absolute SVG coords from the drop handler.
        const dropPos = !saved ? pendingDropPos.current : null;
        // Edge-constrained nodes (AP, TP) snap to surface perimeter.
        // Note: TPs stay pinned even after middleware is inserted in
        // front of them (which gives them a parentId), so the check
        // is intentionally not gated on !n.parentId for TPs.
        if (EDGE_CONSTRAINED_TYPES.includes(n.type) && !saved) {
          const curHW = surfaceSizeRef.current.w / 2;
          const curHH = surfaceSizeRef.current.h / 2;
          if (dropPos) {
            // Constrain the drop position to the surface edge
            const pt = constrainToSurfaceEdge(
              dropPos.x,
              dropPos.y,
              surfaceX,
              surfaceY,
              curHW,
              curHH
            );
            return {
              id: n.id,
              type: n.type,
              label: n.label,
              sublabel: n.sublabel,
              configured: n.configured,
              radius: 0,
              x: pt.x,
              y: pt.y,
              fx: pt.x,
              fy: pt.y,
            };
          }
          const side = n.type === 'access-point' ? -curHW : curHW;
          const edgeX = surfaceX + side;
          return {
            id: n.id,
            type: n.type,
            label: n.label,
            sublabel: n.sublabel,
            configured: n.configured,
            radius: 0,
            x: edgeX,
            y: surfaceY,
            fx: edgeX,
            fy: surfaceY,
          };
        }
        // Human and Caller: positioned to the left of AP
        if ((n.type === 'human' || n.type === 'caller') && !saved) {
          const curHW = surfaceSizeRef.current.w / 2;
          const apInitX = surfaceX - curHW;
          const offset = n.type === 'human' ? -170 : -90;
          const nx = apInitX + offset;
          return {
            id: n.id,
            type: n.type,
            label: n.label,
            sublabel: n.sublabel,
            configured: n.configured,
            radius: 0,
            x: nx,
            y: surfaceY,
            fx: nx,
            fy: surfaceY,
          };
        }
        // Surface-wide nodes (e.g. Agent Identity): auto-place in a grid that
        // fills bottom-left → right then stacks upward, INSIDE the surface.
        // Persist the slot to positionsRef on first placement so the position
        // survives subsequent re-renders (config changes, tab switches, etc.)
        // without drifting if the surface size changes later.
        if (SURFACE_WIDE_TYPES.includes(n.type) && !saved) {
          const halfW = surfaceSizeRef.current.w / 2;
          const halfH = surfaceSizeRef.current.h / 2;
          const slot = computeSurfaceWideSlot(n.id, nodes, surfaceX, surfaceY, halfW, halfH);
          const sdx = slot.x - surfaceX;
          const sdy = slot.y - surfaceY;
          positionsRef.current.set(n.id, { dx: sdx, dy: sdy, fdx: sdx, fdy: sdy });
          // Auto-placement is system-driven — use the silent setter
          // so it never pushes its own slot onto the undo history.
          const sysEmit = onSystemNodeMove ?? onNodeMove;
          if (sysEmit) sysEmit(n.id, sdx, sdy);
          return {
            id: n.id,
            type: n.type,
            label: n.label,
            sublabel: n.sublabel,
            configured: n.configured,
            radius: 0,
            x: slot.x,
            y: slot.y,
            fx: slot.x,
            fy: slot.y,
          };
        }
        // Target (Managed Agent): use saved offset if present, else center on surface.
        if (n.type === 'target') {
          const tx = savedAbs?.x ?? surfaceX;
          const ty = savedAbs?.y ?? surfaceY;
          return {
            id: n.id,
            type: n.type,
            label: n.label,
            sublabel: n.sublabel,
            configured: n.configured,
            radius: 0,
            x: tx,
            y: ty,
            fx: savedAbs?.fx ?? tx,
            fy: savedAbs?.fy ?? ty,
          };
        }
        // NPC with parentId: place outside surface, away from parent
        if (isNpcType(n.type) && n.parentId && !saved) {
          const parentSaved = savedPositions.get(n.parentId);
          const curHW = surfaceSizeRef.current.w / 2;
          const curHH = surfaceSizeRef.current.h / 2;
          const parentNode = nodes.find(p => p.id === n.parentId);
          const parentInsideSurface = parentNode?.type === 'target';
          if (parentSaved) {
            const parentX = surfaceX + parentSaved.dx;
            const parentY = surfaceY + parentSaved.dy;
            let outX: number;
            let outY: number;
            if (parentInsideSurface) {
              // Parent (Managed Agent) sits inside the surface. Place
              // the NPC outside, to the right of the surface, in line
              // with the AP→MA flow. Use the parent's vertical offset
              // so the NPC tracks the MA when it's been moved.
              outX = surfaceX + curHW + 120;
              outY = parentY;
            } else {
              // Direction: from surface center through parent, extend outward.
              // 140px gives a clearer visual gap between the TP on the
              // surface edge and its external NPC than the default 80px.
              const dx = parentX - surfaceX || 1;
              const dy = parentY - surfaceY || 0;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              outX = parentX + (dx / dist) * 140;
              outY = parentY + (dy / dist) * 140;
            }
            return {
              id: n.id,
              type: n.type,
              label: n.label,
              sublabel: n.sublabel,
              configured: n.configured,
              radius: 0,
              x: outX,
              y: outY,
              fx: outX,
              fy: outY,
            };
          }
          // Fallback for a freshly-dropped TP: derive the TP's edge
          // position from the same pendingDropPos and place the NPC
          // 80px further out along the perpendicular of that edge so
          // the external target sits on the natural side (north → above,
          // east → right, etc.) rather than always to the right.
          const parentIsEdgeConstrained =
            !!parentNode && EDGE_CONSTRAINED_TYPES.includes(parentNode.type);
          if (parentIsEdgeConstrained && pendingDropPos.current) {
            const pt = constrainToSurfaceEdge(
              pendingDropPos.current.x,
              pendingDropPos.current.y,
              surfaceX,
              surfaceY,
              curHW,
              curHH
            );
            // Outward unit vector from surface center through the edge point.
            const dx = pt.x - surfaceX;
            const dy = pt.y - surfaceY;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const outX = pt.x + (dx / dist) * 140;
            const outY = pt.y + (dy / dist) * 140;
            return {
              id: n.id,
              type: n.type,
              label: n.label,
              sublabel: n.sublabel,
              configured: n.configured,
              radius: 0,
              x: outX,
              y: outY,
              fx: outX,
              fy: outY,
            };
          }
          // Last-resort fallback: place to the right outside surface
          // (in-line with the AP→MA flow for the managed-agent's
          // external target).
          const outX = surfaceX + curHW + 120;
          const outY = surfaceY;
          return {
            id: n.id,
            type: n.type,
            label: n.label,
            sublabel: n.sublabel,
            configured: n.configured,
            radius: 0,
            x: outX,
            y: outY,
            fx: outX,
            fy: outY,
          };
        }
        return {
          id: n.id,
          type: n.type,
          label: n.label,
          sublabel: n.sublabel,
          configured: n.configured,
          radius: 0,
          x:
            savedAbs?.x ??
            dropPos?.x ??
            width * (NODE_X_WEIGHT[n.type] || 0.5) + (Math.random() - 0.5) * 30,
          y: savedAbs?.y ?? dropPos?.y ?? centerY + (Math.random() - 0.5) * 80,
          fx: savedAbs?.fx ?? (dropPos ? dropPos.x : null),
          fy: savedAbs?.fy ?? (dropPos ? dropPos.y : null),
        };
      }),
    ];

    // Set radius and parentId on each D3 node from CanvasNode
    d3Nodes.forEach(dn => {
      if (dn.id === '__surface__') {
        dn.radius = NODE_RADIUS['surface'];
        return;
      }
      const cn = nodes.find(n => n.id === dn.id);
      // Edge-constrained nodes (AP, TP) are owned by the surface: their
      // radius is always derived from the current surface width so they
      // grow/shrink proportionally and stay visually consistent. Any
      // persisted `cn.radius` on these is intentionally ignored.
      if (EDGE_CONSTRAINED_TYPES.includes(dn.type)) {
        dn.radius = getEdgeNodeRadius(surfaceSizeRef.current.w);
      } else {
        dn.radius = cn?.radius ?? NODE_RADIUS[dn.type] ?? 30;
      }
      dn.parentId = cn?.parentId;
    });

    // Fix NPC nodes whose parent was just placed in this same rebuild (no savedPosition)
    const surfaceX2 = d3Nodes.find(n => n.id === '__surface__')?.x || 0;
    const surfaceY2 = d3Nodes.find(n => n.id === '__surface__')?.y || 0;
    d3Nodes.forEach(dn => {
      const cn = nodes.find(n => n.id === dn.id);
      if (!cn || !isNpcType(dn.type) || !cn.parentId) return;
      if (positionsRef.current.has(dn.id)) return; // already has saved position
      const parentDn = d3Nodes.find(p => p.id === cn.parentId);
      if (!parentDn || parentDn.x == null || parentDn.y == null) return;
      // Only fix if current position is the fallback (east of surface)
      const curHW = surfaceSizeRef.current.w / 2;
      const fallbackX = surfaceX2 + curHW + 80;
      if (Math.abs((dn.x || 0) - fallbackX) > 5) return; // already positioned correctly
      // Place outward from surface center through parent. 110px when the
      // parent is edge-constrained (TP) so the external NPC sits clearly
      // off the surface; 80px otherwise.
      const dx = parentDn.x - surfaceX2 || 1;
      const dy = parentDn.y - surfaceY2 || 0;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const offset = EDGE_CONSTRAINED_TYPES.includes(parentDn.type) ? 140 : 80;
      const outX = parentDn.x + (dx / dist) * offset;
      const outY = parentDn.y + (dy / dist) * offset;
      dn.x = outX;
      dn.y = outY;
      dn.fx = outX;
      dn.fy = outY;
    });

    // ── Synthesised fabric:// chain layout ──
    // The synth function in `synthesizeFabric.ts` emits hop /
    // remote-gw / remote-channel with a position hint derived from
    // the parent CanvasNode's `.position` field — which is only
    // populated *after* the user has moved the parent (or after an
    // auto-layout has run), and is then grid-snapped a few pixels off
    // the live edge-constrained parent. Re-derive the chain from the
    // live d3 positions and pin every synth node so the simulation
    // can't drift them and manual/auto-layout always agree.
    pinSyntheticFabricChain(d3Nodes, nodes, surfaceX2, surfaceY2, surfaceSizeRef.current);

    // Clear pending drop position after use
    pendingDropPos.current = null;

    // Build links — arrows follow data flow direction (parent → child).
    // Pipeline links (AP↔MA, MA↔TP) are emitted from the derived edge
    // model; NPC + decorative links are emitted directly because they
    // do not fit the archetype catalogue yet.

    const d3Links: D3Link[] = [];

    const isPipelineMember = (n: CanvasNode): boolean => {
      // The derived-edge loop owns all pipeline links. Anything that
      // could plausibly participate in an AP↔MA or MA↔TP edge is left
      // out of the generic mapper below to avoid double-emission.
      if (n.type === 'access-point') return true;
      if (n.type === 'target') return true;
      if (_registry.isTransitPointType(n.type)) return true;
      if (_registry.get(n.type)?.dropMode === 'edge') return true;
      return false;
    };

    // ── Generic mapper (non-pipeline, non-NPC, non-decorative) ──
    // Today this only covers anchor children like target-variant under
    // target. NPCs are handled as a separate special case below; pipeline
    // members are handled by the derived-edge loop.
    for (const n of nodes) {
      if (n.type === 'human' || n.type === 'caller') continue;
      const sh = _registry.get(n.type)?.shape;
      if ((sh === 'rect' || sh === 'diamond') && n.type !== 'target') continue;
      if (isNpcType(n.type)) continue;
      // `remote-channel` is a synth-only external actor whose link to
      // its parent `remote-gateway` is emitted as a request/response
      // pair below — skip the generic mapper to avoid double-emission.
      if (n.type === 'remote-channel') continue;
      if (isPipelineMember(n)) continue;
      if (!n.parentId) continue;
      d3Links.push({
        source: n.parentId,
        target: n.id,
        type: 'primary',
        droppable: true,
        direction: 'request',
      });
    }

    // ── NPC links ──
    // NPCs respect connectionDirection. Connections to a Transit Point's
    // external NPC are NOT droppable and render as a single double-headed
    // link. Connections from the Managed Agent keep dual-arrow treatment.
    for (const n of nodes) {
      if (!isNpcType(n.type) || !n.parentId) continue;
      const dir = n.connectionDirection || 'outbound';
      const parentNode = nodes.find(p => p.id === n.parentId);
      const isTpParent = !!parentNode && _registry.isTransitPointType(parentNode.type);
      if (isTpParent) {
        d3Links.push(
          dir === 'inbound'
            ? {
                source: n.id,
                target: n.parentId,
                type: 'primary',
                droppable: false,
                bidirectional: true,
              }
            : {
                source: n.parentId,
                target: n.id,
                type: 'primary',
                droppable: false,
                bidirectional: true,
              }
        );
        continue;
      }
      const isOutboundDroppable =
        !!parentNode && dir === 'outbound' && parentNode.type === 'target';
      d3Links.push(
        dir === 'inbound'
          ? {
              source: n.id,
              target: n.parentId,
              type: 'primary',
              droppable: false,
              direction: 'request',
            }
          : {
              source: n.parentId,
              target: n.id,
              type: 'primary',
              droppable: isOutboundDroppable,
              direction: 'request',
            }
      );
    }

    // ── Synthesised fabric:// chain: hop → remote-gateway ──
    // `synthesizeFabricCanvasNodes` inserts a `local-gateway-hop`
    // (parented on the target/TP) plus a `remote-gateway` (parented
    // on the hop) whenever a target/TP has a `fabric://` endpoint.
    // The generic mapper above skips these (rect shape, non-target,
    // non-NPC), and the NPC loop only handles `isNpcType`, so we'd
    // otherwise render the remote-gateway as a free-floating glyph
    // with no visible connection back to the hop. Draw the missing
    // decorative link here, bidirectional + non-droppable like the
    // TP↔NPC link it visually mirrors.
    //
    // Transit Point fabric routes collapse the hop, so the
    // remote-gateway is parented directly on the TP. There we emit the
    // request/response arrow pair (the TP → remote-gateway hop is the
    // actual boundary crossing), mirroring the TP → hop pair that the
    // un-collapsed Target route still draws.
    for (const n of nodes) {
      if (n.type !== 'remote-gateway' || !n.parentId) continue;
      const parentNode = nodes.find(p => p.id === n.parentId);
      if (!parentNode) continue;
      if (parentNode.type === 'local-gateway-hop') {
        d3Links.push({
          source: parentNode.id,
          target: n.id,
          type: 'primary',
          droppable: false,
          bidirectional: true,
        });
      } else if (_registry.isTransitPointType(parentNode.type)) {
        d3Links.push({
          source: parentNode.id,
          target: n.id,
          type: 'primary',
          droppable: false,
          direction: 'request',
        });
        d3Links.push({
          source: n.id,
          target: parentNode.id,
          type: 'primary',
          droppable: false,
          direction: 'response',
        });
      }
    }

    // ── Remote-channel external actor ──
    // The synth chain extends one more hop to a `remote-channel`
    // external actor parented on the `remote-gateway`. Render a
    // single centred double-headed link (same pattern as TP↔NPC) so
    // the connection reads as a peer relationship and the arrow
    // never overlaps the channel's text label.
    for (const n of nodes) {
      if (n.type !== 'remote-channel' || !n.parentId) continue;
      const parentNode = nodes.find(p => p.id === n.parentId);
      if (!parentNode || parentNode.type !== 'remote-gateway') continue;
      d3Links.push({
        source: parentNode.id,
        target: n.id,
        type: 'primary',
        droppable: false,
        bidirectional: true,
      });
    }

    // ── MA / TP → local-gateway-hop (request / response pair) ──
    // The synth hop sits on the surface perimeter outward of the
    // target/TP; without explicit edges the MA→hop arrow is missing
    // entirely (the generic mapper skips `rect`-shaped non-target
    // children). Emit the same request/response pair the AP↔MA and
    // MA↔TP pipelines use so the canvas reads consistently.
    //
    // These arrows ARE the `ma-external` edge rendering for a fabric://
    // (G2G) target, so they must be droppable: `deriveEdges` builds a
    // valid `ma-external` edge MA→hop, and the drop-target highlighter
    // lights the arrow green off that edge. Leaving the link
    // non-droppable made the drop hit-test (`findNearestEdge`, which
    // skips `droppable === false`) refuse every `ma-external` element
    // (MCP Tool Gating, external identity, networking, …) even though
    // the arrow highlighted as valid.
    for (const n of nodes) {
      if (n.type !== 'local-gateway-hop' || !n.parentId) continue;
      const parentNode = nodes.find(p => p.id === n.parentId);
      if (!parentNode) continue;
      d3Links.push({
        source: parentNode.id,
        target: n.id,
        type: 'primary',
        droppable: true,
        direction: 'request',
      });
      d3Links.push({
        source: n.id,
        target: parentNode.id,
        type: 'primary',
        droppable: true,
        direction: 'response',
      });
    }

    const apNode = d3Nodes.find(n => n.type === 'access-point' && !n.parentId);

    // ── Pipeline edges from the derived model ──
    // For each derived edge + each declared direction, build a chain
    // through slot occupants in declared `slot.order`, then within
    // each catch-all slot order occupants by their projected position
    // along the canonical edge so the chain follows what the user
    // sees on screen (instead of locking in drop-time array order).
    const derivedEdges = deriveEdges(nodes);
    // `nodeById` doubles as the live d3-node lookup used by both the
    // chain emitter (for projection) and the placement loop below.
    const nodeById = new Map(d3Nodes.map(n => [n.id, n] as const));
    const emitChainForEdge = (edge: DerivedEdge, direction: SlotDirection) => {
      const archetype = getArchetype(edge.archetype);
      if (!archetype || !archetype.directions.includes(direction)) return;
      // Canonical chain endpoints: request flows source→target; response
      // is the mirror image. We project each occupant's saved position
      // onto this line to derive `t`, then sort by `t` within each slot.
      const chainSrc = direction === 'request' ? edge.endpoints.source : edge.endpoints.target;
      const chainTgt = direction === 'request' ? edge.endpoints.target : edge.endpoints.source;
      const srcN = nodes.find(n => n.id === chainSrc);
      const tgtN = nodes.find(n => n.id === chainTgt);
      const srcPos = srcN?.position
        ? { x: srcN.position.x + surfaceX, y: srcN.position.y + surfaceY }
        : nodeById.get(chainSrc);
      const tgtPos = tgtN?.position
        ? { x: tgtN.position.x + surfaceX, y: tgtN.position.y + surfaceY }
        : nodeById.get(chainTgt);
      const projectT = (occId: string): number => {
        const cn = nodes.find(n => n.id === occId);
        const occAbs = cn?.position
          ? { x: cn.position.x + surfaceX, y: cn.position.y + surfaceY }
          : nodeById.get(occId);
        if (!occAbs || !srcPos || !tgtPos) return 0;
        const ax = (srcPos as any).x ?? 0;
        const ay = (srcPos as any).y ?? 0;
        const bx = (tgtPos as any).x ?? 0;
        const by = (tgtPos as any).y ?? 0;
        const ldx = bx - ax;
        const ldy = by - ay;
        const llen = ldx * ldx + ldy * ldy || 1;
        const ox = (occAbs as any).x ?? 0;
        const oy = (occAbs as any).y ?? 0;
        return ((ox - ax) * ldx + (oy - ay) * ldy) / llen;
      };

      // Single canonical pipe: emit ONE link from chainSrc → chainTgt
      // regardless of how many middleware sit on it. Middleware nodes
      // are rendered as glyphs on top of this line (via `_pipe` + the
      // projected `t`), not as their own edges. This guarantees:
      //  - one continuous line with one arrowhead (no per-sub-link
      //    arrows that could reverse if a mw is dragged past an
      //    anchor)
      //  - middleware can never visually collapse a sub-link to zero
      //    length when they crowd against an anchor
      // The slot/order model below is still consulted only to compute
      // projected `t` for each middleware (used by drag clamping and
      // deterministic placement).
      const slots = archetype.slots
        .filter(s => s.direction === direction)
        .sort((a, b) => a.order - b.order);
      const occupants: string[] = [];
      for (const slot of slots) {
        const list = [...(edge.slots.get(slot.id) ?? [])];
        if (slot.cardinality === 'many') {
          list.sort((a, b) => projectT(a) - projectT(b));
        }
        for (const id of list) occupants.push(id);
      }
      // Tag the canonical link with the occupant list so hit-testing
      // and any consumer that needs the chain ordering can read it
      // without re-deriving.
      d3Links.push({
        source: chainSrc,
        target: chainTgt,
        type: 'primary',
        droppable: true,
        direction,
        occupants,
      } as D3Link);
    };

    for (const edge of derivedEdges) {
      const archetype = getArchetype(edge.archetype);
      if (!archetype) continue;
      // ma-external shares its visible target→external arrow with the
      // NPC link section below — emitting an extra chain link here
      // would draw a duplicate <line> on top of the NPC arrow and
      // contribute extra forceLink pull. Skip when no slot occupants
      // need a chain. When identity (or any future occupant) is
      // dropped, fall through so the chain renders through it.
      if (
        edge.archetype === 'ma-external' &&
        Array.from(edge.slots.values()).every(list => list.length === 0)
      ) {
        continue;
      }
      for (const dir of archetype.directions) {
        emitChainForEdge(edge, dir);
      }
    }

    // ── MA → outbound NPC: dual-arrow treatment (not yet an archetype) ──
    // The new edge model doesn't cover NPC edges yet, so the response leg
    // is synthesised here. Mirrors the request leg emitted above.
    //
    // Suppress this synthetic response when the matching ma-external
    // edge has slot occupants (e.g. an Agent Identity drop) — in that
    // case the chain emitter above already drew external→…→MA on the
    // response side and a second link would draw a parallel arrow that
    // bypasses the middleware.
    const maExternalOccupiedTargets = new Set<string>();
    for (const edge of derivedEdges) {
      if (edge.archetype !== 'ma-external') continue;
      const occupied = Array.from(edge.slots.values()).some(list => list.length > 0);
      if (occupied) maExternalOccupiedTargets.add(edge.endpoints.target);
    }
    for (const n of nodes) {
      if (!isNpcType(n.type) || !n.parentId) continue;
      const dir = n.connectionDirection || 'outbound';
      if (dir !== 'outbound') continue;
      const parentNode = nodes.find(p => p.id === n.parentId);
      if (!parentNode) continue;
      if (_registry.isTransitPointType(parentNode.type)) continue;
      if (parentNode.type !== 'target') continue;
      if (maExternalOccupiedTargets.has(n.id)) continue;
      d3Links.push({
        source: n.id,
        target: parentNode.id,
        type: 'primary',
        droppable: true,
        direction: 'response',
      });
    }

    // Add decorative flow links: Human → Caller → AP (not droppable)
    if (apNode) {
      d3Links.push(
        { source: '__human__', target: '__caller__', type: 'primary', droppable: false },
        { source: '__caller__', target: apNode.id, type: 'primary', droppable: false }
      );
    }

    d3NodesRef.current = d3Nodes;
    d3LinksRef.current = d3Links;

    // ── Deterministic placement of edge-drop middleware ──
    // For every middleware node (dropMode === 'edge'), find the
    // canonical pipeline anchors via the d3Links it participates in,
    // cache them on `n._pipe`, and place the node on the offset line
    // ONCE — using either the saved position projected onto the line
    // (so reload is exact) or the drop position projected onto the line
    // (so first placement is predictable). Persist the result back to
    // React state via onNodeMove so it survives tab switches.
    //
    // After this step, the simulation never moves these nodes (fx/fy
    // are pinned). This replaces the per-tick snap that was producing
    // drift across remounts.
    const placedEdgeMiddleware: Array<{ id: string; ax: number; ay: number }> = [];
    for (const n of d3Nodes) {
      const def = _registry.get(n.type);
      if (!def || def.dropMode !== 'edge') continue;
      // Canonical anchors come from the derived edge that owns this
      // slot occupant — NOT from the immediate link source/target. With
      // chained sub-links (`AP → mw1 → mw2 → MA`) the immediate
      // neighbours of mw2 are mw1 and MA, which would project mw2 onto
      // the mw1-MA line and create a zigzag. Using `edge.endpoints`
      // restores the AP→MA / MA→TP straight-line invariant the per-tick
      // renderer expects.
      const slotInfo = findSlotForNode(derivedEdges, n.id);
      if (!slotInfo) {
        n._pipe = undefined;
        continue;
      }
      const { edge, slot } = slotInfo;
      const lateral = lateralOffsetFor(slot.direction);
      if (lateral === 0) {
        n._pipe = undefined;
        continue;
      }
      // Stash slot direction on the node so the drag handler can
      // compute lateral offset without depending on link topology
      // (canonical pipe links don't have middleware as endpoints).
      n.direction = slot.direction;
      // Request flows source→target; response is the mirror image.
      const parentId = slot.direction === 'request' ? edge.endpoints.source : edge.endpoints.target;
      const childId = slot.direction === 'request' ? edge.endpoints.target : edge.endpoints.source;
      const parent = nodeById.get(parentId);
      const child = nodeById.get(childId);
      if (!parent || !child) {
        n._pipe = undefined;
        continue;
      }
      n._pipe = { parent, child };
      const scaledLateral = lateralOffsetFor(
        slot.direction,
        pipeAnchorRadius(parent),
        pipeAnchorRadius(child)
      );
      const px = parent.x ?? 0;
      const py = parent.y ?? 0;
      const cx = child.x ?? 0;
      const cy = child.y ?? 0;
      const ldx = cx - px;
      const ldy = cy - py;
      const llen = Math.sqrt(ldx * ldx + ldy * ldy) || 1;
      const ux = ldx / llen;
      const uy = ldy / llen;
      const nx = -uy;
      const ny = ux;
      // Source position used to derive `t` (parameter along the
      // pipeline). Priority order: persisted `n.position` from the
      // CanvasNode (already seeded into savedPositions and applied to
      // n.x/n.y), then live n.x/n.y, then the drop-time hint, then a
      // slot-ordinal distribution derived from the canonical edge
      // model (same algorithm `computeAutoLayout` uses) so multiple
      // newly-placed occupants on the same pipe spread instead of
      // collapsing onto a shared midpoint. Plain midpoint is the
      // last-resort default.
      const cn = nodes.find(c => c.id === n.id);
      const haveSaved = positionsRef.current.has(n.id);
      let cur_x: number;
      let cur_y: number;
      if (haveSaved) {
        cur_x = n.fx ?? n.x ?? px;
        cur_y = n.fy ?? n.y ?? py;
      } else if (cn?.position) {
        cur_x = surfaceX + cn.position.x;
        cur_y = surfaceY + cn.position.y;
      } else if (pendingDropPos.current) {
        const drop = pendingDropPos.current;
        cur_x = drop.x;
        cur_y = drop.y;
      } else {
        // Distribute unsaved occupants along the pipe by their slot
        // ordinal so caller-auth + identity-inbound (or any pair of
        // distinct-slot middleware applied via a template) don't all
        // collapse onto t=0.5. The ordinal list mirrors
        // `computeAutoLayout`'s ordering: archetype.slots filtered by
        // this direction, in `slot.order`, with `edge.slots`
        // occupants concatenated in insertion order within each slot.
        const arch = getArchetype(edge.archetype);
        const ordered: string[] = [];
        if (arch) {
          const slotsInDir = arch.slots
            .filter(s => s.direction === slot.direction)
            .sort((a, b) => a.order - b.order);
          for (const s of slotsInDir) {
            const list = edge.slots.get(s.id) ?? [];
            for (const id of list) ordered.push(id);
          }
        }
        const idx = ordered.indexOf(n.id);
        const tOrd = idx >= 0 && ordered.length > 0 ? (idx + 1) / (ordered.length + 1) : 0.5;
        cur_x = px + ux * llen * tOrd;
        cur_y = py + uy * llen * tOrd;
      }
      const t = ((cur_x - px) * ux + (cur_y - py) * uy) / llen;
      const tClamped = Math.max(0.05, Math.min(0.95, t));
      n._pipeT = tClamped;
      const baseX = px + ux * llen * tClamped;
      const baseY = py + uy * llen * tClamped;
      const snapX = baseX + nx * scaledLateral;
      const snapY = baseY + ny * scaledLateral;
      n.x = snapX;
      n.y = snapY;
      n.fx = snapX;
      n.fy = snapY;
      // Update positionsRef so subsequent rebuilds (within the same
      // mount) restore from here without going through the drop-pos
      // fallback again.
      positionsRef.current.set(n.id, {
        dx: snapX - surfaceX,
        dy: snapY - surfaceY,
        fdx: snapX - surfaceX,
        fdy: snapY - surfaceY,
      });
      // Persist to React state if either we placed from drop hint or
      // the projection moved the node (so CanvasNode.position survives
      // tab switches). Only fire when the React state is stale to avoid
      // a render storm.
      const newDx = snapX - surfaceX;
      const newDy = snapY - surfaceY;
      const havePos = !!cn?.position;
      const sameAsState =
        havePos &&
        Math.abs(cn!.position!.x - newDx) < 0.5 &&
        Math.abs(cn!.position!.y - newDy) < 0.5;
      if (!sameAsState) {
        placedEdgeMiddleware.push({ id: n.id, ax: newDx, ay: newDy });
      }
    }
    // Defer onNodeMove calls until after the current render pass so
    // React doesn't see a state update during render. These are
    // SYSTEM-driven position re-syncs (edge-middleware projection
    // adjusting slot positions after a layout reflow) — route them
    // through the silent setter so they never appear as their own
    // undo step.
    const sysEmit = onSystemNodeMove ?? onNodeMove;
    if (placedEdgeMiddleware.length > 0 && sysEmit) {
      const moves = placedEdgeMiddleware;
      requestAnimationFrame(() => {
        for (const m of moves) sysEmit(m.id, m.ax, m.ay);
      });
    }

    // Force simulation
    const simulation = d3
      .forceSimulation<D3Node>(d3Nodes)
      .force(
        'link',
        d3
          .forceLink<D3Node, D3Link>(d3Links)
          .id(d => d.id)
          .distance(d => (d.type === 'middleware' ? 120 : 160))
          .strength(0.4)
      )
      .force('charge', d3.forceManyBody().strength(-500))
      .force('x', d3.forceX<D3Node>(d => width * (NODE_X_WEIGHT[d.type] || 0.5)).strength(0.15))
      .force('y', d3.forceY<D3Node>(centerY).strength(0.1))
      .force(
        'collision',
        d3.forceCollide<D3Node>().radius(d => d.radius + 20)
      )
      .alphaDecay(0.04);

    simulationRef.current = simulation;

    // If most nodes already have positions, start with low energy so they don't scatter
    const existingCount = d3Nodes.filter(n => savedPositions.has(n.id)).length;
    if (existingCount > 1) {
      simulation.alpha(0.15); // Gentle settle for new node only
    }

    // Draw links
    const linkSelection = g
      .append('g')
      .attr('class', 'links')
      .selectAll<SVGLineElement, D3Link>('line')
      .data(d3Links)
      .enter()
      .append('line')
      .attr('class', 'link')
      .attr('stroke-width', d => (d.type === 'middleware' ? 1.5 : 2))
      .attr('stroke', d => {
        if (d.type === 'middleware') {
          const tgt = d3Nodes.find(
            n => n.id === (typeof d.target === 'string' ? d.target : (d.target as D3Node).id)
          );
          return tgt ? NODE_COLORS[tgt.type] : '#adb5bd';
        }
        const tgt = d3Nodes.find(
          n => n.id === (typeof d.target === 'string' ? d.target : (d.target as D3Node).id)
        );
        return tgt ? NODE_COLORS[tgt.type] : '#adb5bd';
      })
      .attr('stroke-opacity', d => (d.type === 'middleware' ? 0.5 : 0.5))
      .attr('stroke-dasharray', '0')
      .attr('marker-end', 'url(#arrow)')
      .attr('marker-start', d => (d.bidirectional ? 'url(#arrow-start)' : null));

    // Credential-delegation redrive loop. Mirrors the Jury->LLM retry
    // arc in the LLM-pipe flow visualisation: a curved dotted arrow
    // from each credential-delegation node back to the Managed Agent
    // (`target`), depicting that credentials live in the Gateway and
    // are re-injected into traffic heading to the MA. Drawn underneath
    // the pipeline (curve dips below) and styled in light grey so it
    // reads as a secondary annotation.
    const redriveGroup = g.append('g').attr('class', 'cd-redrive');
    const redriveSelection = redriveGroup
      .selectAll<SVGPathElement, D3Node>('path')
      .data(d3Nodes.filter(n => n.type === 'credential-delegation'))
      .enter()
      .append('path')
      .attr('class', 'cd-redrive-arc')
      .attr('fill', 'none')
      .attr('stroke', '#adb5bd')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.7)
      .attr('stroke-dasharray', '4,3')
      .attr('marker-end', 'url(#cd-redrive-arrow)')
      .style('pointer-events', 'none');
    const redriveLabelSelection = redriveGroup
      .selectAll<SVGTextElement, D3Node>('text')
      .data(d3Nodes.filter(n => n.type === 'credential-delegation'))
      .enter()
      .append('text')
      .attr('class', 'cd-redrive-label')
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('font-weight', '600')
      .attr('fill', '#6c757d')
      .style('pointer-events', 'none')
      .text('credential callback');

    // Draw nodes
    const nodeSelection = g
      .append('g')
      .attr('class', 'nodes')
      .selectAll<SVGGElement, D3Node>('g')
      .data(d3Nodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('data-node-id', d => d.id)
      .attr('data-node-type', d => d.type)
      .style('cursor', d => {
        if (d.type === 'surface') return 'pointer';
        return 'pointer';
      });

    // Gesture state shared between the d3.drag handlers (set up later) and
    // the .on('click') handler below. d3-drag uses pointer capture so the
    // browser may not deliver a native click event after a node mousedown;
    // when drag-end detects no movement it sets `clickGesture.suppress=true`
    // and dispatches the activation directly, and the click handler then
    // ignores any duplicate native click that does arrive.
    const clickGesture = { suppress: false };

    // Routes a node activation (real click or drag-end-as-click) into the
    // multi-selection / sidebar pipeline.
    const handleNodeActivation = (d: D3Node, opts: { shiftKey: boolean }) => {
      if (d.type === 'surface') {
        if (selectedNodesRef.current.size > 0) {
          selectedNodesRef.current.clear();
          svg.selectAll('.node').classed('lasso-selected', false);
          emitMultiSelection();
        }
        onNodeClick('__surface__');
        return;
      }
      if (opts.shiftKey) {
        if (selectedNodesRef.current.size === 0) {
          const seed = selectedNodeIdRef.current;
          if (seed && seed !== d.id) selectedNodesRef.current.add(seed);
        }
        if (selectedNodesRef.current.has(d.id)) {
          selectedNodesRef.current.delete(d.id);
        } else {
          selectedNodesRef.current.add(d.id);
        }
        svg
          .selectAll<SVGGElement, D3Node>('.node')
          .classed('lasso-selected', dn => selectedNodesRef.current.has(dn.id));
        emitMultiSelection();
        return;
      }
      if (selectedNodesRef.current.size > 0) {
        selectedNodesRef.current.clear();
        svg.selectAll('.node').classed('lasso-selected', false);
        emitMultiSelection();
      }
      onNodeClick(d.id);
    };

    nodeSelection.on('click', (event, d) => {
      event.stopPropagation();
      if (clickGesture.suppress) {
        clickGesture.suppress = false;
        return;
      }
      handleNodeActivation(d, { shiftKey: !!(event as MouseEvent).shiftKey });
    });

    // ── Surface node: dotted-line rectangle (resizable) ──
    const sW = surfaceSizeRef.current.w;
    const sH = surfaceSizeRef.current.h;
    const sHalfW = sW / 2;
    const sHalfH = sH / 2;

    const surfaceGroup = nodeSelection.filter(d => d.type === 'surface');

    surfaceGroup
      .append('rect')
      .attr('class', 'main-rect')
      .attr('x', -sHalfW)
      .attr('y', -sHalfH)
      .attr('width', sW)
      .attr('height', sH)
      .attr('rx', 14)
      .attr('ry', 14)
      .attr('fill', SURFACE_FILL)
      .attr('stroke', 'rgba(78, 115, 223, 0.28)')
      .attr('stroke-width', 1)
      .attr('filter', 'url(#node-shadow)');

    // ── Surface resize handles ────────────────────────────────────────
    // Eight invisible hit zones around the perimeter (4 edges + 4
    // corners). Each shows the matching resize cursor on hover and
    // highlights with a faint blue tint so the active region is
    // discoverable.
    //
    // Default behaviour: only the dragged edge moves, the opposite
    // edge stays fixed, and the surface center translates by half the
    // delta along the resized axis (so contents appear to stay put
    // relative to the un-dragged edges).
    //
    // Hold Shift while dragging: legacy symmetric mode — both opposite
    // edges expand equally about the surface center, which stays put.
    type ResizeEdge = 'n' | 's' | 'e' | 'w' | 'ne' | 'nw' | 'se' | 'sw';
    interface ResizeHandleSpec {
      edge: ResizeEdge;
      cursor: string;
      rect: (hw: number, hh: number) => { x: number; y: number; w: number; h: number };
    }
    const HANDLE_THICKNESS = 14;
    const CORNER_SIZE = 18;
    const MIN_W = 200;
    const MIN_H = 160;
    const HANDLE_SPECS: ResizeHandleSpec[] = [
      {
        edge: 'n',
        cursor: 'ns-resize',
        rect: (hw, hh) => ({
          x: -hw + CORNER_SIZE,
          y: -hh - HANDLE_THICKNESS / 2,
          w: Math.max(0, 2 * (hw - CORNER_SIZE)),
          h: HANDLE_THICKNESS,
        }),
      },
      {
        edge: 's',
        cursor: 'ns-resize',
        rect: (hw, hh) => ({
          x: -hw + CORNER_SIZE,
          y: hh - HANDLE_THICKNESS / 2,
          w: Math.max(0, 2 * (hw - CORNER_SIZE)),
          h: HANDLE_THICKNESS,
        }),
      },
      {
        edge: 'w',
        cursor: 'ew-resize',
        rect: (hw, hh) => ({
          x: -hw - HANDLE_THICKNESS / 2,
          y: -hh + CORNER_SIZE,
          w: HANDLE_THICKNESS,
          h: Math.max(0, 2 * (hh - CORNER_SIZE)),
        }),
      },
      {
        edge: 'e',
        cursor: 'ew-resize',
        rect: (hw, hh) => ({
          x: hw - HANDLE_THICKNESS / 2,
          y: -hh + CORNER_SIZE,
          w: HANDLE_THICKNESS,
          h: Math.max(0, 2 * (hh - CORNER_SIZE)),
        }),
      },
      {
        edge: 'nw',
        cursor: 'nwse-resize',
        rect: (hw, hh) => ({
          x: -hw - HANDLE_THICKNESS / 2,
          y: -hh - HANDLE_THICKNESS / 2,
          w: CORNER_SIZE + HANDLE_THICKNESS / 2,
          h: CORNER_SIZE + HANDLE_THICKNESS / 2,
        }),
      },
      {
        edge: 'ne',
        cursor: 'nesw-resize',
        rect: (hw, hh) => ({
          x: hw - CORNER_SIZE,
          y: -hh - HANDLE_THICKNESS / 2,
          w: CORNER_SIZE + HANDLE_THICKNESS / 2,
          h: CORNER_SIZE + HANDLE_THICKNESS / 2,
        }),
      },
      {
        edge: 'sw',
        cursor: 'nesw-resize',
        rect: (hw, hh) => ({
          x: -hw - HANDLE_THICKNESS / 2,
          y: hh - CORNER_SIZE,
          w: CORNER_SIZE + HANDLE_THICKNESS / 2,
          h: CORNER_SIZE + HANDLE_THICKNESS / 2,
        }),
      },
      {
        edge: 'se',
        cursor: 'nwse-resize',
        rect: (hw, hh) => ({
          x: hw - CORNER_SIZE,
          y: hh - CORNER_SIZE,
          w: CORNER_SIZE + HANDLE_THICKNESS / 2,
          h: CORNER_SIZE + HANDLE_THICKNESS / 2,
        }),
      },
    ];

    const repositionResizeHandles = () => {
      const hw = surfaceSizeRef.current.w / 2;
      const hh = surfaceSizeRef.current.h / 2;
      surfaceGroup
        .selectAll<SVGRectElement, ResizeHandleSpec>('.surface-resize-handle')
        .each(function (d) {
          const r = d.rect(hw, hh);
          d3.select(this).attr('x', r.x).attr('y', r.y).attr('width', r.w).attr('height', r.h);
        });
    };

    // Shared apply step. Updates every visual + simulation-state piece
    // that depends on surface dimensions or center: the main rect, the
    // 8 handles, surface labels, the group transform, edge-constrained
    // nodes (with cascade to their chained children), and surface-wide
    // node clamping.
    const applySurfaceSize = (newW: number, newH: number, newSx: number, newSy: number) => {
      const newHalfW = newW / 2;
      const newHalfH = newH / 2;
      const surfNode = d3Nodes.find(n => n.id === '__surface__');
      if (!surfNode) return;
      const oldSx = surfNode.x || 0;
      const oldSy = surfNode.y || 0;

      surfaceSizeRef.current = { w: newW, h: newH };
      if (externalSurfaceSizeRef) {
        externalSurfaceSizeRef.current = { w: newW, h: newH };
      }
      surfNode.x = newSx;
      surfNode.y = newSy;
      surfNode.fx = newSx;
      surfNode.fy = newSy;

      surfaceGroup
        .select('.main-rect')
        .attr('x', -newHalfW)
        .attr('y', -newHalfH)
        .attr('width', newW)
        .attr('height', newH);
      repositionResizeHandles();
      surfaceGroup.select('.node-label').attr('dy', newHalfH + 16);
      surfaceGroup.select('.surface-sublabel').attr('dy', newHalfH + 30);

      if (newSx !== oldSx || newSy !== oldSy) {
        // Translate the surface group immediately so visual feedback
        // doesn't lag the next simulation tick.
        surfaceGroup.attr('transform', `translate(${newSx}, ${newSy})`);
      }

      // Re-project edge-constrained nodes (AP, TP) onto the new
      // perimeter and cascade movement to chained interior nodes
      // (target, middleware, etc.) reachable via links.
      const newR = getEdgeNodeRadius(newW);
      d3Nodes.forEach(n => {
        if (!EDGE_CONSTRAINED_TYPES.includes(n.type)) return;
        const oldX = n.x || newSx;
        const oldY = n.y || newSy;
        const pt = constrainToSurfaceEdge(oldX, oldY, newSx, newSy, newHalfW, newHalfH);
        const dx = pt.x - oldX;
        const dy = pt.y - oldY;
        n.x = pt.x;
        n.y = pt.y;
        n.fx = pt.x;
        n.fy = pt.y;
        const g = svg.select(`[data-node-id="${n.id}"]`) as d3.Selection<
          Element,
          unknown,
          null,
          undefined
        >;
        applyNodeGeometry(g, n, newR);
        if (dx === 0 && dy === 0) return;
        const visited = new Set<string>([n.id, '__surface__']);
        const targetDn = d3Nodes.find(nd => nd.type === 'target');
        if (targetDn) visited.add(targetDn.id);
        d3Nodes.forEach(nd => {
          if (nd.id !== n.id && EDGE_CONSTRAINED_TYPES.includes(nd.type)) {
            visited.add(nd.id);
          }
        });
        const queue = [n.id];
        while (queue.length > 0) {
          const current = queue.shift()!;
          for (const link of d3Links) {
            const srcId =
              typeof link.source === 'string' ? link.source : (link.source as D3Node).id;
            const tgtId =
              typeof link.target === 'string' ? link.target : (link.target as D3Node).id;
            let neighbor: string | null = null;
            if (srcId === current && !visited.has(tgtId)) neighbor = tgtId;
            if (tgtId === current && !visited.has(srcId)) neighbor = srcId;
            if (neighbor) {
              visited.add(neighbor);
              const nd = d3Nodes.find(x => x.id === neighbor);
              if (nd) {
                nd.x = (nd.x || 0) + dx;
                nd.y = (nd.y || 0) + dy;
                nd.fx = nd.x;
                nd.fy = nd.y;
                queue.push(neighbor);
              }
            }
          }
        }
      });

      // Surface-wide nodes (e.g. Agent Identity): clamp to new bounds
      // about the new center, preserving user-set offsets where
      // possible.
      d3Nodes.forEach(n => {
        if (!SURFACE_WIDE_TYPES.includes(n.type)) return;
        const r = n.radius || 24;
        const padW = newHalfW - r - 6;
        const padH = newHalfH - r - 6;
        const curDx = (n.x || newSx) - oldSx;
        const curDy = (n.y || newSy) - oldSy;
        const sdx = Math.max(-padW, Math.min(padW, curDx));
        const sdy = Math.max(-padH, Math.min(padH, curDy));
        const nx = newSx + sdx;
        const ny = newSy + sdy;
        n.x = nx;
        n.y = ny;
        n.fx = nx;
        n.fy = ny;
        positionsRef.current.set(n.id, { dx: sdx, dy: sdy, fdx: sdx, fdy: sdy });
        // Note: do NOT call onNodeMove here. This function runs every
        // tick of the live drag and on undo-driven re-application; the
        // resize end-handler batches all moves (edge + surface-wide)
        // into a single onSurfaceResize commit so the gesture is one
        // undo step.
      });

      simulation.alpha(0.01).restart();
    };
    applySurfaceSizeRef.current = applySurfaceSize;

    // Drag start state, captured per drag and shared by all 8 handles.
    let resizeStartHalfW = sHalfW;
    let resizeStartHalfH = sHalfH;
    let resizeStartSx = 0;
    let resizeStartSy = 0;
    let resizeStartEvX = 0;
    let resizeStartEvY = 0;
    // Per-node snapshot of pre-resize positions so the end-handler can
    // emit a move for any node whose absolute position changed during
    // the gesture, including ones moved indirectly by the cascade
    // (e.g. external NPCs chained off an edge-constrained AP).
    const resizeStartPositions = new Map<string, { x: number; y: number }>();
    // AABB (in canvas coords) of every `containedInSurface` node,
    // expanded by node radius + a small visual pad. Captured at drag
    // start so the surface cannot be shrunk past these nodes — the
    // resize stops as if hitting a wall instead of cropping them.
    const RESIZE_NODE_PADDING = 40;
    let containedAabb: { minX: number; maxX: number; minY: number; maxY: number } | null = null;
    // Per-axis bounds contributed by edge-constrained nodes (AP, TP, RGW,
    // etc.). An edge-bound node only restricts the surface dimension
    // *perpendicular* to the edge it lives on: a node on the north/south
    // edge constrains how narrow the surface can get (its x position must
    // stay inside the width); a node on the east/west edge constrains how
    // short it can get (its y position must stay inside the height).
    let edgeXBounds: { minX: number; maxX: number } | null = null;
    let edgeYBounds: { minY: number; maxY: number } | null = null;

    const computeNewSize = (
      edge: ResizeEdge,
      evX: number,
      evY: number,
      shift: boolean
    ): { newW: number; newH: number; newSx: number; newSy: number } => {
      const dx = evX - resizeStartEvX;
      const dy = evY - resizeStartEvY;
      const east = edge.includes('e');
      const west = edge.includes('w');
      const south = edge.includes('s');
      const north = edge.includes('n');
      const dWReq = (east ? dx : 0) + (west ? -dx : 0);
      const dHReq = (south ? dy : 0) + (north ? -dy : 0);
      const startW = resizeStartHalfW * 2;
      const startH = resizeStartHalfH * 2;
      // Effective minimums. The hard floor (MIN_W / MIN_H) is bumped
      // up to whatever is needed to keep every `containedInSurface`
      // node inside the rectangle after this resize. The required
      // width/height depends on which edges are anchored — shrinking
      // from the east needs enough width to still reach the rightmost
      // contained node, etc.
      let effMinW = MIN_W;
      let effMinH = MIN_H;
      if (containedAabb) {
        if (shift) {
          // Symmetric mode: centre stays put, so both half-extents
          // must reach the AABB on their own.
          effMinW = Math.max(
            effMinW,
            2 * Math.max(resizeStartSx - containedAabb.minX, containedAabb.maxX - resizeStartSx)
          );
          effMinH = Math.max(
            effMinH,
            2 * Math.max(resizeStartSy - containedAabb.minY, containedAabb.maxY - resizeStartSy)
          );
        } else {
          // Edge-anchored mode: the opposite edge stays fixed at its
          // pre-resize coordinate, so the width/height must be enough
          // to span from that fixed edge to the far side of the AABB.
          const leftFixed = resizeStartSx - resizeStartHalfW;
          const rightFixed = resizeStartSx + resizeStartHalfW;
          const topFixed = resizeStartSy - resizeStartHalfH;
          const bottomFixed = resizeStartSy + resizeStartHalfH;
          if (east) effMinW = Math.max(effMinW, containedAabb.maxX - leftFixed);
          if (west) effMinW = Math.max(effMinW, rightFixed - containedAabb.minX);
          if (south) effMinH = Math.max(effMinH, containedAabb.maxY - topFixed);
          if (north) effMinH = Math.max(effMinH, bottomFixed - containedAabb.minY);
        }
      }
      // Edge-constrained nodes (perpendicular axis only). Without this
      // the surface can be squashed so far that AP/TP/RGW nodes end up
      // outside the visible rectangle (they get re-snapped on drag-end
      // but the surface itself has already moved past them).
      if (shift) {
        if (edgeXBounds) {
          effMinW = Math.max(
            effMinW,
            2 * Math.max(resizeStartSx - edgeXBounds.minX, edgeXBounds.maxX - resizeStartSx)
          );
        }
        if (edgeYBounds) {
          effMinH = Math.max(
            effMinH,
            2 * Math.max(resizeStartSy - edgeYBounds.minY, edgeYBounds.maxY - resizeStartSy)
          );
        }
      } else {
        const leftFixed = resizeStartSx - resizeStartHalfW;
        const rightFixed = resizeStartSx + resizeStartHalfW;
        const topFixed = resizeStartSy - resizeStartHalfH;
        const bottomFixed = resizeStartSy + resizeStartHalfH;
        if (edgeXBounds) {
          if (east) effMinW = Math.max(effMinW, edgeXBounds.maxX - leftFixed);
          if (west) effMinW = Math.max(effMinW, rightFixed - edgeXBounds.minX);
        }
        if (edgeYBounds) {
          if (south) effMinH = Math.max(effMinH, edgeYBounds.maxY - topFixed);
          if (north) effMinH = Math.max(effMinH, bottomFixed - edgeYBounds.minY);
        }
      }
      let newW: number;
      let newH: number;
      let dCx = 0;
      let dCy = 0;
      if (shift) {
        // Center-anchored: opposite edge expands equally; center stays.
        newW = Math.max(effMinW, startW + 2 * dWReq);
        newH = Math.max(effMinH, startH + 2 * dHReq);
      } else {
        // Edge-anchored: opposite edge stays fixed; center translates
        // by half the actual size delta (post-clamp).
        newW = Math.max(effMinW, startW + dWReq);
        newH = Math.max(effMinH, startH + dHReq);
        const actualDW = newW - startW;
        const actualDH = newH - startH;
        dCx = east ? actualDW / 2 : west ? -actualDW / 2 : 0;
        dCy = south ? actualDH / 2 : north ? -actualDH / 2 : 0;
      }
      return { newW, newH, newSx: resizeStartSx + dCx, newSy: resizeStartSy + dCy };
    };

    HANDLE_SPECS.forEach(spec => {
      const initial = spec.rect(sHalfW, sHalfH);
      surfaceGroup
        .append('rect')
        .datum(spec)
        .attr('class', 'surface-resize-handle')
        .attr('x', initial.x)
        .attr('y', initial.y)
        .attr('width', initial.w)
        .attr('height', initial.h)
        .attr('fill', 'rgba(78, 115, 223, 0)')
        .attr('cursor', spec.cursor)
        .call(
          d3
            .drag<SVGRectElement, ResizeHandleSpec>()
            // Pin coordinates to the SVG so they don't drift when the
            // surface group itself translates mid-drag (edge-anchored
            // resize moves the surface centre, which would otherwise
            // shift the d3.drag local coords away from the cursor).
            .container(() => svgRef.current as any)
            .on('start', function (event) {
              event.sourceEvent.stopPropagation();
              const surfNode = d3Nodes.find(n => n.id === '__surface__');
              resizeStartHalfW = surfaceSizeRef.current.w / 2;
              resizeStartHalfH = surfaceSizeRef.current.h / 2;
              resizeStartSx = surfNode?.x ?? 0;
              resizeStartSy = surfNode?.y ?? 0;
              resizeStartEvX = event.x;
              resizeStartEvY = event.y;
              // Snapshot every node's position so the end-handler can
              // detect anything cascaded by `applySurfaceSize` (incl.
              // NPCs and other interior nodes pulled along by the
              // chained-link cascade) and persist their new positions.
              resizeStartPositions.clear();
              d3Nodes.forEach(n => {
                if (n.id === '__surface__') return;
                resizeStartPositions.set(n.id, { x: n.x ?? 0, y: n.y ?? 0 });
              });
              // Build the contained-node AABB so `computeNewSize` can
              // refuse to shrink the surface past any contained node.
              containedAabb = null;
              edgeXBounds = null;
              edgeYBounds = null;
              let minX = Infinity;
              let maxX = -Infinity;
              let minY = Infinity;
              let maxY = -Infinity;
              let any = false;
              // Per-axis trackers for edge-constrained nodes.
              let exMin = Infinity;
              let exMax = -Infinity;
              let eyMin = Infinity;
              let eyMax = -Infinity;
              let anyEdgeX = false;
              let anyEdgeY = false;
              d3Nodes.forEach(n => {
                if (n.id === '__surface__') return;
                // Synthetic external endpoints (caller, human, NPC
                // outbound) live OUTSIDE the surface rectangle by
                // design — never let them constrain the resize.
                if (n.id.startsWith('__')) return;
                // External NPC endpoints attached to a TP live OUTSIDE
                // the surface (the canonical MA-NPC is already filtered
                // by the `__` prefix check above). If they were allowed
                // to contribute to `containedAabb` the surface would
                // snap to engulf them on the first resize click.
                if (n.type === 'npc-endpoint') return;
                // Surface-wide config nodes auto-arrange inside the
                // surface via applySurfaceSize, so they don't bound it.
                if (SURFACE_WIDE_TYPES.includes(n.type)) return;
                const nx = n.x ?? 0;
                const ny = n.y ?? 0;
                const r = (n.radius ?? 24) + RESIZE_NODE_PADDING;
                if (EDGE_CONSTRAINED_TYPES.includes(n.type)) {
                  // AP / TP — centre is ON one of the four edges, so
                  // they only restrict the dimension *parallel* to
                  // that edge (their radius, NOT with the interior
                  // padding — anything extra would force the surface
                  // to grow on every click). Decide which edge by
                  // drag-start perpendicular distance.
                  const dx = nx - resizeStartSx;
                  const dy = ny - resizeStartSy;
                  const distToVertEdge = Math.abs(resizeStartHalfW - Math.abs(dx));
                  const distToHorizEdge = Math.abs(resizeStartHalfH - Math.abs(dy));
                  const onHorizontalEdge = distToHorizEdge <= distToVertEdge;
                  const edgeR = n.radius ?? 24;
                  if (onHorizontalEdge) {
                    exMin = Math.min(exMin, nx - edgeR);
                    exMax = Math.max(exMax, nx + edgeR);
                    anyEdgeX = true;
                  } else {
                    eyMin = Math.min(eyMin, ny - edgeR);
                    eyMax = Math.max(eyMax, ny + edgeR);
                    anyEdgeY = true;
                  }
                  return;
                }
                // Everything else the user placed (target/MA plus all
                // middleware that sit on pipes — caller-auth,
                // identity, credential-delegation, rate-limit, policy,
                // networking, payment, custom-metadata,
                // extension-rules, …) must stay fully inside the
                // surface rectangle on both axes.
                minX = Math.min(minX, nx - r);
                maxX = Math.max(maxX, nx + r);
                minY = Math.min(minY, ny - r);
                maxY = Math.max(maxY, ny + r);
                any = true;
              });
              if (any) containedAabb = { minX, maxX, minY, maxY };
              if (anyEdgeX) edgeXBounds = { minX: exMin, maxX: exMax };
              if (anyEdgeY) edgeYBounds = { minY: eyMin, maxY: eyMax };
            })
            .on('drag', function (event, d) {
              const shift = !!(event.sourceEvent as MouseEvent | undefined)?.shiftKey;
              const { newW, newH, newSx, newSy } = computeNewSize(d.edge, event.x, event.y, shift);
              applySurfaceSize(newW, newH, newSx, newSy);
            })
            .on('end', function () {
              const surfNode = d3Nodes.find(n => n.id === '__surface__');
              if (!surfNode) return;
              const sx = surfNode.x || 0;
              const sy = surfNode.y || 0;
              const nHalfW = surfaceSizeRef.current.w / 2;
              const nHalfH = surfaceSizeRef.current.h / 2;
              const newR = getEdgeNodeRadius(surfaceSizeRef.current.w);
              // Collect every node displaced by the resize so the parent
              // can persist size + positions as a single undo snapshot.
              const moves: Array<{ id: string; x: number; y: number }> = [];
              const emitted = new Set<string>();
              d3Nodes.forEach(n => {
                if (EDGE_CONSTRAINED_TYPES.includes(n.type)) {
                  const pt = constrainToSurfaceEdge(n.x || sx, n.y || sy, sx, sy, nHalfW, nHalfH);
                  n.x = pt.x;
                  n.y = pt.y;
                  n.fx = pt.x;
                  n.fy = pt.y;
                  const g = svg.select(`[data-node-id="${n.id}"]`) as d3.Selection<
                    Element,
                    unknown,
                    null,
                    undefined
                  >;
                  applyNodeGeometry(g, n, newR);
                  const dx = pt.x - sx;
                  const dy = pt.y - sy;
                  positionsRef.current.set(n.id, { dx, dy, fdx: dx, fdy: dy });
                  moves.push({ id: n.id, x: dx, y: dy });
                  emitted.add(n.id);
                } else if (SURFACE_WIDE_TYPES.includes(n.type)) {
                  // applySurfaceSize already clamped these; just
                  // forward the final offset for the commit.
                  const dx = (n.x || sx) - sx;
                  const dy = (n.y || sy) - sy;
                  moves.push({ id: n.id, x: dx, y: dy });
                  emitted.add(n.id);
                }
              });
              // Capture every other node whose offset from the surface
              // centre changed during the gesture. This MUST consider
              // both absolute movement (cascade: middleware / external
              // NPCs pulled along by edge-constrained nodes) AND surface
              // centre movement (edge-anchored resize shifts (sx, sy)
              // even when interior nodes don't move in canvas space —
              // their stored offset becomes stale and reload would
              // shift them by (newSx - oldSx, newSy - oldSy)).
              const sxShifted = sx !== resizeStartSx || sy !== resizeStartSy;
              d3Nodes.forEach(n => {
                if (n.id === '__surface__') return;
                if (emitted.has(n.id)) return;
                const start = resizeStartPositions.get(n.id);
                if (!start) return;
                const curX = n.x ?? 0;
                const curY = n.y ?? 0;
                const moved = curX !== start.x || curY !== start.y;
                if (!moved && !sxShifted) return;
                const dx = curX - sx;
                const dy = curY - sy;
                positionsRef.current.set(n.id, { dx, dy, fdx: dx, fdy: dy });
                moves.push({ id: n.id, x: dx, y: dy });
              });
              if (onSurfaceResize) {
                onSurfaceResize(
                  { w: surfaceSizeRef.current.w, h: surfaceSizeRef.current.h },
                  moves
                );
              }
              simulation.alpha(0.1).restart();
            }) as any
        );
    });

    // ── Target node (Managed Agent) and other rect-shaped nodes (Agent Identity): solid square ──
    // Diamonds are rendered as a square rotated 45° so the existing rect/resize
    // code paths still apply; the icon is appended to the parent `g` and stays
    // upright.
    nodeSelection
      .filter(d => {
        const s = _registry.get(d.type)?.shape;
        return (s === 'rect' || s === 'diamond') && d.type !== 'surface';
      })
      .append('rect')
      .attr('class', 'main-rect')
      .attr('x', d => -d.radius)
      .attr('y', d => -d.radius)
      .attr('width', d => d.radius * 2)
      .attr('height', d => d.radius * 2)
      .attr('rx', 8)
      .attr('ry', 8)
      .attr('transform', d => (_registry.get(d.type)?.shape === 'diamond' ? 'rotate(45)' : null))
      .attr('fill', d => NODE_COLORS[d.type] || NODE_COLORS['target'])
      .attr('stroke', 'white')
      .attr('stroke-width', 1.5)
      .attr('filter', 'url(#node-shadow)')
      .attr('opacity', d => (d.configured ? 1 : 0.6));

    // ── Other nodes (circles): AP, middleware, NPC, etc ──
    nodeSelection
      .filter(d => {
        const s = _registry.get(d.type)?.shape;
        return d.type !== 'surface' && s !== 'rect' && s !== 'diamond';
      })
      .append('circle')
      .attr('class', 'node-bg')
      .attr('r', d => d.radius + 1)
      .attr('fill', '#f8f9fc')
      .attr('stroke', 'none');

    nodeSelection
      .filter(d => {
        const s = _registry.get(d.type)?.shape;
        return d.type !== 'surface' && s !== 'rect' && s !== 'diamond';
      })
      .append('circle')
      .attr('class', 'main-circle')
      .attr('r', d => d.radius)
      .attr('fill', d => NODE_COLORS[d.type])
      .attr('stroke', 'white')
      .attr('stroke-width', 1.5)
      .attr('filter', 'url(#node-shadow)')
      .attr('opacity', d => (d.configured ? 1 : 0.6));

    // Unconfigured indicator (ring) with tooltip. Also rendered for nodes
    // whose feature dependencies raise an error-severity warning (e.g.
    // credential-delegation missing source auth) — those use a "marching
    // ants" animated dashed stroke instead of the solid ring.
    const featureErrorIds = computeFeatureErrorIds(nodes, protocol);
    nodeSelection
      .filter(d => {
        if (d.type === 'surface') return false;
        if (!d.configured || featureErrorIds.has(d.id)) return true;
        const cn = nodes.find(n => n.id === d.id);
        return policyDefinitionMissing(
          { type: d.type, config: cn?.config },
          surfacePolicyIdsRef.current
        );
      })
      .each(function (d) {
        const el = d3.select(this);
        const cn = nodes.find(n => n.id === d.id);
        const incompleteReason = cn
          ? getIncompleteReason(d.type, cn.config, surfacePolicyIdsRef.current)
          : null;
        const hasFeatureError = featureErrorIds.has(d.id);
        const policyMissing = policyDefinitionMissing(
          { type: d.type, config: cn?.config },
          surfacePolicyIdsRef.current
        );
        const featureReason =
          hasFeatureError && cn
            ? _registry
                .getDependencyWarnings(d.type, cn.config, buildSurfaceContext(protocol, nodes))
                .find(w => w.severity === 'error')?.message
            : null;
        const reason = incompleteReason || featureReason || null;
        const useAnts = hasFeatureError && !incompleteReason && !policyMissing;
        // A policy node with no policy selected (incomplete) or a missing
        // attached policy gets a dotted ring per the surface-builder spec.
        const dottedPolicy = d.type === 'policy' && (!d.configured || policyMissing);
        const ringClass = useAnts ? 'unconfigured-ring marching' : 'unconfigured-ring';
        const shape = _registry.get(d.type)?.shape;
        if (shape === 'rect' || shape === 'diamond') {
          const ring = el
            .append('rect')
            .attr('class', ringClass)
            .attr('x', -(d.radius + 5))
            .attr('y', -(d.radius + 5))
            .attr('width', d.radius * 2 + 10)
            .attr('height', d.radius * 2 + 10)
            .attr('rx', 10)
            .attr('ry', 10)
            .attr('transform', shape === 'diamond' ? 'rotate(45)' : null)
            .attr('fill', 'none')
            .attr('stroke', '#e74a3b')
            .attr('stroke-width', 2)
            .attr('opacity', 0.8);
          if (useAnts) ring.attr('stroke-dasharray', '6 4');
          if (reason) {
            const prefix = useAnts ? 'Missing dependency' : 'Incomplete';
            ring.append('title').text(`${prefix}: ${reason}`);
          }
        } else {
          const ring = el
            .append('circle')
            .attr('class', ringClass)
            .attr('r', d.radius + 5)
            .attr('fill', 'none')
            .attr('stroke', '#e74a3b')
            .attr('stroke-width', 2)
            .attr('opacity', 0.8)
            .attr('pointer-events', 'visible');
          if (dottedPolicy) ring.attr('stroke-dasharray', POLICY_UNCONFIGURED_DASH);
          else if (useAnts) ring.attr('stroke-dasharray', '6 4');
          if (reason) {
            const prefix = useAnts ? 'Missing dependency' : 'Incomplete';
            ring.append('title').text(`${prefix}: ${reason}`);
          }
        }
      });

    // Icon (all node types)
    nodeSelection
      .append('text')
      .attr('class', 'node-icon')
      .attr('font-family', '"Font Awesome 6 Free"')
      .attr('font-weight', '900')
      .attr('font-size', d => {
        if (d.type === 'surface') return '0px'; // surface has no icon itself
        return `${Math.round(d.radius * getShapeKind(d.type).iconScale)}px`;
      })
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('fill', 'white')
      .attr('pointer-events', 'none')
      .text(d => {
        if (d.type === 'surface') return '';
        return NODE_ICONS[d.type] || '';
      });

    // Protocol badge (TP variants only): small pill on the right perimeter
    // showing which protocol the transit point speaks. Rendered as a sibling
    // group so the badge keeps its own font sizing independent of the icon.
    nodeSelection
      .filter(d => _registry.isTransitPointType(d.type))
      .each(function (d) {
        const proto = _registry.getProtocolForType(d.type);
        if (!proto) return;
        const text = proto.toUpperCase();
        const padX = 4;
        const charW = 5.2; // approximate width per char at 8px monospace
        const w = Math.max(18, Math.round(text.length * charW + padX * 2));
        const h = 12;
        const g = d3
          .select(this)
          .append('g')
          .attr('class', 'node-protocol-badge')
          .attr('transform', `translate(${d.radius}, 0)`)
          .attr('pointer-events', 'none');
        g.append('rect')
          .attr('x', -w / 2)
          .attr('y', -h / 2)
          .attr('width', w)
          .attr('height', h)
          .attr('rx', h / 2)
          .attr('fill', '#ffffff')
          .attr('stroke', NODE_COLORS[d.type] || '#6c757d')
          .attr('stroke-width', 1);
        g.append('text')
          .attr('text-anchor', 'middle')
          .attr('dominant-baseline', 'central')
          .attr('font-size', '8px')
          .attr('font-weight', '700')
          .attr('fill', NODE_COLORS[d.type] || '#6c757d')
          .text(text);
      });

    // Type label above nodes
    nodeSelection
      .append('text')
      .attr('class', 'node-type-label')
      .attr('dy', d => {
        if (d.type === 'surface') return -(sHalfH + 10);
        if (d.type === 'target') return -(d.radius + 10);
        return -(d.radius + 10);
      })
      .attr('text-anchor', 'middle')
      .attr('font-size', '9px')
      .attr('font-weight', '600')
      .attr('fill', '#6c757d')
      .attr('pointer-events', 'none')
      .text(d => {
        if (d.type === 'surface') return '';
        // Synth chain reuses local-gateway-hop / remote-gateway /
        // remote-channel for both the fabric:// and proxy:// flavours.
        // The d3 datum doesn't carry `config` (only label/type/coords),
        // so look up the source CanvasNode by id to read the kind tag
        // that synthesizeFabric attached. For proxy, override the
        // registry type-label so the canvas reads
        // MCP Proxy → REST API → MCP Tools instead of
        // GW → Remote GW → Remote Surface.
        const src = nodes.find(n => n.id === d.id);
        if (src?.config?.kind === 'proxy') {
          if (d.type === 'local-gateway-hop') return 'MCP Proxy';
          if (d.type === 'remote-gateway') return 'REST API';
          if (d.type === 'remote-channel') return 'MCP Tools';
        }
        return _registry.get(d.type)?.label ?? '';
      });

    // Name label below nodes
    nodeSelection
      .append('text')
      .attr('class', 'node-label')
      .attr('dy', d => {
        if (d.type === 'surface') return sHalfH + 16;
        if (d.type === 'target') return d.radius + 16;
        return d.radius + 16;
      })
      .attr('text-anchor', 'middle')
      .attr('font-size', '11px')
      .attr('font-weight', '600')
      .attr('fill', '#495057')
      .attr('pointer-events', 'none')
      .text(d => {
        if (d.type === 'surface') {
          const lbl = d.label || 'Agent Surface';
          return lbl.length > 36 ? lbl.substring(0, 34) + '…' : lbl;
        }
        if (!d.label) return '';
        return d.label.length > 32 ? d.label.substring(0, 30) + '…' : d.label;
      });

    // Incomplete reason text — rendered just under the name label so the user
    // doesn't have to click into the node to find out why the red ring is on.
    nodeSelection
      .filter(d => {
        if (d.type === 'surface') return false;
        if (!d.configured) return true;
        const cn = nodes.find(n => n.id === d.id);
        return policyDefinitionMissing(
          { type: d.type, config: cn?.config },
          surfacePolicyIdsRef.current
        );
      })
      .append('text')
      .attr('class', 'node-incomplete-reason')
      .attr('dy', d => {
        const labelOffset = d.label && d.label.length > 0 ? 30 : 16;
        return d.radius + labelOffset;
      })
      .attr('text-anchor', 'middle')
      .text(d => {
        const cn = nodes.find(n => n.id === d.id);
        const reason = cn
          ? getIncompleteReason(d.type, cn.config, surfacePolicyIdsRef.current)
          : null;
        if (!reason) return '';
        return reason.length > 38 ? reason.substring(0, 36) + '…' : reason;
      });

    // Background pill behind ALL node labels for readability against edges
    nodeSelection
      .filter(d => d.type !== 'surface')
      .each(function (d) {
        const g = d3.select(this);
        const labelEl = g.select('.node-label').node() as SVGTextElement | null;
        if (!labelEl) return;
        const bbox = labelEl.getBBox();
        if (bbox.width === 0) return; // no label text
        const padX = 4,
          padY = 2;
        g.insert('rect', '.node-label')
          .attr('class', 'label-bg')
          .attr('x', bbox.x - padX)
          .attr('y', bbox.y - padY)
          .attr('width', bbox.width + padX * 2)
          .attr('height', bbox.height + padY * 2)
          .attr('rx', 3)
          .attr('fill', 'none')
          .attr('pointer-events', 'none');
      });

    // Description label (second line below name) for NPC + actor nodes
    nodeSelection
      .filter(d => isNpcType(d.type) || d.type === 'human' || d.type === 'caller')
      .append('text')
      .attr('class', 'npc-description')
      .attr('dy', d => d.radius + 30)
      .attr('text-anchor', 'middle')
      .attr('font-size', '9px')
      .attr('fill', '#6c757d')
      .attr('pointer-events', 'none')
      .text(d => {
        const node = nodes.find(n => n.id === d.id);
        const desc = node?.description || '';
        return desc.length > 28 ? desc.substring(0, 26) + '…' : desc;
      });

    // Sublabel for surface (protocol)
    nodeSelection
      .filter(d => d.type === 'surface')
      .append('text')
      .attr('class', 'surface-sublabel')
      .attr('dy', sHalfH + 30)
      .attr('text-anchor', 'middle')
      .attr('font-size', '9px')
      .attr('fill', '#6c757d')
      .attr('pointer-events', 'none')
      .text(d => d.sublabel || '');

    // Drag behavior — edge-constrained nodes snap to surface perimeter
    const GRID_SNAP = 10; // quantised grid size when snap-to-grid applies
    let resizingNode = false; // flag to prevent parent drag during resize
    let groupDragStartPositions: Map<string, { x: number; y: number }> | null = null;
    // Drag-end-as-click detection: track whether the gesture moved beyond
    // the click threshold. See `clickGesture` (declared above) for the
    // suppression flag used to avoid double-handling when both the
    // synthetic activation and a native click fire.
    let dragMoved = false;
    let dragStartXY: { x: number; y: number } | null = null;
    const drag = d3
      .drag<SVGGElement, D3Node>()
      .clickDistance(4)
      .filter((event, d) => {
        // The surface itself is not draggable — let mousedown fall
        // through to the SVG-level d3.zoom behaviour so the user can
        // pan the canvas even when the cursor is over the surface
        // background. (Default d3.drag filter blocks ctrl/right-click
        // and 2nd+ buttons; preserve that.)
        if (d.type === 'surface') return false;
        const e = event as MouseEvent;
        return !e.ctrlKey && e.button === 0;
      })
      .on('start', (event, d) => {
        if (d.type === 'surface' || resizingNode) return;
        dragMoved = false;
        dragStartXY = { x: event.x, y: event.y };
        if (!event.active) simulation.alphaTarget(0.2).restart();
        d.fx = d.x;
        d.fy = d.y;
        // If this node is part of a lasso selection, record all selected node positions
        if (selectedNodesRef.current.has(d.id) && selectedNodesRef.current.size > 1) {
          groupDragStartPositions = new Map();
          d3Nodes.forEach(n => {
            if (selectedNodesRef.current.has(n.id)) {
              groupDragStartPositions!.set(n.id, { x: n.x || 0, y: n.y || 0 });
            }
          });
        } else {
          groupDragStartPositions = null;
          // If plain-clicking a non-selected node, clear the lasso selection.
          // Shift-mousedown is reserved for the multi-select toggle path
          // (handled in handleNodeActivation on drag-end-as-click), so we
          // must not clear here — otherwise growing the selection beyond two
          // items is impossible: the third shift-click would wipe {A, B}
          // before its add could run.
          const shiftHeldOnStart = !!(event.sourceEvent as MouseEvent | undefined)?.shiftKey;
          if (
            !shiftHeldOnStart &&
            selectedNodesRef.current.size > 0 &&
            !selectedNodesRef.current.has(d.id)
          ) {
            selectedNodesRef.current.clear();
            svg.selectAll('.node').classed('lasso-selected', false);
          }
        }
      })
      .on('drag', (event, d) => {
        if (d.type === 'surface' || resizingNode) return;
        if (dragStartXY) {
          const dxm = event.x - dragStartXY.x;
          const dym = event.y - dragStartXY.y;
          if (dxm * dxm + dym * dym > 16) dragMoved = true; // >4px
        }
        let x = event.x;
        let y = event.y;
        // Quantise to grid when (gridSnap XOR shift): in grid mode the
        // default snaps and shift opts out; in free mode the default is
        // free and shift forces a snap.
        const shiftHeld = !!event.sourceEvent?.shiftKey;
        if (gridSnapRef.current !== shiftHeld) {
          const surfaceNode = d3Nodes.find(n => n.id === '__surface__');
          const anchorX = surfaceNode?.x || 0;
          const anchorY = surfaceNode?.y || 0;
          x = anchorX + Math.round((x - anchorX) / GRID_SNAP) * GRID_SNAP;
          y = anchorY + Math.round((y - anchorY) / GRID_SNAP) * GRID_SNAP;
        }

        // Group drag: move all selected nodes by the same delta
        if (groupDragStartPositions && groupDragStartPositions.has(d.id)) {
          const startPos = groupDragStartPositions.get(d.id)!;
          const dx = x - startPos.x;
          const dy = y - startPos.y;
          const surfaceNode = d3Nodes.find(n => n.id === '__surface__');
          groupDragStartPositions.forEach((pos, id) => {
            const node = d3Nodes.find(n => n.id === id);
            if (!node) return;
            let nx = pos.x + dx;
            let ny = pos.y + dy;
            if (EDGE_CONSTRAINED_TYPES.includes(node.type) && surfaceNode) {
              const sx = surfaceNode.x || 0;
              const sy = surfaceNode.y || 0;
              const pt = constrainToSurfaceEdge(
                nx,
                ny,
                sx,
                sy,
                surfaceSizeRef.current.w / 2,
                surfaceSizeRef.current.h / 2
              );
              nx = pt.x;
              ny = pt.y;
            } else if (SURFACE_WIDE_TYPES.includes(node.type) && surfaceNode) {
              const sx = surfaceNode.x || 0;
              const sy = surfaceNode.y || 0;
              const r = node.radius || 24;
              const halfW = surfaceSizeRef.current.w / 2 - r - 6;
              const halfH = surfaceSizeRef.current.h / 2 - r - 6;
              nx = Math.max(sx - halfW, Math.min(sx + halfW, nx));
              ny = Math.max(sy - halfH, Math.min(sy + halfH, ny));
            } else if (CONTAINED_IN_SURFACE_TYPES.includes(node.type) && surfaceNode) {
              const sx = surfaceNode.x || 0;
              const sy = surfaceNode.y || 0;
              const r = node.radius || 22;
              const halfW = surfaceSizeRef.current.w / 2 - r - 6;
              const halfH = surfaceSizeRef.current.h / 2 - r - 6;
              nx = Math.max(sx - halfW, Math.min(sx + halfW, nx));
              ny = Math.max(sy - halfH, Math.min(sy + halfH, ny));
            } else if (isNpcType(node.type) && surfaceNode) {
              const sx = surfaceNode.x || 0;
              const sy = surfaceNode.y || 0;
              const r = node.radius || 18;
              const halfW = surfaceSizeRef.current.w / 2 + r + 8;
              const halfH = surfaceSizeRef.current.h / 2 + r + 8;
              const insideX = nx > sx - halfW && nx < sx + halfW;
              const insideY = ny > sy - halfH && ny < sy + halfH;
              if (insideX && insideY) {
                const dxLeft = nx - (sx - halfW);
                const dxRight = sx + halfW - nx;
                const dyTop = ny - (sy - halfH);
                const dyBottom = sy + halfH - ny;
                const minDist = Math.min(dxLeft, dxRight, dyTop, dyBottom);
                if (minDist === dxLeft) nx = sx - halfW;
                else if (minDist === dxRight) nx = sx + halfW;
                else if (minDist === dyTop) ny = sy - halfH;
                else ny = sy + halfH;
              }
            }
            node.fx = nx;
            node.fy = ny;
          });
        } else {
          // Single node drag
          const surfaceNode = d3Nodes.find(n => n.id === '__surface__');
          const dragDef = _registry.get(d.type);
          if (dragDef?.dropMode === 'edge' && d._pipe) {
            // Edge-drop middleware: constrain drag to the pipeline's
            // offset line. The user can slide along the line but the
            // perpendicular distance is forced to the canonical lateral
            // offset so the node always sits exactly on the connector.
            const px = d._pipe.parent.x ?? 0;
            const py = d._pipe.parent.y ?? 0;
            const cx = d._pipe.child.x ?? 0;
            const cy = d._pipe.child.y ?? 0;
            const ldx = cx - px;
            const ldy = cy - py;
            const llen = Math.sqrt(ldx * ldx + ldy * ldy) || 1;
            const ux = ldx / llen;
            const uy = ldy / llen;
            const nx = -uy;
            const ny = ux;
            // Middleware no longer participate as link endpoints —
            // the slot direction is stashed on the node when `_pipe`
            // is computed, so read it directly.
            const direction = d.direction;
            const lateral = lateralOffsetFor(
              direction,
              pipeAnchorRadius(d._pipe.parent),
              pipeAnchorRadius(d._pipe.child)
            );
            const t = ((x - px) * ux + (y - py) * uy) / llen;
            // Node-size-aware clamp: keep middleware clear of both
            // anchor nodes so it can't overlap them or slide past
            // (which would reverse the sub-link arrow direction).
            // The renderer shortens the pipeline line by an extra
            // label-clearance amount at either end (see
            // `computeLinkEndpoints` further down); mirror that here so
            // the middleware can't slide past the *visual* line end
            // and dangle in space next to its anchor's label.
            const hasLabel = (node: D3Node): boolean => {
              const def = _registry.get(node.type);
              if (!def) return !!node.label;
              if (def.dropMode === 'edge') return false;
              return !!def.label;
            };
            const parentLabelClear = hasLabel(d._pipe.parent) && uy > 0 ? uy * 24 : 0;
            let childLabelClear = 0;
            if (hasLabel(d._pipe.child)) {
              if (uy < 0) childLabelClear = Math.max(childLabelClear, -uy * 39);
              if (Math.abs(ux) > 0.3) {
                childLabelClear = Math.max(childLabelClear, Math.abs(ux) * 36);
              }
            }
            const parentR = (d._pipe.parent.radius ?? 24) + parentLabelClear;
            const childR = (d._pipe.child.radius ?? 24) + childLabelClear;
            const selfR = d.radius ?? 14;
            const anchorPad = 8;
            let tMin = Math.max(0.02, (parentR + selfR + anchorPad) / llen);
            let tMax = Math.min(0.98, 1 - (childR + selfR + anchorPad) / llen);
            if (tMin > tMax) {
              const mid = (tMin + tMax) / 2;
              tMin = tMax = mid;
            }
            // Tighten t-range so the projected middleware also stays
            // inside the surface rect (the pipe itself may extend out
            // to an external NPC, but the middleware must not).
            if (surfaceNode) {
              const sx = surfaceNode.x || 0;
              const sy = surfaceNode.y || 0;
              const rr = selfR;
              const pad = 6;
              const xMin = sx - surfaceSizeRef.current.w / 2 + rr + pad;
              const xMax = sx + surfaceSizeRef.current.w / 2 - rr - pad;
              const yMin = sy - surfaceSizeRef.current.h / 2 + rr + pad;
              const yMax = sy + surfaceSizeRef.current.h / 2 - rr - pad;
              const ax = ux * llen;
              const bxc = px + nx * lateral;
              if (Math.abs(ax) > 1e-6) {
                const t1 = (xMin - bxc) / ax;
                const t2 = (xMax - bxc) / ax;
                tMin = Math.max(tMin, Math.min(t1, t2));
                tMax = Math.min(tMax, Math.max(t1, t2));
              }
              const ay = uy * llen;
              const byc = py + ny * lateral;
              if (Math.abs(ay) > 1e-6) {
                const t1 = (yMin - byc) / ay;
                const t2 = (yMax - byc) / ay;
                tMin = Math.max(tMin, Math.min(t1, t2));
                tMax = Math.min(tMax, Math.max(t1, t2));
              }
              if (tMin > tMax) {
                const mid = (tMin + tMax) / 2;
                tMin = tMax = mid;
              }
            }
            const tClamped = Math.max(tMin, Math.min(tMax, t));
            d._pipeT = tClamped;
            const baseX = px + ux * llen * tClamped;
            const baseY = py + uy * llen * tClamped;
            d.fx = baseX + nx * lateral;
            d.fy = baseY + ny * lateral;
          } else if (EDGE_CONSTRAINED_TYPES.includes(d.type) && surfaceNode) {
            const sx = surfaceNode.x || 0;
            const sy = surfaceNode.y || 0;
            const pt = constrainToSurfaceEdge(
              x,
              y,
              sx,
              sy,
              surfaceSizeRef.current.w / 2,
              surfaceSizeRef.current.h / 2
            );
            d.fx = pt.x;
            d.fy = pt.y;
          } else if (d.type === 'target' && surfaceNode) {
            // Target must stay inside the surface bounds
            const sx = surfaceNode.x || 0;
            const sy = surfaceNode.y || 0;
            const halfW = surfaceSizeRef.current.w / 2 - d.radius - 10;
            const halfH = surfaceSizeRef.current.h / 2 - d.radius - 10;
            d.fx = Math.max(sx - halfW, Math.min(sx + halfW, x));
            d.fy = Math.max(sy - halfH, Math.min(sy + halfH, y));
          } else if (SURFACE_WIDE_TYPES.includes(d.type) && surfaceNode) {
            // Surface-wide nodes (e.g. Agent Identity) are constrained to the
            // surface interior so they can't be dragged off the surface.
            const sx = surfaceNode.x || 0;
            const sy = surfaceNode.y || 0;
            const r = d.radius || 24;
            const halfW = surfaceSizeRef.current.w / 2 - r - 6;
            const halfH = surfaceSizeRef.current.h / 2 - r - 6;
            d.fx = Math.max(sx - halfW, Math.min(sx + halfW, x));
            d.fy = Math.max(sy - halfH, Math.min(sy + halfH, y));
          } else if (CONTAINED_IN_SURFACE_TYPES.includes(d.type) && surfaceNode) {
            // Surface-bound free-floating nodes (e.g. Trust Registry):
            // freeform position inside the surface rectangle, clamped
            // so they can never be dragged outside the surface.
            const sx = surfaceNode.x || 0;
            const sy = surfaceNode.y || 0;
            const r = d.radius || 22;
            const halfW = surfaceSizeRef.current.w / 2 - r - 6;
            const halfH = surfaceSizeRef.current.h / 2 - r - 6;
            d.fx = Math.max(sx - halfW, Math.min(sx + halfW, x));
            d.fy = Math.max(sy - halfH, Math.min(sy + halfH, y));
          } else if (isNpcType(d.type) && surfaceNode) {
            // NPCs are external actors and must stay outside the surface
            // boundary. Push the drag position out along the shortest
            // axis whenever it would land inside the surface rect.
            const sx = surfaceNode.x || 0;
            const sy = surfaceNode.y || 0;
            const r = d.radius || 18;
            const halfW = surfaceSizeRef.current.w / 2 + r + 8;
            const halfH = surfaceSizeRef.current.h / 2 + r + 8;
            let nx = x;
            let ny = y;
            const insideX = nx > sx - halfW && nx < sx + halfW;
            const insideY = ny > sy - halfH && ny < sy + halfH;
            if (insideX && insideY) {
              const dxLeft = nx - (sx - halfW);
              const dxRight = sx + halfW - nx;
              const dyTop = ny - (sy - halfH);
              const dyBottom = sy + halfH - ny;
              const minDist = Math.min(dxLeft, dxRight, dyTop, dyBottom);
              if (minDist === dxLeft) nx = sx - halfW;
              else if (minDist === dxRight) nx = sx + halfW;
              else if (minDist === dyTop) ny = sy - halfH;
              else ny = sy + halfH;
            }
            d.fx = nx;
            d.fy = ny;
          } else {
            d.fx = x;
            d.fy = y;
          }
        }
      })
      .on('end', (event, d) => {
        if (d.type === 'surface' || resizingNode) return;
        if (!event.active) simulation.alphaTarget(0);
        // Gesture without movement → treat as a click. d3-drag's pointer
        // capture suppresses the browser's native click event in some
        // browsers, so this is the reliable selection path.
        const wasClick = !dragMoved;
        const sourceEvent = event.sourceEvent as MouseEvent | undefined;
        dragStartXY = null;
        if (wasClick) {
          clickGesture.suppress = true;
          // Clear suppression on the next tick in case no native click
          // arrives, so a follow-up real click still works.
          setTimeout(() => {
            clickGesture.suppress = false;
          }, 0);
          handleNodeActivation(d, { shiftKey: !!sourceEvent?.shiftKey });
          groupDragStartPositions = null;
          return;
        }
        // Report final positions for all moved nodes — always as offsets from
        // the live surface center so persistence survives container resizes.
        const surfaceNode = d3Nodes.find(n => n.id === '__surface__');
        const sx = surfaceNode?.x ?? 0;
        const sy = surfaceNode?.y ?? 0;
        if (groupDragStartPositions) {
          groupDragStartPositions.forEach((_pos, id) => {
            const node = d3Nodes.find(n => n.id === id);
            if (node && onNodeMove) {
              const ax = node.fx ?? node.x ?? 0;
              const ay = node.fy ?? node.y ?? 0;
              onNodeMove(id, ax - sx, ay - sy);
            }
          });
          groupDragStartPositions = null;
        } else {
          const finalX = d.fx ?? d.x ?? event.x;
          const finalY = d.fy ?? d.y ?? event.y;
          if (onNodeMove) onNodeMove(d.id, finalX - sx, finalY - sy);
        }
      });

    nodeSelection.call(drag as any);

    // Node resize handles (visible on hover, draggable). Edge-constrained
    // nodes (AP, TP) are sized by the surface itself, so they don't get a
    // per-node handle — doing so would let the two sources of truth drift.
    nodeSelection
      .filter(d => d.type !== 'surface' && !EDGE_CONSTRAINED_TYPES.includes(d.type))
      .append('circle')
      .attr('class', 'node-resize-handle')
      .attr('cx', d => d.radius * 0.7)
      .attr('cy', d => d.radius * 0.7)
      .attr('r', 5)
      .attr('fill', '#6c757d')
      .attr('stroke', 'white')
      .attr('stroke-width', 1)
      .attr('opacity', 0)
      .attr('cursor', 'nwse-resize')
      .call(
        d3
          .drag<SVGCircleElement, D3Node>()
          .on('start', function (event, d) {
            event.sourceEvent.stopPropagation();
            resizingNode = true;
            (d as any)._resizeStartRadius = d.radius;
            (d as any)._resizeStartX = event.x;
            (d as any)._resizeStartY = event.y;
          })
          .on('drag', function (event, d) {
            const startR = (d as any)._resizeStartRadius as number;
            const startX = (d as any)._resizeStartX as number;
            const startY = (d as any)._resizeStartY as number;
            const startDist = Math.sqrt(startX * startX + startY * startY);
            const curDist = Math.sqrt(event.x * event.x + event.y * event.y);
            const delta = curDist - startDist;
            const { min, max } = getResizeRange(d.type);
            const newR = Math.max(min, Math.min(max, startR + delta));
            applyNodeGeometry(d3.select(this.parentNode as Element), d, newR);
          })
          .on('end', function (_event, d) {
            resizingNode = false;
            // Restart simulation so link positions update to new radius
            simulation.alpha(0.05).restart();
            if (onNodeResize) onNodeResize(d.id, d.radius);
          }) as any
      );

    // Hover effects
    nodeSelection
      .on('mouseenter', function (_event, d) {
        if (d.type === 'surface') return;
        d3.select(this).select('.node-resize-handle').attr('opacity', 0.7);
        if (d.type === 'target') {
          const half = d.radius || TARGET_SQUARE_SIZE / 2;
          const size = half * 2;
          d3.select(this)
            .select('.main-rect')
            .transition()
            .duration(150)
            .attr('x', -(size * 1.1) / 2)
            .attr('y', -(size * 1.1) / 2)
            .attr('width', size * 1.1)
            .attr('height', size * 1.1)
            .attr('stroke-width', 2.5);
        } else {
          d3.select(this)
            .select('.main-circle')
            .transition()
            .duration(150)
            .attr('r', d.radius * 1.12)
            .attr('stroke-width', 2.5);
        }
      })
      .on('mouseleave', function (_event, d) {
        d3.select(this).select('.node-resize-handle').attr('opacity', 0);
        if (d.type === 'target') {
          const half = d.radius || TARGET_SQUARE_SIZE / 2;
          const size = half * 2;
          d3.select(this)
            .select('.main-rect')
            .transition()
            .duration(300)
            .attr('x', -half)
            .attr('y', -half)
            .attr('width', size)
            .attr('height', size)
            .attr('stroke-width', 1.5);
        } else {
          d3.select(this)
            .select('.main-circle')
            .transition()
            .duration(300)
            .attr('r', d.radius)
            .attr('stroke-width', 1.5);
        }
      });

    // Helper: effective radius for link endpoint offset (rect vs circle)
    const effectiveRadius = (node: D3Node): number => {
      if (node.type === 'surface') return surfaceSizeRef.current.w / 2;
      if (node.type === 'target') return node.radius || TARGET_SQUARE_SIZE / 2;
      return node.radius;
    };

    // Diagnostic: expose a console-callable snapshot of all node positions
    // and link endpoints. Use `__surfaceSnapshot()` in the browser console
    // to take a single snapshot (instead of relying on the per-tick
    // __SURFACE_DEBUG__ stream). Useful for before/after comparisons.
    if (typeof window !== 'undefined') {
      (window as { __surfaceNodes?: D3Node[]; __surfaceLinks?: D3Link[] }).__surfaceNodes = d3Nodes;
      (window as { __surfaceNodes?: D3Node[]; __surfaceLinks?: D3Link[] }).__surfaceLinks = d3Links;
    }
    // Tick
    simulation.on('tick', () => {
      const surfaceNode = d3Nodes.find(n => n.id === '__surface__');
      const curHalfW = surfaceSizeRef.current.w / 2;
      const curHalfH = surfaceSizeRef.current.h / 2;

      // Keep edge-constrained nodes on the surface perimeter (only if not being dragged)
      if (surfaceNode) {
        const sx = surfaceNode.x || 0;
        const sy = surfaceNode.y || 0;

        d3Nodes.forEach(n => {
          if (EDGE_CONSTRAINED_TYPES.includes(n.type)) {
            const pt = constrainToSurfaceEdge(n.x || sx, n.y || sy, sx, sy, curHalfW, curHalfH);
            n.x = pt.x;
            n.y = pt.y;
            n.fx = pt.x;
            n.fy = pt.y;
          } else if (isNpcType(n.type)) {
            // NPCs are external actors — never let them end up inside
            // the surface boundary. If a resize would engulf them,
            // push them out along the shortest axis.
            const r = n.radius || 18;
            const halfW = curHalfW + r + 8;
            const halfH = curHalfH + r + 8;
            const nx = n.x || 0;
            const ny = n.y || 0;
            const insideX = nx > sx - halfW && nx < sx + halfW;
            const insideY = ny > sy - halfH && ny < sy + halfH;
            if (insideX && insideY) {
              const dxLeft = nx - (sx - halfW);
              const dxRight = sx + halfW - nx;
              const dyTop = ny - (sy - halfH);
              const dyBottom = sy + halfH - ny;
              const minDist = Math.min(dxLeft, dxRight, dyTop, dyBottom);
              let outX = nx;
              let outY = ny;
              if (minDist === dxLeft) outX = sx - halfW;
              else if (minDist === dxRight) outX = sx + halfW;
              else if (minDist === dyTop) outY = sy - halfH;
              else outY = sy + halfH;
              n.x = outX;
              n.y = outY;
              n.fx = outX;
              n.fy = outY;
            }
          }
        });
      }

      // Edge-drop middleware nodes are placed deterministically once
      // outside the tick handler (see "Deterministic placement of
      // edge-drop middleware" earlier in this file). They stay pinned
      // via fx/fy and don't need per-tick adjustment here.
      //
      // Exception: while a pipe anchor is moving (the user is dragging
      // the MA, AP, or an NPC), reproject every middleware from its
      // cached `_pipeT` so it slides with the pipe in real time.
      // The projection is also clamped to the surface rect so a pipe
      // whose far anchor is external (e.g. target → NPC) can't push
      // middleware outside the surface as the near anchor moves.
      d3Nodes.forEach(n => {
        if (!n._pipe || n._pipeT === undefined) return;
        const px = n._pipe.parent.x ?? 0;
        const py = n._pipe.parent.y ?? 0;
        const cx = n._pipe.child.x ?? 0;
        const cy = n._pipe.child.y ?? 0;
        const ldx = cx - px;
        const ldy = cy - py;
        const llen = Math.sqrt(ldx * ldx + ldy * ldy) || 1;
        const ux = ldx / llen;
        const uy = ldy / llen;
        const nrmX = -uy;
        const nrmY = ux;
        const lateral = lateralOffsetFor(
          n.direction,
          pipeAnchorRadius(n._pipe.parent),
          pipeAnchorRadius(n._pipe.child)
        );
        let t = n._pipeT;
        if (surfaceNode) {
          const sx = surfaceNode.x || 0;
          const sy = surfaceNode.y || 0;
          const rr = n.radius || 14;
          const pad = 6;
          const xMin = sx - curHalfW + rr + pad;
          const xMax = sx + curHalfW - rr - pad;
          const yMin = sy - curHalfH + rr + pad;
          const yMax = sy + curHalfH - rr - pad;
          let tLo = 0;
          let tHi = 1;
          const ax = ux * llen;
          const bxc = px + nrmX * lateral;
          if (Math.abs(ax) > 1e-6) {
            const t1 = (xMin - bxc) / ax;
            const t2 = (xMax - bxc) / ax;
            tLo = Math.max(tLo, Math.min(t1, t2));
            tHi = Math.min(tHi, Math.max(t1, t2));
          }
          const ay = uy * llen;
          const byc = py + nrmY * lateral;
          if (Math.abs(ay) > 1e-6) {
            const t1 = (yMin - byc) / ay;
            const t2 = (yMax - byc) / ay;
            tLo = Math.max(tLo, Math.min(t1, t2));
            tHi = Math.min(tHi, Math.max(t1, t2));
          }
          if (tLo <= tHi) {
            t = Math.max(tLo, Math.min(tHi, t));
          }
        }
        const baseX = px + ux * llen * t;
        const baseY = py + uy * llen * t;
        let projX = baseX + nrmX * lateral;
        let projY = baseY + nrmY * lateral;
        // Hard clamp: if the pipe is so oblique that no `t` keeps the
        // laterally-offset projection inside the surface, clamp the
        // projected point directly to the surface rect. The middleware
        // floats slightly off the pipe line in this edge case but never
        // escapes the surface boundary.
        if (surfaceNode) {
          const sx = surfaceNode.x || 0;
          const sy = surfaceNode.y || 0;
          const rr = n.radius || 14;
          const pad = 6;
          projX = Math.max(sx - curHalfW + rr + pad, Math.min(sx + curHalfW - rr - pad, projX));
          projY = Math.max(sy - curHalfH + rr + pad, Math.min(sy + curHalfH - rr - pad, projY));
        }
        n.x = projX;
        n.y = projY;
        n.fx = projX;
        n.fy = projY;
      });

      // Compute link endpoints once per link, then assign x1/y1/x2/y2.
      // Response-direction links are offset perpendicularly so they appear
      // as a parallel arrow next to the (centered) request arrow. Request
      // arrows stay on the centerline so any middleware dropped on them
      // sits on the geometric center of the node.
      const isMiddlewareNode = (node: D3Node): boolean => {
        const def = _registry.get(node.type);
        return !!def && def.dropMode === 'edge';
      };
      const computeLinkEndpoints = (d: D3Link) => {
        const srcRaw = d.source as D3Node;
        const tgtRaw = d.target as D3Node;
        const srcMw = isMiddlewareNode(srcRaw);
        const tgtMw = isMiddlewareNode(tgtRaw);

        // Resolve the canonical pipeline anchors. For an undivided link
        // these are just the link's source and target. For a split
        // sub-link (one end is a middleware) the middleware is replaced
        // with its cached opposite pipeline anchor, so AP->policy and
        // policy->MA both share the canonical AP->MA pipeline direction.
        // This guarantees the AP and MA endpoints stay at the same
        // rendered point whether or not a middleware is present.
        const srcAnchor: D3Node = srcMw && srcRaw._pipe ? srcRaw._pipe.parent : srcRaw;
        const tgtAnchor: D3Node = tgtMw && tgtRaw._pipe ? tgtRaw._pipe.child : tgtRaw;
        const lateral = lateralOffsetFor(
          d.direction,
          pipeAnchorRadius(srcAnchor),
          pipeAnchorRadius(tgtAnchor)
        );

        const ax = srcAnchor.x || 0;
        const ay = srcAnchor.y || 0;
        const bx = tgtAnchor.x || 0;
        const by = tgtAnchor.y || 0;
        const dxp = bx - ax;
        const dyp = by - ay;
        const distP = Math.sqrt(dxp * dxp + dyp * dyp) || 1;
        const uxp = dxp / distP;
        const uyp = dyp / distP;
        // Perpendicular (90deg CW) along canonical pipeline direction.
        const pnx = -uyp;
        const pny = uxp;

        // Whether a node renders a label below it. Use the registry
        // definition (which always exists for runtime nodes) as the
        // source of truth, instead of the live `n.label` string. The
        // wizard sometimes creates nodes with an empty label that the
        // canvas later backfills from the def — basing the clearance
        // on the def keeps the geometry stable across edit/reload.
        const hasRenderedLabel = (node: D3Node): boolean => {
          const def = _registry.get(node.type);
          if (!def) return !!node.label;
          // Middleware nodes don't render labels (they show only the icon).
          if (def.dropMode === 'edge') return false;
          return !!def.label;
        };

        let x1: number;
        let y1: number;
        if (srcMw) {
          x1 = srcRaw.x || 0;
          y1 = srcRaw.y || 0;
        } else {
          const r = effectiveRadius(srcRaw);
          // Labels sit BELOW the node (dy = r + 16, ≈14 px text height).
          // When the arrow leaves the src going downward (uyp > 0), the
          // departure point lands in the label region — push the start
          // below the label by scaling clearance with the downward
          // component of the approach. Bidirectional links retain the
          // original 20 px constant to preserve their layout.
          let labelOffset = 0;
          if (hasRenderedLabel(srcRaw)) {
            if (d.bidirectional) labelOffset = 20;
            else if (uyp > 0) labelOffset = uyp * 24;
          }
          x1 = (srcRaw.x || 0) + uxp * (r + labelOffset);
          y1 = (srcRaw.y || 0) + uyp * (r + labelOffset);
          if (lateral !== 0) {
            x1 += pnx * lateral;
            y1 += pny * lateral;
          }
        }

        let x2: number;
        let y2: number;
        if (tgtMw) {
          x2 = tgtRaw.x || 0;
          y2 = tgtRaw.y || 0;
        } else {
          const r = effectiveRadius(tgtRaw);
          // Labels sit BELOW the node and extend symmetrically past
          // the node's circle (text-anchor: middle). Two cases need
          // clearance to keep the arrow tip clear of the label text:
          //   • Approaches from below (uyp < 0): tip lands directly
          //     over the label region, so push the tip up.
          //   • Horizontal approaches (|uxp| ≫ 0): the label extends
          //     past the node's left/right edge, so the tip lands
          //     right next to the leading edge of the label text.
          //     Push the tip further from the node along the
          //     approach direction.
          // Approaches from above (uyp > 0) land above the node and
          // don't need any label clearance.
          let labelOffset = 0;
          if (hasRenderedLabel(tgtRaw)) {
            if (uyp < 0) labelOffset = Math.max(labelOffset, -uyp * 39);
            if (Math.abs(uxp) > 0.3) {
              labelOffset = Math.max(labelOffset, Math.abs(uxp) * 36);
            }
          }
          x2 = (tgtRaw.x || 0) - uxp * (r + labelOffset);
          y2 = (tgtRaw.y || 0) - uyp * (r + labelOffset);
          if (lateral !== 0) {
            x2 += pnx * lateral;
            y2 += pny * lateral;
          }
        }

        // Diagnostic logging. Enable by typing this once in the browser
        // console: window.__SURFACE_DEBUG__ = true
        // Disable: window.__SURFACE_DEBUG__ = false
        if (
          typeof window !== 'undefined' &&
          (window as { __SURFACE_DEBUG__?: boolean }).__SURFACE_DEBUG__ &&
          d.direction
        ) {
          const fmt = (n: number | undefined | null) => (n == null ? 'n/a' : n.toFixed(2));
          // Single-line summary so the key numbers show even when the
          // object is collapsed in the browser console.
          const tag = `${srcRaw.id}->${tgtRaw.id}/${d.direction}${
            srcMw ? ' [src=mw]' : ''
          }${tgtMw ? ' [tgt=mw]' : ''}`;
          const summary =
            `src(${fmt(srcRaw.x)},${fmt(srcRaw.y)}) ` +
            `tgt(${fmt(tgtRaw.x)},${fmt(tgtRaw.y)}) ` +
            `anchorSrc=${srcAnchor.id}(${fmt(srcAnchor.x)},${fmt(srcAnchor.y)}) ` +
            `anchorTgt=${tgtAnchor.id}(${fmt(tgtAnchor.x)},${fmt(tgtAnchor.y)}) ` +
            `u=(${fmt(uxp)},${fmt(uyp)}) perp=(${fmt(pnx)},${fmt(pny)}) ` +
            `lat=${lateral} ` +
            `=> (${fmt(x1)},${fmt(y1)})->(${fmt(x2)},${fmt(y2)})`;
          // eslint-disable-next-line no-console
          console.log(`[link] ${tag} | ${summary}`);
        }

        return { x1, y1, x2, y2 };
      };

      linkSelection
        .attr('x1', d => computeLinkEndpoints(d).x1)
        .attr('y1', d => computeLinkEndpoints(d).y1)
        .attr('x2', d => computeLinkEndpoints(d).x2)
        .attr('y2', d => computeLinkEndpoints(d).y2);

      // Credential-delegation redrive arc: curved dotted arrow from
      // the CD node back to the MA (`target`). Curve dips BELOW both
      // nodes (control point pushed downward) so it doesn't collide
      // with element labels above the pipeline.
      const targetNode = d3Nodes.find(n => n.id === 'target');
      // Clearance between the arc endpoint and the MA icon's bottom
      // edge so the arrowhead lands in empty space below the label
      // rather than poking the MA glyph itself.
      const MA_REDRIVE_GAP = 25;
      redriveSelection.attr('d', cd => {
        if (!targetNode) return '';
        const cdR = effectiveRadius(cd);
        const tgtR = effectiveRadius(targetNode);
        const x1 = cd.x || 0;
        const y1 = (cd.y || 0) + cdR;
        const x2 = targetNode.x || 0;
        const y2 = (targetNode.y || 0) + tgtR + MA_REDRIVE_GAP;
        const span = Math.max(60, Math.abs(x2 - x1));
        const cy = Math.max(y1, y2) + span * 0.45;
        return `M${x1},${y1} Q${(x1 + x2) / 2},${cy} ${x2},${y2}`;
      });
      redriveLabelSelection
        .attr('x', cd => {
          if (!targetNode) return cd.x || 0;
          return ((cd.x || 0) + (targetNode.x || 0)) / 2;
        })
        .attr('y', cd => {
          if (!targetNode) return cd.y || 0;
          const cdR = effectiveRadius(cd);
          const tgtR = effectiveRadius(targetNode);
          const y1 = (cd.y || 0) + cdR;
          const y2 = (targetNode.y || 0) + tgtR + MA_REDRIVE_GAP;
          const span = Math.max(60, Math.abs((targetNode.x || 0) - (cd.x || 0)));
          const cy = Math.max(y1, y2) + span * 0.45;
          // Place label near the apex of the curve (midpoint of the
          // quadratic bezier is at y = (y1 + 2*cy + y2) / 4). Nudged
          // down a touch so it sits just under the curve.
          return (y1 + 2 * cy + y2) / 4 + 12;
        });

      nodeSelection.attr('transform', d => `translate(${d.x || 0},${d.y || 0})`);

      // Expose a snapshot helper on `window` so a developer can call it
      // from the browser console at any time (the simulation goes idle
      // once it settles, so per-tick logging stops then). Reinstalled
      // every tick to capture the current closures.
      if (typeof window !== 'undefined') {
        (window as { __surfaceSnapshot?: () => void }).__surfaceSnapshot = () => {
          const fmt = (n: number | undefined | null) => (n == null ? 'n/a' : n.toFixed(2));
          // eslint-disable-next-line no-console
          console.group('[surface snapshot]');
          // eslint-disable-next-line no-console
          console.log('--- nodes ---');
          for (const n of d3Nodes) {
            const def = _registry.get(n.type);
            const tag = def?.dropMode === 'edge' ? ' [middleware]' : '';
            // eslint-disable-next-line no-console
            console.log(
              `node ${n.id}${tag} type=${n.type} pos=(${fmt(n.x)},${fmt(
                n.y
              )}) fx=${fmt(n.fx)} fy=${fmt(n.fy)} r=${n.radius}` +
                (n._pipe ? ` pipe=${n._pipe.parent.id}->${n._pipe.child.id}` : '')
            );
          }
          // eslint-disable-next-line no-console
          console.log('--- links ---');
          for (const l of d3Links) {
            const ep = computeLinkEndpoints(l);
            const s = l.source as D3Node;
            const t = l.target as D3Node;
            // eslint-disable-next-line no-console
            console.log(
              `link ${s.id}->${t.id} dir=${l.direction ?? '-'} bidi=${
                l.bidirectional ?? false
              } => (${fmt(ep.x1)},${fmt(ep.y1)}) -> (${fmt(ep.x2)},${fmt(ep.y2)})`
            );
          }
          // eslint-disable-next-line no-console
          console.groupEnd();
        };
      }

      // Persist positions so they survive rebuilds. Stored as offsets from
      // the surface center; the surface itself isn't tracked because it
      // always anchors to the live container center on rebuild.
      const surfaceForPersist = d3Nodes.find(n => n.id === '__surface__');
      const psx = surfaceForPersist?.x ?? 0;
      const psy = surfaceForPersist?.y ?? 0;
      d3Nodes.forEach(n => {
        if (n.id === '__surface__') return;
        const ax = n.x || 0;
        const ay = n.y || 0;
        positionsRef.current.set(n.id, {
          dx: ax - psx,
          dy: ay - psy,
          fdx: n.fx == null ? null : n.fx - psx,
          fdy: n.fy == null ? null : n.fy - psy,
        });
      });
    });

    return () => {
      // Save final positions before teardown (relative to surface center).
      // Use the local `savedPositions` snapshot of `positionsRef.current` so
      // we don't read the ref in cleanup (the same Map either way).
      const surfaceForTeardown = d3Nodes.find(n => n.id === '__surface__');
      const tsx = surfaceForTeardown?.x ?? 0;
      const tsy = surfaceForTeardown?.y ?? 0;
      d3Nodes.forEach(n => {
        if (n.id === '__surface__') return;
        const ax = n.x || 0;
        const ay = n.y || 0;
        savedPositions.set(n.id, {
          dx: ax - tsx,
          dy: ay - tsy,
          fdx: n.fx == null ? null : n.fx - tsx,
          fdy: n.fy == null ? null : n.fy - tsy,
        });
      });
      simulation.stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [structureKey, surfaceName, protocol, onNodeClick, onCanvasClick, sizeKey]);

  // ─── Lightweight update: labels + configured state (no simulation restart) ─
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);

    // Update surface label
    svg.select('[data-node-id="__surface__"] .node-label').text(() => {
      const label = surfaceName || 'Agent Surface';
      return label.length > 36 ? label.substring(0, 34) + '…' : label;
    });
    svg.select('[data-node-id="__surface__"] .surface-sublabel').text(protocol.toUpperCase());

    // Compute once per render: which nodes have unmet feature-dependency
    // errors. Drives the marching-ants animated ring below alongside the
    // ordinary "incomplete config" ring.
    const updateFeatureErrorIds = computeFeatureErrorIds(nodes, protocol);

    // Update attached node labels and opacity
    nodes.forEach(n => {
      const nodeG = svg.select(`[data-node-id="${n.id}"]`);
      if (nodeG.empty()) return;

      // Sync label into D3Node data so tick offsets stay correct
      const d3Node = d3NodesRef.current.find(dn => dn.id === n.id);
      if (d3Node) d3Node.label = n.label;

      const labelText = n.label
        ? n.label.length > 32
          ? n.label.substring(0, 30) + '…'
          : n.label
        : '';
      nodeG.select('.node-label').text(labelText);

      // Update label background size
      const labelBg = nodeG.select('.label-bg');
      const labelEl = nodeG.select('.node-label').node() as SVGTextElement | null;
      if (labelEl && !labelBg.empty()) {
        const bbox = labelEl.getBBox();
        if (bbox.width > 0) {
          labelBg
            .attr('x', bbox.x - 4)
            .attr('y', bbox.y - 2)
            .attr('width', bbox.width + 8)
            .attr('height', bbox.height + 4);
        } else {
          labelBg.attr('width', 0).attr('height', 0);
        }
      }

      // Update NPC description label
      const descEl = nodeG.select('.npc-description');
      if (!descEl.empty()) {
        const desc = n.description || '';
        descEl.text(desc.length > 28 ? desc.substring(0, 26) + '…' : desc);
      }

      // Update opacity on main shape (circle or rect)
      const mainShape = nodeG.select('.main-circle').empty()
        ? nodeG.select('.main-rect')
        : nodeG.select('.main-circle');
      if (!mainShape.empty()) {
        mainShape.attr('opacity', n.configured ? 1 : 0.6);
      }

      const ring = nodeG.select('.unconfigured-ring');
      const hasFeatureError = updateFeatureErrorIds.has(n.id);
      const policyMissing = policyDefinitionMissing(n, surfacePolicyIds);
      const wantRing = (!n.configured || hasFeatureError || policyMissing) && n.type !== 'surface';
      const useAnts = hasFeatureError && n.configured && !policyMissing;
      // A policy node with no policy selected or a missing attached policy
      // uses a dotted ring (distinct from the solid incomplete ring and the
      // marching-ants feature-error ring).
      const dottedPolicy = n.type === 'policy' && (!n.configured || policyMissing);
      if (!wantRing && !ring.empty()) {
        ring.remove();
      } else if (wantRing && ring.empty()) {
        const ringClass = useAnts ? 'unconfigured-ring marching' : 'unconfigured-ring';
        let newRing: d3.Selection<any, any, any, any>;
        if (n.type === 'target') {
          const r = d3Node?.radius || n.radius || NODE_RADIUS['target'];
          newRing = nodeG
            .insert('rect', '.node-label')
            .attr('class', ringClass)
            .attr('x', -(r + 5))
            .attr('y', -(r + 5))
            .attr('width', r * 2 + 10)
            .attr('height', r * 2 + 10)
            .attr('rx', 10)
            .attr('ry', 10)
            .attr('fill', 'none')
            .attr('stroke', '#e74a3b')
            .attr('stroke-width', 2)
            .attr('opacity', 0.8);
        } else {
          newRing = nodeG
            .insert('circle', '.node-label')
            .attr('class', ringClass)
            .attr('r', (n.radius || NODE_RADIUS[n.type] || 30) + 5)
            .attr('fill', 'none')
            .attr('stroke', '#e74a3b')
            .attr('stroke-width', 2)
            .attr('opacity', 0.8);
        }
        if (dottedPolicy) newRing.attr('stroke-dasharray', POLICY_UNCONFIGURED_DASH);
        else if (useAnts) newRing.attr('stroke-dasharray', '6 4');
      } else if (wantRing && !ring.empty()) {
        // Ring exists — reconcile its style in place (marching, dotted, or
        // solid) so transitions between incomplete-config, missing-policy,
        // and feature-error look right without a teardown/recreate flicker.
        const shouldAnts = useAnts;
        const isAnts = ring.classed('marching');
        if (shouldAnts !== isAnts) {
          ring.classed('marching', shouldAnts);
        }
        if (dottedPolicy) ring.attr('stroke-dasharray', POLICY_UNCONFIGURED_DASH);
        else if (shouldAnts) ring.attr('stroke-dasharray', '6 4');
        else ring.attr('stroke-dasharray', null);
      }

      // Sync the incomplete-reason text under the node label. Always
      // reposition `dy` (not only on insert) so resizes and label
      // additions/removals shift the reason line correctly.
      const reasonEl = nodeG.select('.node-incomplete-reason');
      const reason =
        n.type === 'surface' ? null : getIncompleteReason(n.type, n.config, surfacePolicyIds);
      if (!reason) {
        if (!reasonEl.empty()) reasonEl.remove();
      } else {
        const reasonText = reason.length > 38 ? reason.substring(0, 36) + '…' : reason;
        const r = d3Node?.radius || n.radius || NODE_RADIUS[n.type] || 30;
        const labelOffset = n.label && n.label.length > 0 ? 30 : 16;
        const dy = r + labelOffset;
        if (reasonEl.empty()) {
          nodeG
            .append('text')
            .attr('class', 'node-incomplete-reason')
            .attr('dy', dy)
            .attr('text-anchor', 'middle')
            .text(reasonText);
        } else {
          reasonEl.attr('dy', dy).text(reasonText);
        }
      }
    });
  }, [nodes, surfaceName, protocol, routingReady, surfacePolicyIds]);

  // ─── Single-selection highlight ─────────────────────────────────────
  // Mirror `selectedNodeId` onto a `.node-single-selected` class so the
  // sidebar's currently-active node gets a visible ring on the canvas.
  // Runs independently of the main rebuild because selection changes
  // shouldn't redraw the whole graph.
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll('.node').classed('node-single-selected', false);
    if (selectedNodeId && selectedNodeId !== '__surface__') {
      svg.select(`[data-node-id="${selectedNodeId}"]`).classed('node-single-selected', true);
    }
  }, [selectedNodeId, nodes]);

  // ─── Externally-controlled multi-selection sync ─────────────────────
  // When the parent updates `multiSelectedIds` (e.g. the user unticked
  // a node in the multi-select panel), reflect the change in the
  // canvas's internal ref + d3 classes. The d3 click handlers continue
  // to be the source of truth for canvas-originated changes; this
  // effect is idempotent for those (the values already match).
  useEffect(() => {
    if (!svgRef.current || multiSelectedIds === undefined) return;
    const next = new Set(multiSelectedIds);
    selectedNodesRef.current = next;
    const svg = d3.select(svgRef.current);
    svg.selectAll<SVGGElement, D3Node>('.node').classed('lasso-selected', d => next.has(d.id));
  }, [multiSelectedIds, nodes]);

  // Re-apply the surface size whenever the externally-supplied prop
  // changes — typically driven by undo/redo, where the parent reverts
  // `state.surfaceSize` to a previous value. This routes through the
  // same `applySurfaceSize` machinery that the live drag uses, so the
  // cascading edge-constrained / surface-wide nodes snap back into
  // place alongside the size change. Sibling effect ordering ensures
  // this runs before the position re-sync below.
  useEffect(() => {
    if (!surfaceSize) return;
    const cur = surfaceSizeRef.current;
    if (cur.w === surfaceSize.w && cur.h === surfaceSize.h) return;
    const surfNode = d3NodesRef.current.find(n => n.id === '__surface__');
    if (!surfNode || !applySurfaceSizeRef.current) return;
    applySurfaceSizeRef.current(surfaceSize.w, surfaceSize.h, surfNode.x ?? 0, surfNode.y ?? 0);
  }, [surfaceSize]);

  // Re-sync each node's d3 position from `node.position` when the parent
  // signals an external state change (undo / redo). Without this, the
  // internal positionsRef + simulation keep showing the post-drag values
  // even though state has reverted to the pre-drag snapshot.
  useEffect(() => {
    if (externalRevision === undefined) return;
    const surfNode = d3NodesRef.current.find(n => n.id === '__surface__');
    if (!surfNode) return;
    const sx = surfNode.x ?? 0;
    const sy = surfNode.y ?? 0;
    const positions = positionsRef.current;
    let changed = false;
    for (const n of nodes) {
      if (!n.position) continue;
      // Synthesised fabric:// chain nodes (hop / remote-gw /
      // remote-channel) are not driven by their grid-snapped
      // `position` hint — that lands a few pixels off an
      // edge-constrained parent. They are re-pinned from the live
      // parent position by `pinSyntheticFabricChain` after this loop.
      if (isSyntheticFabricNodeId(n.id)) continue;
      const dn = d3NodesRef.current.find(x => x.id === n.id);
      if (!dn) continue;
      const targetX = sx + n.position.x;
      const targetY = sy + n.position.y;
      if (dn.fx !== targetX || dn.fy !== targetY) {
        dn.x = targetX;
        dn.y = targetY;
        dn.fx = targetX;
        dn.fy = targetY;
        // Edge-drop middleware are reprojected every simulation tick
        // from `_pipeT` onto the live pipe — so just rewriting fx/fy
        // here gets clobbered on the next tick. Recompute `_pipeT`
        // from the new position projected onto the cached pipe so the
        // reprojection lands at the same point.
        if (dn._pipe) {
          const ppx = dn._pipe.parent.x ?? 0;
          const ppy = dn._pipe.parent.y ?? 0;
          const pcx = dn._pipe.child.x ?? 0;
          const pcy = dn._pipe.child.y ?? 0;
          const pdx = pcx - ppx;
          const pdy = pcy - ppy;
          const plen2 = pdx * pdx + pdy * pdy;
          if (plen2 > 1e-6) {
            const t = ((targetX - ppx) * pdx + (targetY - ppy) * pdy) / plen2;
            dn._pipeT = Math.max(0.05, Math.min(0.95, t));
          }
        }
        positions.set(n.id, {
          dx: n.position.x,
          dy: n.position.y,
          fdx: n.position.x,
          fdy: n.position.y,
        });
        changed = true;
      }
    }
    // Re-pin the synthesised fabric:// chain from the now-updated live
    // parent (target/TP) positions. Auto-layout doesn't trigger a full
    // canvas rebuild — only this effect runs — so without this the
    // chain would stay frozen wherever it last landed.
    pinSyntheticFabricChain(
      d3NodesRef.current,
      nodes,
      sx,
      sy,
      surfaceSize ?? surfaceSizeRef.current
    );
    if (changed && simulationRef.current) {
      simulationRef.current.alpha(0.3).restart();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [externalRevision]);

  // Re-anchor the auto-injected human / caller decorations to the
  // AP whenever the AP position actually changes. We track the AP's
  // last known (x, y) in a ref so unrelated re-renders (user dragging
  // caller/human themselves, panel state changes, etc.) don't snap
  // the chain back on top of the user's move.
  useEffect(() => {
    const surfNode = d3NodesRef.current.find(n => n.id === '__surface__');
    if (!surfNode) return;
    const apDn = d3NodesRef.current.find(n => n.type === 'access-point');
    if (!apDn) return;
    const apX = apDn.x ?? 0;
    const apY = apDn.y ?? 0;
    const prev = prevApPosRef.current;
    const revisionChanged = prevAnchorRevisionRef.current !== externalRevision;
    const apMoved = !prev || prev.x !== apX || prev.y !== apY;
    if (!revisionChanged && !apMoved) return;
    prevApPosRef.current = { x: apX, y: apY };
    prevAnchorRevisionRef.current = externalRevision ?? null;
    const sx = surfNode.x ?? 0;
    const sy = surfNode.y ?? 0;
    const callerDn = d3NodesRef.current.find(x => x.id === '__caller__');
    const humanDn = d3NodesRef.current.find(x => x.id === '__human__');
    if (!callerDn && !humanDn) return;
    const apR = apDn.radius || 30;
    const callerR = callerDn?.radius || 20;
    const humanR = humanDn?.radius || 16;
    // Minimum edge-to-edge gap between two connected nodes — keeps
    // every link in the chain (human→caller→AP) the same visible
    // length regardless of node radii.
    const MIN_EDGE_LEN = 70;
    const callerX = apX - apR - MIN_EDGE_LEN - callerR;
    const humanX = callerX - callerR - MIN_EDGE_LEN - humanR;
    // Use AP's y so the chain follows the AP wherever it goes — when
    // the user drags AP up or down, caller/human ride along.
    const chainY = apY;
    const seats: Array<[typeof callerDn, number]> = [
      [callerDn, callerX],
      [humanDn, humanX],
    ];
    let changed = false;
    for (const [dn, targetX] of seats) {
      if (!dn) continue;
      if (dn.fx === targetX && dn.fy === chainY) continue;
      dn.x = targetX;
      dn.y = chainY;
      dn.fx = targetX;
      dn.fy = chainY;
      positionsRef.current.set(dn.id, {
        dx: targetX - sx,
        dy: chainY - sy,
        fdx: targetX - sx,
        fdy: chainY - sy,
      });
      changed = true;
    }
    if (changed && simulationRef.current) {
      simulationRef.current.alpha(0.05).restart();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [externalRevision, surfaceSize, nodes]);

  // Mirror the `gridSnap` prop into a ref so the d3 drag handlers
  // (which capture closures at rebuild time) always see the latest
  // value without having to re-bind on every toggle.
  const gridSnapRef = useRef(gridSnap);
  useEffect(() => {
    gridSnapRef.current = gridSnap;
    if (svgRef.current) {
      d3.select(svgRef.current)
        .select('.canvas-bg')
        .attr('fill', gridSnap ? 'url(#canvas-grid-dots)' : 'transparent');
    }
  }, [gridSnap]);

  // Fit the complete graph whenever the parent bumps `resetViewRev`.
  // The handled cursor is owned by the builder hook, so a request made
  // before this canvas mounts (or in the same render as a variant
  // remount) remains pending until this effect handles it.

  /**
   * Compute a d3-zoom transform that fits the bounding box of all
   * visible actors (nodes + the surface rectangle) into the SVG
   * viewport, centring the bbox on the viewport. We don't simply
   * recentre on the MA because diagrams with TP→EXT NPCs above the
   * surface have an asymmetric vertical extent and would push the
   * NPCs off the top of the viewport.
   */
  const computeFitToActorsTransform = useCallback((): d3.ZoomTransform => {
    const svgEl = svgRef.current;
    if (!svgEl) return d3.zoomIdentity;
    const rect = svgEl.getBoundingClientRect();
    const vw = rect.width;
    const vh = rect.height;
    if (vw <= 0 || vh <= 0) return d3.zoomIdentity;

    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    const grow = (x1: number, y1: number, x2: number, y2: number) => {
      if (x1 < minX) minX = x1;
      if (y1 < minY) minY = y1;
      if (x2 > maxX) maxX = x2;
      if (y2 > maxY) maxY = y2;
    };
    const surfHalfW = surfaceSizeRef.current.w / 2;
    const surfHalfH = surfaceSizeRef.current.h / 2;
    for (const n of d3NodesRef.current) {
      const nx = n.x ?? 0;
      const ny = n.y ?? 0;
      if (n.id === '__surface__') {
        grow(nx - surfHalfW, ny - surfHalfH, nx + surfHalfW, ny + surfHalfH);
      } else {
        const r = n.radius || 24;
        grow(nx - r, ny - r, nx + r, ny + r);
      }
    }
    if (!Number.isFinite(minX)) return d3.zoomIdentity;

    // The canvas has a strip of floating gadgets (~20px) along its
    // top edge. Reserve that strip so the fitted content is centred in
    // the *visible* area below the gadgets rather than the raw
    // viewport — otherwise the top row of actors tucks behind them.
    const TOP_GADGET_INSET = 20;
    const PAD = 40;
    const usableH = vh - TOP_GADGET_INSET;
    const bw = maxX - minX;
    const bh = maxY - minY;
    const k = Math.min(1, (vw - 2 * PAD) / bw, (usableH - 2 * PAD) / bh);
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    const tx = vw / 2 - cx * k;
    const ty = TOP_GADGET_INSET + usableH / 2 - cy * k;
    return d3.zoomIdentity.translate(tx, ty).scale(k);
  }, []);

  useEffect(() => {
    if (resetViewRev === undefined) return;
    if (handledResetViewRevRef.current === resetViewRev) return;
    if (!svgRef.current || !zoomRef.current) return;
    handledResetViewRevRef.current = resetViewRev;
    d3.select(svgRef.current)
      .transition()
      .duration(400)
      .call(zoomRef.current.transform as any, computeFitToActorsTransform());
    if (externalCanvasViewRef) {
      externalCanvasViewRef.current = null;
    }
  }, [resetViewRev, handledResetViewRevRef, externalCanvasViewRef, computeFitToActorsTransform]);

  // Variants context selector — visible only when the surface has a
  // `target-variant` element on it. Pure visual today (lifted state
  // would let panels rebind to a chosen variant later).
  const variantNode = nodes.find(n => n.type === 'target-variant');
  const variantList = useMemo<Array<{ id: string; alias?: string; name?: string }>>(
    () => (Array.isArray(variantNode?.config?.variants) ? variantNode!.config.variants : []),
    [variantNode]
  );
  const variantDefaultId =
    typeof variantNode?.config?.default_variant_id === 'string'
      ? variantNode!.config.default_variant_id
      : undefined;
  const [activeVariantId, setActiveVariantId] = React.useState<string>('__base__');
  // Reset to Base when the variants element disappears.
  React.useEffect(() => {
    if (!variantNode) setActiveVariantId('__base__');
  }, [variantNode]);
  // If the active variant gets deleted, fall back to Base.
  React.useEffect(() => {
    if (activeVariantId !== '__base__' && !variantList.some(v => v.id === activeVariantId)) {
      setActiveVariantId('__base__');
    }
  }, [activeVariantId, variantList]);

  const handleExportPng = useCallback(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const width = Math.max(1, Math.floor(rect.width));
    const height = Math.max(1, Math.floor(rect.height));
    const isDark = document.body.classList.contains('dark-theme');
    const fontFamily =
      getComputedStyle(document.body).fontFamily ||
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif";
    const bgFill = isDark ? '#0f172a' : '#ffffff';

    // FontAwesome glyphs in the canvas are rendered as plain SVG <text>
    // nodes using `font-family: "Font Awesome 6 Free"` weight 900. When the
    // SVG is serialized into a data URL and rasterized through `Image`, the
    // browser cannot resolve external @font-face declarations (those live
    // in the app's CSS, not in the SVG). Fetch the FA solid woff2 once and
    // embed it inline as a data: URI inside the cloned SVG so icons render
    // in the exported PNG.
    void fetchFontAwesomeSolidDataUrl().then(faFontDataUrl => {
      const clone = svg.cloneNode(true) as SVGSVGElement;
      clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
      clone.setAttribute('xmlns:xlink', 'http://www.w3.org/1999/xlink');
      clone.setAttribute('width', String(width));
      clone.setAttribute('height', String(height));
      clone.style.fontFamily = fontFamily;
      const style = document.createElementNS('http://www.w3.org/2000/svg', 'style');
      const faFontFace = faFontDataUrl
        ? `@font-face { font-family: 'Font Awesome 6 Free'; font-style: normal; font-weight: 900; src: url(${faFontDataUrl}) format('woff2'); }`
        : '';
      style.textContent = `${faFontFace} text { font-family: ${fontFamily}; } .node-icon { font-family: 'Font Awesome 6 Free', sans-serif; font-weight: 900; }${
        isDark ? ' .node-label { fill: #94a3b8; } text { fill: #f1f5f9; }' : ''
      }`;
      clone.insertBefore(style, clone.firstChild);
      const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      bg.setAttribute('width', '100%');
      bg.setAttribute('height', '100%');
      bg.setAttribute('fill', bgFill);
      clone.insertBefore(bg, clone.firstChild);
      const xml = new XMLSerializer().serializeToString(clone);
      const svg64 = btoa(unescape(encodeURIComponent(xml)));
      const dataUrl = `data:image/svg+xml;base64,${svg64}`;
      const img = new Image();
      img.onload = () => {
        const scale = 2;
        const canvas = document.createElement('canvas');
        canvas.width = width * scale;
        canvas.height = height * scale;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.scale(scale, scale);
        ctx.drawImage(img, 0, 0, width, height);
        canvas.toBlob(blob => {
          if (!blob) return;
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          const safeName =
            (surfaceName || 'agent-surface')
              .replace(/[^a-z0-9-_]+/gi, '-')
              .replace(/^-+|-+$/g, '')
              .toLowerCase() || 'agent-surface';
          a.href = url;
          a.download = `${safeName}-canvas.png`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        }, 'image/png');
      };
      img.src = dataUrl;
    });
  }, [surfaceName]);

  // Expose imperative export-PNG + reset-pan/zoom to the parent so it
  // can render those toolbar buttons in its own consolidated widget
  // alongside undo/redo/etc. Refs are write-only; the parent calls
  // `ref.current?.()` from its onClick handlers.
  React.useEffect(() => {
    if (exportPngRef) exportPngRef.current = handleExportPng;
    if (resetViewRef) {
      resetViewRef.current = () => {
        if (!svgRef.current || !zoomRef.current) return;
        d3.select(svgRef.current)
          .transition()
          .duration(250)
          .call(zoomRef.current.transform as any, computeFitToActorsTransform());
        if (externalCanvasViewRef) {
          externalCanvasViewRef.current = null;
        }
      };
    }
    return () => {
      if (exportPngRef) exportPngRef.current = null;
      if (resetViewRef) resetViewRef.current = null;
    };
  }, [
    exportPngRef,
    resetViewRef,
    handleExportPng,
    externalCanvasViewRef,
    computeFitToActorsTransform,
  ]);

  return (
    <div
      ref={containerRef}
      className="surface-builder-canvas"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <svg ref={svgRef} />
      {variantNode && (
        <div
          style={{
            position: 'absolute',
            top: 8,
            left: 8,
            zIndex: 5,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '4px 8px',
            background: 'rgba(255,255,255,0.92)',
            border: '1px solid rgba(0,0,0,0.1)',
            borderRadius: 6,
            boxShadow: '0 1px 3px rgba(0,0,0,0.15)',
            backdropFilter: 'blur(6px)',
            fontSize: 12,
          }}
          title="Variant editing context — currently visual only"
        >
          <i className="fas fa-code-branch text-muted" />
          <span className="text-muted">Editing:</span>
          <select
            className="form-select form-select-sm"
            style={{ width: 'auto', minWidth: 120, padding: '2px 24px 2px 6px', fontSize: 12 }}
            value={activeVariantId}
            onChange={e => setActiveVariantId(e.target.value)}
          >
            <option value="__base__">Base{variantDefaultId ? '' : ' (default)'}</option>
            {variantList.map(v => (
              <option key={v.id} value={v.id}>
                {v.alias ? `$${v.alias}` : '$alias?'}
                {v.name ? ` — ${v.name}` : ''}
                {variantDefaultId === v.id ? ' (default)' : ''}
              </option>
            ))}
          </select>
        </div>
      )}
      <button
        type="button"
        className="surface-toolbar-btn"
        title="Reset pan & zoom"
        aria-label="Reset pan and zoom"
        onClick={() => {
          if (!svgRef.current || !zoomRef.current) return;
          d3.select(svgRef.current)
            .transition()
            .duration(250)
            .call(zoomRef.current.transform as any, computeFitToActorsTransform());
          if (externalCanvasViewRef) {
            externalCanvasViewRef.current = null;
          }
        }}
        style={{
          position: 'absolute',
          top: 8,
          right: 48,
          zIndex: 5,
          display: resetViewRef ? 'none' : undefined,
        }}
      >
        <i className="fas fa-crosshairs" />
      </button>
      <button
        type="button"
        className="surface-toolbar-btn"
        title="Download canvas as PNG"
        aria-label="Download canvas as PNG"
        onClick={handleExportPng}
        style={{
          position: 'absolute',
          top: 8,
          right: 88,
          zIndex: 5,
          display: exportPngRef ? 'none' : undefined,
        }}
      >
        <i className="fas fa-camera" />
      </button>
      {dragHint && (
        <div
          className="surface-drag-hint"
          style={{
            position: 'absolute',
            left: dragHint.x,
            top: dragHint.y,
            pointerEvents: 'none',
            padding: '4px 8px',
            borderRadius: 4,
            fontSize: 12,
            fontWeight: 500,
            background: dragHint.ok ? 'rgba(28, 200, 138, 0.95)' : 'rgba(231, 74, 59, 0.95)',
            color: '#fff',
            boxShadow: '0 2px 6px rgba(0,0,0,0.25)',
            maxWidth: 280,
            whiteSpace: 'normal',
            zIndex: 10,
          }}
        >
          {dragHint.text}
        </div>
      )}
      {dragStatus && (
        <div
          className="surface-drag-status"
          style={{
            position: 'absolute',
            left: 8,
            right: 8,
            bottom: 8,
            pointerEvents: 'none',
            padding: '4px 10px',
            borderRadius: 4,
            fontSize: 12,
            fontWeight: 500,
            background: 'transparent',
            color: 'rgba(140, 140, 140, 0.9)',
            textAlign: 'left',
            zIndex: 10,
          }}
        >
          {dragStatus}
        </div>
      )}
      {nodes.length === 0 && (
        <div className="canvas-empty-state">
          <i className="fas fa-project-diagram" />
          <p>Drag elements from the palette onto the canvas</p>
          <p className="small mt-1">
            Start with an Access Point to define how callers reach your agent
          </p>
        </div>
      )}
    </div>
  );
};

export default SurfaceCanvas;
