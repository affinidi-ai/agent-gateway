/**
 * Edge & slot model — first-class representation of the surface-builder
 * graph topology.
 *
 * Today's `nodes[]` + `parentId` shape is the persistence model. The edge
 * model is **derived** per render by `deriveEdges(nodes)` and consumed by
 * both the renderer and the drop handler so they cannot diverge.
 *
 * These types support a read-only adapter that reconstructs
 * `DerivedEdge[]` from today's state without changing runtime
 * behaviour.
 */

import type { CanvasNode } from '../../SurfaceCanvas';
import type { SurfaceNodeType } from '../../nodeTypes';

/** Stable identifier of a slot within an `EdgeArchetypeDef`. */
export type SlotId = string;

/** Stable identifier of an edge archetype (e.g. `ap-ma`, `ma-tp`). */
export type EdgeArchetypeId = string;

export type SlotDirection = 'request' | 'response';

/**
 * One named slot along an edge archetype. Slots are the unit of
 * accept/reject for drag-and-drop and the unit of routing into the
 * AgentSurface payload.
 */
export interface SlotDef {
  id: SlotId;
  direction: SlotDirection;
  /**
   * Render order along the edge from source to target. Lower values
   * sit closer to the source endpoint. Per-endpoint slots
   * (`ownedBy: 'target'` with `order: 0`) appear adjacent to their
   * owner.
   */
  order: number;
  /** Element types this slot accepts. */
  accepts: ReadonlyArray<SurfaceNodeType>;
  cardinality: 'one' | 'many';
  /**
   * For per-endpoint slots, names which endpoint owns the slot. The
   * owner's id is substituted into `payloadPathTemplate` as `{owner}`.
   * Example: per-TP response policy is owned by the TP target endpoint
   * of the MA→TP edge and writes to
   * `transit.points[{owner}].response_policy`.
   */
  ownedBy?: 'source' | 'target';
  /** Dot-notation template into the AgentSurface payload. */
  payloadPathTemplate: string;
  /** User-facing label for drag-time tooltips. */
  label: string;
}

/**
 * One archetype of edge in the surface graph (e.g. AP↔MA, MA↔TP). The
 * archetype owns the slot inventory; `matches` decides whether a given
 * pair of endpoint nodes form an instance of this archetype.
 */
export interface EdgeArchetypeDef {
  id: EdgeArchetypeId;
  /** Returns true when these endpoints form an instance of this archetype. */
  matches: (src: CanvasNode, tgt: CanvasNode) => boolean;
  /** Directions the archetype renders arrows for. */
  directions: ReadonlyArray<SlotDirection>;
  slots: ReadonlyArray<SlotDef>;
}

/**
 * Derived per render — never persisted. One `DerivedEdge` per logical
 * edge in the surface; slot occupancy is keyed by `SlotId`.
 */
export interface DerivedEdge {
  /** Stable id: `${archetype}:${sourceId}:${targetId}`. */
  id: string;
  archetype: EdgeArchetypeId;
  endpoints: { source: string; target: string };
  /** Occupant node ids per slot, in declared `order` then drop order. */
  slots: Map<SlotId, string[]>;
}
