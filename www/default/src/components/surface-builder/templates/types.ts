/**
 * Templates feature — shared types for the placement engine and panel.
 *
 * The data shape from the wire is `SurfaceTemplate` in `../../api`;
 * this file adds frontend-only helpers (placement decisions, diffs)
 * that don't belong on the API surface.
 */

import type { SurfaceTemplate, SurfaceTemplateItem } from '../../../api';
import type { CanvasNode } from '../SurfaceCanvas';

export type { SurfaceTemplate, SurfaceTemplateItem };

/**
 * Per-item decision for conflict resolution.
 *  - `place`: no conflict — append a fresh node.
 *  - `skip`: drop this item from the apply.
 *  - `overwrite`: replace the conflicting node's config with the
 *    template's config (preserving id, position, edges).
 *  - `merge`: deep-merge the template's config into the existing one,
 *    only filling fields the existing config left empty.
 */
export type PlacementDecision = 'place' | 'skip' | 'overwrite' | 'merge';

/** Conflict between a template item and an existing canvas node. */
export interface TemplateItemConflict {
  itemIndex: number;
  item: SurfaceTemplateItem;
  existingNode: CanvasNode;
  suggested: PlacementDecision;
}

/** Items the engine can't process (unknown kind / scope). */
export interface TemplateItemSkip {
  itemIndex: number;
  item: SurfaceTemplateItem;
  reason: string;
}

/** Plan produced before applying — used to decide whether to open the modal. */
export interface TemplatePlan {
  template: SurfaceTemplate;
  clean: { itemIndex: number; item: SurfaceTemplateItem }[];
  conflicts: TemplateItemConflict[];
  unsupported: TemplateItemSkip[];
}

/**
 * Result of running the placement engine. The engine never mutates
 * the caller's state — it returns a new node list plus per-item
 * status the UI can surface.
 *
 * `edgeDrops` are intents the caller must execute via the builder's
 * `handleDrop` (the placement engine is pure and can't run the
 * full edge-binding logic itself).
 */
export interface PlacementResult {
  nextNodes: CanvasNode[];
  placed: SurfaceTemplateItem[];
  skipped: { item: SurfaceTemplateItem; reason: string }[];
  edgeDrops: EdgeDropIntent[];
  nodeDrops: NodeDropIntent[];
}

/**
 * An edge-bound placement the caller must execute after committing
 * `nextNodes`. The caller calls `builder.handleDrop(kind, ctx)` with
 * the resolved source/target IDs, then patches the new node's config
 * by merging `config` onto whatever `handleDrop` set.
 */
export interface EdgeDropIntent {
  item: SurfaceTemplateItem;
  kind: string;
  edgeSourceId: string;
  edgeTargetId: string;
  edgeDirection: 'request' | 'response';
  config: Record<string, unknown>;
}

/**
 * A node-bound placement (for elements with `dropMode: 'node'` such
 * as identity, where the new node becomes a child of an existing
 * node identified by type). Executed via
 * `builder.handleNodeTemplateDrop`.
 */
export interface NodeDropIntent {
  item: SurfaceTemplateItem;
  kind: string;
  targetNodeId: string;
  config: Record<string, unknown>;
}
