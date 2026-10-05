/**
 * Template placement engine.
 *
 * Two-step flow:
 *   1. `planTemplate(template, nodes)` classifies each item as
 *      clean / conflict / unsupported. A conflict is a singleton-
 *      cardinality kind that already exists on the canvas.
 *   2. `applyPlan(plan, nodes, decisions)` runs the per-item
 *      decisions to produce the next node list + summary.
 *
 * `applyTemplate` is a one-shot helper: plan + apply with the
 * engine's suggested defaults (used when the caller doesn't want to
 * open the conflict modal — e.g. plan came back conflict-free).
 *
 * The engine never mutates inputs. Items addressed at scopes the
 * engine doesn't yet route (e.g. `edge`, `surface`) land in
 * `unsupported`.
 */

import type { CanvasNode } from '../SurfaceCanvas';
import type { SurfaceNodeType } from '../nodeTypes';
import { registry } from '../elements';
import { getArchetype } from '../elements/edges/archetypes';
import type {
  EdgeDropIntent,
  NodeDropIntent,
  PlacementDecision,
  PlacementResult,
  SurfaceTemplate,
  SurfaceTemplateItem,
  TemplatePlan,
} from './types';

/**
 * Scopes that resolve to a free-standing canvas node. Edge-bound
 * items (`scope: "edge"`) take a separate path because the engine
 * has to defer to the builder's `handleDrop` to compute the proper
 * parentId / slot topology.
 */
const NODE_PLACEMENT_SCOPES = new Set([
  'target',
  'access_point',
  'transit_point',
  'channel_policy',
  'gateway_policy',
]);

/**
 * Parsed `address` for an `edge`-scope item. Two accepted forms:
 *
 *   1. Concrete node-type pair:  `<src-type>-><tgt-type>[/<direction>]`
 *      e.g. `access-point->target/response`. Resolves to the unique
 *      node of each type currently on the canvas.
 *
 *   2. Archetype shorthand:      `<archetype-id>[/<direction>]`
 *      e.g. `ma-external/request`. Resolves to ANY node pair on the
 *      canvas that the named edge archetype's `matches(s, t)`
 *      predicate accepts. Use this when the target side has multiple
 *      flavours (e.g. `ma-external` accepts npc-endpoint OR
 *      local-gateway-hop OR remote-gateway) so a single template
 *      lands on whichever flavour the user has dropped.
 *
 * Direction defaults to `request` when omitted.
 */
type EdgeAddress =
  | {
      mode: 'pair';
      srcType: SurfaceNodeType;
      tgtType: SurfaceNodeType;
      direction: 'request' | 'response';
    }
  | {
      mode: 'archetype';
      archetypeId: string;
      direction: 'request' | 'response';
    };

function parseEdgeAddress(address: string | undefined): EdgeAddress | null {
  if (!address) return null;
  const [endpoints, dirRaw] = address.split('/');
  if (!endpoints) return null;
  const direction = dirRaw === 'response' ? 'response' : 'request';
  if (endpoints.includes('->')) {
    const [src, tgt] = endpoints.split('->');
    if (!src || !tgt) return null;
    return {
      mode: 'pair',
      srcType: src.trim() as SurfaceNodeType,
      tgtType: tgt.trim() as SurfaceNodeType,
      direction,
    };
  }
  const archetypeId = endpoints.trim();
  if (!archetypeId) return null;
  return { mode: 'archetype', archetypeId, direction };
}

interface ResolvedEdge {
  src: CanvasNode;
  tgt: CanvasNode;
  direction: 'request' | 'response';
}

function describeAddress(addr: EdgeAddress): string {
  return addr.mode === 'pair'
    ? `${addr.srcType}\u2192${addr.tgtType}`
    : `archetype '${addr.archetypeId}'`;
}

function resolveEdgeEndpoints(addr: EdgeAddress, existingNodes: CanvasNode[]): ResolvedEdge | null {
  if (addr.mode === 'pair') {
    const src = existingNodes.find(n => n.type === addr.srcType);
    const tgt = existingNodes.find(n => n.type === addr.tgtType);
    if (!src || !tgt) return null;
    return { src, tgt, direction: addr.direction };
  }
  const arch = getArchetype(addr.archetypeId);
  if (!arch) return null;
  for (const src of existingNodes) {
    for (const tgt of existingNodes) {
      if (src.id === tgt.id) continue;
      if (arch.matches(src, tgt)) {
        return { src, tgt, direction: addr.direction };
      }
    }
  }
  return null;
}

export function planTemplate(template: SurfaceTemplate, existingNodes: CanvasNode[]): TemplatePlan {
  const plan: TemplatePlan = {
    template,
    clean: [],
    conflicts: [],
    unsupported: [],
  };

  // Full-kind templates are applied via `applyFullTemplate` (channel
  // snapshot + replace flow), not via the incremental plan/apply
  // pipeline. Surface a single synthetic unsupported entry so callers
  // routing every template through `planTemplate` get a clear signal
  // instead of a silently empty plan.
  if (template.kind === 'full') {
    plan.unsupported.push({
      itemIndex: 0,
      item: {
        scope: 'surface',
        kind: 'full-template',
        config: {},
      },
      reason: "full templates must be applied via 'applyFullTemplate', not planTemplate",
    });
    return plan;
  }

  (template.items ?? []).forEach((item, itemIndex) => {
    if (item.scope === 'edge') {
      const addr = parseEdgeAddress(item.address);
      if (!addr) {
        plan.unsupported.push({
          itemIndex,
          item,
          reason: `edge item missing or malformed address (got '${item.address ?? ''}')`,
        });
        return;
      }
      if (addr.mode === 'archetype' && !getArchetype(addr.archetypeId)) {
        plan.unsupported.push({
          itemIndex,
          item,
          reason: `unknown edge archetype '${addr.archetypeId}'`,
        });
        return;
      }
      const resolved = resolveEdgeEndpoints(addr, existingNodes);
      if (!resolved) {
        plan.unsupported.push({
          itemIndex,
          item,
          reason: `edge ${describeAddress(addr)} is not on the canvas`,
        });
        return;
      }
      const def = registry.get(item.kind as SurfaceNodeType);
      if (!def) {
        plan.unsupported.push({
          itemIndex,
          item,
          reason: `unknown element kind '${item.kind}'`,
        });
        return;
      }
      // Edge-bound items always take the clean path — the builder's
      // handleDrop owns conflict resolution (it rejects duplicate
      // per-endpoint slots with its own toast).
      plan.clean.push({ itemIndex, item });
      return;
    }
    if (item.scope === 'node') {
      // Node-bound items (dropMode: 'node') become a child of an
      // existing node identified by `address` (a node type, e.g.
      // "target"). Multi-cardinality kinds add a child; singleton
      // kinds with the parent already occupying flag a conflict.
      const targetType = (item.address ?? '').trim() as SurfaceNodeType;
      if (!targetType) {
        plan.unsupported.push({
          itemIndex,
          item,
          reason: "node item missing 'address' (node type to attach to)",
        });
        return;
      }
      const parent = existingNodes.find(n => n.type === targetType);
      if (!parent) {
        plan.unsupported.push({
          itemIndex,
          item,
          reason: `node of type '${targetType}' is not on the canvas`,
        });
        return;
      }
      const def = registry.get(item.kind as SurfaceNodeType);
      if (!def) {
        plan.unsupported.push({
          itemIndex,
          item,
          reason: `unknown element kind '${item.kind}'`,
        });
        return;
      }
      const existing = existingNodes.find(n => n.type === item.kind);
      if (def.cardinality === 'singleton' && existing) {
        plan.conflicts.push({
          itemIndex,
          item,
          existingNode: existing,
          suggested: 'merge',
        });
        return;
      }
      plan.clean.push({ itemIndex, item });
      return;
    }
    if (!NODE_PLACEMENT_SCOPES.has(item.scope)) {
      plan.unsupported.push({
        itemIndex,
        item,
        reason: `scope '${item.scope}' is not supported yet`,
      });
      return;
    }
    const def = registry.get(item.kind as SurfaceNodeType);
    if (!def) {
      plan.unsupported.push({
        itemIndex,
        item,
        reason: `unknown element kind '${item.kind}'`,
      });
      return;
    }
    const existing = existingNodes.find(n => n.type === item.kind);
    if (def.cardinality === 'singleton' && existing) {
      plan.conflicts.push({
        itemIndex,
        item,
        existingNode: existing,
        // Merge is least destructive while still surfacing the
        // template's values for empty fields.
        suggested: 'merge',
      });
      return;
    }
    plan.clean.push({ itemIndex, item });
  });

  return plan;
}

/**
 * Run the resolved plan. `decisions` maps `itemIndex` → user choice
 * for items in `plan.conflicts`. Items in `plan.clean` are always
 * placed; items in `plan.unsupported` are always skipped.
 */
export function applyPlan(
  plan: TemplatePlan,
  existingNodes: CanvasNode[],
  decisions: Record<number, PlacementDecision>
): PlacementResult {
  const nextNodes = existingNodes.slice();
  const placed: SurfaceTemplateItem[] = [];
  const skipped: PlacementResult['skipped'] = [];
  const edgeDrops: EdgeDropIntent[] = [];
  const nodeDrops: NodeDropIntent[] = [];

  plan.unsupported.forEach(s => skipped.push({ item: s.item, reason: s.reason }));

  let yCursor = 80;
  const baseX = 0;

  const appendNew = (item: SurfaceTemplateItem) => {
    const def = registry.get(item.kind as SurfaceNodeType);
    if (!def) {
      skipped.push({ item, reason: `unknown element kind '${item.kind}'` });
      return;
    }
    const baseConfig = typeof def.defaultConfig === 'function' ? def.defaultConfig() : {};
    const mergedConfig = deepMergePreferringRight(baseConfig, item.config ?? {});
    const id = `tpl-${plan.template.id}-${Math.random().toString(36).slice(2, 8)}`;
    nextNodes.push({
      id,
      type: item.kind as SurfaceNodeType,
      label: def.label,
      configured: false,
      config: mergedConfig,
      position: { x: baseX, y: yCursor },
    });
    yCursor += 120;
    placed.push(item);
  };

  plan.clean.forEach(({ item }) => {
    if (item.scope === 'edge') {
      const addr = parseEdgeAddress(item.address);
      if (!addr) {
        skipped.push({ item, reason: 'malformed edge address' });
        return;
      }
      const resolved = resolveEdgeEndpoints(addr, existingNodes);
      if (!resolved) {
        skipped.push({ item, reason: 'edge endpoints disappeared' });
        return;
      }
      edgeDrops.push({
        item,
        kind: item.kind,
        edgeSourceId: resolved.src.id,
        edgeTargetId: resolved.tgt.id,
        edgeDirection: resolved.direction,
        config: item.config ?? {},
      });
      placed.push(item);
      return;
    }
    if (item.scope === 'node') {
      const targetType = (item.address ?? '').trim() as SurfaceNodeType;
      const parent = existingNodes.find(n => n.type === targetType);
      if (!parent) {
        skipped.push({ item, reason: 'target node disappeared' });
        return;
      }
      nodeDrops.push({
        item,
        kind: item.kind,
        targetNodeId: parent.id,
        config: item.config ?? {},
      });
      placed.push(item);
      return;
    }
    appendNew(item);
  });

  plan.conflicts.forEach(conflict => {
    const decision = decisions[conflict.itemIndex] ?? conflict.suggested;
    switch (decision) {
      case 'skip':
        skipped.push({ item: conflict.item, reason: 'skipped by user' });
        return;
      case 'place':
        // User explicitly chose to add a second instance even though
        // this is a singleton kind. We honour it.
        appendNew(conflict.item);
        return;
      case 'overwrite': {
        const idx = nextNodes.findIndex(n => n.id === conflict.existingNode.id);
        if (idx < 0) {
          skipped.push({ item: conflict.item, reason: 'existing node disappeared' });
          return;
        }
        const def = registry.get(conflict.item.kind as SurfaceNodeType);
        const baseConfig =
          def && typeof def.defaultConfig === 'function' ? def.defaultConfig() : {};
        const merged = deepMergePreferringRight(baseConfig, conflict.item.config ?? {});
        nextNodes[idx] = { ...nextNodes[idx], config: merged, configured: false };
        placed.push(conflict.item);
        return;
      }
      case 'merge': {
        const idx = nextNodes.findIndex(n => n.id === conflict.existingNode.id);
        if (idx < 0) {
          skipped.push({ item: conflict.item, reason: 'existing node disappeared' });
          return;
        }
        const existingCfg = nextNodes[idx].config ?? {};
        const mergedCfg = mergeFillingEmpty(existingCfg, conflict.item.config ?? {});
        nextNodes[idx] = { ...nextNodes[idx], config: mergedCfg };
        placed.push(conflict.item);
        return;
      }
    }
  });

  return { nextNodes, placed, skipped, edgeDrops, nodeDrops };
}

/** One-shot apply with the engine's suggested defaults. */
export function applyTemplate(
  template: SurfaceTemplate,
  existingNodes: CanvasNode[]
): PlacementResult {
  const plan = planTemplate(template, existingNodes);
  return applyPlan(plan, existingNodes, {});
}

/** Deep-merge where right wins for non-object leaves. */
function deepMergePreferringRight(left: any, right: any): any {
  if (right === undefined || right === null) return left;
  if (typeof right !== 'object' || Array.isArray(right)) return right;
  if (typeof left !== 'object' || Array.isArray(left) || left === null) {
    return right;
  }
  const out: Record<string, unknown> = { ...left };
  for (const k of Object.keys(right)) {
    out[k] = deepMergePreferringRight(left[k], right[k]);
  }
  return out;
}

/**
 * Merge semantics: write `incoming` only where `existing` is null /
 * undefined / empty string. Object fields recurse; non-object
 * existing values that are empty are replaced.
 */
function mergeFillingEmpty(existing: any, incoming: any): any {
  if (incoming === undefined || incoming === null) return existing;
  if (typeof incoming !== 'object' || Array.isArray(incoming)) {
    return isEmpty(existing) ? incoming : existing;
  }
  if (typeof existing !== 'object' || Array.isArray(existing) || existing === null) {
    return isEmpty(existing) ? incoming : existing;
  }
  const out: Record<string, unknown> = { ...existing };
  for (const k of Object.keys(incoming)) {
    out[k] = mergeFillingEmpty(existing[k], incoming[k]);
  }
  return out;
}

function isEmpty(v: unknown): boolean {
  return v === undefined || v === null || v === '';
}
