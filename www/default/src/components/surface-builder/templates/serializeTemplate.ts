/**
 * Inverse of the placement engine: convert canvas nodes back into
 * `SurfaceTemplateItem`s suitable for saving as a user template.
 *
 * The inverse is heuristic by necessity — the placement engine's
 * routing decisions (which slot an edge-bound element occupies, which
 * archetype it belongs to) are not all stored on the node. We use the
 * common-case mapping that matches every shipped builtin template:
 *
 *   - `dropMode: 'canvas'` → free-standing node with a scope derived
 *     from the element's role (access_point / target / transit_point;
 *     `surface` for catch-all surface-wide elements).
 *   - `dropMode: 'edge'`   → `scope: 'edge'` between access-point
 *     and target, direction taken from the node's persisted
 *     `direction` field (defaults to `request`).
 *   - `dropMode: 'node'`   → `scope: 'node'`, address = the parent
 *     node's `type` (e.g. identity attached to `target`).
 *
 * Nodes the user can't sensibly template (the auto-injected human
 * actor, the caller, the surface itself, the access-point, the
 * target) are reported via `canSerializeNode = false` so the form
 * can hide them from the picker.
 */

import type { CanvasNode } from '../SurfaceCanvas';
import { registry } from '../elements';
import { deriveEdges } from '../elements/edges/deriveEdges';
import type { ElementDefinition } from '../elements/types';
import type { SurfaceTemplateItem } from '../../../api';

/** Nodes that never make sense to ship inside a user template. */
const EXCLUDED_TYPES = new Set<string>([
  'human',
  'caller',
  'surface',
  'access-point',
  'target',
  'managed-agent',
  'target-variant',
]);

export function canSerializeNode(node: CanvasNode): boolean {
  if (EXCLUDED_TYPES.has(node.type)) return false;
  const def = registry.get(node.type);
  if (!def) return false;
  return true;
}

/**
 * Best-effort label for a node row in the create-template picker.
 * Falls back to the element label, then to the raw type.
 */
export function describeNode(node: CanvasNode): string {
  const def = registry.get(node.type);
  const configName =
    (node.config && typeof node.config === 'object' && (node.config as any).name) || '';
  if (configName) return String(configName);
  if (node.label) return node.label;
  return def?.label ?? node.type;
}

/**
 * Build a `SurfaceTemplateItem` from a placed canvas node. Returns
 * `null` if the node is not serializable (excluded type, unknown
 * element).
 */
export function nodeToTemplateItem(
  node: CanvasNode,
  allNodes: CanvasNode[]
): SurfaceTemplateItem | null {
  if (!canSerializeNode(node)) return null;
  const def = registry.get(node.type) as ElementDefinition | undefined;
  if (!def) return null;

  const config = stripIdentityFields(node.config);

  if (def.dropMode === 'edge') {
    const direction = (node as any).direction === 'response' ? 'response' : 'request';
    // Resolve which edge archetype this node lives on so the
    // serialized address (`<archetype>/<direction>`) is
    // canvas-shape-agnostic. Falls back to the legacy concrete
    // `access-point->target/<dir>` pair only if the node hasn't been
    // bound to a derived edge yet (shouldn't happen in practice).
    const archetypeId = findArchetypeForEdgeNode(node, allNodes);
    const address = archetypeId
      ? `${archetypeId}/${direction}`
      : `access-point->target/${direction}`;
    return {
      scope: 'edge',
      address,
      kind: def.type,
      config,
    };
  }

  if (def.dropMode === 'node') {
    const parent = node.parentId ? allNodes.find(n => n.id === node.parentId) : undefined;
    const parentType = parent?.type ?? 'target';
    return {
      scope: 'node',
      address: parentType,
      kind: def.type,
      config,
    };
  }

  // dropMode === 'canvas': free-standing node.
  let scope: SurfaceTemplateItem['scope'] = 'surface';
  if (registry.isTransitPointType(def.type)) scope = 'transit_point';
  else if (def.surfaceWide) scope = 'surface';
  // (access-point / target / managed-agent are excluded above.)

  return {
    scope,
    kind: def.type,
    config,
  };
}

/**
 * Look up which edge archetype owns this edge-bound node by deriving
 * the canvas's edges and checking each archetype's slot membership.
 * Returns the archetype id (e.g. `ma-external`) or null if the node
 * isn't bound to any derived edge.
 */
function findArchetypeForEdgeNode(node: CanvasNode, allNodes: CanvasNode[]): string | null {
  const edges = deriveEdges(allNodes);
  for (const edge of edges) {
    for (const ids of edge.slots.values()) {
      if (ids.includes(node.id)) return edge.archetype;
    }
  }
  return null;
}

/**
 * Strip fields that are instance-specific and shouldn't ship with a
 * reusable template (ids the gateway assigns at create time, secrets,
 * etc.). Conservative for now — just drops top-level `id` /
 * `surface_id` if present.
 */
function stripIdentityFields(config: unknown): Record<string, unknown> | undefined {
  if (!config || typeof config !== 'object') return undefined;
  const out: Record<string, unknown> = { ...(config as Record<string, unknown>) };
  delete out.id;
  delete out.surface_id;
  return Object.keys(out).length > 0 ? out : undefined;
}
