import type { AgentSurface } from '../../api';
import type { CanvasNode } from './SurfaceCanvas';
import type { SurfaceNodeType } from './nodeTypes';
import { readCanvasSurfaceSize, readCanvasView, registry } from './elements';
import { computeAutoLayout } from './autoLayout';

/**
 * Reconstruct the live canvas nodes from a saved AgentSurface payload.
 * Mirrors the wizard's drop-time defaults so the canvas-only nodes
 * (human, caller, the External-Target NPC) appear when the surface
 * predates the canvas blob or was authored elsewhere.
 *
 * Shared by SurfaceDetailPage (load + variant switch + json import) and
 * AddSurfacePage (json import) so a single function defines what "this
 * payload becomes on the canvas" means everywhere.
 */
function reconstructNodesFromSurface(surface: AgentSurface | null): CanvasNode[] {
  if (!surface) return [];
  const reconstructed = registry.nodesFromPayload(surface).map(n => ({
    id: n.id,
    type: n.type as SurfaceNodeType,
    label: n.label,
    configured: n.configured,
    config: n.config,
    parentId: n.parentId,
    ...(n.position ? { position: n.position } : {}),
    ...(typeof n.radius === 'number' ? { radius: n.radius } : {}),
    ...(n.direction ? { direction: n.direction } : {}),
    ...(n.slotId ? { slotId: n.slotId } : {}),
    ...(n.config?.npc_description ? { description: n.config.npc_description } : {}),
    ...(n.config?.description ? { description: n.config.description } : {}),
  })) as CanvasNode[];

  const hasHuman = reconstructed.some(n => n.id === '__human__');
  const hasCaller = reconstructed.some(n => n.id === '__caller__');
  const hasManagedAgentNpc = reconstructed.some(
    n => n.type === 'npc-endpoint' && n.parentId === 'target'
  );
  const prefix: CanvasNode[] = [];
  if (!hasHuman) {
    prefix.push({ id: '__human__', type: 'human', label: 'Human', configured: true, config: {} });
  }
  if (!hasCaller) {
    prefix.push({
      id: '__caller__',
      type: 'caller',
      label: 'Caller',
      configured: true,
      config: {},
    });
  }
  const suffix: CanvasNode[] = [];
  if (!hasManagedAgentNpc && reconstructed.some(n => n.id === 'target')) {
    suffix.push({
      id: '__managed-agent-npc__',
      type: 'npc-endpoint',
      label: 'External Target',
      configured: true,
      config: {
        name: 'External Target',
        npc_description: 'External agent endpoint',
        connection_direction: 'outbound',
        connected_to: 'target',
      },
      parentId: 'target',
      connectionDirection: 'outbound',
      description: 'External agent endpoint',
    });
  }
  const nodes = [...prefix, ...reconstructed, ...suffix];
  return nodes;
}

export interface HydratedSurfaceCanvas {
  nodes: CanvasNode[];
  surfaceSize: { width: number; height: number } | null;
  view: { x: number; y: number; k: number } | null;
  didAutoLayout: boolean;
}

export function hydrateSurfaceCanvas(surface: AgentSurface | null): HydratedSurfaceCanvas {
  const nodes = reconstructNodesFromSurface(surface);
  const surfaceSize = readCanvasSurfaceSize(surface);
  const view = readCanvasView(surface);
  const visibleNodes = nodes.filter(node => node.type !== 'target-variant');
  if (visibleNodes.every(node => node.position)) {
    return { nodes, surfaceSize, view, didAutoLayout: false };
  }

  const layout = computeAutoLayout(nodes);
  const positions = new Map(layout.positions.map(position => [position.id, position] as const));
  const laidOutNodes = nodes.map(node => {
    const position = positions.get(node.id);
    return position ? { ...node, position: { x: position.x, y: position.y } } : node;
  });
  return {
    nodes: laidOutNodes,
    surfaceSize: { width: layout.surfaceSize.w, height: layout.surfaceSize.h },
    view: null,
    didAutoLayout: true,
  };
}

export function nodesFromSurface(surface: AgentSurface | null): CanvasNode[] {
  return hydrateSurfaceCanvas(surface).nodes;
}
