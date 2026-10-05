import type { CanvasNode } from '../SurfaceCanvas';
import { registry } from './registry';
import type { Protocol, SurfaceContext } from './types';

/**
 * Build a `SurfaceContext` from the canvas node list.
 * Used by `registry.getDependencyWarnings()` and similar context-aware checks.
 */
export function buildSurfaceContext(
  protocol: string | undefined,
  allNodes: CanvasNode[] | undefined
): SurfaceContext {
  const nodes = allNodes ?? [];
  const accessPoint = nodes.find(n => n.type === 'access-point');
  const target = nodes.find(n => n.type === 'target');
  const transitPoints = nodes.filter(n => registry.isTransitPointType(n.type));
  return {
    protocol: (protocol as Protocol) || 'a2a',
    accessPoint: accessPoint?.config ?? {},
    target: target?.config ?? {},
    transitPoints: transitPoints.map(t => t.config ?? {}),
    allNodes: nodes,
  };
}
