import type { SurfaceNodeType } from './nodeTypes';

export function shouldShowDependencyWarnings(
  type: SurfaceNodeType,
  hasAttemptedSave: boolean
): boolean {
  return type !== 'payment' || hasAttemptedSave;
}
