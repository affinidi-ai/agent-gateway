import type { SurfaceNodeType } from './nodeTypes';

export function shouldShowDependencyWarnings(
  type: SurfaceNodeType,
  hasAttemptedSave: boolean,
  config?: Record<string, unknown>
): boolean {
  if (type !== 'payment') return true;
  return hasAttemptedSave || !!config?.unsupported_legacy;
}
