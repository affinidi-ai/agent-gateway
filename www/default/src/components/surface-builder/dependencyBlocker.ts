import { registry } from './elements/registry';

export interface DependencyError {
  nodeId: string;
  nodeType: string;
  message: string;
}

/**
 * The first error-severity feature dependency as a blocking reason, or null.
 * Blocks Save, and switching variants: a switch rebuilds the outgoing
 * variant from the canvas, which drops what such a node cannot save.
 */
export function dependencyErrorBlocker(
  errors: ReadonlyArray<DependencyError>
): { message: string; nodeId: string } | null {
  const first = errors[0];
  if (!first) return null;
  const label = registry.get(first.nodeType)?.label ?? first.nodeType;
  return { message: `${label}: ${first.message}`, nodeId: first.nodeId };
}
