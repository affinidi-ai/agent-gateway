import type { Protocol } from './elements/types';

interface ExistingSurface {
  name?: unknown;
  access_point?: { protocol?: unknown };
}

/**
 * Default name for a new surface: `<protocol>_surface_<n>`, where `n` is one
 * more than the number of existing surfaces of that protocol, bumped past any
 * name already taken (compared case-insensitively).
 */
export function defaultSurfaceName(
  protocol: Protocol,
  existing: readonly ExistingSurface[]
): string {
  const taken = new Set(
    existing.map(s => (typeof s.name === 'string' ? s.name.trim().toLowerCase() : ''))
  );
  let n = existing.filter(s => s.access_point?.protocol === protocol).length + 1;
  while (taken.has(`${protocol}_surface_${n}`)) n += 1;
  return `${protocol}_surface_${n}`;
}
