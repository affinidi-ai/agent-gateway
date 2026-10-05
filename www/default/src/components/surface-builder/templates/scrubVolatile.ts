/**
 * Strip per-surface volatile listener / identity fields from a
 * surface payload so re-using the same template can't produce two
 * surfaces sharing a listener route or TP id. There is no scalar
 * token vocabulary for transit points (a surface can hold many), so
 * they are blanked rather than substituted.
 *
 * Pure function; never mutates input.
 */

const VOLATILE_TP_STRUCTURED_FIELDS = ['listen_address', 'listen_path', 'id', 'alias'] as const;

// Canvas-blob fields are UI mirrors of structured config. The
// structured side is authoritative on apply, so AP mirrors don't
// need scrubbing — but TPs have their structured listener fields
// blanked above, which means the canvas mirror would silently leak
// back onto the panel if we left it in place.
const VOLATILE_TP_CANVAS_FIELDS = [
  'listen_address',
  'listen_path',
  'route_prefix',
  'route_suffix',
  'id',
  'alias',
] as const;

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export function scrubVolatileTemplateFields<T = unknown>(payload: T): T {
  if (!isObject(payload)) return payload;
  const out = JSON.parse(JSON.stringify(payload)) as Record<string, unknown>;

  const transit = out.transit;
  if (isObject(transit)) {
    const points = (transit as Record<string, unknown>).points;
    if (Array.isArray(points)) {
      for (const tp of points) {
        if (!isObject(tp)) continue;
        for (const f of VOLATILE_TP_STRUCTURED_FIELDS) {
          if (f in tp) delete (tp as Record<string, unknown>)[f];
        }
      }
    }
  }

  const canvas = out.canvas;
  if (isObject(canvas)) {
    const nodes = (canvas as Record<string, unknown>).nodes;
    if (Array.isArray(nodes)) {
      for (const n of nodes) {
        if (!isObject(n)) continue;
        const cfg = (n as Record<string, unknown>).config;
        if (!isObject(cfg)) continue;
        const type = (n as Record<string, unknown>).type;
        if (typeof type === 'string' && type.startsWith('transit-point-')) {
          for (const f of VOLATILE_TP_CANVAS_FIELDS) {
            if (f in cfg) delete (cfg as Record<string, unknown>)[f];
          }
        }
      }
    }
  }

  return out as unknown as T;
}

/**
 * Scan an `AgentSurface`-ish payload for two listeners that would
 * register the same `(listen_address, path)` tuple. Returns the
 * conflict string or `null` when none. Handles the access point's
 * `route` and every `transit.points[i].listen_path` together because
 * the gateway register both kinds against the same listener.
 *
 * Note: only catches *within-payload* duplicates. Cross-surface
 * collisions are the gateway's job to reject on POST.
 */
export function findDuplicateListenerRoutes(payload: unknown): string | null {
  if (!isObject(payload)) return null;
  const seen = new Map<string, string>();
  const record = (host: unknown, route: unknown, label: string): string | null => {
    if (typeof host !== 'string' || typeof route !== 'string') return null;
    if (!host || !route) return null;
    const key = `${host}${route}`;
    const existing = seen.get(key);
    if (existing && existing !== label) {
      return `${label} listens on ${host}${route}, which collides with ${existing}. Choose a different Surface Prefix or Custom Path for ${label} to resolve.`;
    }
    seen.set(key, label);
    return null;
  };

  const ap = (payload as Record<string, unknown>).access_point;
  if (isObject(ap)) {
    const err = record(ap.listen_address, ap.route, 'access point');
    if (err) return err;
  }

  const transit = (payload as Record<string, unknown>).transit;
  if (isObject(transit)) {
    const points = (transit as Record<string, unknown>).points;
    if (Array.isArray(points)) {
      for (let i = 0; i < points.length; i++) {
        const tp = points[i];
        if (!isObject(tp)) continue;
        const alias = typeof tp.alias === 'string' && tp.alias ? tp.alias : `tp[${i}]`;
        const err = record(tp.listen_address, tp.listen_path, `transit point ${alias}`);
        if (err) return err;
      }
    }
  }

  return null;
}
