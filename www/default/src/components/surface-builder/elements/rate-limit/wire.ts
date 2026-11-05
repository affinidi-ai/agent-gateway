/** A rate limit as the gateway stores it (`RateLimitConfig`). */
export interface RateLimitWire {
  requests: number;
  window_secs: number;
  burst?: number;
}

/** The Rate Limit panel's limit fields: the shared limit, then the per-caller one. */
export const RATE_LIMIT_FIELDS = [
  'requests',
  'window_secs',
  'burst',
  'caller_requests',
  'caller_window_secs',
  'caller_burst',
] as const;

/** The Rate Limit panel's fields, as strings from its numeric inputs. */
export type RateLimitPanelConfig = Partial<Record<(typeof RATE_LIMIT_FIELDS)[number], string>>;

/**
 * Whether a saved canvas copy of a Transit Point's rate-limit node carries a
 * limit. The stored surface is the only source of those, so a copy that
 * carries one the stored surface no longer has was removed through the API.
 */
export function carriesRateLimit(config: Record<string, unknown> | undefined): boolean {
  return RATE_LIMIT_FIELDS.some(field => config?.[field] != null && config[field] !== '');
}

/**
 * The per-caller limit of a Transit Point (`transit.points[].per_caller_rate_limit`),
 * from the panel's `caller_*` fields. Only a Transit Point's rate-limit node
 * carries them.
 */
export function perCallerRateLimitConfigToWire(
  c: RateLimitPanelConfig | undefined
): RateLimitWire | undefined {
  if (!c?.caller_requests) return undefined;
  return {
    requests: parseInt(c.caller_requests),
    window_secs: parseInt(c.caller_window_secs ?? '') || 60,
    ...(c.caller_burst ? { burst: parseInt(c.caller_burst) } : {}),
  };
}

function limitFromWire(
  limit: Partial<RateLimitWire> | null | undefined,
  prefix: '' | 'caller_'
): RateLimitPanelConfig {
  if (limit?.requests == null) return {};
  return {
    [`${prefix}requests`]: String(limit.requests),
    [`${prefix}window_secs`]: String(limit.window_secs ?? 60),
    ...(limit.burst != null ? { [`${prefix}burst`]: String(limit.burst) } : {}),
  };
}

/**
 * The panel's flat config for a stored Transit Point's limits: the shared
 * limit as `requests`, `window_secs` and `burst`, and the per-caller limit
 * with a `caller_` prefix, as strings for the numeric inputs.
 */
export function rateLimitConfigFromWire(
  shared: Partial<RateLimitWire> | null | undefined,
  perCaller: Partial<RateLimitWire> | null | undefined
): RateLimitPanelConfig {
  return { ...limitFromWire(shared, ''), ...limitFromWire(perCaller, 'caller_') };
}
