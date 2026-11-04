/**
 * The per-caller limit of a Transit Point (`transit.points[].per_caller_rate_limit`),
 * from the panel's `caller_*` fields. Only a Transit Point's rate-limit node
 * carries them.
 */
export function perCallerRateLimitConfigToWire(c: any): Record<string, any> | undefined {
  if (!c?.caller_requests) return undefined;
  return {
    requests: parseInt(c.caller_requests),
    window_secs: parseInt(c.caller_window_secs) || 60,
    ...(c.caller_burst ? { burst: parseInt(c.caller_burst) } : {}),
  };
}

/**
 * The panel's flat config for a stored Transit Point's limits: the shared
 * limit as `requests`, `window_secs` and `burst`, and the per-caller limit
 * with a `caller_` prefix, as strings for the numeric inputs.
 */
export function rateLimitConfigFromWire(shared: any, perCaller: any): Record<string, string> {
  const config: Record<string, string> = {};
  if (shared && shared.requests != null) {
    config.requests = String(shared.requests);
    config.window_secs = String(shared.window_secs ?? 60);
    if (shared.burst != null) config.burst = String(shared.burst);
  }
  if (perCaller && perCaller.requests != null) {
    config.caller_requests = String(perCaller.requests);
    config.caller_window_secs = String(perCaller.window_secs ?? 60);
    if (perCaller.burst != null) config.caller_burst = String(perCaller.burst);
  }
  return config;
}
