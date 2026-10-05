import { apiClient } from '../api';
import type { Issuer } from '../types';

let cached: Promise<Issuer[]> | null = null;

interface CacheReadOptions {
  /** Bypass any resolved/in-flight value and read the latest register from the API. */
  refresh?: boolean;
}

/**
 * Returns the gateway's configured issuers. By default, the resolved
 * promise is memoized so concurrent and subsequent callers share the same
 * in-flight or resolved request. Pass `{ refresh: true }` for editors whose
 * dropdowns must reflect issuers created elsewhere in the current session.
 * A failed fetch is not cached, so the next caller will retry.
 */
export function getIssuers(options: CacheReadOptions = {}): Promise<Issuer[]> {
  if (options.refresh) cached = null;
  if (cached) return cached;
  cached = apiClient.listIssuers().catch(err => {
    cached = null;
    throw err;
  });
  return cached;
}

/** Drop the cached promise so the next `getIssuers()` call refetches. */
export function clearIssuersCache(): void {
  cached = null;
}
