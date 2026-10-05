import { apiClient } from '../api';
import type { Authority } from '../types';

let cached: Promise<Authority[]> | null = null;

interface CacheReadOptions {
  /** Bypass any resolved/in-flight value and read the latest register from the API. */
  refresh?: boolean;
}

/**
 * Returns the gateway's configured authorities. By default, the resolved
 * promise is memoized so concurrent and subsequent callers share the same
 * in-flight or resolved request. Pass `{ refresh: true }` for editors whose
 * dropdowns must reflect authorities created elsewhere in the current session.
 * A failed fetch is not cached, so the next caller will retry.
 */
export function getAuthorities(options: CacheReadOptions = {}): Promise<Authority[]> {
  if (options.refresh) cached = null;
  if (cached) return cached;
  cached = apiClient.listAuthorities().catch(err => {
    cached = null;
    throw err;
  });
  return cached;
}

/** Drop the cached promise so the next `getAuthorities()` call refetches. */
export function clearAuthoritiesCache(): void {
  cached = null;
}
