import { useCallback, useEffect, useState } from 'react';
import { ApiError, apiClient } from '../../api';
import type { UserNameResolver } from './eventNarrative';

let cached: Promise<Record<string, string>> | null = null;

/**
 * Loads `user_id → username` once per page load. A caller without access to
 * the users list (403) gets an empty map, kept so the list is not asked for
 * again; any other failure is forgotten so a later visit asks again.
 */
function loadUserNames(): Promise<Record<string, string>> {
  cached ??= apiClient
    .get('/users')
    .then(response => {
      const names: Record<string, string> = {};
      if (Array.isArray(response.data)) {
        for (const user of response.data) {
          if (typeof user?.user_id === 'string' && typeof user?.username === 'string') {
            names[user.user_id] = user.username;
          }
        }
      }
      return names;
    })
    .catch(error => {
      if (!(error instanceof ApiError && error.status === 403)) cached = null;
      return {};
    });
  return cached;
}

/** Drop the loaded names so the next lookup asks for the users list again. */
export function clearUserNames(): void {
  cached = null;
}

/**
 * Resolves the user ids policy change records name to usernames. Records hold
 * ids only; an id the dashboard cannot resolve stays an id. The users list is
 * asked for only once `needed`, when the page shows a policy change. Call it
 * once per page and pass the resolver down.
 */
export function useUserNames(needed: boolean): UserNameResolver {
  const [names, setNames] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!needed) return undefined;
    let active = true;
    loadUserNames().then(loaded => {
      if (active) setNames(loaded);
    });
    return () => {
      active = false;
    };
  }, [needed]);

  return useCallback((userId: string) => names[userId], [names]);
}
