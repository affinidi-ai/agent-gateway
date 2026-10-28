import { useCallback, useEffect, useState } from 'react';
import { ApiError, apiClient, sessionManager } from '../../api';
import type { UserNameResolver } from './eventNarrative';

/** The names loaded for one session, so another session never sees them. */
let cached: { session: string | null; names: Promise<Record<string, string>> } | null = null;

/**
 * Loads `user_id → username` once per session. A caller refused the users
 * list (403) gets an empty map, kept for that session so the list is not
 * asked for again; any other failure is forgotten so a later visit asks
 * again. Signing out and in, as anyone, starts a new session and a new load.
 */
function loadUserNames(): Promise<Record<string, string>> {
  const session = sessionManager.getSessionToken();
  if (cached?.session === session) return cached.names;
  const names = apiClient
    .get('/users')
    .then(response => {
      const loaded: Record<string, string> = {};
      if (Array.isArray(response.data)) {
        for (const user of response.data) {
          if (typeof user?.user_id === 'string' && typeof user?.username === 'string') {
            loaded[user.user_id] = user.username;
          }
        }
      }
      return loaded;
    })
    .catch(error => {
      if (!(error instanceof ApiError && error.status === 403) && cached?.names === names) {
        cached = null;
      }
      return {};
    });
  cached = { session, names };
  return names;
}

/** Drop the loaded names so the next lookup asks for the users list again. */
export function clearUserNames(): void {
  cached = null;
}

/**
 * Resolves the user ids policy change records name to usernames. Records hold
 * ids only; an id the dashboard cannot resolve stays an id. The users list is
 * asked for only once `needed`: the page shows a policy change and the viewer
 * has `users.view`. Call it once per page and pass the resolver down.
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
