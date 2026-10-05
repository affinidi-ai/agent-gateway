import { useCallback, useEffect, useState } from 'react';
import { formatDID } from '../../utils/stringUtils';
import { getIssuers } from '../../utils/issuersCache';
import type { NameResolver } from './trustChain';

/**
 * Resolves DIDs to human-readable names for the trust-chain ladder. Loads the
 * gateway's issuers once (memoised via `issuersCache`) and builds a
 * `did → name` map; anything unresolved falls back to a truncated DID
 * (`formatDID`). Returns a stable resolver that re-derives when the map loads.
 */
export function useDidNames(): NameResolver {
  const [names, setNames] = useState<Record<string, string>>({});

  useEffect(() => {
    let active = true;
    Promise.resolve()
      .then(getIssuers)
      .then(issuers => {
        if (!active) return;
        const map: Record<string, string> = {};
        for (const i of issuers) {
          if (i.did && i.name) map[i.did] = i.name;
        }
        setNames(map);
      })
      .catch(() => {
        /* leave the map empty — resolver falls back to formatDID */
      });
    return () => {
      active = false;
    };
  }, []);

  return useCallback(
    (did: string | null | undefined) => {
      if (!did) return '';
      return names[did] ?? formatDID(did);
    },
    [names]
  );
}
