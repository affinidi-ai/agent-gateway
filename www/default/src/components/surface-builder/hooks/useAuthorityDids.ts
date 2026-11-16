import { useEffect, useState } from 'react';
import type { Authority } from '../../../types';
import { getAuthorities, subscribeAuthorities } from '../../../utils/authoritiesCache';
import { authorityDidSet } from '../elements/_shared/authorityReference';

/**
 * DIDs of the Authorities register, read when the page opens and again when the tab becomes
 * visible, so an Authority added in another tab clears a Trust Check or Trust Recorder that
 * names it. `null` until the first read succeeds; a failed read keeps the last good list.
 */
export function useAuthorityDids(): ReadonlySet<string> | null {
  const [dids, setDids] = useState<ReadonlySet<string> | null>(null);

  useEffect(() => {
    let alive = true;
    const apply = (list: Authority[]) => {
      if (alive) setDids(authorityDidSet(list));
    };
    const read = () => {
      getAuthorities({ refresh: true })
        .then(apply)
        .catch(() => {});
    };
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') read();
    };
    const unsubscribe = subscribeAuthorities(apply);
    document.addEventListener('visibilitychange', onVisibilityChange);
    read();
    return () => {
      alive = false;
      unsubscribe();
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, []);

  return dids;
}
