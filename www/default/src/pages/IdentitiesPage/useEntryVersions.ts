import { useCallback, useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';
import type { Identity } from '../../types';
import {
  entryVersions,
  membersWithRotations,
  rotationCount,
  type IdentityVersion,
  type RotationsByHash,
} from './identityVersions';

export type EntryVersionsState =
  | { status: 'loading' }
  | { status: 'error'; message: string; retry: () => void }
  | { status: 'ready'; versions: IdentityVersion[] };

interface FetchResult {
  key: string;
  rotations?: RotationsByHash;
  error?: string;
}

const NONE_TO_FETCH = '[]';
const NO_ROTATIONS: RotationsByHash = {};

/**
 * The versions of an entry, fetching the rotations of each member that has any when first
 * used. It fetches again only when a member's rotation count changes, so a live row update
 * does not; until that answers, the versions built from the earlier lists stay shown.
 */
export function useEntryVersions<T extends Identity>(
  members: T[],
  currentDid: string
): EntryVersionsState {
  const fetchKey = JSON.stringify(
    membersWithRotations(members).map(member => [member.identity_hash, rotationCount(member)])
  );
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<FetchResult>();

  useEffect(() => {
    if (fetchKey === NONE_TO_FETCH) return undefined;
    let active = true;
    const hashes = (JSON.parse(fetchKey) as Array<[string, number]>).map(([hash]) => hash);
    Promise.all(hashes.map(hash => apiClient.getIdentityRotations(hash))).then(
      lists => {
        if (!active) return;
        const rotations: RotationsByHash = {};
        hashes.forEach((hash, index) => {
          rotations[hash] = lists[index];
        });
        setResult({ key: fetchKey, rotations });
      },
      (error: unknown) => {
        if (!active) return;
        setResult({
          key: fetchKey,
          error: error instanceof Error && error.message ? error.message : 'Unknown error',
        });
      }
    );
    return () => {
      active = false;
    };
  }, [fetchKey, attempt]);

  const retry = useCallback(() => {
    setResult(undefined);
    setAttempt(value => value + 1);
  }, []);

  // A result for an earlier key keeps its versions shown while the new fetch runs.
  const rotations = fetchKey === NONE_TO_FETCH ? NO_ROTATIONS : result?.rotations;
  const versions = useMemo(
    () => (rotations ? entryVersions(members, currentDid, rotations) : undefined),
    [members, currentDid, rotations]
  );

  if (fetchKey !== NONE_TO_FETCH && result?.error && result.key === fetchKey) {
    return { status: 'error', message: result.error, retry };
  }
  return versions ? { status: 'ready', versions } : { status: 'loading' };
}
