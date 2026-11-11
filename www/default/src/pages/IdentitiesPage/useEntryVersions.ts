import { useCallback, useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';
import type { Identity } from '../../types';
import {
  entryVersions,
  membersWithRotations,
  rotationCount,
  timelineFields,
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
 * does not; until that answers it is loading, because the earlier lists do not match the
 * updated fields. Unmounting aborts the fetch.
 */
export function useEntryVersions<T extends Identity>(
  members: T[],
  currentDid: string
): EntryVersionsState {
  const fetchKey = JSON.stringify(
    membersWithRotations(members).map(member => [member.identity_hash, rotationCount(member)])
  );
  const timelineKey = JSON.stringify(members.map(timelineFields));
  const [timelineMembers, setTimelineMembers] = useState({ key: timelineKey, members });
  if (timelineMembers.key !== timelineKey) {
    setTimelineMembers({ key: timelineKey, members });
  }
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<FetchResult>();

  useEffect(() => {
    if (fetchKey === NONE_TO_FETCH) return undefined;
    const controller = new AbortController();
    const hashes = (JSON.parse(fetchKey) as Array<[string, number]>).map(([hash]) => hash);
    Promise.all(hashes.map(hash => apiClient.getIdentityRotations(hash, controller.signal))).then(
      lists => {
        if (controller.signal.aborted) return;
        const rotations: RotationsByHash = {};
        hashes.forEach((hash, index) => {
          rotations[hash] = lists[index];
        });
        setResult({ key: fetchKey, rotations });
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        setResult({
          key: fetchKey,
          error: error instanceof Error && error.message ? error.message : 'Unknown error',
        });
      }
    );
    return () => {
      controller.abort();
    };
  }, [fetchKey, attempt]);

  const retry = useCallback(() => {
    setResult(undefined);
    setAttempt(value => value + 1);
  }, []);

  const current = result?.key === fetchKey ? result : undefined;
  const rotations = fetchKey === NONE_TO_FETCH ? NO_ROTATIONS : current?.rotations;
  const versions = useMemo(
    () => (rotations ? entryVersions(timelineMembers.members, currentDid, rotations) : undefined),
    [timelineMembers, currentDid, rotations]
  );

  if (fetchKey !== NONE_TO_FETCH && current?.error) {
    return { status: 'error', message: current.error, retry };
  }
  return versions ? { status: 'ready', versions } : { status: 'loading' };
}
