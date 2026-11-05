import { useCallback, useMemo } from 'react';
import type { Identity } from '../../types';
import { groupIdentityVersions, type IdentityVersion } from './identityVersions';
import { matchesRecorderFilter, type RecorderFilter } from './recorderFilter';
import { isSharedManagedDid } from './sharedManagedDid';

type SurfaceRef = Pick<
  Identity,
  | 'surface_id'
  | 'surface_name'
  | 'surface_deleted'
  | 'channel_name'
  | 'channel_config_id'
  | 'origin'
>;

const NO_VERSIONS: IdentityVersion[] = [];

export interface SurfaceLink {
  id: string;
  name: string;
  deleted: boolean;
}

interface UseIdentityRowsOptions<T extends Identity> {
  identities: T[];
  channels?: Array<{ config_id: string; name: string }>;
  searchTerm: string;
  recorderFilter?: RecorderFilter;
}

export interface IdentityRowsView<T extends Identity> {
  /** One row per entry: the primary DID of a surface identity, or a lone identity. */
  filteredIdentities: T[];
  /** Number of entries before filtering. */
  entryCount: number;
  hasNamingMetadata: boolean;
  hasRecorderStatus: boolean;
  liveSurfaceNames: Map<string, string>;
  surfaceLinkFor: (identity: SurfaceRef) => SurfaceLink | null;
  surfaceLinksFor: (identity: SurfaceRef & Pick<Identity, 'managed_surfaces'>) => SurfaceLink[];
  /** The versions of the entry whose primary DID is `did`, newest first. */
  versionsFor: (did: string) => IdentityVersion[];
  /** Whether the entry whose primary DID is `did` had older rotations dropped. */
  rotationsDroppedFor: (did: string) => boolean;
  /** The identity whose DID is `did`, for the actions on an earlier version. */
  identityFor: (did: string) => T | undefined;
  /** The primary DID of the entry holding `did`, or `did` itself when no entry holds it. */
  primaryDidFor: (did: string) => string;
}

export function useIdentityRows<T extends Identity>({
  identities,
  channels,
  searchTerm,
  recorderFilter = 'all',
}: UseIdentityRowsOptions<T>): IdentityRowsView<T> {
  const hasNamingMetadata = useMemo(
    () =>
      identities.some(
        identity =>
          identity.origin !== undefined ||
          identity.display_name !== undefined ||
          identity.managed_surfaces !== undefined
      ),
    [identities]
  );

  const hasRecorderStatus = useMemo(
    () => identities.some(identity => Boolean(identity.trust_recorder)),
    [identities]
  );

  const liveSurfaceNames = useMemo(
    () => new Map((channels || []).map(channel => [channel.config_id, channel.name])),
    [channels]
  );

  const surfaceLinkFor = useCallback(
    (identity: SurfaceRef): SurfaceLink | null => {
      const deletedId = identity.surface_deleted
        ? identity.surface_id || identity.channel_config_id
        : undefined;
      if (deletedId) {
        const name = identity.surface_name || identity.channel_name || deletedId;
        return { id: deletedId, name, deleted: true };
      }
      if (identity.surface_id) {
        const name =
          liveSurfaceNames.get(identity.surface_id) ||
          identity.surface_name ||
          identity.channel_name ||
          identity.surface_id;
        return { id: identity.surface_id, name, deleted: false };
      }
      if (identity.origin !== 'managed' && identity.channel_name && identity.channel_config_id) {
        return { id: identity.channel_config_id, name: identity.channel_name, deleted: false };
      }
      return null;
    },
    [liveSurfaceNames]
  );

  const surfaceLinksFor = useCallback(
    (identity: SurfaceRef & Pick<Identity, 'managed_surfaces'>): SurfaceLink[] => {
      if (isSharedManagedDid(identity)) {
        return (identity.managed_surfaces ?? []).map(surface => ({
          id: surface.surface_id,
          name:
            liveSurfaceNames.get(surface.surface_id) || surface.surface_name || surface.surface_id,
          deleted: false,
        }));
      }
      const link = surfaceLinkFor(identity);
      return link ? [link] : [];
    },
    [liveSurfaceNames, surfaceLinkFor]
  );

  const entries = useMemo(() => groupIdentityVersions(identities), [identities]);

  const { versionsByPrimary, droppedByPrimary, primaryByDid } = useMemo(() => {
    const versions = new Map<string, IdentityVersion[]>();
    const dropped = new Set<string>();
    const primaries = new Map<string, string>();
    entries.forEach(entry => {
      versions.set(entry.primary.did, entry.versions);
      if (entry.rotationsDropped) dropped.add(entry.primary.did);
      entry.dids.forEach(did => primaries.set(did, entry.primary.did));
    });
    return { versionsByPrimary: versions, droppedByPrimary: dropped, primaryByDid: primaries };
  }, [entries]);

  const versionsFor = useCallback(
    (did: string) => versionsByPrimary.get(did) ?? NO_VERSIONS,
    [versionsByPrimary]
  );

  const rotationsDroppedFor = useCallback(
    (did: string) => droppedByPrimary.has(did),
    [droppedByPrimary]
  );

  const identitiesByDid = useMemo(
    () => new Map(identities.map(identity => [identity.did, identity])),
    [identities]
  );

  const identityFor = useCallback((did: string) => identitiesByDid.get(did), [identitiesByDid]);

  const primaryDidFor = useCallback((did: string) => primaryByDid.get(did) ?? did, [primaryByDid]);

  const filteredIdentities = useMemo(() => {
    const searchLower = searchTerm.trim().toLowerCase();
    return entries
      .filter(({ primary, dids }) => {
        if (hasRecorderStatus && !matchesRecorderFilter(primary, recorderFilter)) return false;
        if (!searchLower) return true;
        return [
          primary.name,
          ...dids,
          primary.origin === 'managed' ? undefined : primary.channel_name,
          primary.identity_hash,
          primary.display_name,
          primary.surface_name,
          primary.credential_principal?.name,
          ...(primary.managed_surfaces ?? []).map(surface => surface.surface_name),
        ].some(value => typeof value === 'string' && value.toLowerCase().includes(searchLower));
      })
      .map(entry => entry.primary);
  }, [entries, searchTerm, hasRecorderStatus, recorderFilter]);

  return {
    filteredIdentities,
    entryCount: entries.length,
    hasNamingMetadata,
    hasRecorderStatus,
    liveSurfaceNames,
    surfaceLinkFor,
    surfaceLinksFor,
    versionsFor,
    rotationsDroppedFor,
    identityFor,
    primaryDidFor,
  };
}
