import { useCallback, useMemo } from 'react';
import type { Identity } from '../../types';
import { groupIdentityVersions, type IdentityVersion } from './identityVersions';
import { matchesRecorderFilter, type RecorderFilter } from './recorderFilter';

type SurfaceRef = Pick<
  Identity,
  'surface_id' | 'surface_name' | 'channel_name' | 'channel_config_id'
>;

const isUnnamed = (identity: Pick<Identity, 'display_name' | 'display_name_pending'>): boolean =>
  !identity.display_name && identity.display_name_pending !== true;

const NO_VERSIONS: IdentityVersion[] = [];

export interface SurfaceLink {
  id: string;
  name: string;
}

interface UseIdentityRowsOptions<T extends Identity> {
  identities: T[];
  channels?: Array<{ config_id: string; name: string }>;
  searchTerm: string;
  showUnnamedOnly: boolean;
  recorderFilter?: RecorderFilter;
}

export interface IdentityRowsView<T extends Identity> {
  /** One row per entry: the primary DID of a surface identity, or a lone identity. */
  filteredIdentities: T[];
  /** Number of entries before filtering. */
  entryCount: number;
  hasNamingMetadata: boolean;
  hasRecorderStatus: boolean;
  unnamedCount: number;
  liveSurfaceNames: Map<string, string>;
  surfaceLinkFor: (identity: SurfaceRef) => SurfaceLink | null;
  /** The versions of the entry whose primary DID is `did`, newest first. */
  versionsFor: (did: string) => IdentityVersion[];
  /** The primary DID of the entry holding `did`, or `did` itself when no entry holds it. */
  primaryDidFor: (did: string) => string;
}

export function useIdentityRows<T extends Identity>({
  identities,
  channels,
  searchTerm,
  showUnnamedOnly,
  recorderFilter = 'all',
}: UseIdentityRowsOptions<T>): IdentityRowsView<T> {
  const hasNamingMetadata = useMemo(
    () =>
      identities.some(
        identity =>
          identity.origin !== undefined ||
          identity.display_name !== undefined ||
          identity.name_conflict !== undefined
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
      if (identity.surface_id) {
        const name =
          liveSurfaceNames.get(identity.surface_id) ||
          identity.surface_name ||
          identity.channel_name ||
          identity.surface_id;
        return { id: identity.surface_id, name };
      }
      if (identity.channel_name && identity.channel_config_id) {
        return { id: identity.channel_config_id, name: identity.channel_name };
      }
      return null;
    },
    [liveSurfaceNames]
  );

  const entries = useMemo(() => groupIdentityVersions(identities), [identities]);

  const { versionsByPrimary, primaryByDid } = useMemo(() => {
    const versions = new Map<string, IdentityVersion[]>();
    const primaries = new Map<string, string>();
    entries.forEach(entry => {
      versions.set(entry.primary.did, entry.versions);
      entry.dids.forEach(did => primaries.set(did, entry.primary.did));
    });
    return { versionsByPrimary: versions, primaryByDid: primaries };
  }, [entries]);

  const versionsFor = useCallback(
    (did: string) => versionsByPrimary.get(did) ?? NO_VERSIONS,
    [versionsByPrimary]
  );

  const primaryDidFor = useCallback((did: string) => primaryByDid.get(did) ?? did, [primaryByDid]);

  const unnamedCount = useMemo(
    () => entries.filter(entry => isUnnamed(entry.primary)).length,
    [entries]
  );

  const filteredIdentities = useMemo(() => {
    const searchLower = searchTerm.trim().toLowerCase();
    return entries
      .filter(({ primary, dids }) => {
        if (hasNamingMetadata && showUnnamedOnly && !isUnnamed(primary)) return false;
        if (hasRecorderStatus && !matchesRecorderFilter(primary, recorderFilter)) return false;
        if (!searchLower) return true;
        return [
          primary.name,
          ...dids,
          primary.channel_name,
          primary.identity_hash,
          primary.display_name,
          primary.surface_name,
          primary.credential_principal?.name,
        ].some(value => typeof value === 'string' && value.toLowerCase().includes(searchLower));
      })
      .map(entry => entry.primary);
  }, [entries, searchTerm, hasNamingMetadata, showUnnamedOnly, hasRecorderStatus, recorderFilter]);

  return {
    filteredIdentities,
    entryCount: entries.length,
    hasNamingMetadata,
    hasRecorderStatus,
    unnamedCount,
    liveSurfaceNames,
    surfaceLinkFor,
    versionsFor,
    primaryDidFor,
  };
}
