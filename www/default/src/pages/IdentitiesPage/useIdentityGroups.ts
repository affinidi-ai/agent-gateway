import { useCallback, useMemo } from 'react';
import type { Identity } from '../../types';
import { groupIdentities, IdentityGroup } from './identityGrouping';

type SurfaceRef = Pick<
  Identity,
  'surface_id' | 'surface_name' | 'channel_name' | 'channel_config_id'
>;

const isUnnamed = (identity: Pick<Identity, 'display_name' | 'display_name_pending'>): boolean =>
  !identity.display_name && identity.display_name_pending !== true;

export interface SurfaceLink {
  id: string;
  name: string;
}

interface UseIdentityGroupsOptions<T extends Identity> {
  identities: T[];
  channels?: Array<{ config_id: string; name: string }>;
  searchTerm: string;
  showUnnamedOnly: boolean;
}

export interface IdentityGroupsView<T extends Identity> {
  identityGroups: IdentityGroup<T>[];
  filteredGroups: IdentityGroup<T>[];
  hasNamingMetadata: boolean;
  unnamedCount: number;
  liveSurfaceNames: Map<string, string>;
  surfaceLinkFor: (identity: SurfaceRef) => SurfaceLink | null;
}

export function useIdentityGroups<T extends Identity>({
  identities,
  channels,
  searchTerm,
  showUnnamedOnly,
}: UseIdentityGroupsOptions<T>): IdentityGroupsView<T> {
  const identityGroups = useMemo(() => groupIdentities(identities), [identities]);

  const hasNamingMetadata = useMemo(
    () =>
      identities.some(
        identity =>
          identity.origin !== undefined ||
          identity.display_name !== undefined ||
          identity.group_key !== undefined ||
          identity.name_conflict !== undefined
      ),
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

  const unnamedCount = useMemo(
    () => identityGroups.filter(group => isUnnamed(group.primary)).length,
    [identityGroups]
  );

  const filteredGroups = useMemo(() => {
    const searchLower = searchTerm.trim().toLowerCase();
    return identityGroups.filter(group => {
      if (hasNamingMetadata && showUnnamedOnly && !isUnnamed(group.primary)) return false;
      if (!searchLower) return true;
      return group.members.some(identity =>
        [
          identity.name,
          identity.did,
          identity.channel_name,
          identity.identity_hash,
          identity.display_name,
          identity.surface_name,
          identity.credential_principal?.name,
        ].some(value => typeof value === 'string' && value.toLowerCase().includes(searchLower))
      );
    });
  }, [identityGroups, searchTerm, hasNamingMetadata, showUnnamedOnly]);

  return {
    identityGroups,
    filteredGroups,
    hasNamingMetadata,
    unnamedCount,
    liveSurfaceNames,
    surfaceLinkFor,
  };
}
