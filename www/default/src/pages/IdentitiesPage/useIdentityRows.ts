import { useCallback, useMemo } from 'react';
import type { Identity } from '../../types';

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

interface UseIdentityRowsOptions<T extends Identity> {
  identities: T[];
  channels?: Array<{ config_id: string; name: string }>;
  searchTerm: string;
  showUnnamedOnly: boolean;
}

export interface IdentityRowsView<T extends Identity> {
  filteredIdentities: T[];
  hasNamingMetadata: boolean;
  unnamedCount: number;
  liveSurfaceNames: Map<string, string>;
  surfaceLinkFor: (identity: SurfaceRef) => SurfaceLink | null;
}

export function useIdentityRows<T extends Identity>({
  identities,
  channels,
  searchTerm,
  showUnnamedOnly,
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

  const unnamedCount = useMemo(() => identities.filter(isUnnamed).length, [identities]);

  const filteredIdentities = useMemo(() => {
    const searchLower = searchTerm.trim().toLowerCase();
    return identities.filter(identity => {
      if (hasNamingMetadata && showUnnamedOnly && !isUnnamed(identity)) return false;
      if (!searchLower) return true;
      return [
        identity.name,
        identity.did,
        identity.channel_name,
        identity.identity_hash,
        identity.display_name,
        identity.surface_name,
        identity.credential_principal?.name,
      ].some(value => typeof value === 'string' && value.toLowerCase().includes(searchLower));
    });
  }, [identities, searchTerm, hasNamingMetadata, showUnnamedOnly]);

  return {
    filteredIdentities,
    hasNamingMetadata,
    unnamedCount,
    liveSurfaceNames,
    surfaceLinkFor,
  };
}
