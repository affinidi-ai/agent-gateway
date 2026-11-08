import { useCallback, useMemo } from 'react';
import type { Identity } from '../../types';
import { matchesRecorderFilter, type RecorderFilter } from './recorderFilter';
import { isSharedManagedDid } from './sharedManagedDid';

type SurfaceRef = Pick<
  Identity,
  'surface_id' | 'surface_name' | 'channel_name' | 'channel_config_id' | 'origin'
>;

export interface SurfaceLink {
  id: string;
  name: string;
}

interface UseIdentityRowsOptions<T extends Identity> {
  identities: T[];
  channels?: Array<{ config_id: string; name: string }>;
  searchTerm: string;
  recorderFilter?: RecorderFilter;
}

export interface IdentityRowsView<T extends Identity> {
  filteredIdentities: T[];
  hasNamingMetadata: boolean;
  hasRecorderStatus: boolean;
  liveSurfaceNames: Map<string, string>;
  surfaceLinkFor: (identity: SurfaceRef) => SurfaceLink | null;
  surfaceLinksFor: (identity: SurfaceRef & Pick<Identity, 'managed_surfaces'>) => SurfaceLink[];
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
      if (identity.surface_id) {
        const name =
          liveSurfaceNames.get(identity.surface_id) ||
          identity.surface_name ||
          identity.channel_name ||
          identity.surface_id;
        return { id: identity.surface_id, name };
      }
      if (identity.origin !== 'managed' && identity.channel_name && identity.channel_config_id) {
        return { id: identity.channel_config_id, name: identity.channel_name };
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
        }));
      }
      const link = surfaceLinkFor(identity);
      return link ? [link] : [];
    },
    [liveSurfaceNames, surfaceLinkFor]
  );

  const filteredIdentities = useMemo(() => {
    const searchLower = searchTerm.trim().toLowerCase();
    return identities.filter(identity => {
      if (hasRecorderStatus && !matchesRecorderFilter(identity, recorderFilter)) return false;
      if (!searchLower) return true;
      return [
        identity.name,
        identity.did,
        identity.origin === 'managed' ? undefined : identity.channel_name,
        identity.identity_hash,
        identity.display_name,
        identity.surface_name,
        identity.credential_principal?.name,
        ...(identity.managed_surfaces ?? []).map(surface => surface.surface_name),
      ].some(value => typeof value === 'string' && value.toLowerCase().includes(searchLower));
    });
  }, [identities, searchTerm, hasRecorderStatus, recorderFilter]);

  return {
    filteredIdentities,
    hasNamingMetadata,
    hasRecorderStatus,
    liveSurfaceNames,
    surfaceLinkFor,
    surfaceLinksFor,
  };
}
