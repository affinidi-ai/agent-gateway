import type { Identity } from '../../types';

/** A shared managed DID is the managed agent on more than one live surface. */
export const isSharedManagedDid = (identity: Pick<Identity, 'managed_surfaces'>): boolean =>
  (identity.managed_surfaces?.length ?? 0) > 1;

export const surfaceCountLabel = (count: number): string =>
  `${count} ${count === 1 ? 'surface' : 'surfaces'}`;
