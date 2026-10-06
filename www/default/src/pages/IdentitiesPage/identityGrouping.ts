import type { CredentialPrincipal } from '../../types';

export interface GroupableIdentity {
  did: string;
  created_at?: string;
  last_used_at?: string;
  last_used?: string;
  identity_hash?: string;
  agent_identity?: Record<string, unknown>;
  credential_principal?: CredentialPrincipal;
  group_key?: string;
}

export type IdentityChangeKind = 'did' | 'credential' | 'claims';

export interface IdentityChange<T extends GroupableIdentity> {
  at?: string;
  kinds: IdentityChangeKind[];
  changedClaims: string[];
  previous: T;
  current: T;
}

export interface IdentityGroup<T extends GroupableIdentity> {
  key: string;
  primary: T;
  members: T[];
  changes: IdentityChange<T>[];
}

const toTime = (value?: string): number => {
  if (!value) return 0;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
};

export const lastActivityTime = (identity: GroupableIdentity): number =>
  toTime(identity.last_used_at || identity.last_used || identity.created_at);

const creationTime = (identity: GroupableIdentity): number =>
  toTime(identity.created_at) || lastActivityTime(identity);

export const groupKeyOf = (identity: GroupableIdentity): string =>
  identity.group_key || `did:${identity.did}`;

const stableStringify = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value) ?? 'undefined';
};

export const changedClaimKeys = (
  previous?: Record<string, unknown>,
  current?: Record<string, unknown>
): string[] => {
  const before = previous ?? {};
  const after = current ?? {};
  return Array.from(new Set([...Object.keys(before), ...Object.keys(after)]))
    .filter(key => stableStringify(before[key]) !== stableStringify(after[key]))
    .sort();
};

const diff = <T extends GroupableIdentity>(previous: T, current: T): IdentityChange<T> => {
  const kinds: IdentityChangeKind[] = [];
  if (previous.did !== current.did) kinds.push('did');
  if (
    previous.credential_principal?.id !== current.credential_principal?.id ||
    previous.identity_hash !== current.identity_hash
  ) {
    kinds.push('credential');
  }
  const changedClaims = changedClaimKeys(previous.agent_identity, current.agent_identity);
  if (changedClaims.length > 0) kinds.push('claims');
  return { at: current.created_at, kinds, changedClaims, previous, current };
};

export function groupIdentities<T extends GroupableIdentity>(identities: T[]): IdentityGroup<T>[] {
  const buckets = new Map<string, T[]>();
  identities.forEach(identity => {
    const key = groupKeyOf(identity);
    const bucket = buckets.get(key);
    if (bucket) bucket.push(identity);
    else buckets.set(key, [identity]);
  });

  return Array.from(buckets.entries()).map(([key, members]) => {
    const primary = members.reduce((latest, candidate) =>
      lastActivityTime(candidate) > lastActivityTime(latest) ? candidate : latest
    );
    const chronological = [...members].sort((a, b) => creationTime(a) - creationTime(b));
    const changes = chronological
      .slice(1)
      .map((current, index) => diff(chronological[index], current))
      .filter(change => change.kinds.length > 0);
    return { key, primary, members, changes };
  });
}
