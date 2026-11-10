import type { Identity } from '../../types';

export interface FieldChange {
  field: string;
  /** Absent when the field was added, and for every field of the first version. */
  from?: unknown;
  /** Absent when the field was removed. */
  to?: unknown;
}

export interface IdentityVersion {
  /** 1 for the oldest version of the entry. */
  number: number;
  kind: 'did' | 'rotation';
  did: string;
  /** `null` for a rotation recorded before the gateway tracked rotations. */
  at: string | null;
  changes: FieldChange[];
  current: boolean;
}

export interface IdentityEntry<T extends Identity> {
  /** The most recently used DID, with the usage count summed and last use taken across versions. */
  primary: T;
  /** Every DID of the entry, the primary included. */
  dids: string[];
  /** Newest first; empty for a single DID that was never rotated. */
  versions: IdentityVersion[];
}

type Fields = Record<string, unknown>;

const time = (value?: string | null): number => {
  const parsed = value ? Date.parse(value) : NaN;
  return Number.isNaN(parsed) ? 0 : parsed;
};

const lastUse = (identity: Identity): string | undefined =>
  identity.last_used_at || identity.last_used || undefined;

const usageOf = (identity: Identity): number => identity.usage_count || identity.use_count || 0;

/**
 * `mtls`, `api_key` or `jwt_claim` for a credential-derived identity, `a2a_proxy` for a
 * managed synthetic identity, `payload` otherwise.
 */
const sourceOf = (identity: Identity): string => {
  const type = identity.agent_identity?.credential_type;
  return typeof type === 'string' ? type : 'payload';
};

/** A managed identity derived from a stored certificate or API key, whose rotations are recorded. */
export const recordsRotations = (identity: Identity): boolean =>
  identity.origin === 'managed' && ['mtls', 'api_key'].includes(sourceOf(identity));

/**
 * A surface has one Managed Agent, so its managed identities, from its responses and from
 * its requests through any Transit Point, whatever their source, are versions of each other.
 * A `from_jwt_claim` DID is one parallel agent per claim value, so it is never grouped.
 */
const groupKey = (identity: Identity): string => {
  if (identity.origin !== 'managed' || !identity.surface_id || sourceOf(identity) === 'jwt_claim') {
    return `did|${identity.did}`;
  }
  return `surface|${identity.surface_id}`;
};

/** The identity's fields before its rotation at `index`; `rotations.length` gives the current ones. */
function fieldsBefore(identity: Identity, index: number): Fields {
  const rotations = identity.rotations ?? [];
  const fields: Fields = { ...(identity.agent_identity ?? {}) };
  for (let i = rotations.length - 1; i >= index; i--) {
    Object.assign(fields, rotations[i].previous ?? {});
  }
  return fields;
}

function diff(before: Fields | undefined, after: Fields): FieldChange[] {
  if (!before) {
    return Object.keys(after)
      .sort()
      .map(field => ({ field, to: after[field] }));
  }
  const fields = Array.from(new Set([...Object.keys(before), ...Object.keys(after)])).sort();
  return fields.flatMap(field => {
    const inBefore = field in before;
    const inAfter = field in after;
    if (inBefore && inAfter && JSON.stringify(before[field]) === JSON.stringify(after[field])) {
      return [];
    }
    const change: FieldChange = { field };
    if (inBefore) change.from = before[field];
    if (inAfter) change.to = after[field];
    return [change];
  });
}

/**
 * One timeline of the entry's DIDs and the credential rotations inside them, newest first.
 * A new DID is compared with the DID created before it, a rotation with its DID's fields
 * before it. A rotation of unknown time is placed at its DID's creation.
 */
function timeline<T extends Identity>(members: T[], currentDid: string): IdentityVersion[] {
  const byCreation = [...members].sort((a, b) => time(a.created_at) - time(b.created_at));
  const events: Array<Omit<IdentityVersion, 'number' | 'current'> & { sortAt: number }> = [];
  let previousDidFields: Fields | undefined;

  byCreation.forEach(identity => {
    const rotations = identity.rotations ?? [];
    const created = fieldsBefore(identity, 0);
    events.push({
      kind: 'did',
      did: identity.did,
      at: identity.created_at,
      changes: diff(previousDidFields, created),
      sortAt: time(identity.created_at),
    });
    rotations.forEach((rotation, index) => {
      events.push({
        kind: 'rotation',
        did: identity.did,
        at: rotation.rotated_at,
        changes: diff(fieldsBefore(identity, index), fieldsBefore(identity, index + 1)),
        sortAt: rotation.rotated_at ? time(rotation.rotated_at) : time(identity.created_at),
      });
    });
    previousDidFields = fieldsBefore(identity, rotations.length);
  });

  const ordered = events
    .map((event, position) => ({ event, position }))
    .sort((a, b) => a.event.sortAt - b.event.sortAt || a.position - b.position)
    .map(({ event }) => event);
  const currentIndex = ordered.map(event => event.did).lastIndexOf(currentDid);

  return ordered
    .map(({ sortAt: _sortAt, ...event }, index) => ({
      ...event,
      number: index + 1,
      current: index === currentIndex,
    }))
    .reverse();
}

function entryOf<T extends Identity>(members: T[]): IdentityEntry<T> {
  const latest = members.reduce((best, member) =>
    time(lastUse(member)) > time(lastUse(best)) ? member : best
  );
  const dids = members.map(member => member.did);
  if (members.length === 1) {
    return {
      primary: latest,
      dids,
      versions: latest.rotations?.length ? timeline(members, latest.did) : [],
    };
  }
  return {
    primary: {
      ...latest,
      usage_count: members.reduce((sum, member) => sum + usageOf(member), 0),
      last_used_at: lastUse(latest),
    },
    dids,
    versions: timeline(members, latest.did),
  };
}

/**
 * One entry per surface Managed Agent: a surface's managed DIDs are its versions, with the
 * most recently used DID as the primary. Every other identity is an entry of its own.
 * Entries keep the order of their first identity.
 */
export function groupIdentityVersions<T extends Identity>(identities: T[]): IdentityEntry<T>[] {
  const groups = new Map<string, T[]>();
  identities.forEach(identity => {
    const key = groupKey(identity);
    const members = groups.get(key) ?? [];
    members.push(identity);
    groups.set(key, members);
  });
  return Array.from(groups.values()).map(entryOf);
}
