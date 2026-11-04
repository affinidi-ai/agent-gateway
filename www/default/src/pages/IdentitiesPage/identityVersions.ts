import type { Identity, ManagedSlot } from '../../types';

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

const slotKey = (slot?: ManagedSlot): string | undefined => {
  if (!slot) return undefined;
  return slot.kind === 'transit_point' ? `transit_point:${slot.alias}` : 'protected';
};

/**
 * Managed identities of one surface, source and slot are versions of each other. A
 * `from_jwt_claim` DID is one parallel agent per claim value, so it is never grouped.
 */
const surfaceSourceKey = (identity: Identity): string | undefined => {
  if (identity.origin !== 'managed' || !identity.surface_id) return undefined;
  const source = sourceOf(identity);
  if (source === 'jwt_claim') return undefined;
  return `${identity.surface_id}|${source}`;
};

/**
 * Group key of each identity: records written before slot tracking join the only slot of
 * their surface and source, or stay together apart from the slotted ones when there are
 * several.
 */
function groupKeys<T extends Identity>(identities: T[]): Map<T, string> {
  const slotsBySurfaceSource = new Map<string, Set<string>>();
  identities.forEach(identity => {
    const base = surfaceSourceKey(identity);
    const slot = slotKey(identity.slot);
    if (!base || !slot) return;
    const slots = slotsBySurfaceSource.get(base) ?? new Set<string>();
    slots.add(slot);
    slotsBySurfaceSource.set(base, slots);
  });

  return new Map(
    identities.map(identity => {
      const base = surfaceSourceKey(identity);
      if (!base) return [identity, `did|${identity.did}`];
      const slots = slotsBySurfaceSource.get(base);
      const slot = slotKey(identity.slot) ?? (slots?.size === 1 ? [...slots][0] : 'unrecorded');
      return [identity, `${base}|${slot}`];
    })
  );
}

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
 * One entry per surface identity: a surface's managed DIDs of the same source and slot are
 * its versions, with the most recently used DID as the primary. Every other identity is an
 * entry of its own. Entries keep the order of their first identity.
 */
export function groupIdentityVersions<T extends Identity>(identities: T[]): IdentityEntry<T>[] {
  const keys = groupKeys(identities);
  const groups = new Map<string, T[]>();
  identities.forEach(identity => {
    const key = keys.get(identity)!;
    const members = groups.get(key) ?? [];
    members.push(identity);
    groups.set(key, members);
  });
  return Array.from(groups.values()).map(entryOf);
}
